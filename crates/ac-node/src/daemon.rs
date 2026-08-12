//! The client's event loop.
//!
//! `ac-net` builds the swarm and owns the protocols; this drives it. What it deliberately
//! does *not* do is decide who to talk to.
//!
//! Discovery reports every peer the server knows about, and this module dials none of
//! them. Choosing which are worth connecting to is a product decision — group membership
//! in milestone 2 — and the app layer will make it. Dialling itself is already available
//! (`Swarm::dial`), and who is currently connected is already answerable
//! (`Swarm::connected_peers`), so no interface is invented here ahead of a real caller.
//!
//! # Admission
//!
//! What it *does* decide is who may stay. Every peer connection runs a mutual attestation
//! exchange — see [`ac_net::admission`] — and one that does not complete is closed. That is an
//! authorization check on a live connection, not on the act of connecting, and the
//! distinction is the one `ac_net::authz` spends its module docs on: the credential is
//! signed by the server, so verifying it needs no prior knowledge of the peer and cannot
//! deadlock the way a locally-held trust list does.

use std::time::Instant;

use anyhow::{Context, Result};
use libp2p::futures::StreamExt;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, autonat, identify, mdns, ping, relay, rendezvous, request_response, upnp};

use crate::file_link::FileLink;
use crate::group_link::GroupLink;
use crate::peer_link::PeerLink;
use ac_net::admission::{Admission, AdmissionAction, AdmissionEvent, Notice as AdmissionNotice};
use ac_net::attest;
use ac_net::authz::AcceptAnyPeer;
use ac_net::config::{Config, Paths};
use ac_net::connectivity::Connectivity;
use ac_net::identity::Identity;
use ac_net::link::{HOUSEKEEPING_TICK, ServerLink};
use ac_net::proto::{AttestRequest, PeerAttestRequest, PeerAttestResponse};
use ac_net::swarm::{AcBehaviourEvent, Role, build};

/// This node's application layer: four protocols in one slot.
///
/// They live in `ac-groups`, `ac-files` and `ac-peers`, none of which can add a field to
/// `AcBehaviour` from outside its own crate — so the binary supplies them through the app slot
/// instead. That is the whole reason the slot exists, and why `ac-net` names no group, file or
/// session type.
///
/// Composed here rather than in `ac-net` because the slot takes exactly one behaviour and this
/// is the only place that knows which ones a client speaks. The derive generates `AppEvent`
/// with a variant per field, which is what the routing below matches on.
///
/// `blobs` is a bare stream protocol rather than request-response: a file is far too large to
/// buffer as one message, and chunking it would mean reassembling out-of-order pieces, hashing
/// in a second pass, and reading from disk inside the event loop.
///
/// `sessions` is the odd one out: it carries no data at all, only the question "are you done
/// with me too?". It obeys the slot's first rule the same as the rest — it may *ask* to close
/// a connection and can never refuse one.
#[derive(libp2p::swarm::NetworkBehaviour)]
pub struct App {
    pub groups: ac_groups::wire::Behaviour,
    pub manifests: ac_files::wire::Behaviour,
    pub blobs: libp2p_stream::Behaviour,
    pub sessions: ac_peers::wire::Behaviour,
}

/// None of these is const-constructible, so this is a function where the `dummy::Behaviour` it
/// replaced was a `const`.
pub fn app() -> App {
    App {
        groups: ac_groups::wire::behaviour(),
        manifests: ac_files::wire::behaviour(),
        blobs: libp2p_stream::Behaviour::new(),
        sessions: ac_peers::wire::behaviour(),
    }
}

/// A convenient alias for the concrete swarm this module drives.
pub type ClientSwarm = libp2p::Swarm<ac_net::swarm::AcBehaviour<AcceptAnyPeer, App>>;

/// Listen, optionally dial, and run until interrupted.
///
/// The authorizer is [`AcceptAnyPeer`]: a client accepts connections from anyone, because
/// refusing by identity would prevent a peer from ever delivering the group membership
/// proof that authorizes it. Resource limits, not identity, bound what a stranger costs.
pub async fn run(
    identity: &Identity,
    config: &Config,
    paths: &Paths,
    dial: &[Multiaddr],
) -> Result<()> {
    let mut swarm = build(identity, config, Role::Client, AcceptAnyPeer, app())
        .context("building the swarm")?;

    println!("peer {}", identity.peer_id());

    for addr in dial {
        swarm
            .dial(addr.clone())
            .with_context(|| format!("dialling {addr}"))?;
        tracing::info!(%addr, "dialling");
    }

    // Each step waits for what the previous one produces — see `ServerLink`.
    let mut link = match &config.server {
        Some(server) => {
            swarm
                .dial(server.clone())
                .with_context(|| format!("dialling the server at {server}"))?;
            tracing::info!(%server, "dialling the server");
            ServerLink::for_server(server)
        }
        None => None,
    };

    // Admission. Always present, including on a node that has never enrolled: such a node
    // has nothing to verify anyone against, so it closes every peer connection rather than
    // leaving one open and unchecked.
    let (mut admission, notes) = Admission::load(
        &paths.attestation_file(),
        identity.peer_id(),
        link.as_ref().map(|l| l.server),
        attest::now(),
    );
    for note in notes {
        report_admission(&note);
    }

    // The application layer. Its store is the same `state.sqlite` the CLI writes, which is
    // how `ac group add` in another process reaches a running daemon.
    let mut groups = GroupLink::open(paths, identity)?;
    let mut files = FileLink::open(paths, identity)?;
    // The supervisor. Opened last because it needs the server's peer id, which comes from the
    // link above — presence is asked of the server and the server is never hung up on.
    let mut peers = PeerLink::open(paths, identity, link.as_ref().map(|l| l.server))?;

    // Inbound blob streams do not arrive as swarm events; `libp2p_stream` hands them over on
    // this handle instead, which is why it is taken once here and polled in the loop.
    let mut blobs = FileLink::accept_blobs(&mut swarm)?;

    // How each peer is reachable, and why. The only record of whether milestone 1's
    // headline claim — relayed connections upgrade to direct — actually held.
    let mut connectivity = Connectivity::default();

    // One clock for both schedules the supervisor keeps — reconnection and re-discovery.
    // Neither needs sub-second precision, and a single tick is easier to reason about than
    // two futures racing in the `select!`.
    let mut tick = tokio::time::interval(HOUSEKEEPING_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = tick.tick() => {
                if let Some(link) = &mut link {
                    link.housekeeping(&mut swarm);
                }
                let server_connected = admission
                    .server()
                    .is_some_and(|server| swarm.is_connected(&server));
                let actions = admission.on(AdmissionEvent::Tick {
                    now: Instant::now(),
                    at: attest::now(),
                    server_connected,
                });
                dispatch_admission(&mut swarm, actions, &mut groups, &mut files, &mut peers);
                groups.housekeeping(&mut swarm, &connectivity, Instant::now(), attest::now());
                files.housekeeping(&mut swarm, &connectivity, Instant::now(), attest::now());
                // Last, so it sees the round outcomes the file layer produced this turn.
                peers.housekeeping(&mut swarm, &mut files, &mut groups, &connectivity, attest::now());
            }

            event = swarm.select_next_some() => {
                track(&mut connectivity, &swarm, &event);

                // Admission runs before the `ServerLink` arm so that a peer which fails
                // the check is closed in the same turn it was seen, rather than lingering
                // for a tick. The server itself is exempt and skipped inside.
                match &event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        let actions = admission.on(AdmissionEvent::Connected {
                            peer: *peer_id,
                            now: Instant::now(),
                        });
                        dispatch_admission(&mut swarm, actions, &mut groups, &mut files, &mut peers);
                    }
                    SwarmEvent::ConnectionClosed { peer_id, .. } => {
                        let still_connected = swarm.is_connected(peer_id);
                        let actions = admission.on(AdmissionEvent::Disconnected {
                            peer: *peer_id,
                            still_connected,
                        });
                        dispatch_admission(&mut swarm, actions, &mut groups, &mut files, &mut peers);
                        if !still_connected {
                            groups.on_disconnected(&mut swarm, *peer_id);
                            files.on_disconnected(&mut swarm, *peer_id);
                            peers.on_disconnected(&mut swarm, &mut files, &mut groups, *peer_id);
                        }
                    }
                    // The one discovery path that needs no server at all, so it is handled
                    // here rather than inside the `ServerLink` arm below. An mDNS address is
                    // direct by construction, which makes it strictly better than the circuit
                    // the supervisor would otherwise build.
                    SwarmEvent::Behaviour(AcBehaviourEvent::Mdns(mdns::Event::Discovered(found))) => {
                        for (peer, addr) in found {
                            peers.discovered(
                                *peer,
                                std::slice::from_ref(addr),
                                &mut files,
                                &mut groups,
                                &mut swarm,
                            );
                        }
                    }
                    // A dial that never landed. The supervisor's backoff already advanced
                    // when the attempt went out — this is what stops the peer also being
                    // treated as online, so the next round rotates past them.
                    SwarmEvent::OutgoingConnectionError { peer_id: Some(peer), .. } => {
                        peers.dial_failed(&mut swarm, &mut files, &mut groups, *peer);
                    }
                    _ => {}
                }

                if let Some(link) = &mut link {
                    match &event {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            link.reserve(&mut swarm, *peer_id);
                        }
                        SwarmEvent::ConnectionClosed { peer_id, .. } => {
                            link.on_disconnected(*peer_id, swarm.is_connected(peer_id));
                        }
                        // Registering needs an external address, and on a NATed node the
                        // first one to exist is the relay circuit. So this is both "we
                        // became reachable" and "we now have something worth publishing".
                        SwarmEvent::ExternalAddrConfirmed { .. } => {
                            link.publish(&mut swarm);
                        }
                        SwarmEvent::Behaviour(AcBehaviourEvent::RendezvousClient(
                            rendezvous::client::Event::Discovered { registrations, .. },
                        )) => {
                            report_discovered(registrations, identity.peer_id());
                            for registration in registrations {
                                let peer = registration.record.peer_id();
                                if peer != identity.peer_id() {
                                    peers.discovered(
                                        peer,
                                        registration.record.addresses(),
                                        &mut files,
                                        &mut groups,
                                        &mut swarm,
                                    );
                                }
                            }
                        }
                        _ => {}
                    }
                }

                // Dispatched by value rather than by reference, because answering an
                // inbound request means taking ownership of its `ResponseChannel`.
                match event {
                    SwarmEvent::Behaviour(AcBehaviourEvent::PeerAttest(event)) => {
                        on_peer_attest(
                            &mut swarm, &mut admission, &mut groups, &mut files, &mut peers, event,
                        );
                    }
                    SwarmEvent::Behaviour(AcBehaviourEvent::Attest(event)) => {
                        on_renewal(
                            &mut swarm, &mut admission, &mut groups, &mut files, &mut peers, event,
                        );
                    }
                    SwarmEvent::Behaviour(AcBehaviourEvent::App(AppEvent::Groups(event))) => {
                        groups.on_event(&mut swarm, event);
                    }
                    SwarmEvent::Behaviour(AcBehaviourEvent::App(AppEvent::Manifests(event))) => {
                        // The supervisor's holdings queries share this behaviour with the file
                        // layer's offers and pages, so ids are unique across the two and this
                        // is a claim rather than a race.
                        if let Some(event) =
                            peers.claim_manifest(&mut swarm, &mut files, &mut groups, event)
                        {
                            files.on_event(&mut swarm, event);
                        }
                    }
                    // `libp2p_stream` emits nothing through the behaviour — its `ToSwarm` is
                    // `()`. Inbound streams arrive on the `IncomingStreams` handle instead.
                    SwarmEvent::Behaviour(AcBehaviourEvent::App(AppEvent::Blobs(()))) => {}
                    SwarmEvent::Behaviour(AcBehaviourEvent::App(AppEvent::Sessions(event))) => {
                        peers.on_session(&mut swarm, &mut files, &mut groups, event);
                    }
                    SwarmEvent::Behaviour(AcBehaviourEvent::Presence(event)) => {
                        peers.on_presence(&mut swarm, &mut files, &mut groups, event);
                    }
                    other => on_event(other),
                }
            }

            // Inbound blob streams. Handed straight to a task with its own database handles,
            // so a peer reading a large file never occupies the event loop.
            Some((peer, stream)) = blobs.next() => {
                files.on_inbound_blob(peer, stream);
            }

            _ = tokio::signal::ctrl_c() => {
                tracing::info!("interrupted, shutting down");
                return Ok(());
            }
        }
    }
}

/// Translate swarm events into connectivity transitions, and report the interesting ones.
///
/// This is the only place the two halves meet: [`Connectivity`] takes plain values so it
/// can be tested without a network, and this turns libp2p's events into those values.
pub fn track<A: ac_net::authz::PeerAuthorizer, X: libp2p::swarm::NetworkBehaviour>(
    connectivity: &mut Connectivity,
    swarm: &libp2p::Swarm<ac_net::swarm::AcBehaviour<A, X>>,
    event: &SwarmEvent<AcBehaviourEvent<A, X>>,
) {
    match event {
        SwarmEvent::ConnectionEstablished {
            peer_id, endpoint, ..
        } => {
            let relayed = endpoint
                .get_remote_address()
                .iter()
                .any(|p| p == Protocol::P2pCircuit);
            connectivity.connected(*peer_id, relayed);
        }

        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            // A peer holds a relayed *and* a direct connection while an upgrade settles,
            // so one closing does not mean the peer is gone. The swarm knows which.
            connectivity.disconnected(*peer_id, swarm.is_connected(peer_id));
        }

        SwarmEvent::Behaviour(AcBehaviourEvent::Dcutr(event)) => {
            let succeeded = event.result.is_ok();
            connectivity.hole_punch(event.remote_peer_id, succeeded);

            let peer = event.remote_peer_id;
            match &event.result {
                Ok(_) => {
                    let took = connectivity
                        .get(&peer)
                        .and_then(|s| s.upgrade_took())
                        .unwrap_or_default();
                    println!("direct {peer} after {:.1}s", took.as_secs_f32());
                }
                // Expected under symmetric NAT, where no amount of retrying helps. The
                // relayed connection remains and stays usable.
                Err(e) => {
                    tracing::info!(%peer, error = %e, "hole punch failed; staying relayed");
                }
            }
        }

        _ => {}
    }
}

/// Report everything the server returned, and connect to none of it.
///
/// Every peer, unfiltered — including ones this node will never want. Which of them are
/// worth a connection is a product decision, so nothing here makes it. Until the app layer
/// does, `ac run` discovers peers and dials only what `--dial` names.
///
/// Addresses arrive inside a signed `PeerRecord`, but nothing would depend on that
/// signature even when they are used: dialling `/p2p/<peer>` proves possession of the key
/// regardless, so a wrong address costs a failed dial and nothing more.
fn report_discovered(registrations: &[rendezvous::Registration], me: libp2p::PeerId) {
    for registration in registrations {
        let peer = registration.record.peer_id();
        if peer == me {
            continue;
        }

        tracing::info!(
            %peer,
            addresses = ?registration.record.addresses(),
            "discovered a peer"
        );
    }
}

/// Carry out what [`Admission`] asked for.
///
/// This and [`GroupLink::dispatch`] are the only places a swarm and a layer's actions meet;
/// everything above them is policy that runs with no socket.
fn dispatch_admission(
    swarm: &mut ClientSwarm,
    actions: Vec<AdmissionAction>,
    groups: &mut GroupLink,
    files: &mut FileLink,
    peers: &mut PeerLink,
) {
    for action in actions {
        match action {
            AdmissionAction::Send { peer, attestation } => {
                match swarm.behaviour_mut().peer_attest.as_mut() {
                    Some(behaviour) => {
                        behaviour.send_request(
                            &peer,
                            PeerAttestRequest {
                                attestation: *attestation,
                            },
                        );
                    }
                    // Only a server builds without this protocol, and a server never runs
                    // this loop. Silence here would look exactly like a peer that never
                    // answers, so it is worth a line rather than a shrug.
                    None => tracing::error!(
                        %peer,
                        "asked to attest without the peer-attest protocol mounted"
                    ),
                }
            }

            AdmissionAction::Renew { server } => match swarm.behaviour_mut().attest.as_mut() {
                Some(behaviour) => {
                    behaviour.send_request(&server, AttestRequest);
                }
                None => tracing::error!(
                    %server,
                    "asked to renew without the attest protocol mounted"
                ),
            },

            AdmissionAction::Close { peer, why } => {
                println!("refused {peer} ({why})");
                let _ = swarm.disconnect_peer_id(peer);
            }

            // Admitted is not yet usable by the app layer: the group layer hears about it
            // once the connection has settled — see `GroupLink::settling`.
            AdmissionAction::Admitted { peer, username } => {
                println!("verified {username} {peer}");
                groups.attested(peer);
                files.attested(peer);
                peers.attested(peer);
            }

            AdmissionAction::Note(note) => report_admission(&note),
        }
    }
}

/// The binary owns the wording; the machine owns the facts.
fn report_admission(note: &AdmissionNotice) {
    match note {
        AdmissionNotice::Attested { username, hours } => {
            println!("attested as {username} for {hours}h");
        }
        AdmissionNotice::RenewalRefused { reason } => {
            tracing::warn!(reason, "attestation refused");
        }
        AdmissionNotice::IssuedUnusable { error } => {
            tracing::error!(
                error,
                "the server issued an attestation this node cannot use"
            );
        }
        AdmissionNotice::NotCached { path, error } => {
            tracing::warn!(path = %path.display(), error, "could not cache the attestation");
        }
        AdmissionNotice::NotEnrolled => {
            tracing::warn!(
                "this node has not enrolled, so it can verify nobody and can prove nothing \
                 about itself. Every peer connection will be closed. Run `ac join` first."
            );
        }
    }
}

/// One `/ac/peer-attest/1.0.0` event.
///
/// An inbound request is answered in this same turn: the channel is held across
/// `on_request`, which always yields exactly one response, so it can never be stranded.
fn on_peer_attest(
    swarm: &mut ClientSwarm,
    admission: &mut Admission,
    groups: &mut GroupLink,
    files: &mut FileLink,
    peers: &mut PeerLink,
    event: request_response::Event<PeerAttestRequest, PeerAttestResponse>,
) {
    let actions = match event {
        request_response::Event::Message { peer, message, .. } => match message {
            request_response::Message::Request {
                request, channel, ..
            } => {
                let (response, actions) =
                    admission.on_request(peer, &request.attestation, Instant::now(), attest::now());
                if let Some(behaviour) = swarm.behaviour_mut().peer_attest.as_mut() {
                    // Best effort. A rejected peer is disconnected by the action below,
                    // which can truncate this — the closed connection is the message that
                    // matters, and the reason string is a courtesy to whoever reads both
                    // sides' logs.
                    let _ = behaviour.send_response(channel, response);
                }
                actions
            }

            request_response::Message::Response { response, .. } => match response {
                PeerAttestResponse::Accepted => admission.on(AdmissionEvent::Accepted { peer }),
                PeerAttestResponse::Rejected(why) => {
                    admission.on(AdmissionEvent::Rejected { peer, why })
                }
            },
        },

        request_response::Event::OutboundFailure { peer, error, .. } => {
            admission.on(AdmissionEvent::ExchangeFailed {
                peer,
                error: error.to_string(),
            })
        }

        // Their request to us failed mid-flight. Not fatal on its own — their side will
        // retry or time out — so this only stops *us* from having verified them, which the
        // deadline already covers.
        request_response::Event::InboundFailure { peer, error, .. } => {
            tracing::debug!(%peer, %error, "inbound attestation failed");
            Vec::new()
        }

        request_response::Event::ResponseSent { .. } => Vec::new(),
    };

    dispatch_admission(swarm, actions, groups, files, peers);
}

/// The server's answer to a renewal request.
fn on_renewal(
    swarm: &mut ClientSwarm,
    admission: &mut Admission,
    groups: &mut GroupLink,
    files: &mut FileLink,
    peers: &mut PeerLink,
    event: request_response::Event<AttestRequest, ac_net::proto::AttestResponse>,
) {
    let actions = match event {
        request_response::Event::Message {
            message: request_response::Message::Response { response, .. },
            ..
        } => admission.on(AdmissionEvent::Renewed(ac_net::admission::renewal_of(
            response,
        ))),

        request_response::Event::OutboundFailure { error, .. } => admission.on(
            AdmissionEvent::Renewed(ac_net::admission::Renewal::Failed {
                error: error.to_string(),
            }),
        ),

        other => {
            tracing::trace!(?other, "attest event");
            Vec::new()
        }
    };

    dispatch_admission(swarm, actions, groups, files, peers);
}

fn on_event(event: SwarmEvent<AcBehaviourEvent<AcceptAnyPeer, App>>) {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            // Printed rather than logged, and with the peer id appended, so the output
            // can be pasted straight into another node's `--dial`.
            println!("listening {address}");
        }

        SwarmEvent::ConnectionEstablished {
            peer_id, endpoint, ..
        } => {
            tracing::info!(
                peer = %peer_id,
                addr = %endpoint.get_remote_address(),
                role = if endpoint.is_dialer() { "dialer" } else { "listener" },
                "connected"
            );
        }

        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
            tracing::info!(peer = %peer_id, cause = ?cause, "disconnected");
        }

        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            tracing::warn!(peer = ?peer_id, %error, "outgoing connection failed");
        }

        SwarmEvent::IncomingConnectionError {
            send_back_addr,
            error,
            ..
        } => {
            tracing::warn!(from = %send_back_addr, %error, "incoming connection failed");
        }

        // What a peer reports seeing us as. Everything about NAT traversal starts here:
        // AutoNAT verifies these candidates, and DCUtR punches toward the confirmed one.
        SwarmEvent::Behaviour(AcBehaviourEvent::Identify(identify::Event::Received {
            peer_id,
            info,
            ..
        })) => {
            tracing::info!(
                peer = %peer_id,
                agent = %info.agent_version,
                observed_addr = %info.observed_addr,
                protocols = info.protocols.len(),
                // Addresses the peer advertises for itself. Expected to be zero until a
                // peer has a confirmed external address, because we ask identify to omit
                // raw listen addresses — see the config in ac_net::swarm.
                advertised_addrs = info.listen_addrs.len(),
                "identified"
            );
            // The names matter when a peer is missing a capability: a client that cannot
            // reserve a relay slot will show `/libp2p/circuit/relay/0.2.0/hop` absent
            // here, which is far quicker to spot than inferring it from a failure.
            tracing::debug!(
                peer = %peer_id,
                protocols = ?info.protocols.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
                "peer protocols"
            );
            println!("observed {} by {}", info.observed_addr, peer_id);
        }

        // The swarm has decided one of those candidates is really ours. This is the
        // reachability verdict in its most useful form: an address others can dial.
        SwarmEvent::ExternalAddrConfirmed { address } => {
            println!("external {address}");
        }

        SwarmEvent::ExternalAddrExpired { address } => {
            tracing::warn!(%address, "external address no longer valid");
        }

        // A gateway forwarded a port: the best outcome available, since it means no relay
        // and no hole punch are needed at all.
        SwarmEvent::Behaviour(AcBehaviourEvent::Upnp(upnp::Event::NewExternalAddr(address))) => {
            println!("upnp {address}");
        }

        SwarmEvent::Behaviour(AcBehaviourEvent::Upnp(event)) => {
            // The common case on home networks: no IGD, or a gateway that is itself
            // behind another NAT. Not an error, just the path we cannot take.
            tracing::info!(?event, "no port mapping available");
        }

        // AutoNAT's answer for one candidate address. `Ok` means a server dialled us back
        // successfully, which is what promotes a candidate to a confirmed external
        // address; `Err` means we are behind something that blocks unsolicited inbound.
        SwarmEvent::Behaviour(AcBehaviourEvent::AutonatClient(autonat::v2::client::Event {
            tested_addr,
            server,
            result,
            ..
        })) => match result {
            Ok(()) => println!("reachable {tested_addr}"),
            Err(e) => {
                tracing::info!(addr = %tested_addr, %server, error = %e, "address not reachable");
            }
        },

        SwarmEvent::Behaviour(AcBehaviourEvent::RelayClient(
            relay::client::Event::ReservationReqAccepted {
                relay_peer_id,
                renewal,
                limit,
            },
        )) => {
            // The reservation is what makes the circuit address usable. `limit` is the
            // relay telling us how much it will carry per circuit — whatever *that* server
            // was configured with, which need not match ours, so it is logged rather than
            // assumed.
            println!(
                "reserved via {relay_peer_id}{}",
                if renewal { " (renewed)" } else { "" }
            );
            tracing::info!(relay = %relay_peer_id, renewal, ?limit, "relay reservation");
        }

        SwarmEvent::Behaviour(AcBehaviourEvent::RelayClient(event)) => {
            tracing::info!(?event, "relay client event");
        }

        // LAN peers, found without the server. Reported, not dialled — same rule as
        // rendezvous results: whether a peer is worth connecting to is not this layer's
        // decision.
        SwarmEvent::Behaviour(AcBehaviourEvent::Mdns(mdns::Event::Discovered(found))) => {
            for (peer, addr) in found {
                tracing::info!(%peer, %addr, "discovered a peer on the local network");
            }
        }

        SwarmEvent::Behaviour(AcBehaviourEvent::Mdns(mdns::Event::Expired(gone))) => {
            for (peer, addr) in gone {
                tracing::debug!(%peer, %addr, "local peer stopped announcing");
            }
        }

        SwarmEvent::Behaviour(AcBehaviourEvent::RendezvousClient(event)) => match event {
            rendezvous::client::Event::Registered { ttl, namespace, .. } => {
                println!("registered {namespace} (ttl {ttl}s)");
            }
            rendezvous::client::Event::Discovered { registrations, .. } => {
                println!("discovered {} peer(s)", registrations.len());
            }
            rendezvous::client::Event::RegisterFailed { error, .. } => {
                tracing::warn!(?error, "the server refused our registration");
            }
            rendezvous::client::Event::DiscoverFailed { error, .. } => {
                tracing::warn!(?error, "the server refused our discovery request");
            }
            other => tracing::debug!(?other, "rendezvous client event"),
        },

        SwarmEvent::Behaviour(AcBehaviourEvent::Ping(ping::Event {
            peer,
            result: Ok(rtt),
            ..
        })) => {
            tracing::debug!(peer = %peer, rtt_ms = rtt.as_millis(), "ping");
        }

        SwarmEvent::Behaviour(AcBehaviourEvent::Ping(ping::Event {
            peer,
            result: Err(e),
            ..
        })) => {
            tracing::warn!(peer = %peer, error = %e, "ping failed");
        }

        // A listener dying is never routine — for a circuit address it means the relay
        // reservation was refused or lost, which is exactly the failure this stage exists
        // to make visible. Buried at trace level it looks like nothing happened at all.
        SwarmEvent::ListenerError { listener_id, error } => {
            tracing::warn!(?listener_id, %error, "listener error");
        }

        SwarmEvent::ListenerClosed {
            listener_id,
            addresses,
            reason,
        } => {
            tracing::warn!(?listener_id, ?addresses, ?reason, "listener closed");
        }

        other => tracing::trace!(?other, "swarm event"),
    }
}
