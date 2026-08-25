use std::time::Instant;

use anyhow::{Context, Result};
use libp2p::futures::StreamExt;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, autonat, identify, mdns, ping, relay, rendezvous, request_response, upnp};

use crate::file_link::FileLink;
use crate::group_link::GroupLink;
use crate::peer_link::PeerLink;
use ac_files::wire::{ManifestRequest, ManifestResponse};
use ac_groups::wire::{GroupRequest, GroupResponse};
use ac_net::admission::{Admission, AdmissionAction, AdmissionEvent, Notice as AdmissionNotice};
use ac_net::attest;
use ac_net::authz::AcceptAnyPeer;
use ac_net::config::{Config, Paths};
use ac_net::connectivity::Connectivity;
use ac_net::identity::Identity;
use ac_net::link::{HOUSEKEEPING_TICK, ServerLink};
use ac_net::proto::{AttestRequest, PeerAttestRequest, PeerAttestResponse};
use ac_net::roster::Roster;
use ac_net::swarm::{AcBehaviourEvent, Role, build};
use ac_peers::wire::{SessionRequest, SessionResponse};

/// This node's application layer: four protocols in one slot.
#[derive(libp2p::swarm::NetworkBehaviour)]
pub struct App {
    pub groups: request_response::cbor::Behaviour<GroupRequest, GroupResponse>,
    pub manifests: request_response::cbor::Behaviour<ManifestRequest, ManifestResponse>,
    pub blobs: libp2p_stream::Behaviour,
    pub sessions: request_response::cbor::Behaviour<SessionRequest, SessionResponse>,
}

/// None of these is const-constructible, so this is a function where the `dummy::Behaviour` it
/// replaced was a `const`.
pub fn app() -> App {
    App {
        groups: cbor_behaviour(
            ac_groups::wire::GROUP_PROTOCOL,
            ac_groups::wire::MAX_REQUEST_BYTES,
            ac_groups::wire::MAX_RESPONSE_BYTES,
        ),
        manifests: cbor_behaviour(
            ac_files::wire::MANIFEST_PROTOCOL,
            ac_files::wire::MAX_REQUEST_BYTES,
            ac_files::wire::MAX_RESPONSE_BYTES,
        ),
        blobs: libp2p_stream::Behaviour::new(),
        sessions: cbor_behaviour(
            ac_peers::wire::SESSION_PROTOCOL,
            ac_peers::wire::MAX_SESSION_BYTES,
            ac_peers::wire::MAX_SESSION_BYTES,
        ),
    }
}

/// One CBOR request-response behaviour, built from what a protocol declares about itself.
fn cbor_behaviour<Req, Resp>(
    protocol: &'static str,
    max_request: u64,
    max_response: u64,
) -> request_response::cbor::Behaviour<Req, Resp>
where
    Req: serde::Serialize + serde::de::DeserializeOwned + Send + 'static,
    Resp: serde::Serialize + serde::de::DeserializeOwned + Send + 'static,
{
    let codec = request_response::cbor::codec::Codec::default()
        .set_request_size_maximum(max_request)
        .set_response_size_maximum(max_response);

    request_response::cbor::Behaviour::with_codec(
        codec,
        [(
            libp2p::StreamProtocol::new(protocol),
            request_response::ProtocolSupport::Full,
        )],
        request_response::Config::default(),
    )
}

/// A convenient alias for the concrete swarm this module drives.
pub type ClientSwarm = libp2p::Swarm<ac_net::swarm::AcBehaviour<AcceptAnyPeer, App>>;

/// Listen, optionally dial, and run until interrupted.
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

    let (mut admission, notes) = Admission::load(
        &paths.attestation_file(),
        identity.peer_id(),
        link.as_ref().map(|l| l.server),
        attest::now(),
    );
    for note in notes {
        report_admission(&note);
    }

    let mut groups = GroupLink::open(paths, identity)?;
    let mut files = FileLink::open(paths, identity)?;
    let mut peers = PeerLink::open(paths, identity, link.as_ref().map(|l| l.server))?;

    let mut blobs = FileLink::accept_blobs(&mut swarm)?;
    let mut connectivity = Connectivity::default();

    let mut roster = Roster::default();

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
                dispatch_admission(&mut swarm, actions, &mut roster);

                for peer in roster.promote(&connectivity) {
                    peers.peer_ready(&mut swarm, &mut files, &mut groups, &roster, peer);
                }

                groups.housekeeping(&mut swarm, &roster, Instant::now(), attest::now());
                files.housekeeping(&mut swarm, &roster, Instant::now(), attest::now());
                peers.housekeeping(&mut swarm, &mut files, &mut groups, &roster, attest::now());
            }

            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        let relayed = endpoint
                            .get_remote_address()
                            .iter()
                            .any(|p| p == Protocol::P2pCircuit);
                        connectivity.connected(peer_id, relayed);

                        let actions = admission.on(AdmissionEvent::Connected {
                            peer: peer_id,
                            now: Instant::now(),
                        });
                        dispatch_admission(&mut swarm, actions, &mut roster);

                        if let Some(link) = &mut link {
                            link.reserve(&mut swarm, peer_id);
                        }
                        report_connected(peer_id, &endpoint);
                    }

                    SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                        // The swarm's answer, asked once and used by all four: a peer holds a
                        // relayed *and* a direct connection while an upgrade settles, so one
                        // closing is not the peer leaving.
                        let still_connected = swarm.is_connected(&peer_id);
                        connectivity.disconnected(peer_id, still_connected);

                        let actions = admission.on(AdmissionEvent::Disconnected {
                            peer: peer_id,
                            still_connected,
                        });
                        dispatch_admission(&mut swarm, actions, &mut roster);

                        if roster.disconnected(&peer_id, still_connected) {
                            peers.on_disconnected(&mut swarm, &mut files, &mut groups, &roster, peer_id);
                        }
                        if let Some(link) = &mut link {
                            link.on_disconnected(peer_id, still_connected);
                        }
                        tracing::info!(peer = %peer_id, cause = ?cause, "disconnected");
                    }

                    SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                        if let Some(peer) = peer_id {
                            peers.dial_failed(&mut swarm, &mut files, &mut groups, &roster, peer);
                        }
                        tracing::warn!(peer = ?peer_id, %error, "outgoing connection failed");
                    }

                    SwarmEvent::ExternalAddrConfirmed { address } => {
                        if let Some(link) = &mut link {
                            link.publish(&mut swarm);
                        }
                        println!("external {address}");
                    }

                    SwarmEvent::Behaviour(AcBehaviourEvent::Mdns(mdns::Event::Discovered(found))) => {
                        for (peer, addr) in &found {
                            tracing::info!(%peer, %addr, "discovered a peer on the local network");
                            peers.discovered(
                                *peer,
                                std::slice::from_ref(addr),
                                &mut files,
                                &mut groups,
                                &mut swarm,
                                &roster,
                            );
                        }
                    }

                    SwarmEvent::Behaviour(AcBehaviourEvent::RendezvousClient(
                        rendezvous::client::Event::Discovered { registrations, .. },
                    )) => {
                        report_discovered(&registrations, identity.peer_id());
                        for registration in &registrations {
                            let peer = registration.record.peer_id();
                            if peer != identity.peer_id() {
                                peers.discovered(
                                    peer,
                                    registration.record.addresses(),
                                    &mut files,
                                    &mut groups,
                                    &mut swarm,
                                    &roster,
                                );
                            }
                        }
                        println!("discovered {} peer(s)", registrations.len());
                    }

                    SwarmEvent::Behaviour(AcBehaviourEvent::Dcutr(event)) => {
                        let peer = event.remote_peer_id;
                        connectivity.hole_punch(peer, event.result.is_ok());

                        match &event.result {
                            Ok(_) => {
                                let took = connectivity
                                    .get(&peer)
                                    .and_then(|s| s.upgrade_took())
                                    .unwrap_or_default();
                                println!("direct {peer} after {:.1}s", took.as_secs_f32());
                            }
                            Err(e) => {
                                tracing::info!(%peer, error = %e, "hole punch failed; staying relayed");
                            }
                        }
                    }

                    SwarmEvent::Behaviour(AcBehaviourEvent::PeerAttest(event)) => {
                        on_peer_attest(&mut swarm, &mut admission, &mut roster, event);
                    }
                    SwarmEvent::Behaviour(AcBehaviourEvent::Attest(event)) => {
                        on_renewal(&mut swarm, &mut admission, &mut roster, event);
                    }
                    SwarmEvent::Behaviour(AcBehaviourEvent::App(AppEvent::Groups(event))) => {
                        groups.on_event(&mut swarm, &roster, event);
                    }
                    SwarmEvent::Behaviour(AcBehaviourEvent::App(AppEvent::Manifests(event))) => {
                        if let Some(event) =
                            peers.claim_manifest(&mut swarm, &mut files, &mut groups, &roster, event)
                        {
                            files.on_event(&mut swarm, &roster, event);
                        }
                    }
                    SwarmEvent::Behaviour(AcBehaviourEvent::App(AppEvent::Blobs(()))) => {}
                    SwarmEvent::Behaviour(AcBehaviourEvent::App(AppEvent::Sessions(event))) => {
                        peers.on_session(&mut swarm, &mut files, &mut groups, &roster, event);
                    }
                    SwarmEvent::Behaviour(AcBehaviourEvent::Presence(event)) => {
                        peers.on_presence(&mut swarm, &mut files, &mut groups, &roster, event);
                    }
                    other => on_event(other),
                }
            }

            Some((peer, stream)) = blobs.next() => {
                if roster.is_ready(&peer) {
                    files.on_inbound_blob(peer, stream);
                } else {
                    tracing::debug!(%peer, "declining a blob stream from a peer that is not ready");
                    drop(stream);
                }
            }

            _ = tokio::signal::ctrl_c() => {
                tracing::info!("interrupted, shutting down");
                return Ok(());
            }
        }
    }
}

/// A connection, and which way it was opened.
fn report_connected(peer: libp2p::PeerId, endpoint: &libp2p::core::ConnectedPoint) {
    tracing::info!(
        %peer,
        addr = %endpoint.get_remote_address(),
        role = if endpoint.is_dialer() { "dialer" } else { "listener" },
        "connected"
    );
}

/// Report everything the server returned, and connect to none of it.
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
fn dispatch_admission(swarm: &mut ClientSwarm, actions: Vec<AdmissionAction>, roster: &mut Roster) {
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

            // Admitted is not yet usable by the app layer. The roster holds them back until
            // the connection has stopped changing shape — see `Roster::promote`.
            AdmissionAction::Admitted { peer, username } => {
                println!("verified {username} {peer}");
                roster.admitted(peer);
            }

            AdmissionAction::Note(note) => report_admission(&note),
        }
    }
}

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
fn on_peer_attest(
    swarm: &mut ClientSwarm,
    admission: &mut Admission,
    roster: &mut Roster,
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

    dispatch_admission(swarm, actions, roster);
}

/// The server's answer to a renewal request.
fn on_renewal(
    swarm: &mut ClientSwarm,
    admission: &mut Admission,
    roster: &mut Roster,
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

    dispatch_admission(swarm, actions, roster);
}

/// Swarm events this node only reports on.
fn on_event(event: SwarmEvent<AcBehaviourEvent<AcceptAnyPeer, App>>) {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            // Printed rather than logged, and with the peer id appended, so the output
            // can be pasted straight into another node's `--dial`.
            println!("listening {address}");
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

        SwarmEvent::Behaviour(AcBehaviourEvent::Mdns(mdns::Event::Expired(gone))) => {
            for (peer, addr) in gone {
                tracing::debug!(%peer, %addr, "local peer stopped announcing");
            }
        }

        SwarmEvent::Behaviour(AcBehaviourEvent::RendezvousClient(event)) => match event {
            rendezvous::client::Event::Registered { ttl, namespace, .. } => {
                println!("registered {namespace} (ttl {ttl}s)");
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
