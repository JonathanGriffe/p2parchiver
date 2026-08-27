use std::time::Instant;

use anyhow::{Context, Result};
use libp2p::futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, autonat, identify, mdns, ping, relay, rendezvous, request_response, upnp};

use crate::file_link::FileLink;
use crate::group_link::GroupLink;
use crate::peer_link::PeerLink;
use ac_files::wire::{ManifestRequest, ManifestResponse};
use ac_groups::wire::{GroupRequest, GroupResponse};
use ac_net::admission_link::AdmissionLink;
use ac_net::attest;
use ac_net::authz::AcceptAnyPeer;
use ac_net::config::{Config, Paths};
use ac_net::connectivity::Connectivity;
use ac_net::identity::Identity;
use ac_net::link::{HOUSEKEEPING_TICK, ServerLink};
use ac_net::roster::Roster;
use ac_net::swarm::{AcBehaviourEvent, Role, build};
use ac_peers::wire::{SessionRequest, SessionResponse};

#[derive(libp2p::swarm::NetworkBehaviour)]
pub struct App {
    pub groups: request_response::cbor::Behaviour<GroupRequest, GroupResponse>,
    pub manifests: request_response::cbor::Behaviour<ManifestRequest, ManifestResponse>,
    pub blobs: libp2p_stream::Behaviour,
    pub sessions: request_response::cbor::Behaviour<SessionRequest, SessionResponse>,
}

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

pub type ClientSwarm = libp2p::Swarm<ac_net::swarm::AcBehaviour<AcceptAnyPeer, App>>;

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

    let mut admission = AdmissionLink::load(
        &paths.attestation_file(),
        identity.peer_id(),
        link.as_ref().map(|l| l.server),
        attest::now(),
    );

    let mut groups = GroupLink::open(paths, identity)?;
    let mut files = FileLink::open(paths, identity)?;
    let mut peers = PeerLink::open(
        paths,
        identity,
        link.as_ref().map(|l| l.server),
        attest::now(),
    )?;

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
                admission.housekeeping(&mut swarm, &mut roster, attest::now());

                connectivity.expire_upgrades();
                promote_ready(&mut swarm, &mut roster, &connectivity, &mut peers, &mut files, &mut groups);

                groups.housekeeping(&mut swarm, &roster, Instant::now(), attest::now());
                files.housekeeping(&mut swarm, &roster, Instant::now(), attest::now());
                peers.housekeeping(&mut swarm, &mut files, &mut groups, &roster, attest::now());
            }

            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        connectivity.connected(peer_id, endpoint.is_relayed());

                        admission.connected(&mut swarm, &mut roster, peer_id);

                        if let Some(link) = &mut link {
                            link.reserve(&mut swarm, peer_id);
                        }
                        report_connected(peer_id, &endpoint);
                    }

                    SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                        let still_connected = swarm.is_connected(&peer_id);
                        let agreed = peers.close_was_agreed(&peer_id);
                        connectivity.disconnected(peer_id, still_connected);

                        admission.disconnected(&mut swarm, &mut roster, peer_id, still_connected);

                        if roster.disconnected(&peer_id, still_connected) {
                            peers.on_disconnected(&mut swarm, &mut files, &mut groups, &roster, peer_id);
                        }
                        if let Some(link) = &mut link {
                            link.on_disconnected(peer_id, still_connected);
                        }
                        if agreed {
                            tracing::info!(peer = %peer_id, "hung up, as agreed");
                        } else {
                            tracing::info!(peer = %peer_id, cause = ?cause, "disconnected");
                        }
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

                        promote_ready(&mut swarm, &mut roster, &connectivity, &mut peers, &mut files, &mut groups);
                    }

                    SwarmEvent::Behaviour(AcBehaviourEvent::PeerAttest(event)) => {
                        admission.on_peer_attest(&mut swarm, &mut roster, attest::now(), event);
                        promote_ready(&mut swarm, &mut roster, &connectivity, &mut peers, &mut files, &mut groups);
                    }
                    SwarmEvent::Behaviour(AcBehaviourEvent::Attest(event)) => {
                        admission.on_renewal(&mut swarm, &mut roster, event);
                    }
                    SwarmEvent::Behaviour(AcBehaviourEvent::App(AppEvent::Groups(event))) => {
                        groups.on_event(&mut swarm, &roster, event);
                    }
                    SwarmEvent::Behaviour(AcBehaviourEvent::App(AppEvent::Manifests(event))) => {
                        files.on_event(&mut swarm, &roster, event);
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

                peers.collect(&mut swarm, &mut files, &mut groups, &roster);
            }

            Some(outcome) = peers.next_transfer() => {
                peers.on_transfer(&mut swarm, &mut files, &mut groups, &roster, outcome);
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

fn promote_ready(
    swarm: &mut ClientSwarm,
    roster: &mut Roster,
    connectivity: &Connectivity,
    peers: &mut PeerLink,
    files: &mut FileLink,
    groups: &mut GroupLink,
) {
    for peer in roster.promote(connectivity) {
        peers.peer_ready(swarm, files, groups, roster, peer);
    }
}

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

/// Swarm events this node only reports on.
fn on_event(event: SwarmEvent<AcBehaviourEvent<AcceptAnyPeer, App>>) {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            println!("listening {address}");
        }

        SwarmEvent::IncomingConnectionError {
            send_back_addr,
            error,
            ..
        } => {
            tracing::warn!(from = %send_back_addr, %error, "incoming connection failed");
        }

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
                advertised_addrs = info.listen_addrs.len(),
                "identified"
            );
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

        SwarmEvent::Behaviour(AcBehaviourEvent::Upnp(upnp::Event::NewExternalAddr(address))) => {
            println!("upnp {address}");
        }

        SwarmEvent::Behaviour(AcBehaviourEvent::Upnp(event)) => {
            tracing::info!(?event, "no port mapping available");
        }

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
