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

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use libp2p::futures::StreamExt;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, autonat, identify, mdns, ping, relay, rendezvous, upnp};

use ac_net::authz::AcceptAnyPeer;
use ac_net::config::Config;
use ac_net::connectivity::Connectivity;
use ac_net::identity::Identity;
use ac_net::proto::RENDEZVOUS_NAMESPACE;
use ac_net::swarm::{AcBehaviourEvent, Role, build};

/// Listen, optionally dial, and run until interrupted.
///
/// The authorizer is [`AcceptAnyPeer`]: a client accepts connections from anyone, because
/// refusing by identity would prevent a peer from ever delivering the group membership
/// proof that authorizes it. Resource limits, not identity, bound what a stranger costs.
pub async fn run(identity: &Identity, config: &Config, dial: &[Multiaddr]) -> Result<()> {
    let mut swarm =
        build(identity, config, Role::Client, AcceptAnyPeer).context("building the swarm")?;

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
            }

            event = swarm.select_next_some() => {
                track(&mut connectivity, &swarm, &event);

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
                        }
                        _ => {}
                    }
                }
                on_event(event);
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
fn track<A: ac_net::authz::PeerAuthorizer>(
    connectivity: &mut Connectivity,
    swarm: &libp2p::Swarm<ac_net::swarm::AcBehaviour<A>>,
    event: &SwarmEvent<AcBehaviourEvent<A>>,
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

/// First reconnect delay, doubling up to [`MAX_BACKOFF`].
const MIN_BACKOFF: Duration = Duration::from_secs(1);

/// Ceiling on the reconnect delay. A server down for hours should be retried patiently,
/// not hammered — but a minute is short enough that recovery is not something a person
/// waits out.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// How often the registry is re-read and our own registration refreshed.
///
/// A peer that comes online is invisible until the next poll, so this *is* the
/// notification latency: rendezvous has no push, and asking is the only mechanism.
///
/// Comfortably inside the server's registration TTL (two hours), so a refresh is never
/// close to lapsing.
const DISCOVERY_INTERVAL: Duration = Duration::from_secs(300);

/// How often the supervisor checks whether anything is due.
///
/// Deliberately coarser than the backoff it drives: the first retry is nominally one
/// second, but detecting a dead server takes ~25 seconds in the first place, so finer
/// granularity would buy nothing while waking the task — and polling every behaviour —
/// five times as often.
const HOUSEKEEPING_TICK: Duration = Duration::from_secs(5);

/// The link to the server, and everything needed to keep it up.
///
/// The initial handshake is a chain, and the ordering is forced rather than stylistic:
///
/// ```text
/// connect  ──► reserve a relay slot  ──► circuit address confirmed  ──► register + discover
/// ```
///
/// Reserving before the connection exists makes the relay behaviour issue its own competing
/// dial; registering before an external address exists fails with `NoExternalAddresses`.
/// Both failures are quiet, so each step waits on the event proving its precondition.
///
/// The same chain has to run **again** after any reconnection, because a reservation dies
/// with the connection that made it. That is why `reserved` and `published` are cleared on
/// disconnect rather than being one-shot latches.
struct ServerLink {
    server: libp2p::PeerId,
    /// Kept so the server can be redialled; the config is not consulted again.
    address: Multiaddr,
    circuit: Multiaddr,
    reserved: bool,
    published: bool,
    /// When to next attempt a reconnect. `None` while connected.
    retry_at: Option<Instant>,
    backoff: Duration,
    next_discovery: Instant,
}

impl ServerLink {
    /// `None` if the address carries no peer id — nothing to wait for, and a circuit
    /// address without one is rejected by the transport anyway.
    fn for_server(server: &Multiaddr) -> Option<Self> {
        let peer = server.iter().find_map(|p| match p {
            Protocol::P2p(peer) => Some(peer),
            _ => None,
        })?;

        Some(Self {
            server: peer,
            address: server.clone(),
            circuit: server.clone().with(Protocol::P2pCircuit),
            reserved: false,
            published: false,
            retry_at: None,
            backoff: MIN_BACKOFF,
            next_discovery: Instant::now() + DISCOVERY_INTERVAL,
        })
    }

    /// The server connection dropped: start over.
    ///
    /// Everything built on that connection is gone with it — the relay reservation was
    /// bound to it, and the rendezvous registration cannot be refreshed without it — so the
    /// flags reset and the whole chain reruns once a new connection lands.
    fn on_disconnected(&mut self, peer: libp2p::PeerId, still_connected: bool) {
        if peer != self.server || still_connected {
            return;
        }

        self.reserved = false;
        self.published = false;
        self.retry_at = Some(Instant::now() + self.backoff);
        tracing::warn!(
            server = %self.server,
            retry_in_s = self.backoff.as_secs(),
            "lost the server; will reconnect"
        );
    }

    /// Redial if it is due, and re-read the registry if that is due.
    ///
    /// Driven by a periodic tick rather than by per-event timers: there are two schedules
    /// and neither needs sub-second precision, so one clock is easier to reason about than
    /// two futures being polled in a `select!`.
    fn housekeeping<A: ac_net::authz::PeerAuthorizer>(
        &mut self,
        swarm: &mut libp2p::Swarm<ac_net::swarm::AcBehaviour<A>>,
    ) {
        let now = Instant::now();

        if let Some(due) = self.retry_at
            && now >= due
        {
            // Backoff grows on the *attempt*, not on its failure: a dial that fails
            // silently would otherwise retry at the same rate forever.
            self.backoff = (self.backoff * 2).min(MAX_BACKOFF);
            self.retry_at = Some(now + self.backoff);

            tracing::info!(server = %self.server, "reconnecting");
            if let Err(e) = swarm.dial(self.address.clone()) {
                tracing::debug!(server = %self.server, error = %e, "reconnect dial not started");
            }
        }

        if now >= self.next_discovery {
            self.next_discovery = now + DISCOVERY_INTERVAL;
            self.discover(swarm);
        }
    }

    /// Re-read the registry.
    ///
    /// A **full** query, deliberately: the discovery cookie returns only registrations
    /// added since it was issued, so it can find a peer that arrived and never report one
    /// that left. A list built from deltas accumulates ghosts.
    fn discover<A: ac_net::authz::PeerAuthorizer>(
        &self,
        swarm: &mut libp2p::Swarm<ac_net::swarm::AcBehaviour<A>>,
    ) {
        if !self.published {
            // Not registered yet, so there is nothing to refresh and the server may not
            // even know us. The initial `publish` will do the first query.
            return;
        }
        let Ok(namespace) = rendezvous::Namespace::new(RENDEZVOUS_NAMESPACE.to_owned()) else {
            return;
        };
        let Some(client) = swarm.behaviour_mut().rendezvous_client.as_mut() else {
            return;
        };

        // Re-registering as well as re-reading: a registration expires on the server's TTL,
        // and letting it lapse would make this node vanish from everyone else's view.
        if let Err(e) = client.register(namespace.clone(), self.server, None) {
            tracing::debug!(error = %e, "could not refresh the registration");
        }
        client.discover(Some(namespace), None, None, self.server);
    }

    /// Ask for the reservation, if this is the connection we were waiting for.
    fn reserve<A: ac_net::authz::PeerAuthorizer>(
        &mut self,
        swarm: &mut libp2p::Swarm<ac_net::swarm::AcBehaviour<A>>,
        connected: libp2p::PeerId,
    ) {
        if self.reserved || connected != self.server {
            return;
        }
        // Reserving means listening on a `/p2p-circuit` address; there is no separate
        // call. Once per connection: renewal within a connection is the relay client
        // behaviour's job, and asking again would open a second listener for the same
        // circuit. The flag clears on disconnect, so a reconnection reserves afresh.
        self.reserved = true;

        // The server is back; stop retrying and forget how long we had been waiting, so a
        // later outage starts from a short delay rather than the last one's ceiling.
        self.retry_at = None;
        self.backoff = MIN_BACKOFF;

        match swarm.listen_on(self.circuit.clone()) {
            Ok(_) => tracing::info!(relay = %self.server, "requesting a relay reservation"),
            Err(e) => tracing::warn!(relay = %self.server, error = %e, "could not reserve"),
        }
    }

    /// Publish our addresses and ask who else is here.
    ///
    /// Called when an external address is confirmed, because registration carries a signed
    /// record of those addresses and libp2p refuses to build one from an empty set.
    ///
    /// # Address changes
    ///
    /// This runs once per connection and then short-circuits, so a *later* address — a
    /// laptop moving from wifi to ethernet, or waking from sleep — does not republish here.
    /// It does not need to: `if-watch` (inside libp2p's QUIC and TCP transports) rebinds
    /// listeners on an interface change, AutoNAT re-confirms, and [`Self::housekeeping`]
    /// re-registers on its next tick. The cost is that a moved node is stale in the
    /// registry for up to one refresh interval.
    fn publish<A: ac_net::authz::PeerAuthorizer>(
        &mut self,
        swarm: &mut libp2p::Swarm<ac_net::swarm::AcBehaviour<A>>,
    ) {
        if self.published {
            return;
        }

        let namespace = match rendezvous::Namespace::new(RENDEZVOUS_NAMESPACE.to_owned()) {
            Ok(ns) => ns,
            Err(e) => {
                tracing::error!(error = %e, "the rendezvous namespace is not valid");
                return;
            }
        };

        let Some(client) = swarm.behaviour_mut().rendezvous_client.as_mut() else {
            return;
        };

        if let Err(e) = client.register(namespace.clone(), self.server, None) {
            // Most likely still no external address; a later confirmation retries.
            tracing::debug!(error = %e, "not ready to register yet");
            return;
        }
        self.published = true;

        // One discovery now. Repeating it on a schedule, so a peer that comes online
        // later is noticed, is the supervisor's job in stage 10.
        client.discover(Some(namespace), None, None, self.server);
        tracing::info!(server = %self.server, "registered and discovering");
    }
}

fn on_event(event: SwarmEvent<AcBehaviourEvent<AcceptAnyPeer>>) {
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
            // relay telling us how much it will carry — 128 KiB by default, which is
            // signalling-sized on purpose.
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
