//! The link to this node's server: reconnection, the relay reservation, and the registry.
//!
//! Unlike [`crate::admission`], this is **not** an event/action machine, and that is a
//! deliberate exception rather than an oversight.
//!
//! Admission holds policy — who is verified, who gets closed, when to renew — which is worth
//! separating from the swarm because it can then be tested without one. This holds no policy.
//! Its entire job is to drive the swarm: dial when the backoff expires, listen on a circuit
//! once a reservation exists, register once an external address exists. `LinkAction::Dial`,
//! `LinkAction::Listen` and `LinkAction::Register` would re-describe three libp2p calls in a
//! private vocabulary and be handed straight back to libp2p, and a test of the machine would
//! assert that we asked to dial rather than that dialling works.
//!
//! Applying the rule uniformly would cost more here than it returns, and being selective about
//! it is more honest than pretending every layer wants the same shape.
//!
//! # The ordering it exists to enforce
//!
//! Each step waits for what the previous one produces: connect, then reserve a circuit, then
//! listen on it, then — once that produces a confirmed external address — register in the
//! rendezvous namespace. Doing any of them early fails in a way that looks like a bug.

use std::time::{Duration, Instant};

use libp2p::{Multiaddr, PeerId, multiaddr::Protocol, rendezvous};

use crate::authz::PeerAuthorizer;
use crate::proto::RENDEZVOUS_NAMESPACE;
use crate::swarm::AcBehaviour;

/// First reconnect delay, doubling up to [`MAX_BACKOFF`].
pub const MIN_BACKOFF: Duration = Duration::from_secs(1);

/// Ceiling on the reconnect delay. A server down for hours should be retried patiently,
/// not hammered — but a minute is short enough that recovery is not something a person
/// waits out.
pub const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// How often the registry is re-read and our own registration refreshed.
///
/// A peer that comes online is invisible until the next poll, so this *is* the
/// notification latency: rendezvous has no push, and asking is the only mechanism.
///
/// Comfortably inside the server's registration TTL (two hours), so a refresh is never
/// close to lapsing.
pub const DISCOVERY_INTERVAL: Duration = Duration::from_secs(300);

/// How often the supervisor checks whether anything is due.
///
/// Deliberately coarser than the backoff it drives: the first retry is nominally one
/// second, but detecting a dead server takes ~25 seconds in the first place, so finer
/// granularity would buy nothing while waking the task — and polling every behaviour —
/// five times as often.
pub const HOUSEKEEPING_TICK: Duration = Duration::from_secs(5);

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
pub struct ServerLink {
    pub server: PeerId,
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
    pub fn for_server(server: &Multiaddr) -> Option<Self> {
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
    pub fn on_disconnected(&mut self, peer: PeerId, still_connected: bool) {
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
    pub fn housekeeping<A: PeerAuthorizer, X: libp2p::swarm::NetworkBehaviour>(
        &mut self,
        swarm: &mut libp2p::Swarm<AcBehaviour<A, X>>,
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
    pub fn discover<A: PeerAuthorizer, X: libp2p::swarm::NetworkBehaviour>(
        &self,
        swarm: &mut libp2p::Swarm<AcBehaviour<A, X>>,
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
    pub fn reserve<A: PeerAuthorizer, X: libp2p::swarm::NetworkBehaviour>(
        &mut self,
        swarm: &mut libp2p::Swarm<AcBehaviour<A, X>>,
        connected: PeerId,
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
    pub fn publish<A: PeerAuthorizer, X: libp2p::swarm::NetworkBehaviour>(
        &mut self,
        swarm: &mut libp2p::Swarm<AcBehaviour<A, X>>,
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
