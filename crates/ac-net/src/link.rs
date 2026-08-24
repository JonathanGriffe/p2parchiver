use std::time::{Duration, Instant};

use libp2p::{Multiaddr, PeerId, multiaddr::Protocol, rendezvous};

use crate::authz::PeerAuthorizer;
use crate::proto::RENDEZVOUS_NAMESPACE;
use crate::swarm::AcBehaviour;

/// First reconnect delay, doubling up to [`MAX_BACKOFF`].
pub const MIN_BACKOFF: Duration = Duration::from_secs(1);
pub const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// How often the registry is re-read and our own registration refreshed.
pub const DISCOVERY_INTERVAL: Duration = Duration::from_secs(300);

/// How often the supervisor checks whether anything is due.
pub const HOUSEKEEPING_TICK: Duration = Duration::from_secs(5);

/// The link to the server, and everything needed to keep it up.
pub struct ServerLink {
    pub server: PeerId,
    address: Multiaddr,
    circuit: Multiaddr,
    reserved: bool,
    published: bool,
    retry_at: Option<Instant>,
    backoff: Duration,
    next_discovery: Instant,
}

impl ServerLink {
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
    pub fn housekeeping<A: PeerAuthorizer, X: libp2p::swarm::NetworkBehaviour>(
        &mut self,
        swarm: &mut libp2p::Swarm<AcBehaviour<A, X>>,
    ) {
        let now = Instant::now();

        if let Some(due) = self.retry_at
            && now >= due
        {
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
        self.reserved = true;

        self.retry_at = None;
        self.backoff = MIN_BACKOFF;

        match swarm.listen_on(self.circuit.clone()) {
            Ok(_) => tracing::info!(relay = %self.server, "requesting a relay reservation"),
            Err(e) => tracing::warn!(relay = %self.server, error = %e, "could not reserve"),
        }
    }

    /// Publish our addresses and ask who else is here.
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

        client.discover(Some(namespace), None, None, self.server);
        tracing::info!(server = %self.server, "registered and discovering");
    }
}
