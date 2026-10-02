use std::time::{Duration, Instant};

use libp2p::{Multiaddr, PeerId, multiaddr::Protocol};

use crate::authz::PeerAuthorizer;
use crate::swarm::AcBehaviour;

/// First reconnect delay, doubling up to [`MAX_BACKOFF`].
pub const MIN_BACKOFF: Duration = Duration::from_secs(1);
pub const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// How often the supervisor checks whether anything is due.
pub const HOUSEKEEPING_TICK: Duration = Duration::from_secs(5);

/// The link to the server, and everything needed to keep it up.
pub struct ServerLink {
    pub server: PeerId,
    address: Multiaddr,
    circuit: Multiaddr,
    reserved: bool,
    retry_at: Option<Instant>,
    backoff: Duration,
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
            retry_at: None,
            backoff: MIN_BACKOFF,
        })
    }

    /// The server connection dropped: start over.
    pub fn on_disconnected(&mut self, peer: PeerId, still_connected: bool) {
        if peer != self.server || still_connected {
            return;
        }

        self.reserved = false;
        self.retry_at = Some(Instant::now() + self.backoff);
        tracing::warn!(
            server = %self.server,
            retry_in_s = self.backoff.as_secs(),
            "lost the server; will reconnect"
        );
    }

    /// Redial if it is due.
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
}
