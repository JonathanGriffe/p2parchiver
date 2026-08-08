//! Connection-level authorization: the mechanism, never the policy.
//!
//! This is the *server's* gate. Relay bandwidth is consumed the moment a connection
//! exists, so the server has to decide who may open one before it does. Clients do not
//! use it that way — see below.
//!
//! # Why clients do not filter connections by identity
//!
//! An obvious-looking design gives every node a list of peers it will accept and refuses
//! the rest. It deadlocks the moment membership changes while someone is offline:
//!
//! > A adds B to a group. B syncs and goes offline. A adds C. B returns. C holds a
//! > membership log signed by A proving C belongs — but B's list predates C, so B refuses
//! > the connection, and C can never deliver the proof that would authorize it.
//!
//! Connection-level authorization prevents delivery of the very credential that would
//! authorize the connection. So clients accept anyone and authorize *data* instead: a
//! peer asking for objects must present a group membership log signed by that group's
//! admin, which the recipient verifies itself. That proof is self-authenticating, so a
//! returning member can be vouched for by a peer it has never met.
//!
//! What is left at the connection layer is resource exhaustion, not access — handled by
//! [`crate::limits`], not by identity.

use std::task::{Context, Poll};

use libp2p::PeerId;
use libp2p::core::transport::PortUse;
use libp2p::core::{Endpoint, Multiaddr};
use libp2p::swarm::{
    ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm, dummy,
};

/// Decides whether a peer may hold a connection to us.
///
/// Implemented by each binary, so `ac-net` never learns *why* a peer is refused. The
/// indirection is load-bearing: `libp2p::allow_block_list` does the same job against an
/// in-memory set, which cannot be updated by a CLI running in another process. Backing
/// this with a SQLite query keeps a running daemon current with no IPC or cache
/// invalidation, and connections are rare enough that a point query costs nothing.
pub trait PeerAuthorizer: Send + 'static {
    fn is_allowed(&self, peer: &PeerId) -> bool;
}

/// Accepts every peer id. What clients use, per the module docs.
///
/// Not the same as "unprotected": connection *counts* are still capped by
/// [`crate::limits`], which sits alongside this in the behaviour. This decides only
/// whether a peer's identity disqualifies it, and on a client nothing does.
#[derive(Debug, Clone, Copy, Default)]
pub struct AcceptAnyPeer;

impl PeerAuthorizer for AcceptAnyPeer {
    fn is_allowed(&self, _peer: &PeerId) -> bool {
        true
    }
}

/// Returned to the swarm when a peer is refused.
#[derive(Debug, thiserror::Error)]
#[error("peer {peer} is not authorized")]
pub struct NotAuthorized {
    pub peer: PeerId,
}

/// Refuses connections that the [`PeerAuthorizer`] rejects.
///
/// Denial happens during connection establishment rather than after, so a refused peer
/// never reaches a state where it could open a stream. Checking on
/// `SwarmEvent::ConnectionEstablished` and closing afterwards would leave a window in
/// which an unauthorized peer holds a live, encrypted connection to protocols we mount.
///
/// The check runs only at establishment. A peer whose authorization is withdrawn keeps
/// the connection it already holds until that connection ends on its own. For the server
/// that is acceptable, because revocation bites where it matters — a revoked client
/// cannot renew a relay reservation or a rendezvous registration, and both are periodic.
pub struct Behaviour<A> {
    authorizer: A,
}

impl<A> Behaviour<A> {
    pub fn new(authorizer: A) -> Self {
        Self { authorizer }
    }

    pub fn authorizer(&self) -> &A {
        &self.authorizer
    }
}

impl<A: PeerAuthorizer> Behaviour<A> {
    fn enforce(&self, peer: PeerId) -> Result<(), ConnectionDenied> {
        if self.authorizer.is_allowed(&peer) {
            Ok(())
        } else {
            tracing::debug!(%peer, "refusing connection: not authorized");
            Err(ConnectionDenied::new(NotAuthorized { peer }))
        }
    }
}

impl<A> NetworkBehaviour for Behaviour<A>
where
    A: PeerAuthorizer,
{
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = std::convert::Infallible;

    fn handle_established_inbound_connection(
        &mut self,
        _: ConnectionId,
        peer: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.enforce(peer)?;
        Ok(dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: ConnectionId,
        peer: PeerId,
        _: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.enforce(peer)?;
        Ok(dummy::ConnectionHandler)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        _: ConnectionId,
        peer: Option<PeerId>,
        _: &[Multiaddr],
        _: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        // Refusing here saves dialling a peer we would reject on arrival. Only possible
        // when the peer id is known up front, which it is not for an address without
        // `/p2p/...`; that case is caught by the established hook above.
        if let Some(peer) = peer {
            self.enforce(peer)?;
        }
        Ok(vec![])
    }

    fn on_swarm_event(&mut self, _: FromSwarm) {}

    fn on_connection_handler_event(
        &mut self,
        _: PeerId,
        _: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        // `dummy::ConnectionHandler` never produces an event.
        match event {}
    }

    fn poll(&mut self, _: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    struct OnlyThese(HashSet<PeerId>);

    impl PeerAuthorizer for OnlyThese {
        fn is_allowed(&self, peer: &PeerId) -> bool {
            self.0.contains(peer)
        }
    }

    fn peer() -> PeerId {
        libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id()
    }

    fn addr() -> Multiaddr {
        "/ip4/127.0.0.1/tcp/1".parse().unwrap()
    }

    #[test]
    fn accept_any_peer_admits_anyone() {
        let mut b = Behaviour::new(AcceptAnyPeer);
        assert!(
            b.handle_established_inbound_connection(
                ConnectionId::new_unchecked(0),
                peer(),
                &addr(),
                &addr()
            )
            .is_ok()
        );
    }

    #[test]
    fn a_peer_outside_the_policy_is_denied_inbound() {
        let allowed = peer();
        let mut b = Behaviour::new(OnlyThese(HashSet::from([allowed])));

        assert!(
            b.handle_established_inbound_connection(
                ConnectionId::new_unchecked(0),
                allowed,
                &addr(),
                &addr()
            )
            .is_ok()
        );
        assert!(
            b.handle_established_inbound_connection(
                ConnectionId::new_unchecked(1),
                peer(),
                &addr(),
                &addr()
            )
            .is_err()
        );
    }

    #[test]
    fn denial_is_symmetric_for_outbound() {
        let mut b = Behaviour::new(OnlyThese(HashSet::new()));
        assert!(
            b.handle_established_outbound_connection(
                ConnectionId::new_unchecked(0),
                peer(),
                &addr(),
                Endpoint::Dialer,
                PortUse::Reuse,
            )
            .is_err()
        );
    }

    #[test]
    fn a_dial_to_an_unauthorized_peer_is_refused_before_it_starts() {
        let mut b = Behaviour::new(OnlyThese(HashSet::new()));
        assert!(
            b.handle_pending_outbound_connection(
                ConnectionId::new_unchecked(0),
                Some(peer()),
                &[],
                Endpoint::Dialer,
            )
            .is_err()
        );
    }

    #[test]
    fn an_address_without_a_peer_id_is_left_to_the_established_hook() {
        // Nothing to enforce against yet; refusing here would block every dial by bare
        // address, including the very first one to a server.
        let mut b = Behaviour::new(OnlyThese(HashSet::new()));
        assert!(
            b.handle_pending_outbound_connection(
                ConnectionId::new_unchecked(0),
                None,
                &[],
                Endpoint::Dialer,
            )
            .is_ok()
        );
    }
}
