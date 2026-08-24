use std::task::{Context, Poll};

use libp2p::PeerId;
use libp2p::core::transport::PortUse;
use libp2p::core::{Endpoint, Multiaddr};
use libp2p::swarm::{
    ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm, dummy,
};

/// Decides whether a peer may hold a connection to us.
pub trait PeerAuthorizer: Send + 'static {
    fn is_allowed(&self, peer: &PeerId) -> bool;
}

/// The client policy : accepts every peer id.
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
