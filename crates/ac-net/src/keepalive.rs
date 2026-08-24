use std::task::{Context, Poll};

use either::Either;
use libp2p::PeerId;
use libp2p::core::transport::PortUse;
use libp2p::core::{Endpoint, Multiaddr};
use libp2p::ping;
use libp2p::swarm::{
    ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm, dummy,
};

/// Pings one peer and ignores the rest.
pub struct Behaviour {
    /// The only peer worth keeping a mapping open for. `None` on a server, which is
    /// publicly reachable and has no mapping to keep.
    keep: Option<PeerId>,
    inner: ping::Behaviour,
}

impl Behaviour {
    pub fn new(keep: Option<PeerId>, config: ping::Config) -> Self {
        Self {
            keep,
            inner: ping::Behaviour::new(config),
        }
    }

    fn pings(&self, peer: &PeerId) -> bool {
        self.keep == Some(*peer)
    }
}

impl NetworkBehaviour for Behaviour {
    /// A real ping handler on the server's connections, an inert one everywhere else.
    type ConnectionHandler = Either<THandler<ping::Behaviour>, dummy::ConnectionHandler>;
    type ToSwarm = ping::Event;

    fn handle_established_inbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if !self.pings(&peer) {
            return Ok(Either::Right(dummy::ConnectionHandler));
        }
        Ok(Either::Left(
            self.inner
                .handle_established_inbound_connection(id, peer, local, remote)?,
        ))
    }

    fn handle_established_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        role: Endpoint,
        port: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if !self.pings(&peer) {
            return Ok(Either::Right(dummy::ConnectionHandler));
        }
        Ok(Either::Left(
            self.inner
                .handle_established_outbound_connection(id, peer, addr, role, port)?,
        ))
    }

    fn handle_pending_inbound_connection(
        &mut self,
        id: ConnectionId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        self.inner
            .handle_pending_inbound_connection(id, local, remote)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: Option<PeerId>,
        addrs: &[Multiaddr],
        role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        self.inner
            .handle_pending_outbound_connection(id, peer, addrs, role)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        self.inner.on_swarm_event(event);
    }

    fn on_connection_handler_event(
        &mut self,
        peer: PeerId,
        id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {
            Either::Left(event) => self.inner.on_connection_handler_event(peer, id, event),
            // The inert handler never speaks.
            Either::Right(never) => match never {},
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        self.inner.poll(cx).map(|event| event.map_in(Either::Left))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> PeerId {
        libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id()
    }

    fn addr() -> Multiaddr {
        "/ip4/127.0.0.1/tcp/1".parse().expect("a valid address")
    }

    fn behaviour(keep: Option<PeerId>) -> Behaviour {
        Behaviour::new(keep, ping::Config::new())
    }

    /// Left is the real ping handler, Right the inert one.
    fn is_pinged(b: &mut Behaviour, peer: PeerId) -> bool {
        let handler = b
            .handle_established_outbound_connection(
                ConnectionId::new_unchecked(0),
                peer,
                &addr(),
                Endpoint::Dialer,
                PortUse::Reuse,
            )
            .expect("ping never denies a connection");
        matches!(handler, Either::Left(_))
    }

    #[test]
    fn the_server_is_pinged_and_peers_are_not() {
        // The whole point: a quiet peer connection carries nothing, so the swarm's idle
        // timeout can reap it. Pinging it would hold it open for no one's benefit.
        let server = peer();
        let mut b = behaviour(Some(server));

        assert!(is_pinged(&mut b, server), "the mapping worth keeping open");
        assert!(!is_pinged(&mut b, peer()), "a peer is left to lapse");
    }

    #[test]
    fn an_inbound_connection_is_judged_the_same_way() {
        let server = peer();
        let mut b = behaviour(Some(server));

        let pinged = |b: &mut Behaviour, p| {
            matches!(
                b.handle_established_inbound_connection(
                    ConnectionId::new_unchecked(0),
                    p,
                    &addr(),
                    &addr(),
                )
                .expect("ping never denies a connection"),
                Either::Left(_)
            )
        };

        assert!(pinged(&mut b, server));
        assert!(!pinged(&mut b, peer()));
    }

    #[test]
    fn a_node_with_no_server_pings_nobody() {
        let mut b = behaviour(None);
        assert!(!is_pinged(&mut b, peer()));
    }
}
