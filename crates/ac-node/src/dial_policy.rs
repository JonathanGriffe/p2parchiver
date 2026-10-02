use std::collections::HashMap;

use libp2p::multiaddr::Protocol;
use libp2p::swarm::DialError;
use libp2p::{Multiaddr, PeerId};

/// Candidate direct addresses kept per peer, as many as libp2p dials at once
const MAX_DIRECT_ADDRS: usize = 8;

/// Whether an address is worth ever dialling.
fn dialable(addr: &Multiaddr) -> bool {
    if addr.iter().any(|p| matches!(p, Protocol::P2pCircuit)) {
        // The relay path is the fallback, never a "direct" candidate.
        return false;
    }

    !addr.iter().any(|p| match p {
        Protocol::Ip4(ip) => ip.octets()[0] == 172 && (16..32).contains(&ip.octets()[1]),
        Protocol::Ip6(ip) => (ip.segments()[0] & 0xffc0) == 0xfe80,
        _ => false,
    })
}

/// The address as libp2p dials it and reports it failing, with `/p2p/<peer>` appended.
fn named(peer: PeerId, addr: &Multiaddr) -> Option<Multiaddr> {
    addr.clone().with_p2p(peer).ok()
}

/// Where to dial each peer: its mDNS addresses while it announces any, else the relay.
pub struct DialPolicy {
    relay: Option<Multiaddr>,
    lan: HashMap<PeerId, Lan>,
}

#[derive(Default)]
struct Lan {
    /// Each ending in `/p2p/<peer>`.
    addrs: Vec<Multiaddr>,
    /// The last dial to `addrs` failed, so the next goes through the relay.
    relay_next: bool,
}

impl DialPolicy {
    pub fn new(relay: Option<Multiaddr>) -> Self {
        Self {
            relay,
            lan: HashMap::new(),
        }
    }

    /// mDNS announced this address for the peer.
    pub fn announced(&mut self, peer: PeerId, addr: &Multiaddr) {
        let Some(addr) = named(peer, addr).filter(dialable) else {
            return;
        };
        let lan = self.lan.entry(peer).or_default();
        if !lan.addrs.contains(&addr) && lan.addrs.len() < MAX_DIRECT_ADDRS {
            lan.addrs.push(addr);
        }
    }

    /// mDNS stopped announcing this address, so it is no longer dialed.
    pub fn expired(&mut self, peer: PeerId, addr: &Multiaddr) {
        let (Some(addr), Some(lan)) = (named(peer, addr), self.lan.get_mut(&peer)) else {
            return;
        };
        lan.addrs.retain(|a| a != &addr);
        if lan.addrs.is_empty() {
            self.lan.remove(&peer);
        }
    }

    /// A dial to the peer failed. Only a transport-level failure at one of its LAN
    /// addresses counts: a local refusal, such as `Denied`, says nothing about the address.
    pub fn failed(&mut self, peer: PeerId, error: &DialError) {
        let Some(lan) = self.lan.get_mut(&peer) else {
            return;
        };
        let is_lan = |addr: &Multiaddr| named(peer, addr).is_some_and(|a| lan.addrs.contains(&a));
        let failed = match error {
            DialError::Transport(tried) => tried.iter().any(|(addr, _)| is_lan(addr)),
            DialError::WrongPeerId { address, .. } => is_lan(address),
            _ => false,
        };
        lan.relay_next |= failed;
    }

    /// The addresses to dial the peer at now, all in one attempt: its LAN addresses, or the
    /// circuit through the relay, which also takes the one attempt owed after a failed LAN
    /// dial. Empty when it has no LAN address and there is no server to relay through.
    pub fn next(&mut self, peer: PeerId) -> Vec<Multiaddr> {
        let relay = self
            .relay
            .clone()
            .map(|relay| relay.with(Protocol::P2pCircuit).with(Protocol::P2p(peer)));
        let Some(lan) = self.lan.get_mut(&peer) else {
            return relay.into_iter().collect();
        };
        if std::mem::take(&mut lan.relay_next) && relay.is_some() {
            return relay.into_iter().collect();
        }
        lan.addrs.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LAN: &str = "/ip4/192.168.1.5/tcp/4001";

    /// A policy with a server to relay through, and the circuit to `peer`.
    fn with_relay(peer: PeerId) -> (DialPolicy, Multiaddr) {
        let server: Multiaddr =
            format!("/ip4/203.0.113.1/udp/4001/quic-v1/p2p/{}", PeerId::random())
                .parse()
                .unwrap();
        let circuit = server
            .clone()
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(peer));
        (DialPolicy::new(Some(server)), circuit)
    }

    /// A policy with a relay and one peer announcing a LAN address.
    /// Returns the policy, the peer, its LAN address as dialed, and the circuit to it.
    fn with_lan_peer() -> (DialPolicy, PeerId, Multiaddr, Multiaddr) {
        let them = PeerId::random();
        let (mut policy, relayed) = with_relay(them);
        policy.announced(them, &LAN.parse().unwrap());
        let lan = format!("{LAN}/p2p/{them}").parse().unwrap();
        (policy, them, lan, relayed)
    }

    /// A dial that failed at each of these addresses.
    fn transport_failure(addrs: &[Multiaddr]) -> DialError {
        DialError::Transport(
            addrs
                .iter()
                .map(|addr| {
                    let refused = std::io::Error::other("connection refused");
                    (addr.clone(), libp2p::TransportError::Other(refused))
                })
                .collect(),
        )
    }

    #[test]
    fn an_address_nobody_else_can_route_to_is_not_a_candidate() {
        let yes: Multiaddr = "/ip4/192.168.1.140/tcp/4001".parse().unwrap();
        let lan: Multiaddr = "/ip4/10.0.0.9/udp/4001/quic-v1".parse().unwrap();
        assert!(dialable(&yes));
        assert!(dialable(&lan));

        for junk in [
            "/ip4/172.17.0.1/tcp/4001", // docker0
            "/ip4/172.19.0.1/tcp/4001", // a user-defined bridge
            "/ip4/172.31.0.1/tcp/4001", // the top of the pool
            "/ip6/fe80::1/tcp/4001",    // link-local, no zone survives a multiaddr
        ] {
            assert!(
                !dialable(&junk.parse().unwrap()),
                "{junk} should be refused"
            );
        }

        // 172.15 and 172.32 are outside the pool and stay dialable.
        assert!(dialable(&"/ip4/172.15.0.1/tcp/4001".parse().unwrap()));
        assert!(dialable(&"/ip4/172.32.0.1/tcp/4001".parse().unwrap()));
    }

    #[test]
    fn a_peer_with_no_lan_address_is_dialed_through_the_relay() {
        let them = PeerId::random();
        let (mut policy, relayed) = with_relay(them);
        assert_eq!(policy.next(them), vec![relayed]);
    }

    #[test]
    fn every_lan_address_is_dialed_at_once_with_the_peer_named() {
        let (mut policy, them, lan, _) = with_lan_peer();
        let other: Multiaddr = "/ip4/192.168.1.5/udp/4002/quic-v1".parse().unwrap();
        policy.announced(them, &other);

        assert_eq!(
            policy.next(them),
            vec![lan, other.with(Protocol::P2p(them))]
        );
    }

    #[test]
    fn a_failed_lan_dial_goes_through_the_relay_once_then_tries_the_address_again() {
        let (mut policy, them, lan, relayed) = with_lan_peer();

        let tried = policy.next(them);
        assert_eq!(tried, vec![lan.clone()]);
        policy.failed(them, &transport_failure(&tried));
        assert_eq!(
            policy.next(them),
            vec![relayed],
            "the next attempt is relayed"
        );
        assert_eq!(
            policy.next(them),
            vec![lan],
            "and the address is tried again after that"
        );
    }

    #[test]
    fn a_dial_failing_at_every_lan_address_sends_the_next_through_the_relay() {
        let (mut policy, them, lan, relayed) = with_lan_peer();
        let other: Multiaddr = "/ip4/192.168.1.5/udp/4002/quic-v1".parse().unwrap();
        policy.announced(them, &other);

        let tried = policy.next(them);
        policy.failed(them, &transport_failure(&tried));
        assert_eq!(policy.next(them), vec![relayed]);
        assert_eq!(
            policy.next(them),
            vec![lan, other.with(Protocol::P2p(them))]
        );
    }

    #[test]
    fn a_dial_refused_locally_does_not_send_the_next_attempt_through_the_relay() {
        let (mut policy, them, lan, _) = with_lan_peer();

        assert_eq!(policy.next(them), vec![lan.clone()]);
        let denied = DialError::Denied {
            cause: libp2p::swarm::ConnectionDenied::new(std::io::Error::other("too many")),
        };
        policy.failed(them, &denied);
        assert_eq!(policy.next(them), vec![lan]);
    }

    #[test]
    fn a_failed_relayed_dial_leaves_the_lan_address_alone() {
        let (mut policy, them, lan, relayed) = with_lan_peer();

        let tried = policy.next(them);
        policy.failed(them, &transport_failure(&tried));
        let tried = policy.next(them);
        assert_eq!(tried, vec![relayed]);
        policy.failed(them, &transport_failure(&tried));
        assert_eq!(policy.next(them), vec![lan]);
    }

    #[test]
    fn an_address_mdns_reports_expired_is_no_longer_dialed() {
        let (mut policy, them, lan, relayed) = with_lan_peer();
        let other: Multiaddr = "/ip4/192.168.1.5/udp/4001/quic-v1".parse().unwrap();
        policy.announced(them, &other);

        policy.expired(them, &lan);
        assert_eq!(
            policy.next(them),
            vec![other.clone().with(Protocol::P2p(them))],
            "the address still announced is dialed alone"
        );

        policy.expired(them, &other);
        assert_eq!(policy.next(them), vec![relayed]);
    }
}
