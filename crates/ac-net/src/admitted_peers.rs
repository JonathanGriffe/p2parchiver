use std::collections::HashMap;

use libp2p::PeerId;

use crate::connectivity::Connectivity;

/// How far a peer has got. Admission is not the same thing as being usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Standing {
    Settling,
    Ready,
}

/// Peers connected right now whose attestation checked out, each settling or ready.
#[derive(Debug, Default)]
pub struct AdmittedPeers {
    peers: HashMap<PeerId, Standing>,
}

impl AdmittedPeers {
    /// Their attestation checked out; they settle before they are ready.
    pub fn admitted(&mut self, peer: PeerId) {
        self.peers.insert(peer, Standing::Settling);
    }

    /// A connection closed.
    pub fn disconnected(&mut self, peer: &PeerId, still_connected: bool) -> bool {
        if still_connected {
            return false;
        }
        self.peers.remove(peer) == Some(Standing::Ready)
    }

    /// Promote everyone whose connection has stopped changing shape, and name them.
    pub fn promote(&mut self, connectivity: &Connectivity) -> Vec<PeerId> {
        let mut ready = Vec::new();
        for (peer, standing) in self.peers.iter_mut() {
            if *standing == Standing::Ready || !connectivity.is_settled(peer) {
                continue;
            }
            *standing = Standing::Ready;
            ready.push(*peer);
        }
        ready
    }

    /// Whether this peer may be talked to: admitted, and settled.
    pub fn is_ready(&self, peer: &PeerId) -> bool {
        self.peers.get(peer) == Some(&Standing::Ready)
    }

    /// Whether this peer's attestation checked out, settled or not.
    pub fn is_admitted(&self, peer: &PeerId) -> bool {
        self.peers.contains_key(peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> PeerId {
        PeerId::random()
    }

    #[test]
    fn an_admitted_peer_is_not_ready_until_promoted() {
        let mut admitted_peers = AdmittedPeers::default();
        let p = peer();
        admitted_peers.admitted(p);

        assert!(!admitted_peers.is_ready(&p), "admitted is not yet usable");

        assert_eq!(admitted_peers.promote(&Connectivity::default()), vec![p]);
        assert!(admitted_peers.is_ready(&p));
    }

    #[test]
    fn a_peer_still_settling_may_be_answered() {
        let mut admitted_peers = AdmittedPeers::default();
        let p = peer();
        admitted_peers.admitted(p);

        let mut connectivity = Connectivity::default();
        connectivity.connected(p, true);
        assert!(
            admitted_peers.promote(&connectivity).is_empty(),
            "a punch is in flight"
        );

        assert!(!admitted_peers.is_ready(&p));
        assert!(
            admitted_peers.is_admitted(&p),
            "answering waits on the attestation, not on the connection settling"
        );
    }

    #[test]
    fn a_peer_that_was_never_admitted_is_answered_nothing() {
        let admitted_peers = AdmittedPeers::default();
        assert!(!admitted_peers.is_admitted(&peer()));
    }

    #[test]
    fn a_peer_is_named_once() {
        let mut admitted_peers = AdmittedPeers::default();
        let p = peer();
        admitted_peers.admitted(p);

        assert_eq!(admitted_peers.promote(&Connectivity::default()), vec![p]);
        assert!(admitted_peers.promote(&Connectivity::default()).is_empty());
    }

    #[test]
    fn an_unpunched_peer_waits() {
        let mut admitted_peers = AdmittedPeers::default();
        let p = peer();
        admitted_peers.admitted(p);

        let mut connectivity = Connectivity::default();
        connectivity.connected(p, true);

        assert!(
            admitted_peers.promote(&connectivity).is_empty(),
            "a relayed connection with a punch in flight has not settled"
        );
        assert!(!admitted_peers.is_ready(&p));

        connectivity.connected(p, false);
        assert_eq!(
            admitted_peers.promote(&connectivity),
            vec![p],
            "the punch landed"
        );
    }

    #[test]
    fn a_stranger_is_never_ready() {
        let admitted_peers = AdmittedPeers::default();
        assert!(
            !admitted_peers.is_ready(&peer()),
            "attestation is the only way in"
        );
    }

    #[test]
    fn a_second_connection_closing_does_not_evict() {
        // The shape that made per-peer addressing pick a corpse: a peer reconnects, and the
        // stale connection is reaped afterwards. Dropping them on that close would take the
        // live one down with it.
        let mut admitted_peers = AdmittedPeers::default();
        let p = peer();
        admitted_peers.admitted(p);
        admitted_peers.promote(&Connectivity::default());

        assert!(
            !admitted_peers.disconnected(&p, true),
            "they still have one open"
        );
        assert!(admitted_peers.is_ready(&p));

        assert!(
            admitted_peers.disconnected(&p, false),
            "the last one closed"
        );
        assert!(!admitted_peers.is_ready(&p));
    }

    #[test]
    fn a_peer_that_never_settled_reports_no_promotion_to_undo() {
        let mut admitted_peers = AdmittedPeers::default();
        let p = peer();
        admitted_peers.admitted(p);

        assert!(
            !admitted_peers.disconnected(&p, false),
            "nothing was told about them, so nothing needs telling now"
        );
        assert!(!admitted_peers.is_ready(&p));
    }

    #[test]
    fn re_attesting_starts_the_wait_again() {
        // A reconnecting peer is announced again, so the entry is replaced rather than merged:
        // the new connection has its own shape and has not settled.
        let mut admitted_peers = AdmittedPeers::default();
        let p = peer();
        admitted_peers.admitted(p);
        admitted_peers.promote(&Connectivity::default());

        admitted_peers.admitted(p);
        assert!(!admitted_peers.is_ready(&p));
        assert_eq!(admitted_peers.promote(&Connectivity::default()), vec![p]);
    }
}
