use std::collections::HashMap;

use libp2p::PeerId;

use crate::connectivity::{Connectivity, State};

/// How far a peer has got. Admission is not the same thing as being usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Standing {
    Settling,
    Ready,
}

#[derive(Debug, Default)]
pub struct Roster {
    peers: HashMap<PeerId, Standing>,
}

impl Roster {
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
            if *standing == Standing::Ready || !settled(connectivity, peer) {
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
}

/// Whether a peer's connection has stopped changing shape.
fn settled(connectivity: &Connectivity, peer: &PeerId) -> bool {
    !matches!(
        connectivity.get(peer).map(|s| s.effective_state()),
        Some(State::UpgradePending)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> PeerId {
        PeerId::random()
    }

    #[test]
    fn an_admitted_peer_is_not_ready_until_promoted() {
        let mut roster = Roster::default();
        let p = peer();
        roster.admitted(p);

        assert!(!roster.is_ready(&p), "admitted is not yet usable");

        assert_eq!(roster.promote(&Connectivity::default()), vec![p]);
        assert!(roster.is_ready(&p));
    }

    #[test]
    fn a_peer_is_named_once() {
        let mut roster = Roster::default();
        let p = peer();
        roster.admitted(p);

        assert_eq!(roster.promote(&Connectivity::default()), vec![p]);
        assert!(roster.promote(&Connectivity::default()).is_empty());
    }

    #[test]
    fn an_unpunched_peer_waits() {
        let mut roster = Roster::default();
        let p = peer();
        roster.admitted(p);

        let mut connectivity = Connectivity::default();
        connectivity.connected(p, true);

        assert!(
            roster.promote(&connectivity).is_empty(),
            "a relayed connection with a punch in flight has not settled"
        );
        assert!(!roster.is_ready(&p));

        connectivity.connected(p, false);
        assert_eq!(roster.promote(&connectivity), vec![p], "the punch landed");
    }

    #[test]
    fn a_stranger_is_never_ready() {
        let roster = Roster::default();
        assert!(!roster.is_ready(&peer()), "attestation is the only way in");
    }

    #[test]
    fn a_second_connection_closing_does_not_evict() {
        // The shape that made per-peer addressing pick a corpse: a peer reconnects, and the
        // stale connection is reaped afterwards. Dropping them on that close would take the
        // live one down with it.
        let mut roster = Roster::default();
        let p = peer();
        roster.admitted(p);
        roster.promote(&Connectivity::default());

        assert!(!roster.disconnected(&p, true), "they still have one open");
        assert!(roster.is_ready(&p));

        assert!(roster.disconnected(&p, false), "the last one closed");
        assert!(!roster.is_ready(&p));
    }

    #[test]
    fn a_peer_that_never_settled_reports_no_promotion_to_undo() {
        let mut roster = Roster::default();
        let p = peer();
        roster.admitted(p);

        assert!(
            !roster.disconnected(&p, false),
            "nothing was told about them, so nothing needs telling now"
        );
        assert!(!roster.is_ready(&p));
    }

    #[test]
    fn re_attesting_starts_the_wait_again() {
        // A reconnecting peer is announced again, so the entry is replaced rather than merged:
        // the new connection has its own shape and has not settled.
        let mut roster = Roster::default();
        let p = peer();
        roster.admitted(p);
        roster.promote(&Connectivity::default());

        roster.admitted(p);
        assert!(!roster.is_ready(&p));
        assert_eq!(roster.promote(&Connectivity::default()), vec![p]);
    }
}
