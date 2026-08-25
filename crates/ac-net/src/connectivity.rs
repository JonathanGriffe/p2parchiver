use std::collections::HashMap;
use std::time::{Duration, Instant};

use libp2p::PeerId;

pub const UPGRADE_TIMEOUT: Duration = Duration::from_secs(15);

/// How a peer is reachable right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Disconnected,
    UpgradePending,
    Relayed,
    Direct,
}

impl State {
    pub fn is_relayed(self) -> bool {
        matches!(self, State::UpgradePending | State::Relayed)
    }
}

/// What is known about one peer.
#[derive(Debug, Clone)]
pub struct PeerState {
    pub state: State,
    pub since: Instant,
    pub reason: &'static str,
    pub attempts: u32,
    relayed_since: Option<Instant>,
}

impl PeerState {
    fn new(state: State, reason: &'static str) -> Self {
        Self {
            state,
            since: Instant::now(),
            reason,
            attempts: 0,
            relayed_since: None,
        }
    }

    fn enter(&mut self, state: State, reason: &'static str) {
        if self.state != state {
            self.since = Instant::now();
        }
        self.state = state;
        self.reason = reason;
    }

    pub fn upgrade_took(&self) -> Option<Duration> {
        if self.state != State::Direct {
            return None;
        }
        Some(self.since.duration_since(self.relayed_since?))
    }

    /// The effective connection state. When the upgrade is pending, the connection is still relayed.
    pub fn effective_state(&self) -> State {
        if self.state == State::UpgradePending && self.since.elapsed() > UPGRADE_TIMEOUT {
            State::Relayed
        } else {
            self.state
        }
    }
}

/// Per-peer connection state.
#[derive(Debug, Default)]
pub struct Connectivity {
    peers: HashMap<PeerId, PeerState>,
}

impl Connectivity {
    /// A connection was established.
    pub fn connected(&mut self, peer: PeerId, relayed: bool) {
        let entry = self
            .peers
            .entry(peer)
            .or_insert_with(|| PeerState::new(State::Disconnected, "new peer"));

        if relayed {
            // A direct connection beats a relayed one
            if entry.state == State::Direct {
                return;
            }
            entry.relayed_since.get_or_insert_with(Instant::now);
            entry.enter(State::UpgradePending, "relayed connection established");
        } else {
            entry.enter(State::Direct, "direct connection established");
        }
    }

    /// A connection closed. `still_connected` is whether any other connection to that peer
    /// remains.
    pub fn disconnected(&mut self, peer: PeerId, still_connected: bool) {
        let Some(entry) = self.peers.get_mut(&peer) else {
            return;
        };

        if still_connected {
            // Almost always the relayed connection being retired after a successful
            // upgrade.
            return;
        }
        entry.enter(State::Disconnected, "all connections closed");
        entry.relayed_since = None;
    }

    /// DCUtR reported an outcome.
    pub fn hole_punch(&mut self, peer: PeerId, succeeded: bool) {
        let Some(entry) = self.peers.get_mut(&peer) else {
            return;
        };
        entry.attempts += 1;

        if succeeded {
            entry.enter(State::Direct, "hole punch succeeded");
        } else {
            entry.enter(State::Relayed, "hole punch failed; staying relayed");
        }
    }

    /// Whether this peer's connection has stopped changing shape.
    pub fn is_settled(&self, peer: &PeerId) -> bool {
        !matches!(
            self.peers.get(peer).map(|s| s.effective_state()),
            Some(State::UpgradePending)
        )
    }

    pub fn get(&self, peer: &PeerId) -> Option<&PeerState> {
        self.peers.get(peer)
    }

    pub fn state(&self, peer: &PeerId) -> State {
        self.peers
            .get(peer)
            .map_or(State::Disconnected, |p| p.state)
    }

    pub fn connected_peers(&self) -> impl Iterator<Item = (&PeerId, &PeerState)> {
        self.peers
            .iter()
            .filter(|(_, s)| s.state != State::Disconnected)
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

    #[test]
    fn an_unseen_peer_is_disconnected() {
        assert_eq!(Connectivity::default().state(&peer()), State::Disconnected);
    }

    #[test]
    fn a_relayed_connection_starts_an_upgrade() {
        // No "upgrade started" event exists, so establishing the relayed connection is
        // itself the signal: DCUtR begins immediately.
        let mut c = Connectivity::default();
        let p = peer();
        c.connected(p, true);

        assert_eq!(c.state(&p), State::UpgradePending);
        assert_eq!(c.get(&p).unwrap().attempts, 0, "none reported yet");
    }

    #[test]
    fn only_a_pending_upgrade_is_unsettled() {
        // What `Roster::promote` asks. The unknown-peer case is load-bearing: it is why a test
        // holding an empty `Connectivity` promotes everyone, and why a node that somehow
        // admitted a peer it never saw connect is not held for ever.
        let mut c = Connectivity::default();
        let p = peer();
        assert!(c.is_settled(&p), "nothing in flight to wait on");

        c.connected(p, true);
        assert!(!c.is_settled(&p), "a punch is in flight");

        c.hole_punch(p, false);
        assert!(
            c.is_settled(&p),
            "relayed is a final answer, not a degraded one"
        );

        c.connected(p, true);
        c.peers.get_mut(&p).unwrap().since =
            Instant::now() - UPGRADE_TIMEOUT - Duration::from_secs(1);
        assert!(
            c.is_settled(&p),
            "the side that is never told a punch failed still stops waiting"
        );
    }

    #[test]
    fn a_direct_connection_needs_no_upgrade() {
        let mut c = Connectivity::default();
        let p = peer();
        c.connected(p, false);

        assert_eq!(c.state(&p), State::Direct);
    }

    #[test]
    fn the_full_relayed_to_direct_path() {
        // The sequence milestone 1 exists to demonstrate.
        let mut c = Connectivity::default();
        let p = peer();

        c.connected(p, true);
        assert_eq!(c.state(&p), State::UpgradePending);

        c.hole_punch(p, true);
        c.connected(p, false);
        assert_eq!(c.state(&p), State::Direct);

        // The relayed connection is retired afterwards; the peer stays direct.
        c.disconnected(p, true);
        assert_eq!(c.state(&p), State::Direct);
    }

    #[test]
    fn a_failed_punch_settles_on_relayed() {
        // The correct outcome under symmetric NAT, not a bug.
        let mut c = Connectivity::default();
        let p = peer();

        c.connected(p, true);
        c.hole_punch(p, false);

        assert_eq!(c.state(&p), State::Relayed);
        assert_eq!(
            c.get(&p).unwrap().effective_state(),
            State::Relayed,
            "a settled relayed connection is not still pending"
        );
    }

    #[test]
    fn attempts_are_counted_across_connections() {
        let mut c = Connectivity::default();
        let p = peer();
        c.connected(p, true);

        for _ in 0..3 {
            c.connected(p, true); // libp2p retries over the relayed connection
            c.hole_punch(p, false);
        }
        assert_eq!(c.get(&p).unwrap().attempts, 3);

        c.disconnected(p, false);
        c.connected(p, true);
        assert_eq!(
            c.get(&p).unwrap().attempts,
            3,
            "a reconnection does not clear the record"
        );
    }

    #[test]
    fn a_late_relayed_connection_does_not_downgrade_a_direct_one() {
        // Both peers dialling each other produces a second relayed connection after the
        // upgrade has already succeeded. Reporting "relayed" then would be wrong.
        let mut c = Connectivity::default();
        let p = peer();

        c.connected(p, true);
        c.hole_punch(p, true);
        c.connected(p, false);
        c.connected(p, true);

        assert_eq!(c.state(&p), State::Direct);
    }

    #[test]
    fn losing_every_connection_disconnects() {
        let mut c = Connectivity::default();
        let p = peer();

        c.connected(p, true);
        c.disconnected(p, false);

        assert_eq!(c.state(&p), State::Disconnected);
    }

    #[test]
    fn relayed_states_are_flagged_as_relayed() {
        // What a caller checks before sending anything that may outgrow one circuit.
        assert!(State::UpgradePending.is_relayed());
        assert!(State::Relayed.is_relayed());
        assert!(!State::Direct.is_relayed());
        assert!(!State::Disconnected.is_relayed());
    }

    #[test]
    fn the_upgrade_is_timed_from_the_relayed_connection() {
        let mut c = Connectivity::default();
        let p = peer();

        c.connected(p, true);
        assert!(
            c.get(&p).unwrap().upgrade_took().is_none(),
            "not yet direct"
        );

        c.hole_punch(p, true);
        c.connected(p, false);
        assert!(
            c.get(&p).unwrap().upgrade_took().is_some(),
            "a direct peer should report how long the upgrade took"
        );
    }

    #[test]
    fn reconnecting_after_a_drop_starts_over() {
        let mut c = Connectivity::default();
        let p = peer();

        c.connected(p, true);
        c.hole_punch(p, true);
        c.connected(p, false);
        c.disconnected(p, false);
        c.connected(p, true);

        assert_eq!(c.state(&p), State::UpgradePending);
        assert!(
            c.get(&p).unwrap().upgrade_took().is_none(),
            "the previous upgrade's timing must not leak into a new connection"
        );
    }

    #[test]
    fn a_pending_upgrade_settles_on_relayed_once_it_times_out() {
        let mut c = Connectivity::default();
        let p = peer();
        c.connected(p, true);
        assert_eq!(c.get(&p).unwrap().effective_state(), State::UpgradePending);

        c.peers.get_mut(&p).unwrap().since =
            Instant::now() - UPGRADE_TIMEOUT - Duration::from_secs(1);

        assert_eq!(c.get(&p).unwrap().effective_state(), State::Relayed);
        assert_eq!(
            c.get(&p).unwrap().state,
            State::UpgradePending,
            "the raw state is untouched; only the reading of it changes"
        );
    }

    #[test]
    fn a_timed_out_direct_connection_is_still_direct() {
        // The deadline applies only to a pending upgrade. A long-lived direct connection
        // must not decay into "relayed" just by being old.
        let mut c = Connectivity::default();
        let p = peer();
        c.connected(p, false);
        c.peers.get_mut(&p).unwrap().since =
            Instant::now() - UPGRADE_TIMEOUT - Duration::from_secs(1);

        assert_eq!(c.get(&p).unwrap().effective_state(), State::Direct);
    }

    #[test]
    fn events_for_an_unknown_peer_are_ignored() {
        // Ordering is not guaranteed; a close or a punch result can arrive for a peer we
        // never saw connect. Panicking on that would take down the daemon.
        let mut c = Connectivity::default();
        c.disconnected(peer(), false);
        c.hole_punch(peer(), true);
        assert_eq!(c.connected_peers().count(), 0);
    }
}
