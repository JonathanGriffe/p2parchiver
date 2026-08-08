//! How we are connected to each peer, and why.
//!
//! Milestone 1's deliverable is evidence, not a feeling: it has to be possible to say
//! whether a pair of nodes ended up talking directly or through the relay, and if directly,
//! how long it took. That is what this records.
//!
//! Deliberately free of libp2p types beyond [`PeerId`], so the whole machine can be driven
//! from a scripted sequence in a unit test. The network half of stage 9 cannot be tested
//! on one host — two peers on loopback connect directly and prove nothing — so the logic
//! half needs to be testable on its own.
//!
//! # Why there is no "upgrade started" input
//!
//! DCUtR reports only success or failure; it has no "beginning now" event, because the
//! attempt starts automatically the instant a relayed connection is established. So
//! [`State::UpgradePending`] is *derived* — a relayed connection whose outcome has not
//! arrived — rather than observed. The distinction it draws is still worth having: it
//! separates "still trying" from "gave up, staying relayed", and those are different
//! answers to the only question this module exists to answer.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use libp2p::PeerId;

/// libp2p gives up after this many dial attempts, so a peer that has used them all will
/// not spontaneously improve.
pub const MAX_HOLE_PUNCH_ATTEMPTS: u32 = 3;

/// After this long with no outcome, a pending upgrade is treated as failed.
///
/// Needed because **only one side is told**. DCUtR's initiator is whichever peer *received*
/// the relayed connection; it gets the result event, and the other side gets nothing at
/// all. Without a deadline the responder would report `UpgradePending` forever after a
/// failure it never heard about — which is exactly what a loopback run produced.
///
/// Sized against what DCUtR actually does: at most three attempts, each roughly two round
/// trips plus a dial. Seconds, not tens of seconds.
///
/// Erring short is safe and erring long is not. Settling prematurely costs nothing —
/// should the punch land afterwards, the direct connection arrives as its own event and
/// moves the peer straight to [`State::Direct`]. Settling too late means a diagnostic that
/// never reaches a verdict, which is what a 30-second value produced.
pub const UPGRADE_TIMEOUT: Duration = Duration::from_secs(15);

/// How a peer is reachable right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// No connection.
    Disconnected,
    /// Through the relay, with the hole punch still outstanding.
    UpgradePending,
    /// Through the relay, and it is going to stay that way — the hole punch failed or was
    /// never attempted. Not a degraded mode to fix later: for a symmetric-NAT pair this is
    /// the correct final answer.
    Relayed,
    /// Peer to peer, no relay in the path.
    Direct,
}

impl State {
    /// Whether traffic to this peer crosses the relay, and so is subject to its limits —
    /// 128 KiB per circuit today. The thing a caller has to check before sending anything
    /// substantial.
    pub fn is_relayed(self) -> bool {
        matches!(self, State::UpgradePending | State::Relayed)
    }
}

/// What is known about one peer.
#[derive(Debug, Clone)]
pub struct PeerState {
    pub state: State,
    /// When the current state began, for "DIRECT after 1.8s".
    pub since: Instant,
    /// Why the last transition happened, for a human reading a report.
    pub reason: &'static str,
    /// Hole punches attempted against this peer.
    pub attempts: u32,
    /// When the first relayed connection appeared, so the upgrade can be timed end to end.
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

    /// How long the upgrade took, measured from the first relayed connection.
    ///
    /// `None` for a peer that was never relayed — a direct connection that needed no
    /// upgrade has no duration to report, which is different from one that took 0s.
    pub fn upgrade_took(&self) -> Option<Duration> {
        if self.state != State::Direct {
            return None;
        }
        Some(self.since.duration_since(self.relayed_since?))
    }

    /// The state as a caller should read it.
    ///
    /// Differs from the raw [`Self::state`] in one case: a pending upgrade that has waited
    /// past [`UPGRADE_TIMEOUT`] is reported as [`State::Relayed`]. Only DCUtR's initiator
    /// receives the result, so the responding side would otherwise sit in
    /// `UpgradePending` indefinitely after a failure nobody told it about.
    ///
    /// Deliberately derived on read rather than driven by a timer: there is nothing to
    /// wake up for, and a timer would be a second source of truth to keep in step.
    pub fn effective_state(&self) -> State {
        if self.state == State::UpgradePending && self.since.elapsed() > UPGRADE_TIMEOUT {
            State::Relayed
        } else {
            self.state
        }
    }

    /// Whether libp2p will keep trying, or has spent its attempts — or its time.
    pub fn may_still_upgrade(&self) -> bool {
        self.effective_state() == State::UpgradePending && self.attempts < MAX_HOLE_PUNCH_ATTEMPTS
    }
}

/// Per-peer connection state.
#[derive(Debug, Default)]
pub struct Connectivity {
    peers: HashMap<PeerId, PeerState>,
}

impl Connectivity {
    /// A connection was established.
    ///
    /// `relayed` is whether its address contains `/p2p-circuit`.
    pub fn connected(&mut self, peer: PeerId, relayed: bool) {
        let entry = self
            .peers
            .entry(peer)
            .or_insert_with(|| PeerState::new(State::Disconnected, "new peer"));

        if relayed {
            // A direct connection already beats a relayed one; a second relayed connection
            // arriving afterwards must not undo that.
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
    /// remains — a peer legitimately holds a relayed *and* a direct connection while an
    /// upgrade settles, so one closing does not mean the peer is gone.
    pub fn disconnected(&mut self, peer: PeerId, still_connected: bool) {
        let Some(entry) = self.peers.get_mut(&peer) else {
            return;
        };

        if still_connected {
            // Almost always the relayed connection being retired after a successful
            // upgrade. Nothing to record: the surviving connection defines the state.
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
            // The direct connection arrives as its own `connected` call; this only records
            // that DCUtR is why, rather than a coincidental direct dial.
            entry.enter(State::Direct, "hole punch succeeded");
        } else {
            // Correct outcome for a symmetric-NAT pair, not a failure to fix.
            entry.enter(State::Relayed, "hole punch failed; staying relayed");
        }
    }

    pub fn get(&self, peer: &PeerId) -> Option<&PeerState> {
        self.peers.get(peer)
    }

    pub fn state(&self, peer: &PeerId) -> State {
        self.peers
            .get(peer)
            .map_or(State::Disconnected, |p| p.state)
    }

    /// Every peer with a live connection, and how.
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
        assert!(c.get(&p).unwrap().may_still_upgrade());
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
        assert!(
            !c.get(&p).unwrap().may_still_upgrade(),
            "a settled relayed connection is not still pending"
        );
    }

    #[test]
    fn attempts_are_counted_and_run_out() {
        let mut c = Connectivity::default();
        let p = peer();
        c.connected(p, true);

        for _ in 0..MAX_HOLE_PUNCH_ATTEMPTS {
            c.connected(p, true); // libp2p retries over the relayed connection
            c.hole_punch(p, false);
        }

        assert_eq!(c.get(&p).unwrap().attempts, MAX_HOLE_PUNCH_ATTEMPTS);
        assert!(!c.get(&p).unwrap().may_still_upgrade());
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
        // What a caller checks before sending anything larger than the circuit's 128 KiB.
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
        // The responder in a DCUtR exchange is never told the outcome — only the peer
        // that received the relayed connection gets the result event. Without this, it
        // would report "still trying" forever after a failure it never heard about.
        let mut c = Connectivity::default();
        let p = peer();
        c.connected(p, true);
        assert_eq!(c.get(&p).unwrap().effective_state(), State::UpgradePending);

        c.peers.get_mut(&p).unwrap().since =
            Instant::now() - UPGRADE_TIMEOUT - Duration::from_secs(1);

        assert_eq!(c.get(&p).unwrap().effective_state(), State::Relayed);
        assert!(!c.get(&p).unwrap().may_still_upgrade());
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
