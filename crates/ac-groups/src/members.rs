//! The result of folding a chain: who belongs, right now.
//!
//! Deliberately a plain value with no I/O and no libp2p beyond [`PeerId`], so the fold can be
//! driven from a scripted sequence in a unit test — the same shape as
//! `ac_net::connectivity`.

use std::collections::BTreeMap;

use ac_net::PeerId;
use sha2::{Digest, Sha256};

use crate::standing::StandingSet;

/// One member, as the admin's log describes them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub peer: PeerId,
    /// Advisory display text chosen by the admin.
    ///
    /// **Never** compared for authorization. The authoritative name for a peer is what its own
    /// server-signed attestation asserts when it connects; this is what the admin typed, and
    /// the two can legitimately disagree if someone re-enrolled under a new name.
    pub username: String,
    /// The entry that added them. Survives a username change.
    pub since_seq: u64,
    pub is_admin: bool,
}

/// Membership as of some point in the chain.
///
/// `BTreeMap` rather than `HashMap` so iteration order is deterministic: the standings digest
/// is computed over members in order, and two nodes must agree on it byte for byte.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Members {
    by_peer: BTreeMap<PeerId, Member>,
}

impl Members {
    /// Add a member, or update the advisory username of one already present.
    ///
    /// Re-adding is valid and means "correct the username". Treating it as an error would turn
    /// a harmless duplicate into a permanently frozen group, and it cannot corrupt the fold.
    /// `since_seq` is kept from the original add, because that is when they joined.
    pub fn insert(&mut self, peer: PeerId, username: String, seq: u64, is_admin: bool) {
        self.by_peer
            .entry(peer)
            .and_modify(|m| m.username = username.clone())
            .or_insert(Member {
                peer,
                username,
                since_seq: seq,
                is_admin,
            });
    }

    pub fn remove(&mut self, peer: &PeerId) -> bool {
        self.by_peer.remove(peer).is_some()
    }

    pub fn contains(&self, peer: &PeerId) -> bool {
        self.by_peer.contains_key(peer)
    }

    pub fn get(&self, peer: &PeerId) -> Option<&Member> {
        self.by_peer.get(peer)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Member> {
        self.by_peer.values()
    }

    pub fn len(&self) -> usize {
        self.by_peer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_peer.is_empty()
    }

    /// A digest of what each member has said about itself, for `GroupHead.standings`.
    ///
    /// Folded over **members only**, in peer-id order, so two nodes holding the same chain
    /// converge on the same value even if one is also carrying standings for peers the other
    /// has never heard of. Without that restriction a node could never stop re-syncing.
    pub fn standings_digest(&self, standings: &StandingSet) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([0x02]); // domain separation from the id and entry-hash tags
        for member in self.iter() {
            if let Some((seq, in_group)) = standings.latest(&member.peer) {
                hasher.update(member.peer.to_bytes());
                hasher.update(seq.to_le_bytes());
                hasher.update([u8::from(in_group)]);
            }
        }
        hasher.finalize().into()
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
    fn re_adding_updates_the_name_and_keeps_the_join_point() {
        let mut m = Members::default();
        let p = peer();
        m.insert(p, "alice".into(), 3, false);
        m.insert(p, "alice-laptop".into(), 9, false);

        let member = m.get(&p).unwrap();
        assert_eq!(member.username, "alice-laptop");
        assert_eq!(member.since_seq, 3, "they joined at 3, not 9");
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn removing_reports_whether_there_was_anything_to_remove() {
        let mut m = Members::default();
        let p = peer();
        assert!(!m.remove(&p));
        m.insert(p, "alice".into(), 0, false);
        assert!(m.remove(&p));
        assert!(!m.contains(&p));
    }

    #[test]
    fn the_standings_digest_ignores_insertion_order() {
        // Two nodes that hold the same members and the same standings must agree byte for
        // byte, however the rows came to them.
        let peers: Vec<_> = (0..6).map(|_| peer()).collect();

        let mut forwards = Members::default();
        let mut backwards = Members::default();
        for (i, p) in peers.iter().enumerate() {
            forwards.insert(*p, format!("u{i}"), i as u64, false);
        }
        for (i, p) in peers.iter().enumerate().rev() {
            backwards.insert(*p, format!("u{i}"), i as u64, false);
        }

        let mut a = StandingSet::default();
        let mut b = StandingSet::default();
        for (i, p) in peers.iter().enumerate() {
            a.insert(*p, 1, i % 2 == 0);
        }
        for (i, p) in peers.iter().enumerate().rev() {
            b.insert(*p, 1, i % 2 == 0);
        }

        assert_eq!(
            forwards.standings_digest(&a),
            backwards.standings_digest(&b)
        );
    }

    #[test]
    fn the_standings_digest_ignores_standings_for_non_members() {
        // Junk one node happens to hold must not keep the two of them re-syncing forever.
        let mut members = Members::default();
        let alice = peer();
        members.insert(alice, "alice".into(), 0, true);

        let mut lean = StandingSet::default();
        lean.insert(alice, 1, true);

        let mut cluttered = lean.clone();
        cluttered.insert(peer(), 4, false);
        cluttered.insert(peer(), 9, true);

        assert_eq!(
            members.standings_digest(&lean),
            members.standings_digest(&cluttered)
        );
    }

    #[test]
    fn the_standings_digest_notices_a_changed_position() {
        let mut members = Members::default();
        let alice = peer();
        members.insert(alice, "alice".into(), 0, true);

        let mut before = StandingSet::default();
        before.insert(alice, 1, true);
        let mut after = StandingSet::default();
        after.insert(alice, 2, false);

        assert_ne!(
            members.standings_digest(&before),
            members.standings_digest(&after)
        );
    }

    #[test]
    fn iteration_is_ordered_by_peer_id() {
        // The standings digest folds over members in iteration order, so two nodes that hold
        // the same members must iterate them the same way or their digests diverge.
        let mut m = Members::default();
        let peers: Vec<_> = (0..8).map(|_| peer()).collect();
        for (i, p) in peers.iter().enumerate() {
            m.insert(*p, format!("user{i}"), i as u64, false);
        }

        let seen: Vec<_> = m.iter().map(|x| x.peer).collect();
        let mut sorted = seen.clone();
        sorted.sort();
        assert_eq!(seen, sorted);
    }
}
