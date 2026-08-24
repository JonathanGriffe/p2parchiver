use std::collections::BTreeMap;

use ac_net::PeerId;
use sha2::{Digest, Sha256};

use crate::standing::StandingSet;

/// One member, as the admin's log describes them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub peer: PeerId,
    pub username: String,
    pub is_admin: bool,
}

/// Membership as of some point in the chain.
/// `BTreeMap` rather than `HashMap` so iteration order is deterministic: the standings digest
/// is computed over members in order, and two nodes must agree on it byte for byte.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Members {
    by_peer: BTreeMap<PeerId, Member>,
}

impl Members {
    /// Add a member, or update the advisory username of one already present.
    pub fn insert(&mut self, peer: PeerId, username: String, is_admin: bool) {
        self.by_peer
            .entry(peer)
            .and_modify(|m| m.username = username.clone())
            .or_insert(Member {
                peer,
                username,
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
    pub fn standings_digest(&self, standings: &StandingSet) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([0x02]); // domain separation from the id and entry-hash tags
        for member in self.iter() {
            if let Some((seq, position)) = standings.latest(&member.peer) {
                hasher.update(member.peer.to_bytes());
                hasher.update(seq.to_le_bytes());
                hasher.update([position.tag()]);
            }
        }
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::standing::Position;
    use ac_net::identity::Keypair;

    fn peer() -> PeerId {
        Keypair::generate_ed25519().public().to_peer_id()
    }

    fn standing(seq: u64, position: Position) -> crate::standing::Standing {
        crate::standing::Standing::author(
            &Keypair::generate_ed25519(),
            crate::id::GroupId::ZERO,
            seq,
            position,
            0,
        )
        .unwrap()
    }

    fn pos(yes: bool) -> Position {
        if yes { Position::In } else { Position::Out }
    }

    #[test]
    fn re_adding_updates_the_name_rather_than_duplicating_the_member() {
        let mut m = Members::default();
        let p = peer();
        m.insert(p, "alice".into(), false);
        m.insert(p, "alice-laptop".into(), false);

        assert_eq!(m.get(&p).unwrap().username, "alice-laptop");
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn removing_reports_whether_there_was_anything_to_remove() {
        let mut m = Members::default();
        let p = peer();
        assert!(!m.remove(&p));
        m.insert(p, "alice".into(), false);
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
            forwards.insert(*p, format!("u{i}"), false);
        }
        for (i, p) in peers.iter().enumerate().rev() {
            backwards.insert(*p, format!("u{i}"), false);
        }

        let mut a = StandingSet::default();
        let mut b = StandingSet::default();
        for (i, p) in peers.iter().enumerate() {
            a.insert(*p, standing(1, pos(i % 2 == 0)), 1, pos(i % 2 == 0));
        }
        for (i, p) in peers.iter().enumerate().rev() {
            b.insert(*p, standing(1, pos(i % 2 == 0)), 1, pos(i % 2 == 0));
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
        members.insert(alice, "alice".into(), true);

        let mut lean = StandingSet::default();
        lean.insert(alice, standing(1, Position::In), 1, Position::In);

        let mut cluttered = lean.clone();
        cluttered.insert(peer(), standing(4, Position::Out), 4, Position::Out);
        cluttered.insert(peer(), standing(9, Position::In), 9, Position::In);

        assert_eq!(
            members.standings_digest(&lean),
            members.standings_digest(&cluttered)
        );
    }

    #[test]
    fn the_standings_digest_notices_a_changed_position() {
        let mut members = Members::default();
        let alice = peer();
        members.insert(alice, "alice".into(), true);

        let mut before = StandingSet::default();
        before.insert(alice, standing(1, Position::In), 1, Position::In);
        let mut after = StandingSet::default();
        after.insert(alice, standing(2, Position::Out), 2, Position::Out);

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
            m.insert(*p, format!("user{i}"), false);
        }

        let seen: Vec<_> = m.iter().map(|x| x.peer).collect();
        let mut sorted = seen.clone();
        sorted.sort();
        assert_eq!(seen, sorted);
    }
}
