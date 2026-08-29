use std::collections::BTreeMap;

use ac_net::PeerId;
use sha2::{Digest, Sha256};

use crate::standing::StandingSet;

/// One member. The chain says only who they are; what they are called is their own claim,
/// carried in their standing, so a member who has not spoken yet has no name at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub peer: PeerId,
    pub username: Option<String>,
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
    /// Add a member. Re-adding one already present changes nothing: the chain carries no name
    /// to update, and admin-ness is settled by the genesis.
    pub fn insert(&mut self, peer: PeerId, is_admin: bool) {
        self.by_peer.entry(peer).or_insert(Member {
            peer,
            username: None,
            is_admin,
        });
    }

    /// Set one member's name directly, for a caller reading a cache rather than the standings.
    pub fn set_username(&mut self, peer: &PeerId, username: Option<String>) {
        if let Some(member) = self.by_peer.get_mut(peer) {
            member.username = username;
        }
    }

    /// Fill in what each member has called itself. Anyone whose standing has not reached this
    /// node keeps no name, rather than borrowing one from somewhere it was never claimed.
    pub fn name_from(&mut self, standings: &StandingSet) {
        for member in self.by_peer.values_mut() {
            member.username = standings.username(&member.peer).map(str::to_owned);
        }
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
                // The name is part of what a member has said about itself. Left out, two nodes
                // holding different names for the same peer would agree they are in step and
                // never reconcile. Length-prefixed so no two names can run together.
                let name = standings.username(&member.peer).unwrap_or_default();
                hasher.update((name.len() as u64).to_le_bytes());
                hasher.update(name.as_bytes());
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

    fn standing(seq: u64, position: Position, username: &str) -> crate::standing::Standing {
        crate::standing::Standing::author(
            &Keypair::generate_ed25519(),
            crate::id::GroupId::ZERO,
            seq,
            position,
            username,
            0,
        )
        .unwrap()
    }

    fn pos(yes: bool) -> Position {
        if yes { Position::In } else { Position::Out }
    }

    #[test]
    fn re_adding_the_same_member_does_not_duplicate_them() {
        let mut m = Members::default();
        let p = peer();
        m.insert(p, false);
        m.insert(p, false);

        assert_eq!(m.len(), 1);
    }

    /// The chain says who is in; only the member says what they are called. Anyone whose
    /// standing has not arrived has no name at all rather than a borrowed one.
    #[test]
    fn a_member_is_nameless_until_their_own_standing_arrives() {
        let mut m = Members::default();
        let p = peer();
        m.insert(p, false);
        assert_eq!(m.get(&p).unwrap().username, None);

        let mut set = StandingSet::default();
        set.insert(
            p,
            standing(1, Position::In, "alice"),
            1,
            Position::In,
            "alice".to_owned(),
        );
        m.name_from(&set);

        assert_eq!(m.get(&p).unwrap().username.as_deref(), Some("alice"));
    }

    /// Two nodes holding the same members and standings but different names for one of them
    /// must not agree they are in step, or neither will ever fetch the other's view.
    #[test]
    fn the_standings_digest_follows_the_name_a_member_claims() {
        let p = peer();
        let mut members = Members::default();
        members.insert(p, false);

        let digest_for = |name: &str| {
            let mut set = StandingSet::default();
            set.insert(
                p,
                standing(1, Position::In, name),
                1,
                Position::In,
                name.to_owned(),
            );
            members.standings_digest(&set)
        };

        assert_ne!(digest_for("alice"), digest_for("alicia"));
        assert_eq!(digest_for("alice"), digest_for("alice"));
    }

    #[test]
    fn removing_reports_whether_there_was_anything_to_remove() {
        let mut m = Members::default();
        let p = peer();
        assert!(!m.remove(&p));
        m.insert(p, false);
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
        for p in &peers {
            forwards.insert(*p, false);
        }
        for p in peers.iter().rev() {
            backwards.insert(*p, false);
        }

        let mut a = StandingSet::default();
        let mut b = StandingSet::default();
        for (i, p) in peers.iter().enumerate() {
            a.insert(
                *p,
                standing(1, pos(i % 2 == 0), "someone"),
                1,
                pos(i % 2 == 0),
                "someone".to_owned(),
            );
        }
        for (i, p) in peers.iter().enumerate().rev() {
            b.insert(
                *p,
                standing(1, pos(i % 2 == 0), "someone"),
                1,
                pos(i % 2 == 0),
                "someone".to_owned(),
            );
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
        members.insert(alice, true);

        let mut lean = StandingSet::default();
        lean.insert(
            alice,
            standing(1, Position::In, "someone"),
            1,
            Position::In,
            "someone".to_owned(),
        );

        let mut cluttered = lean.clone();
        cluttered.insert(
            peer(),
            standing(4, Position::Out, "someone"),
            4,
            Position::Out,
            "someone".to_owned(),
        );
        cluttered.insert(
            peer(),
            standing(9, Position::In, "someone"),
            9,
            Position::In,
            "someone".to_owned(),
        );

        assert_eq!(
            members.standings_digest(&lean),
            members.standings_digest(&cluttered)
        );
    }

    #[test]
    fn the_standings_digest_notices_a_changed_position() {
        let mut members = Members::default();
        let alice = peer();
        members.insert(alice, true);

        let mut before = StandingSet::default();
        before.insert(
            alice,
            standing(1, Position::In, "someone"),
            1,
            Position::In,
            "someone".to_owned(),
        );
        let mut after = StandingSet::default();
        after.insert(
            alice,
            standing(2, Position::Out, "someone"),
            2,
            Position::Out,
            "someone".to_owned(),
        );

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
        for p in &peers {
            m.insert(*p, false);
        }

        let seen: Vec<_> = m.iter().map(|x| x.peer).collect();
        let mut sorted = seen.clone();
        sorted.sort();
        assert_eq!(seen, sorted);
    }
}
