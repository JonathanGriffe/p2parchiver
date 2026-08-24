use ac_net::PeerId;
use ac_net::identity::{Keypair, public_key_of};
use serde::{Deserialize, Serialize};

use crate::id::GroupId;

/// Ceiling on one standing, checked before the bytes are parsed.
pub const MAX_STANDING_BYTES: usize = 1024;

/// Where a member says it stands. Signed, so it can only ever be their own word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Position {
    /// We hold the chain that names us and have not decided yet.
    Unanswered,
    In,
    Out,
}

impl Position {
    /// A stable byte for the standings digest. Two nodes must agree on it exactly, so it is
    /// written down rather than derived from the variant order.
    pub fn tag(self) -> u8 {
        match self {
            Position::Unanswered => 0,
            Position::In => 1,
            Position::Out => 2,
        }
    }

    pub fn is_departure(self) -> bool {
        matches!(self, Position::Out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandingBody {
    pub group: GroupId,
    pub peer: String,
    pub seq: u64,
    pub position: Position,
    pub at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Standing {
    /// CBOR encoding of a [`StandingBody`], signed and verified as these exact bytes.
    ///
    /// Framed as a CBOR byte string on the wire; see [`crate::chain::Entry::body`].
    #[serde(with = "crate::bytes::blob")]
    pub body: Vec<u8>,
    #[serde(with = "crate::bytes::blob")]
    pub signature: Vec<u8>,
}

impl Standing {
    /// Sign a statement about the signer's own position.
    pub fn author(
        key: &Keypair,
        group: GroupId,
        seq: u64,
        position: Position,
        at: i64,
    ) -> Result<Self, StandingError> {
        let body = StandingBody {
            group,
            peer: key.public().to_peer_id().to_base58(),
            seq,
            position,
            at,
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&body, &mut bytes).map_err(|_| StandingError::Encode)?;
        let signature = key.sign(&bytes).map_err(|_| StandingError::Signing)?;

        Ok(Self {
            body: bytes,
            signature,
        })
    }

    /// The seq to author next, given what we already hold for ourselves.
    pub fn next_seq(latest_known: Option<u64>) -> u64 {
        latest_known.unwrap_or(0) + 1
    }

    /// Decode without checking anything. For logging only.
    pub fn body(&self) -> Result<StandingBody, StandingError> {
        ciborium::from_reader(self.body.as_slice()).map_err(|_| StandingError::Malformed)
    }

    /// Check everything and return what was asserted.
    ///
    pub fn verify(&self, group: GroupId) -> Result<StandingBody, StandingError> {
        if self.wire_len() > MAX_STANDING_BYTES {
            return Err(StandingError::TooLarge {
                bytes: self.wire_len(),
            });
        }
        let body = self.body()?;

        if body.group != group {
            return Err(StandingError::WrongGroup { found: body.group });
        }
        let peer: PeerId = body
            .peer
            .parse()
            .map_err(|_| StandingError::UnparseablePeer)?;
        let key = public_key_of(&peer).map_err(|_| StandingError::SubjectKey {
            peer: body.peer.clone(),
        })?;
        if !key.verify(&self.body, &self.signature) {
            return Err(StandingError::BadSignature);
        }
        Ok(body)
    }

    /// The subject, without verifying the signature.
    pub fn subject(&self) -> Result<PeerId, StandingError> {
        self.body()?
            .peer
            .parse()
            .map_err(|_| StandingError::UnparseablePeer)
    }

    pub fn wire_len(&self) -> usize {
        self.body.len() + self.signature.len()
    }
}

/// The ordering rule
/// Higher seq wins. On a tie the lexicographically smaller body wins, which is arbitrary
/// but deterministic, so every node converges on the same winner without coordinating.
fn wins(mine: (u64, &[u8]), theirs: (u64, &[u8])) -> bool {
    match mine.0.cmp(&theirs.0) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => mine.1 < theirs.1,
    }
}

/// One statement, kept beside what its body decoded to so reads never re-decode.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Held {
    standing: Standing,
    seq: u64,
    position: Position,
}

/// The latest position each member has claimed for itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StandingSet(std::collections::BTreeMap<PeerId, Held>);

impl StandingSet {
    /// Record a position, keeping whichever statement wins under [`wins`].
    pub fn insert(
        &mut self,
        peer: PeerId,
        standing: Standing,
        seq: u64,
        position: Position,
    ) -> bool {
        if let Some(held) = self.0.get(&peer)
            && !wins((seq, &standing.body), (held.seq, &held.standing.body))
        {
            return false;
        }
        self.0.insert(
            peer,
            Held {
                standing,
                seq,
                position,
            },
        );
        true
    }

    pub fn latest(&self, peer: &PeerId) -> Option<(u64, Position)> {
        self.0.get(peer).map(|h| (h.seq, h.position))
    }

    /// Whether this peer's own latest word is that it has left.
    pub fn departed(&self, peer: &PeerId) -> bool {
        matches!(self.0.get(peer), Some(h) if h.position.is_departure())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&PeerId, u64, Position)> {
        self.0.iter().map(|(p, h)| (p, h.seq, h.position))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StandingError {
    #[error("the standing is not valid CBOR")]
    Malformed,
    #[error("the standing could not be encoded")]
    Encode,
    #[error("the standing could not be signed")]
    Signing,
    #[error("the standing is {bytes} bytes, over the {MAX_STANDING_BYTES} byte limit")]
    TooLarge { bytes: usize },
    #[error("the standing names an unparseable peer id")]
    UnparseablePeer,
    #[error("no public key can be recovered from peer id {peer}")]
    SubjectKey { peer: String },
    #[error("the signature is not the subject's own")]
    BadSignature,
    #[error("the standing is for group {found}, not this one")]
    WrongGroup { found: GroupId },
}

#[cfg(test)]
mod tests {
    use super::*;

    const AT: i64 = 1_000_000;

    fn key() -> Keypair {
        Keypair::generate_ed25519()
    }

    fn group() -> GroupId {
        GroupId::of_genesis(b"a group")
    }

    /// Sign an arbitrary body with an arbitrary key, bypassing [`Standing::author`]'s
    /// insistence that the two match. Only a forger would do this.
    fn forge(key: &Keypair, body: &StandingBody) -> Standing {
        let mut bytes = Vec::new();
        ciborium::into_writer(body, &mut bytes).unwrap();
        let signature = key.sign(&bytes).unwrap();
        Standing {
            body: bytes,
            signature,
        }
    }

    #[test]
    fn a_standing_verifies_and_reports_what_was_asserted() {
        let bob = key();
        let s = Standing::author(&bob, group(), 1, Position::Out, AT).unwrap();

        let body = s.verify(group()).unwrap();
        assert_eq!(body.peer, bob.public().to_peer_id().to_base58());
        assert_eq!(body.position, Position::Out);
        assert_eq!(body.seq, 1);
    }

    #[test]
    fn a_standing_can_only_speak_for_its_signer() {
        let (alice, bob) = (key(), key());
        let forged = forge(
            &alice,
            &StandingBody {
                group: group(),
                peer: bob.public().to_peer_id().to_base58(),
                seq: 1,
                position: Position::Out,
                at: AT,
            },
        );

        assert_eq!(forged.verify(group()), Err(StandingError::BadSignature));
    }

    #[test]
    fn a_standing_for_another_group_is_refused() {
        let bob = key();
        let s = Standing::author(&bob, group(), 1, Position::Out, AT).unwrap();
        let elsewhere = GroupId::of_genesis(b"a different group");

        assert!(matches!(
            s.verify(elsewhere),
            Err(StandingError::WrongGroup { .. })
        ));
    }

    #[test]
    fn a_standing_survives_cbor_and_still_verifies() {
        let bob = key();
        let s = Standing::author(&bob, group(), 1, Position::Out, AT).unwrap();

        let mut buf = Vec::new();
        ciborium::into_writer(&s, &mut buf).unwrap();
        let delivered: Standing = ciborium::from_reader(buf.as_slice()).unwrap();

        assert!(delivered.verify(group()).is_ok());
    }

    #[test]
    fn a_higher_seq_supersedes() {
        let bob = key();
        let first = Standing::author(&bob, group(), 1, Position::Out, AT).unwrap();
        let second = Standing::author(&bob, group(), 2, Position::In, AT).unwrap();

        let (Ok(first_body), Ok(second_body)) = (first.body(), second.body()) else {
            panic!("failed to parse body");
        };

        assert!(wins(
            (second_body.seq, &second.body),
            (first_body.seq, &first.body)
        ));
        assert!(!wins(
            (first_body.seq, &first.body),
            (second_body.seq, &second.body)
        ));
    }

    #[test]
    fn equivocation_resolves_the_same_way_whichever_arrives_first() {
        // Two statements at one seq means the subject's database was rolled back. Nodes must
        // converge without coordinating, so the rule is deterministic rather than
        // arrival-ordered.
        let bob = key();
        let a = Standing::author(&bob, group(), 1, Position::In, AT).unwrap();
        let b = Standing::author(&bob, group(), 1, Position::Out, AT + 1).unwrap();
        assert_ne!(a.body, b.body);

        let (Ok(a_body), Ok(b_body)) = (a.body(), b.body()) else {
            panic!("failed to parse body");
        };

        let winner_ab = if wins((a_body.seq, &a.body), (b_body.seq, &b.body)) {
            &b
        } else {
            &a
        };
        let winner_ba = if wins((b_body.seq, &b.body), (a_body.seq, &a.body)) {
            &a
        } else {
            &b
        };
        assert_eq!(winner_ab.body, winner_ba.body);
    }

    #[test]
    fn an_oversized_standing_is_refused_before_it_is_parsed() {
        let s = Standing {
            body: vec![0u8; MAX_STANDING_BYTES + 1],
            signature: Vec::new(),
        };
        assert!(matches!(
            s.verify(group()),
            Err(StandingError::TooLarge { .. })
        ));
    }

    #[test]
    fn a_set_refuses_a_statement_it_has_already_bettered() {
        let bob = key();
        let bob_peer = bob.public().to_peer_id();
        let old = Standing::author(&bob, group(), 1, Position::In, AT).unwrap();
        let new = Standing::author(&bob, group(), 2, Position::Out, AT).unwrap();

        let mut set = StandingSet::default();
        assert!(set.insert(bob_peer, new, 2, Position::Out));
        assert!(
            !set.insert(bob_peer, old, 1, Position::In),
            "a rollback must not take"
        );
        assert_eq!(set.latest(&bob_peer), Some((2, Position::Out)));
    }

    #[test]
    fn the_next_seq_climbs_past_anything_already_seen() {
        // A node restored from a backup must not re-use a seq it already spent, or it
        // equivocates against itself.
        assert_eq!(Standing::next_seq(None), 1);
        assert_eq!(Standing::next_seq(Some(4)), 5);
    }
}
