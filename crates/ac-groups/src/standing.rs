//! A member's statement about its own membership.
//!
//! A member cannot write to the admin's chain — that is what keeps the chain single-writer and
//! fork-free. But **removing yourself needs no authority**, so a member signs its own position
//! and that statement travels beside the chain in its own per-member sequence space, where it
//! commutes with everything the admin does.
//!
//! # Self-only by construction
//!
//! [`Standing::verify`] deliberately takes **no subject parameter**, unlike
//! `ac_net::attest::Attestation::verify`. It reads the peer out of the signed body and
//! recovers the verifying key from *that*, so a standing can only ever speak for whoever
//! signed it. A caller cannot forget to bind the two, because there is nothing to bind.
//!
//! # What it does and does not do
//!
//! A standing is **advisory**. It does not change membership: the fold is over the admin's
//! chain alone. Its job is to reach the admin, who ratifies it with a `Remove` — and to be
//! visible in `ac group show` in the meantime. The leaver does not depend on any of that:
//! their own local state stops them participating the instant they leave, and nobody else can
//! write that.

use ac_net::PeerId;
use ac_net::identity::{Keypair, public_key_of};
use serde::{Deserialize, Serialize};

use crate::id::GroupId;

/// Ceiling on one standing, checked before the bytes are parsed.
pub const MAX_STANDING_BYTES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandingBody {
    pub group: GroupId,
    /// The subject, who is also necessarily the signer.
    pub peer: String,
    /// A per-(group, peer) counter starting at 1. Unrelated to the chain's seq: the two
    /// advance independently, which is exactly why a standing cannot fork the chain.
    pub seq: u64,
    pub in_group: bool,
    /// Advisory. Never validated, never used for ordering.
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
    ///
    /// `seq` must exceed every seq this node has ever authored **or ingested** for itself —
    /// see [`Self::next_seq`]. Without that, a node restored from a backup equivocates against
    /// its own earlier statement.
    pub fn author(
        key: &Keypair,
        group: GroupId,
        seq: u64,
        in_group: bool,
        at: i64,
    ) -> Result<Self, StandingError> {
        let body = StandingBody {
            group,
            peer: key.public().to_peer_id().to_base58(),
            seq,
            in_group,
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
    /// No subject parameter: the subject comes out of the signed body and the key is recovered
    /// from it. That is what makes "it can only speak for its signer" a property of the
    /// function rather than of every call site.
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

    /// Whether `self` should replace `other` as the latest statement by this subject.
    ///
    /// Higher seq wins. On a tie the lexicographically smaller body wins — which is arbitrary
    /// but **deterministic**, so every node converges on the same winner without coordinating.
    /// A tie means the subject equivocated (two statements at one seq), which under one key
    /// means a restored backup; since standings are advisory the consequence is a display
    /// discrepancy and a delayed ratification, never a wrong authorization.
    pub fn supersedes(&self, other: &Standing) -> bool {
        let (Ok(mine), Ok(theirs)) = (self.body(), other.body()) else {
            return false;
        };
        match mine.seq.cmp(&theirs.seq) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Less => false,
            std::cmp::Ordering::Equal => self.body < other.body,
        }
    }
}

/// The latest position each member has claimed for itself.
///
/// One entry per peer — an earlier statement is superseded, never accumulated — so this is
/// bounded by the membership rather than by how often people change their minds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StandingSet(std::collections::BTreeMap<PeerId, (u64, bool)>);

impl StandingSet {
    /// Record a position, keeping whichever statement wins under [`Standing::supersedes`].
    pub fn insert(&mut self, peer: PeerId, seq: u64, in_group: bool) {
        let entry = self.0.entry(peer).or_insert((seq, in_group));
        if seq >= entry.0 {
            *entry = (seq, in_group);
        }
    }

    pub fn latest(&self, peer: &PeerId) -> Option<(u64, bool)> {
        self.0.get(peer).copied()
    }

    /// Whether this peer's own latest word is that it has left.
    pub fn departed(&self, peer: &PeerId) -> bool {
        matches!(self.0.get(peer), Some((_, false)))
    }

    pub fn iter(&self) -> impl Iterator<Item = (&PeerId, u64, bool)> {
        self.0
            .iter()
            .map(|(p, (seq, in_group))| (p, *seq, *in_group))
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
        let s = Standing::author(&bob, group(), 1, false, AT).unwrap();

        let body = s.verify(group()).unwrap();
        assert_eq!(body.peer, bob.public().to_peer_id().to_base58());
        assert!(!body.in_group);
        assert_eq!(body.seq, 1);
    }

    #[test]
    fn a_standing_can_only_speak_for_its_signer() {
        // The central security property. Alice signs a statement claiming Bob has left.
        // `verify` recovers the key from the peer named *in the body*, so Alice's signature
        // is checked against Bob's key and fails — and no call site can forget to bind them,
        // because there is no subject parameter to pass wrongly.
        let (alice, bob) = (key(), key());
        let forged = forge(
            &alice,
            &StandingBody {
                group: group(),
                peer: bob.public().to_peer_id().to_base58(),
                seq: 1,
                in_group: false,
                at: AT,
            },
        );

        assert_eq!(forged.verify(group()), Err(StandingError::BadSignature));
    }

    #[test]
    fn a_standing_for_another_group_is_refused() {
        let bob = key();
        let s = Standing::author(&bob, group(), 1, false, AT).unwrap();
        let elsewhere = GroupId::of_genesis(b"a different group");

        assert!(matches!(
            s.verify(elsewhere),
            Err(StandingError::WrongGroup { .. })
        ));
    }

    #[test]
    fn a_standing_survives_cbor_and_still_verifies() {
        let bob = key();
        let s = Standing::author(&bob, group(), 1, false, AT).unwrap();

        let mut buf = Vec::new();
        ciborium::into_writer(&s, &mut buf).unwrap();
        let delivered: Standing = ciborium::from_reader(buf.as_slice()).unwrap();

        assert!(delivered.verify(group()).is_ok());
    }

    #[test]
    fn a_higher_seq_supersedes() {
        let bob = key();
        let first = Standing::author(&bob, group(), 1, false, AT).unwrap();
        let second = Standing::author(&bob, group(), 2, true, AT).unwrap();

        assert!(second.supersedes(&first));
        assert!(!first.supersedes(&second));
    }

    #[test]
    fn equivocation_resolves_the_same_way_whichever_arrives_first() {
        // Two statements at one seq means the subject's database was rolled back. Nodes must
        // converge without coordinating, so the rule is deterministic rather than
        // arrival-ordered.
        let bob = key();
        let a = Standing::author(&bob, group(), 1, true, AT).unwrap();
        let b = Standing::author(&bob, group(), 1, false, AT + 1).unwrap();
        assert_ne!(a.body, b.body);

        let winner_ab = if b.supersedes(&a) { &b } else { &a };
        let winner_ba = if a.supersedes(&b) { &a } else { &b };
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
    fn the_next_seq_climbs_past_anything_already_seen() {
        // A node restored from a backup must not re-use a seq it already spent, or it
        // equivocates against itself.
        assert_eq!(Standing::next_seq(None), 1);
        assert_eq!(Standing::next_seq(Some(4)), 5);
    }
}
