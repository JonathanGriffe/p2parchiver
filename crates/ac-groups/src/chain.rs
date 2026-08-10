//! The membership log: an append-only chain of entries signed by one admin.
//!
//! Mirrors [`ac_net::attest`] in every structural respect, and for the same reasons. A body is
//! defined by its *encoding*: it travels as verbatim CBOR bytes, and the signature is checked
//! over those bytes exactly as received rather than over a re-encoding of a decoded value.
//! Re-encoding would make every signature depend on the serializer producing byte-identical
//! output forever, across library versions and field reorderings.
//!
//! # Why [`Chain`] is the only way in
//!
//! An [`Entry`] on its own is untrusted bytes. Every rule — signature, authorship, linkage,
//! and the preconditions of each operation — lives in [`Chain::extend`], and a `Chain` value
//! can only be produced by passing them. That is the same shape as `Attestation::verify` being
//! the sole path to a trusted `Statement`: it makes "did anyone check this?" a question the
//! type system answers.
//!
//! # One writer
//!
//! Only the group's admin may append. A hash chain therefore cannot legitimately fork, which
//! is what lets merging be "extend the prefix we hold" rather than a conflict-resolution
//! algorithm. Two validly-signed entries at one position mean a restored backup, a copied key,
//! or two admin processes — all of which want a human, so the store quarantines rather than
//! guessing (see `store::put`).
//!
//! Members cannot write here. A member's own position is a [`crate::standing::Standing`],
//! which lives beside the chain in its own sequence space precisely so that "anyone may remove
//! themselves" does not make the chain multi-writer.
//!
//! # If compaction is ever added, it must carry tombstones
//!
//! There is no compaction today and no pressing need for one: a chain holds one entry per
//! *membership change*, so a group is tens of entries — single-digit kilobytes over its whole
//! life. The wire cap is a denial-of-service backstop, not a size someone will reach.
//!
//! Should an `Op::Snapshot` ever replace a prefix, note that [`Chain::departure_seq`] finds a
//! removal by **scanning for the `Remove` entry**, and that is what tells a removed peer they
//! were removed (see [`crate::store::Groups::serve_up_to`]). Pruning that entry would make a
//! long-removed peer indistinguishable from a stranger, silently restoring the failure that
//! mechanism exists to prevent: nobody offers them the group, so nobody answers them, and
//! their own node claims they still belong forever.
//!
//! So a snapshot must carry a **tombstone list** — the peers removed at or before it, with the
//! seq. That is bounded by how many people have ever been removed rather than by how much has
//! happened, so it compacts nearly as well while keeping the property intact.

use ac_net::PeerId;
use ac_net::attest::normalise_username;
use ac_net::identity::public_key_of;
use libp2p::identity::Keypair;
use serde::{Deserialize, Serialize};

use crate::id::{EntryHash, GroupId, NO_PARENT};
use crate::members::Members;

/// Ceiling on one entry, checked before the bytes are parsed.
///
/// An honest entry is ~250 bytes: two base58 peer ids, a username, and a signature. The
/// margin is generous because the cost of being wrong is refusing a legitimate entry forever,
/// while the cost of being generous is bounded by the per-response cap in `wire`.
pub const MAX_ENTRY_BYTES: usize = 4096;

/// Ceiling on a group's display name.
pub const MAX_NAME_LEN: usize = 64;

/// What one entry asserts.
///
/// Peer ids are base58 `String`s rather than [`PeerId`], because this type is defined by its
/// encoding — it is what gets signed and hashed — and a textual peer id is stable in a way a
/// library type's serde representation is not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryBody {
    /// The group this belongs to. [`GroupId::ZERO`] in the genesis entry, whose hash *is* the
    /// group id — the field cannot name a value derived from itself.
    pub group: GroupId,
    pub seq: u64,
    /// Hash of the previous entry's body; [`NO_PARENT`] at the genesis.
    pub prev: EntryHash,
    /// Advisory. **Never** validated and never used for ordering — see the module docs on
    /// clocks in [`Chain::extend`].
    pub at: i64,
    pub op: Op,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Op {
    /// Creates the group and names its one permanent writer.
    ///
    /// `nonce` is 16 random bytes. Without it, two groups of the same name created by the same
    /// admin in the same second would hash to one id and silently merge into one chain.
    Create {
        admin: String,
        username: String,
        nonce: [u8; 16],
        name: String,
    },
    Add {
        peer: String,
        /// Advisory display text chosen by the admin. Never used for authorization; the
        /// authoritative name is what a peer's own attestation asserts at connection time.
        username: String,
    },
    Remove {
        peer: String,
    },
    Rename {
        name: String,
    },
}

/// An [`EntryBody`] and the admin's signature over its encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// CBOR encoding of an [`EntryBody`], signed and verified as these exact bytes.
    ///
    /// The `with` attribute frames it as a CBOR byte string on the wire. That changes nothing
    /// about what was signed — these bytes are opaque here and are verified as they arrive —
    /// and nothing about storage, which is a SQLite `BLOB`. See [`crate::bytes`].
    #[serde(with = "crate::bytes::blob")]
    pub body: Vec<u8>,
    #[serde(with = "crate::bytes::blob")]
    pub signature: Vec<u8>,
}

impl Entry {
    /// Hash of the signed bytes. This is the `prev` of the next entry, and at the genesis it
    /// is what the group id is derived from.
    pub fn hash(&self) -> EntryHash {
        EntryHash::of_body(&self.body)
    }

    /// Decode without checking anything.
    ///
    /// For logging and for inspecting an entry that has already been through [`Chain`]. Never
    /// use it to decide anything — that is what [`Chain::extend`] is for, and the difference
    /// is the whole point of the type.
    pub fn body(&self) -> Result<EntryBody, ChainError> {
        ciborium::from_reader(self.body.as_slice()).map_err(|_| ChainError::Malformed)
    }

    pub fn wire_len(&self) -> usize {
        self.body.len() + self.signature.len()
    }

    fn sign(key: &Keypair, body: &EntryBody) -> Result<Self, ChainError> {
        let mut bytes = Vec::new();
        ciborium::into_writer(body, &mut bytes).map_err(|_| ChainError::Encode)?;
        let signature = key.sign(&bytes).map_err(|_| ChainError::Signing)?;

        let entry = Self {
            body: bytes,
            signature,
        };
        if entry.wire_len() > MAX_ENTRY_BYTES {
            return Err(ChainError::TooLarge {
                seq: body.seq,
                bytes: entry.wire_len(),
            });
        }
        Ok(entry)
    }
}

/// An entry that has passed every rule, kept alongside what it decoded to.
#[derive(Debug, Clone)]
struct Verified {
    entry: Entry,
    body: EntryBody,
    hash: EntryHash,
}

/// A validated membership log.
///
/// Holds no invalid state: every entry has been checked against its predecessor, so there is
/// no fork and no gap inside a `Chain`.
#[derive(Debug, Clone)]
pub struct Chain {
    id: GroupId,
    admin: PeerId,
    entries: Vec<Verified>,
}

impl Chain {
    /// Create a group. This node becomes its one permanent writer.
    pub fn create(
        key: &Keypair,
        name: &str,
        username: &str,
        nonce: [u8; 16],
        at: i64,
    ) -> Result<Self, ChainError> {
        let admin = key.public().to_peer_id();
        let body = EntryBody {
            group: GroupId::ZERO,
            seq: 0,
            prev: NO_PARENT,
            at,
            op: Op::Create {
                admin: admin.to_base58(),
                username: username.to_owned(),
                nonce,
                name: name.to_owned(),
            },
        };
        Self::load(vec![Entry::sign(key, &body)?])
    }

    /// Verify a complete chain from its genesis.
    pub fn load(entries: Vec<Entry>) -> Result<Self, ChainError> {
        let mut iter = entries.into_iter();
        let genesis = iter.next().ok_or(ChainError::NoGenesis)?;

        let (id, admin, verified) = Self::check_genesis(genesis)?;
        let mut chain = Self {
            id,
            admin,
            entries: vec![verified],
        };
        let rest: Vec<Entry> = iter.collect();
        chain.extend(&rest)?;
        Ok(chain)
    }

    /// Append a batch, or change nothing.
    ///
    /// All-or-nothing on purpose: a partially-applied batch would leave the caller unable to
    /// say what it holds, and the store's fork check depends on knowing that every entry
    /// below the head was accepted under the same rules.
    ///
    /// `entries` must start at [`Self::len`] and link to [`Self::head`].
    pub fn extend(&mut self, entries: &[Entry]) -> Result<usize, ChainError> {
        let mut staged = Vec::with_capacity(entries.len());

        // Validated against a running view so that an entry can be checked against the state
        // its predecessors in the *same* batch produce — otherwise `Remove` of someone added
        // two entries earlier in the batch would be refused.
        let mut view = self.clone();

        for entry in entries {
            let verified = view.check_next(entry)?;
            view.entries.push(verified.clone());
            staged.push(verified);
        }

        let applied = staged.len();
        self.entries.extend(staged);
        Ok(applied)
    }

    /// Sign and append, in that order — so a node can only author chains it would itself
    /// accept. Admin only.
    pub fn author(&mut self, key: &Keypair, op: Op, at: i64) -> Result<Entry, ChainError> {
        if key.public().to_peer_id() != self.admin {
            return Err(ChainError::NotAdmin);
        }
        let body = EntryBody {
            group: self.id,
            seq: self.len(),
            prev: self.head(),
            at,
            op,
        };
        let entry = Entry::sign(key, &body)?;
        self.extend(std::slice::from_ref(&entry))?;
        Ok(entry)
    }

    pub fn id(&self) -> GroupId {
        self.id
    }

    pub fn admin(&self) -> PeerId {
        self.admin
    }

    /// The number of entries, which is also the seq the next entry must carry.
    pub fn len(&self) -> u64 {
        self.entries.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        false // a Chain always holds at least its genesis
    }

    pub fn head(&self) -> EntryHash {
        self.entries.last().map(|e| e.hash).unwrap_or(NO_PARENT)
    }

    /// The hash at `seq`, for the store's fork check.
    pub fn hash_at(&self, seq: u64) -> Option<EntryHash> {
        self.entries.get(seq as usize).map(|e| e.hash)
    }

    /// The latest name: the most recent `Rename`, else the one `Create` gave.
    pub fn name(&self) -> &str {
        self.entries
            .iter()
            .rev()
            .find_map(|e| match &e.body.op {
                Op::Rename { name } | Op::Create { name, .. } => Some(name.as_str()),
                _ => None,
            })
            .unwrap_or("")
    }

    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter().map(|e| &e.entry)
    }

    /// Entries in `from..to`, for answering a `Fetch`.
    pub fn entries_between(&self, from: u64, to: u64) -> impl Iterator<Item = &Entry> {
        let from = from.min(to) as usize;
        self.entries
            .iter()
            .take(to as usize)
            .skip(from)
            .map(|e| &e.entry)
    }

    /// Entries from `from` onward.
    pub fn entries_from(&self, from: u64) -> impl Iterator<Item = &Entry> {
        self.entries_between(from, self.len())
    }

    /// The seq of the **most recent** entry that removed `peer`, if they are out now.
    ///
    /// This is what lets a removed peer be told *why* they stopped hearing from anyone.
    /// Everything up to and including that entry happened while they were still a member, so
    /// serving it discloses nothing they were not already entitled to — and without it a
    /// removal is silent, permanent, and leaves their own node claiming they still belong.
    ///
    /// Scans the whole chain rather than stopping at the first `Remove`, because membership
    /// can cycle: added, removed, added, removed again. The answer must be the last removal,
    /// or a peer who rejoined and left again would be served a stale prefix.
    ///
    /// `None` if they are a **current** member — including one re-added after their last
    /// removal, who is entitled to the whole log — or if the chain has never mentioned them.
    pub fn departure_seq(&self, peer: &PeerId) -> Option<u64> {
        let wanted = peer.to_base58();
        let mut removed_at = None;

        for (seq, e) in self.entries.iter().enumerate() {
            match &e.body.op {
                Op::Add { peer, .. } if *peer == wanted => removed_at = None,
                Op::Remove { peer } if *peer == wanted => removed_at = Some(seq as u64),
                Op::Create { admin, .. } if *admin == wanted => removed_at = None,
                _ => {}
            }
        }
        removed_at
    }

    /// Current membership: `Create`/`Add`/`Remove`/`Rename` applied in seq order.
    ///
    /// Standings do not enter this. A departure is a signal that prompts the admin to write a
    /// `Remove`; until then the chain still lists the member, and the member's own local state
    /// is what stops it participating.
    pub fn fold(&self) -> Members {
        let mut members = Members::default();
        for (seq, e) in self.entries.iter().enumerate() {
            let seq = seq as u64;
            match &e.body.op {
                Op::Create {
                    admin, username, ..
                } => {
                    if let Ok(peer) = admin.parse() {
                        members.insert(peer, username.clone(), seq, true);
                    }
                }
                Op::Add { peer, username } => {
                    if let Ok(peer) = peer.parse() {
                        members.insert(peer, username.clone(), seq, false);
                    }
                }
                Op::Remove { peer } => {
                    if let Ok(peer) = peer.parse::<PeerId>() {
                        members.remove(&peer);
                    }
                }
                Op::Rename { .. } => {}
            }
        }
        members
    }

    /// Rules for the first entry. Establishes the id and the admin.
    fn check_genesis(entry: Entry) -> Result<(GroupId, PeerId, Verified), ChainError> {
        if entry.wire_len() > MAX_ENTRY_BYTES {
            return Err(ChainError::TooLarge {
                seq: 0,
                bytes: entry.wire_len(),
            });
        }
        let body = entry.body()?;

        if body.seq != 0 {
            return Err(ChainError::OutOfOrder {
                want: 0,
                got: body.seq,
            });
        }
        if body.prev != NO_PARENT || body.group != GroupId::ZERO {
            return Err(ChainError::MalformedGenesis);
        }

        let Op::Create {
            admin,
            username,
            name,
            ..
        } = &body.op
        else {
            return Err(ChainError::NoGenesis);
        };
        check_name(name, 0)?;
        check_username(username, 0)?;

        // Decoding before verifying is safe: the key we check against comes out of the body,
        // and the id is a hash of that same body — so a forged genesis produces a *different*
        // group, and cannot impersonate an existing one.
        let admin: PeerId = admin.parse().map_err(|_| ChainError::UnparseablePeer {
            seq: 0,
            peer: admin.clone(),
        })?;
        verify_signature(&entry, &admin, 0)?;

        let id = GroupId::of_genesis(&entry.body);
        let hash = entry.hash();
        Ok((id, admin, Verified { entry, body, hash }))
    }

    /// Rules for every entry after the first.
    fn check_next(&self, entry: &Entry) -> Result<Verified, ChainError> {
        // Size first, before anything is parsed, so an oversized entry costs nothing.
        if entry.wire_len() > MAX_ENTRY_BYTES {
            return Err(ChainError::TooLarge {
                seq: self.len(),
                bytes: entry.wire_len(),
            });
        }
        let body = entry.body()?;
        let seq = body.seq;

        if seq != self.len() {
            return Err(ChainError::OutOfOrder {
                want: self.len(),
                got: seq,
            });
        }
        if body.group != self.id {
            return Err(ChainError::WrongGroup {
                seq,
                found: body.group,
            });
        }
        if body.prev != self.head() {
            return Err(ChainError::BrokenLink { seq });
        }
        verify_signature(entry, &self.admin, seq)?;

        // Everything below is now known to be what the admin signed.
        match &body.op {
            Op::Create { .. } => return Err(ChainError::SecondGenesis { seq }),
            Op::Rename { name } => check_name(name, seq)?,
            Op::Add { peer, username } => {
                let peer = parse_peer(peer, seq)?;
                check_username(username, seq)?;
                // A peer whose key cannot be recovered could never sign a standing, so it
                // could never leave. Refusing the `Add` is kinder than admitting someone who
                // can never get out.
                public_key_of(&peer).map_err(|_| ChainError::UnusablePeer {
                    seq,
                    peer: peer.to_base58(),
                })?;
            }
            Op::Remove { peer } => {
                let peer = parse_peer(peer, seq)?;
                if peer == self.admin {
                    return Err(ChainError::SelfRemoval { seq });
                }
                if !self.fold().contains(&peer) {
                    return Err(ChainError::NotAMember {
                        seq,
                        peer: peer.to_base58(),
                    });
                }
            }
        }

        let hash = entry.hash();
        Ok(Verified {
            entry: entry.clone(),
            body,
            hash,
        })
    }
}

fn verify_signature(entry: &Entry, admin: &PeerId, seq: u64) -> Result<(), ChainError> {
    let key = public_key_of(admin).map_err(|_| ChainError::AdminKey {
        admin: admin.to_base58(),
    })?;
    if !key.verify(&entry.body, &entry.signature) {
        return Err(ChainError::BadSignature { seq });
    }
    Ok(())
}

fn parse_peer(raw: &str, seq: u64) -> Result<PeerId, ChainError> {
    raw.parse().map_err(|_| ChainError::UnparseablePeer {
        seq,
        peer: raw.to_owned(),
    })
}

fn check_name(name: &str, seq: u64) -> Result<(), ChainError> {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(ChainError::BadName { seq });
    }
    Ok(())
}

fn check_username(username: &str, seq: u64) -> Result<(), ChainError> {
    normalise_username(username)
        .map(|_| ())
        .map_err(|_| ChainError::BadUsername { seq })
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    #[error("the entry is not valid CBOR")]
    Malformed,
    #[error("the entry could not be encoded")]
    Encode,
    #[error("the entry could not be signed")]
    Signing,
    #[error("entry {seq} is {bytes} bytes, over the {MAX_ENTRY_BYTES} byte limit")]
    TooLarge { seq: u64, bytes: usize },
    #[error("the first entry does not create a group")]
    NoGenesis,
    #[error("the first entry is not a well-formed genesis")]
    MalformedGenesis,
    #[error("entry {seq} creates a group that already exists")]
    SecondGenesis { seq: u64 },
    #[error("expected entry {want}, got entry {got}")]
    OutOfOrder { want: u64, got: u64 },
    #[error("entry {seq} does not link to the entry before it")]
    BrokenLink { seq: u64 },
    #[error("entry {seq} belongs to group {found}, not this one")]
    WrongGroup { seq: u64, found: GroupId },
    #[error("no public key can be recovered from admin peer id {admin}")]
    AdminKey { admin: String },
    #[error("entry {seq} is not signed by this group's admin")]
    BadSignature { seq: u64 },
    #[error("entry {seq} names an unparseable peer id: {peer}")]
    UnparseablePeer { seq: u64, peer: String },
    #[error("entry {seq} adds {peer}, whose key cannot be recovered; they could never leave")]
    UnusablePeer { seq: u64, peer: String },
    #[error("entry {seq} removes the admin, which would leave the group with no writer")]
    SelfRemoval { seq: u64 },
    #[error("entry {seq} removes {peer}, who is not a member")]
    NotAMember { seq: u64, peer: String },
    #[error("entry {seq} carries an unusable group name")]
    BadName { seq: u64 },
    #[error("entry {seq} carries an unusable username")]
    BadUsername { seq: u64 },
    #[error("this node does not hold the admin key for this group")]
    NotAdmin,
}

#[cfg(test)]
mod tests {
    use super::*;

    const AT: i64 = 1_000_000;

    fn key() -> Keypair {
        Keypair::generate_ed25519()
    }

    fn peer() -> PeerId {
        key().public().to_peer_id()
    }

    /// A peer id that hashes its key rather than inlining it — an RSA key, or one from another
    /// implementation. No public key is recoverable, so it can never sign anything we check.
    fn opaque_peer() -> PeerId {
        let hashed = libp2p::multihash::Multihash::<64>::wrap(0x12, &[7u8; 32]).unwrap();
        PeerId::from_multihash(hashed).unwrap()
    }

    fn group(admin: &Keypair) -> Chain {
        Chain::create(admin, "family", "alice", [1u8; 16], AT).unwrap()
    }

    #[test]
    fn a_group_is_named_by_the_hash_of_its_genesis() {
        let admin = key();
        let chain = group(&admin);

        let genesis = chain.entries().next().unwrap();
        assert_eq!(chain.id(), GroupId::of_genesis(&genesis.body));
        assert_eq!(chain.admin(), admin.public().to_peer_id());
        assert_eq!(chain.name(), "family");
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn the_nonce_keeps_two_identical_creations_apart() {
        // Same admin, same name, same second. Without the nonce these would hash to one id and
        // silently merge into a single chain.
        let admin = key();
        let a = Chain::create(&admin, "family", "alice", [1u8; 16], AT).unwrap();
        let b = Chain::create(&admin, "family", "alice", [2u8; 16], AT).unwrap();

        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn an_entry_survives_cbor_and_still_verifies() {
        // A signature checked over re-encoded bytes would pass in-process and fail on the
        // wire. This is the same property `attest.rs` protects.
        let admin = key();
        let chain = group(&admin);

        let mut buf = Vec::new();
        ciborium::into_writer(chain.entries().next().unwrap(), &mut buf).unwrap();
        let delivered: Entry = ciborium::from_reader(buf.as_slice()).unwrap();

        assert!(Chain::load(vec![delivered]).is_ok());
    }

    #[test]
    fn tampering_with_a_body_breaks_the_chain() {
        let admin = key();
        let mut chain = group(&admin);
        let bob = peer();
        chain
            .author(
                &admin,
                Op::Add {
                    peer: bob.to_base58(),
                    username: "bob".into(),
                },
                AT,
            )
            .unwrap();

        // Re-encode the decoded body with a different username, keeping the signature.
        let entries: Vec<Entry> = chain.entries().cloned().collect();
        let mut body = entries[1].body().unwrap();
        body.op = Op::Add {
            peer: bob.to_base58(),
            username: "mallory".into(),
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&body, &mut bytes).unwrap();
        let forged = Entry {
            body: bytes,
            signature: entries[1].signature.clone(),
        };

        assert!(matches!(
            Chain::load(vec![entries[0].clone(), forged]),
            Err(ChainError::BadSignature { seq: 1 })
        ));
    }

    #[test]
    fn an_entry_signed_by_someone_else_is_refused() {
        let admin = key();
        let mut chain = group(&admin);
        let impostor = key();

        assert!(matches!(
            chain.author(
                &impostor,
                Op::Rename {
                    name: "theirs".into()
                },
                AT
            ),
            Err(ChainError::NotAdmin)
        ));
    }

    #[test]
    fn a_gap_and_a_replay_are_both_refused() {
        let admin = key();
        let mut chain = group(&admin);
        let e1 = chain
            .author(
                &admin,
                Op::Rename {
                    name: "second".into(),
                },
                AT,
            )
            .unwrap();

        // Replaying an entry we already hold.
        assert!(matches!(
            chain.extend(&[e1]),
            Err(ChainError::OutOfOrder { want: 2, got: 1 })
        ));

        // A batch that starts past our head.
        let mut ahead = group(&admin);
        ahead
            .author(
                &admin,
                Op::Rename {
                    name: "second".into(),
                },
                AT,
            )
            .unwrap();
        let far = ahead
            .author(
                &admin,
                Op::Rename {
                    name: "third".into(),
                },
                AT,
            )
            .unwrap();
        let mut behind = group(&admin);
        assert!(matches!(
            behind.extend(&[far]),
            Err(ChainError::OutOfOrder { want: 1, got: 2 })
        ));
    }

    #[test]
    fn an_entry_from_another_group_is_refused() {
        let admin = key();
        let mut theirs = Chain::create(&admin, "other", "alice", [9u8; 16], AT).unwrap();
        let foreign = theirs
            .author(
                &admin,
                Op::Rename {
                    name: "renamed".into(),
                },
                AT,
            )
            .unwrap();

        let mut ours = group(&admin);
        assert!(matches!(
            ours.extend(&[foreign]),
            Err(ChainError::WrongGroup { seq: 1, .. })
        ));
    }

    #[test]
    fn only_the_first_entry_may_create() {
        let admin = key();
        let mut chain = group(&admin);

        assert!(matches!(
            chain.author(
                &admin,
                Op::Create {
                    admin: admin.public().to_peer_id().to_base58(),
                    username: "alice".into(),
                    nonce: [3u8; 16],
                    name: "again".into(),
                },
                AT,
            ),
            Err(ChainError::SecondGenesis { seq: 1 })
        ));
    }

    #[test]
    fn the_admin_cannot_be_removed() {
        // It would leave the chain with no eligible writer and no way to appoint one.
        let admin = key();
        let mut chain = group(&admin);

        assert!(matches!(
            chain.author(
                &admin,
                Op::Remove {
                    peer: admin.public().to_peer_id().to_base58()
                },
                AT,
            ),
            Err(ChainError::SelfRemoval { seq: 1 })
        ));
    }

    #[test]
    fn removing_someone_who_is_not_a_member_is_refused() {
        let admin = key();
        let mut chain = group(&admin);

        assert!(matches!(
            chain.author(
                &admin,
                Op::Remove {
                    peer: peer().to_base58()
                },
                AT,
            ),
            Err(ChainError::NotAMember { seq: 1, .. })
        ));
    }

    #[test]
    fn adding_a_peer_whose_key_cannot_be_recovered_is_refused() {
        // They could never sign a standing, so they could never leave. Better to refuse the
        // add than to admit someone with no way out.
        let admin = key();
        let mut chain = group(&admin);

        assert!(matches!(
            chain.author(
                &admin,
                Op::Add {
                    peer: opaque_peer().to_base58(),
                    username: "ghost".into(),
                },
                AT,
            ),
            Err(ChainError::UnusablePeer { seq: 1, .. })
        ));
    }

    #[test]
    fn an_oversized_entry_is_refused_before_it_is_parsed() {
        let admin = key();
        let mut chain = group(&admin);
        let huge = Entry {
            body: vec![0u8; MAX_ENTRY_BYTES + 1],
            signature: Vec::new(),
        };

        assert!(matches!(
            chain.extend(&[huge]),
            Err(ChainError::TooLarge { .. })
        ));
    }

    #[test]
    fn the_fold_applies_operations_in_sequence_order() {
        let admin = key();
        let admin_peer = admin.public().to_peer_id();
        let (bob, carol) = (peer(), peer());
        let mut chain = group(&admin);

        for (p, name) in [(bob, "bob"), (carol, "carol")] {
            chain
                .author(
                    &admin,
                    Op::Add {
                        peer: p.to_base58(),
                        username: name.into(),
                    },
                    AT,
                )
                .unwrap();
        }
        chain
            .author(
                &admin,
                Op::Remove {
                    peer: bob.to_base58(),
                },
                AT,
            )
            .unwrap();

        let members = chain.fold();
        assert!(members.contains(&admin_peer));
        assert!(members.contains(&carol));
        assert!(!members.contains(&bob));
        assert!(members.get(&admin_peer).unwrap().is_admin);
    }

    #[test]
    fn someone_removed_can_be_added_again() {
        let admin = key();
        let bob = peer();
        let mut chain = group(&admin);

        let add = |c: &mut Chain| {
            c.author(
                &admin,
                Op::Add {
                    peer: bob.to_base58(),
                    username: "bob".into(),
                },
                AT,
            )
            .unwrap()
        };
        add(&mut chain);
        chain
            .author(
                &admin,
                Op::Remove {
                    peer: bob.to_base58(),
                },
                AT,
            )
            .unwrap();
        add(&mut chain);

        assert!(chain.fold().contains(&bob));
    }

    #[test]
    fn a_clock_running_backwards_does_not_reorder_membership() {
        // `at` is advisory and never validated, so a skewed clock on the admin's laptop must
        // not be able to change what the chain means — or to brick a group.
        let admin = key();
        let bob = peer();
        let mut chain = group(&admin);

        chain
            .author(
                &admin,
                Op::Add {
                    peer: bob.to_base58(),
                    username: "bob".into(),
                },
                AT + 5_000,
            )
            .unwrap();
        chain
            .author(
                &admin,
                Op::Remove {
                    peer: bob.to_base58(),
                },
                AT - 5_000, // earlier timestamp, later entry
            )
            .unwrap();

        assert!(!chain.fold().contains(&bob), "seq decides, not the clock");
    }

    #[test]
    fn a_bad_entry_leaves_the_chain_untouched() {
        // `extend` is all-or-nothing: a caller that saw an error must still know exactly what
        // it holds, and the store's fork check depends on every entry below the head having
        // passed the same rules.
        let admin = key();
        let mut chain = group(&admin);
        let good = {
            let mut scratch = group(&admin);
            scratch
                .author(
                    &admin,
                    Op::Rename {
                        name: "second".into(),
                    },
                    AT,
                )
                .unwrap()
        };
        let bad = Entry {
            body: b"not cbor".to_vec(),
            signature: vec![0u8; 64],
        };

        assert!(chain.extend(&[good, bad]).is_err());
        assert_eq!(chain.len(), 1, "nothing was applied");
        assert_eq!(chain.name(), "family");
    }

    #[test]
    fn a_batch_is_validated_against_its_own_earlier_entries() {
        // Adding then removing the same peer inside one batch must work: the `Remove` is
        // checked against the state the `Add` two entries earlier produced.
        let admin = key();
        let bob = peer();
        let mut source = group(&admin);
        let batch = vec![
            source
                .author(
                    &admin,
                    Op::Add {
                        peer: bob.to_base58(),
                        username: "bob".into(),
                    },
                    AT,
                )
                .unwrap(),
            source
                .author(
                    &admin,
                    Op::Remove {
                        peer: bob.to_base58(),
                    },
                    AT,
                )
                .unwrap(),
        ];

        let mut fresh = Chain::load(vec![source.entries().next().unwrap().clone()]).unwrap();
        assert_eq!(fresh.extend(&batch).unwrap(), 2);
        assert!(!fresh.fold().contains(&bob));
    }

    #[test]
    fn a_departure_points_at_the_last_removal_not_the_first() {
        // Membership can cycle. Serving a peer their *first* removal would hand them a stale
        // prefix and hide the rejoin that followed it.
        let admin = key();
        let bob = peer();
        let mut chain = group(&admin);

        let add = |c: &mut Chain| {
            c.author(
                &admin,
                Op::Add {
                    peer: bob.to_base58(),
                    username: "bob".into(),
                },
                AT,
            )
            .unwrap();
        };
        let remove = |c: &mut Chain| {
            c.author(
                &admin,
                Op::Remove {
                    peer: bob.to_base58(),
                },
                AT,
            )
            .unwrap();
        };

        add(&mut chain); // 1
        remove(&mut chain); // 2
        add(&mut chain); // 3
        remove(&mut chain); // 4

        assert_eq!(chain.departure_seq(&bob), Some(4));
    }

    #[test]
    fn someone_re_added_after_their_last_removal_has_no_departure() {
        // They are a current member again, so they are entitled to the whole log.
        let admin = key();
        let bob = peer();
        let mut chain = group(&admin);

        for op in [
            Op::Add {
                peer: bob.to_base58(),
                username: "bob".into(),
            },
            Op::Remove {
                peer: bob.to_base58(),
            },
            Op::Add {
                peer: bob.to_base58(),
                username: "bob".into(),
            },
        ] {
            chain.author(&admin, op, AT).unwrap();
        }

        assert_eq!(chain.departure_seq(&bob), None);
        assert!(chain.fold().contains(&bob));
    }

    #[test]
    fn a_peer_the_chain_never_mentions_has_no_departure() {
        // Distinct from "removed": a stranger must not be served anything at all.
        let admin = key();
        assert_eq!(group(&admin).departure_seq(&peer()), None);
    }

    #[test]
    fn the_admin_never_has_a_departure() {
        let admin = key();
        let chain = group(&admin);
        assert_eq!(chain.departure_seq(&admin.public().to_peer_id()), None);
    }

    #[test]
    fn entries_between_bounds_both_ends() {
        let admin = key();
        let mut chain = group(&admin);
        for name in ["a", "b", "c"] {
            chain
                .author(&admin, Op::Rename { name: name.into() }, AT)
                .unwrap();
        }

        assert_eq!(chain.entries_between(1, 3).count(), 2);
        assert_eq!(chain.entries_between(0, chain.len()).count(), 4);
        assert_eq!(chain.entries_between(2, 2).count(), 0);
        assert_eq!(chain.entries_between(3, 1).count(), 0, "inverted is empty");
    }

    #[test]
    fn a_chain_reloads_from_its_own_entries() {
        let admin = key();
        let mut chain = group(&admin);
        chain
            .author(
                &admin,
                Op::Add {
                    peer: peer().to_base58(),
                    username: "bob".into(),
                },
                AT,
            )
            .unwrap();

        let reloaded = Chain::load(chain.entries().cloned().collect()).unwrap();
        assert_eq!(reloaded.id(), chain.id());
        assert_eq!(reloaded.head(), chain.head());
        assert_eq!(reloaded.fold(), chain.fold());
    }
}
