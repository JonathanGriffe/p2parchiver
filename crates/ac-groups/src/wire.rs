//! The `/ac/group/3.0.0` protocol.
//!
//! The **only** module in this crate permitted to name `libp2p::request_response`. Everything
//! else — the chain, the standings, the store, the sync machine — is free of networking types,
//! which is what lets the sync policy be tested without a socket.

use libp2p::StreamProtocol;
use libp2p::request_response::{self, ProtocolSupport};
use serde::{Deserialize, Serialize};

use crate::chain::Entry;
use crate::id::{EntryHash, GroupId};
use crate::standing::Standing;

/// Bumped on any incompatible change to the types below. The version lives in the name because
/// multistream-select negotiates on it, so an incompatible peer fails cleanly at negotiation
/// rather than misreading a message — the same convention as `ac_net::proto`.
///
/// `2.0.0` moved the hashes below from CBOR integer arrays to byte strings; `3.0.0` did the
/// same for the bodies and signatures inside `Entry` and `Standing`, which dominated the cost.
/// Both are changes of encoding, not of meaning, so an older peer would decode them as garbage
/// rather than fail — exactly what a version in the name exists to prevent.
pub const GROUP_PROTOCOL: &str = "/ac/group/3.0.0";

/// Ceiling on how many groups one `Offer` may name.
///
/// A peer genuinely in more than this many groups is beyond what this milestone targets, and
/// without a cap an `Offer` is an unbounded allocation on the receiving side.
pub const MAX_HEADS_PER_OFFER: usize = 128;

/// Largest request we will decode. An `Offer` of 128 heads is ~10 KiB.
const MAX_REQUEST_BYTES: u64 = 64 * 1024;

/// Largest response we will decode.
///
/// A **denial-of-service backstop, not a chunk boundary.** `request_response` buffers whole
/// messages in memory, so an unbounded response is a memory attack. There is no chunking: one
/// `Fetch` is answered by one response carrying everything from `from` to the head. A chain
/// holds one entry per membership change at ~250 bytes, so this ceiling is roughly 4000
/// entries — a decade of implausible churn. A chain that will not fit is a failure worth
/// surfacing rather than a case to handle; compaction is the answer if it ever arrives.
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

/// What a node knows about one group, as offered to a peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupHead {
    #[serde(with = "crate::bytes::group_id")]
    pub group: GroupId,
    /// Number of entries held, so `head_seq - 1` is the last entry's seq.
    pub head_seq: u64,
    #[serde(with = "crate::bytes::entry_hash")]
    pub head_hash: EntryHash,
    /// Digest over the standings we hold for this group's members.
    ///
    /// **This is the only way a dropped standing heals.** Two nodes can agree on the chain
    /// exactly and still disagree on standings — a standing arrives for a peer we had not yet
    /// added, and is refused. Without something to compare, that difference would persist
    /// until the next chain append, which may be never. An equal head with a differing digest
    /// triggers a fetch that returns no entries and the full standing set.
    #[serde(with = "crate::bytes::digest")]
    pub standings: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupRequest {
    /// "These are the groups I believe we share." Filtered by the *sender's* own view.
    Offer(Vec<GroupHead>),
    /// Everything from `from` to the head. `from` makes the transfer incremental; it is not a
    /// chunk offset, and one response carries the whole tail.
    Fetch {
        #[serde(with = "crate::bytes::group_id")]
        group: GroupId,
        from: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupResponse {
    Offer(Vec<GroupHead>),
    Entries {
        #[serde(with = "crate::bytes::group_id")]
        group: GroupId,
        from: u64,
        entries: Vec<Entry>,
        standings: Vec<Standing>,
    },
    /// Refused, with **no reason given, deliberately**.
    ///
    /// Distinguishing "I have never heard of that group" from "you are not a member of it"
    /// would turn guessing a `GroupId` into a membership oracle. One variant means a stranger
    /// learns nothing from asking.
    Unavailable,
}

pub type Behaviour = request_response::cbor::Behaviour<GroupRequest, GroupResponse>;

/// Build the behaviour a client mounts in `AcBehaviour`'s app slot.
///
/// `ProtocolSupport::Full` because the exchange is symmetric: either side may offer, and
/// either side may be asked. Size maxima are set explicitly — the codec defaults are 1 MiB
/// request and 10 MiB response, far more than this protocol should ever accept.
pub fn behaviour() -> Behaviour {
    let codec = request_response::cbor::codec::Codec::default()
        .set_request_size_maximum(MAX_REQUEST_BYTES)
        .set_response_size_maximum(MAX_RESPONSE_BYTES);

    Behaviour::with_codec(
        codec,
        [(StreamProtocol::new(GROUP_PROTOCOL), ProtocolSupport::Full)],
        request_response::Config::default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{Chain, Op};
    use libp2p::identity::Keypair;

    const AT: i64 = 1_000_000;

    fn round_trip<T: Serialize + serde::de::DeserializeOwned>(value: &T) -> T {
        ciborium::from_reader(encoded(value).as_slice()).unwrap()
    }

    fn encoded<T: Serialize>(value: &T) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(value, &mut buf).unwrap();
        buf
    }

    fn sample() -> (Chain, Standing) {
        let admin = Keypair::generate_ed25519();
        let mut chain = Chain::create(&admin, "family", "alice", [1u8; 16], AT).unwrap();
        let bob = Keypair::generate_ed25519();
        chain
            .author(
                &admin,
                Op::Add {
                    peer: bob.public().to_peer_id().to_base58(),
                    username: "bob".into(),
                },
                AT,
            )
            .unwrap();
        let standing = Standing::author(&bob, chain.id(), 1, false, AT).unwrap();
        (chain, standing)
    }

    #[test]
    fn a_head_does_not_pay_double_for_its_hashes() {
        // A `GroupHead` is 104 bytes of fact: three 32-byte hashes and a u64. serde encodes
        // `[u8; 32]` as a sequence of 32 integers, and CBOR spends two bytes on any integer
        // above 23 — so a random hash cost close to 64 bytes, and a head came to 194.
        //
        // The three hashes now go as CBOR byte strings. What remains is the field-name map
        // keys, which are legible and cheap by comparison. Asserted as a ceiling rather than
        // an exact width so a new field is not a test failure, but a regression to
        // integer-array encoding is.
        let (chain, _) = sample();
        let head = GroupHead {
            group: chain.id(),
            head_seq: chain.len(),
            head_hash: chain.head(),
            standings: [200u8; 32],
        };

        let size = encoded(&head).len();
        assert!(
            size <= 150,
            "a head encodes to {size} bytes; it was 194 before the hashes became byte strings"
        );

        // The bytes chosen above are all >23, which is exactly the case the old encoding
        // punished, so this would fail loudly if the adapters were dropped.
        assert_eq!(round_trip(&head), head, "and still round-trips");
    }

    #[test]
    fn a_chain_transfers_at_a_size_that_leaves_room_for_real_history() {
        // Entries are the bulk of everything that crosses the wire, and the chain never
        // shrinks — there is no compaction — so the per-entry cost sets how long a group can
        // live. Two ceilings follow from it, and the tighter one is not the obvious one:
        //
        //   * `MAX_RESPONSE_BYTES` (1 MiB) — a chain past this cannot transfer to anyone.
        //   * a relay circuit's 128 KiB budget — a chain past *this* cannot reach a peer that
        //     is only reachable relayed, and retrying gets a fresh circuit with the same
        //     limit, so it fails permanently rather than slowly.
        //
        // Measured, not assumed: an earlier plan put an entry at ~250 bytes when it was 590,
        // and drew the ceiling 8x too high as a result.
        let admin = Keypair::generate_ed25519();
        let mut chain = Chain::create(&admin, "family", "alice", [1u8; 16], AT).unwrap();

        for i in 0..50 {
            let p = Keypair::generate_ed25519()
                .public()
                .to_peer_id()
                .to_base58();
            chain
                .author(
                    &admin,
                    Op::Add {
                        peer: p.clone(),
                        username: format!("user{i}"),
                    },
                    AT,
                )
                .unwrap();
            chain.author(&admin, Op::Remove { peer: p }, AT).unwrap();
        }

        let response = GroupResponse::Entries {
            group: chain.id(),
            from: 0,
            entries: chain.entries().cloned().collect(),
            standings: Vec::new(),
        };
        let per_entry = encoded(&response).len() / chain.len() as usize;

        assert!(
            per_entry <= 340,
            "an entry costs {per_entry} bytes on the wire. It was 590 before bodies and \
             signatures were framed as byte strings; a regression there halves how much \
             history a group can carry before it stops being transferable."
        );
    }

    #[test]
    fn every_message_survives_cbor() {
        let (chain, standing) = sample();
        let head = GroupHead {
            group: chain.id(),
            head_seq: chain.len(),
            head_hash: chain.head(),
            standings: [7u8; 32],
        };

        assert_eq!(round_trip(&head), head);

        for request in [
            GroupRequest::Offer(vec![head.clone()]),
            GroupRequest::Fetch {
                group: chain.id(),
                from: 3,
            },
        ] {
            assert_eq!(round_trip(&request), request);
        }

        for response in [
            GroupResponse::Offer(vec![head]),
            GroupResponse::Entries {
                group: chain.id(),
                from: 0,
                entries: chain.entries().cloned().collect(),
                standings: vec![standing],
            },
            GroupResponse::Unavailable,
        ] {
            assert_eq!(round_trip(&response), response);
        }
    }

    #[test]
    fn a_chain_still_verifies_after_the_wire() {
        // The property a re-encoding bug would break: entries that pass every unit test in
        // process and fail the moment they cross a connection.
        let (chain, standing) = sample();
        let sent = GroupResponse::Entries {
            group: chain.id(),
            from: 0,
            entries: chain.entries().cloned().collect(),
            standings: vec![standing],
        };

        let GroupResponse::Entries {
            entries, standings, ..
        } = round_trip(&sent)
        else {
            panic!("expected entries");
        };

        let delivered = Chain::load(entries).expect("the chain must survive the wire");
        assert_eq!(delivered.id(), chain.id());
        assert_eq!(delivered.head(), chain.head());
        assert!(standings[0].verify(chain.id()).is_ok());
    }
}
