use serde::{Deserialize, Serialize};

use crate::chain::Entry;
use crate::id::{EntryHash, GroupId};
use crate::standing::Standing;

pub const GROUP_PROTOCOL: &str = "/ac/group/5.0.0";

pub const MAX_HEADS_PER_ANSWER: usize = 128;

/// Largest request we will decode. An `Offer` of 128 heads is ~10 KiB.
pub const MAX_REQUEST_BYTES: u64 = 64 * 1024;

/// Largest response we will decode.
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

/// What a node knows about one group, as offered to a peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupHead {
    #[serde(with = "crate::bytes::group_id")]
    pub group: GroupId,
    pub head_seq: u64,
    #[serde(with = "crate::bytes::entry_hash")]
    pub head_hash: EntryHash,
    #[serde(with = "crate::bytes::digest")]
    pub standings: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupRequest {
    Ask,
    Fetch {
        #[serde(with = "crate::bytes::group_id")]
        group: GroupId,
        from: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupResponse {
    Heads(Vec<GroupHead>),
    Entries {
        #[serde(with = "crate::bytes::group_id")]
        group: GroupId,
        from: u64,
        entries: Vec<Entry>,
        standings: Vec<Standing>,
    },
    Unavailable,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::standing::Position;
    use ac_net::identity::Keypair;

    use crate::chain::{Chain, Op};

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
        let mut chain = Chain::create(&admin, "family", [1u8; 16], AT).unwrap();
        let bob = Keypair::generate_ed25519();
        chain
            .author(
                &admin,
                Op::Add {
                    peer: bob.public().to_peer_id().to_base58(),
                },
                AT,
            )
            .unwrap();
        let standing = Standing::author(&bob, chain.id(), 1, Position::Out, "someone", AT).unwrap();
        (chain, standing)
    }

    #[test]
    fn a_head_does_not_pay_double_for_its_hashes() {
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
        let admin = Keypair::generate_ed25519();
        let mut chain = Chain::create(&admin, "family", [1u8; 16], AT).unwrap();

        for _ in 0..50 {
            let p = Keypair::generate_ed25519()
                .public()
                .to_peer_id()
                .to_base58();
            chain
                .author(&admin, Op::Add { peer: p.clone() }, AT)
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
            GroupRequest::Ask,
            GroupRequest::Fetch {
                group: chain.id(),
                from: 3,
            },
        ] {
            assert_eq!(round_trip(&request), request);
        }

        for response in [
            GroupResponse::Heads(vec![head]),
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
