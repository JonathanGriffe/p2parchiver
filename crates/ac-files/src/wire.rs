use ac_groups::id::GroupId;
use serde::{Deserialize, Serialize};

use crate::path::RelPath;
use crate::store::FileRow;

pub const MANIFEST_PROTOCOL: &str = "/ac/manifest/3.0.0";

pub const BLOB_PROTOCOL: &str = "/ac/blob/1.0.0";

pub const MAX_HEADS_PER_ANSWER: usize = 128;
pub const MAX_ENTRIES_PER_RESPONSE: usize = 2048;

pub const MAX_HOLDINGS_QUERY: usize = 512;

pub const MAX_REQUEST_BYTES: u64 = 64 * 1024;

pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

/// What one peer believes about one group's catalogue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileHead {
    #[serde(with = "ac_groups::bytes::group_id")]
    pub group: GroupId,
    #[serde(with = "ac_groups::bytes::digest")]
    pub digest: [u8; 32],
    pub count: u64,
}

/// One catalogue row, as it crosses the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub path: String,
    #[serde(with = "ac_groups::bytes::digest")]
    pub hash: [u8; 32],
    pub size: u64,
    pub modified: i64,
    pub added_at: i64,
    pub removed_at: Option<i64>,
    /// Base58, as peer ids appear everywhere else here.
    pub added_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManifestRequest {
    Ask,
    Changes { group: GroupId, after: u64 },
    Holdings { group: GroupId, paths: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManifestResponse {
    Heads(Vec<FileHead>),
    Changes {
        group: GroupId,
        entries: Vec<ManifestEntry>,
        next: u64,
        more: bool,
        #[serde(with = "ac_groups::bytes::digest")]
        digest: [u8; 32],
    },
    Holdings {
        group: GroupId,
        #[serde(with = "ac_groups::bytes::blob")]
        held: Vec<u8>,
    },
    Unavailable,
}

/// Pack "do I hold this" answers into the bitmap [`ManifestResponse::Holdings`] carries.
pub fn pack_holdings(held: impl IntoIterator<Item = bool>) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, yes) in held.into_iter().enumerate() {
        if i % 8 == 0 {
            out.push(0);
        }
        if yes {
            let last = out.len() - 1;
            out[last] |= 1 << (i % 8);
        }
    }
    out
}

/// Read bit `i` back out.
pub fn holds(bitmap: &[u8], i: usize) -> bool {
    bitmap
        .get(i / 8)
        .is_some_and(|byte| byte & (1 << (i % 8)) != 0)
}

/// Sent by the opener of a blob stream, length-prefixed, before any bytes flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobRequest {
    #[serde(with = "ac_groups::bytes::group_id")]
    pub group: GroupId,
    pub path: String,
    #[serde(with = "ac_groups::bytes::digest")]
    pub hash: [u8; 32],
    pub offset: u64,
}

/// The answer to a [`BlobRequest`], before the bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlobReply {
    Sending { size: u64 },
    Unavailable,
}

impl ManifestEntry {
    /// What we would tell a peer about one of our rows.
    pub fn of(row: &FileRow) -> Option<Self> {
        let mut hash = [0u8; 32];
        hex::decode_to_slice(&row.hash, &mut hash).ok()?;

        Some(Self {
            path: row.path.to_string(),
            hash,
            size: row.size,
            modified: row.modified,
            added_at: row.added_at,
            removed_at: row.removed_at,
            added_by: row.added_by.to_base58(),
        })
    }

    /// Turn a peer's entry into a row, or reject it.
    pub fn into_row(self) -> Option<FileRow> {
        Some(FileRow {
            path: RelPath::parse(&self.path).ok()?,
            size: self.size,
            hash: hex::encode(self.hash),
            modified: self.modified,
            added_at: self.added_at,
            added_by: self.added_by.parse().ok()?,
            removed_at: self.removed_at,
            have: false,
            seen_seq: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ac_net::PeerId;
    use ac_net::identity::Keypair;
    use std::str::FromStr;

    fn peer() -> PeerId {
        Keypair::generate_ed25519().public().to_peer_id()
    }

    fn encoded<T: Serialize>(value: &T) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::into_writer(value, &mut out).unwrap();
        out
    }

    fn entry(path: &str) -> ManifestEntry {
        ManifestEntry {
            path: path.to_owned(),
            hash: [7u8; 32],
            size: 4_200_000,
            modified: 1_700_000_000,
            added_at: 1_700_000_000,
            removed_at: None,
            added_by: peer().to_base58(),
        }
    }

    #[test]
    fn a_row_survives_the_round_trip() {
        let row = FileRow {
            path: RelPath::parse("photos/2024/beach.jpg").unwrap(),
            size: 4_200_000,
            hash: hex::encode([9u8; 32]),
            modified: 1_700_000_000,
            added_at: 1_700_000_100,
            added_by: peer(),
            removed_at: Some(1_700_000_200),
            have: true,
            seen_seq: 412,
        };

        let back = ManifestEntry::of(&row).unwrap().into_row().unwrap();

        assert_eq!(back.path, row.path);
        assert_eq!(back.hash, row.hash);
        assert_eq!(back.size, row.size);
        assert_eq!(back.added_at, row.added_at);
        assert_eq!(back.removed_at, row.removed_at);
        assert_eq!(back.added_by, row.added_by);
    }

    #[test]
    fn nothing_local_crosses_the_wire() {
        // `have` and `seen_seq` mean different things on every node. If either travelled, two
        // peers with the same catalogue would disagree on the digest and resync for ever.
        let row = FileRow {
            have: true,
            seen_seq: 412,
            ..FileRow {
                path: RelPath::parse("a.jpg").unwrap(),
                size: 1,
                hash: hex::encode([1u8; 32]),
                modified: 0,
                added_at: 0,
                added_by: peer(),
                removed_at: None,
                have: false,
                seen_seq: 0,
            }
        };
        let back = ManifestEntry::of(&row).unwrap().into_row().unwrap();

        assert!(!back.have, "a peer does not decide what is on our disk");
        assert_eq!(back.seen_seq, 0, "our log position is ours to assign");
    }

    #[test]
    fn a_hostile_path_is_refused_at_the_edge() {
        // The path arrives from another node. It becomes a `RelPath` here or not at all.
        for path in ["../../.ssh/authorized_keys", "/etc/passwd", "a/../b", ""] {
            let mut e = entry("ok.jpg");
            e.path = path.to_owned();
            assert!(e.into_row().is_none(), "{path:?} should be refused");
        }
    }

    #[test]
    fn an_unparseable_peer_is_refused() {
        let mut e = entry("a.jpg");
        e.added_by = "not-a-peer-id".to_owned();
        assert!(e.into_row().is_none());
    }

    #[test]
    fn a_full_page_fits_in_a_response() {
        // The two caps have to agree: `MAX_ENTRIES_PER_RESPONSE` is what bounds a page, and
        // `MAX_RESPONSE_BYTES` is what the codec will decode. If a full page did not fit, a
        // peer with a large catalogue could never send one and sync would stall permanently
        // rather than slowly.
        let entries: Vec<_> = (0..MAX_ENTRIES_PER_RESPONSE)
            .map(|i| entry(&format!("photos/2024/holiday-{i:05}.jpg")))
            .collect();

        let response = ManifestResponse::Changes {
            group: GroupId::from_str(&hex::encode([3u8; 32])).unwrap(),
            entries,
            next: 4096,
            more: true,
            digest: [5u8; 32],
        };

        let size = encoded(&response).len() as u64;
        assert!(
            size < MAX_RESPONSE_BYTES,
            "a full page is {size} bytes against a {MAX_RESPONSE_BYTES} ceiling; \
             lower MAX_ENTRIES_PER_RESPONSE or raise the response cap"
        );
    }

    #[test]
    fn a_hash_costs_what_it_weighs() {
        let size = encoded(&entry("a.jpg")).len();
        assert!(
            size <= 175,
            "a manifest entry costs {size} bytes; the byte-string adapters have probably \
             been dropped from `hash`"
        );
    }

    #[test]
    fn an_offer_of_the_maximum_fits_in_a_request() {
        let heads: Vec<_> = (0..MAX_HEADS_PER_ANSWER)
            .map(|i| FileHead {
                group: GroupId::from_str(&hex::encode([i as u8; 32])).unwrap(),
                digest: [200u8; 32],
                count: 10_000,
            })
            .collect();

        let size = encoded(&ManifestResponse::Heads(heads)).len() as u64;
        assert!(size < MAX_RESPONSE_BYTES, "an answer is {size} bytes");
    }

    #[test]
    fn a_bitmap_round_trips_in_order() {
        let answers = [
            true, false, false, true, false, false, false, false, true, true,
        ];
        let packed = pack_holdings(answers);

        assert_eq!(packed.len(), 2, "ten bits fit in two bytes");
        for (i, expected) in answers.iter().enumerate() {
            assert_eq!(holds(&packed, i), *expected, "bit {i}");
        }
    }

    #[test]
    fn an_empty_answer_packs_to_nothing() {
        assert!(pack_holdings(std::iter::empty()).is_empty());
        assert!(!holds(&[], 0), "and reads as holding nothing");
    }

    #[test]
    fn a_short_bitmap_withholds_rather_than_invents() {
        // A peer returning fewer bits than we asked about must not appear to hold files it
        // never answered for: the cost of a false negative is asking someone else, the cost
        // of a false positive is a stream opened for bytes that are not there.
        let packed = pack_holdings([true, true]);
        assert!(holds(&packed, 0));
        assert!(!holds(&packed, 99));
    }

    #[test]
    fn a_full_holdings_query_fits_in_a_request() {
        // The count cap and the byte cap have to agree, or a query built to the documented
        // limit would be refused by our own codec.
        let paths: Vec<String> = (0..MAX_HOLDINGS_QUERY)
            .map(|i| format!("photos/2024/holiday-{i:05}.jpg"))
            .collect();

        let size = encoded(&ManifestRequest::Holdings {
            group: GroupId::from_str(&hex::encode([1u8; 32])).unwrap(),
            paths,
        })
        .len() as u64;

        assert!(
            size < MAX_REQUEST_BYTES,
            "a full holdings query is {size} bytes against a {MAX_REQUEST_BYTES} ceiling"
        );
    }

    #[test]
    fn a_full_holdings_answer_is_tiny() {
        // The reason the answer is a bitmap and not a list of paths: 512 files cost 64 bytes
        // rather than the length of 512 paths.
        let size = encoded(&ManifestResponse::Holdings {
            group: GroupId::from_str(&hex::encode([1u8; 32])).unwrap(),
            held: pack_holdings((0..MAX_HOLDINGS_QUERY).map(|i| i % 3 == 0)),
        })
        .len();

        assert!(size < 128, "a 512-file answer is {size} bytes");
    }

    #[test]
    fn every_message_survives_cbor() {
        let group = GroupId::from_str(&hex::encode([1u8; 32])).unwrap();
        let head = FileHead {
            group,
            digest: [2u8; 32],
            count: 3,
        };

        for request in [
            ManifestRequest::Ask,
            ManifestRequest::Changes { group, after: 412 },
        ] {
            let bytes = encoded(&request);
            let back: ManifestRequest = ciborium::from_reader(&bytes[..]).unwrap();
            assert_eq!(back, request);
        }

        for response in [
            ManifestResponse::Heads(vec![head]),
            ManifestResponse::Changes {
                group,
                entries: vec![entry("a.jpg")],
                next: 9,
                more: false,
                digest: [4u8; 32],
            },
            ManifestResponse::Unavailable,
        ] {
            let bytes = encoded(&response);
            let back: ManifestResponse = ciborium::from_reader(&bytes[..]).unwrap();
            assert_eq!(back, response);
        }

        let request = ManifestRequest::Holdings {
            group,
            paths: vec!["a.jpg".to_owned(), "b/c.jpg".to_owned()],
        };
        let back: ManifestRequest = ciborium::from_reader(&encoded(&request)[..]).unwrap();
        assert_eq!(back, request);

        let response = ManifestResponse::Holdings {
            group,
            held: pack_holdings([true, false]),
        };
        let back: ManifestResponse = ciborium::from_reader(&encoded(&response)[..]).unwrap();
        assert_eq!(back, response);

        let request = BlobRequest {
            group,
            path: "a.jpg".to_owned(),
            hash: [6u8; 32],
            offset: 1024,
        };
        let back: BlobRequest = ciborium::from_reader(&encoded(&request)[..]).unwrap();
        assert_eq!(back, request);

        for reply in [BlobReply::Sending { size: 10 }, BlobReply::Unavailable] {
            let back: BlobReply = ciborium::from_reader(&encoded(&reply)[..]).unwrap();
            assert_eq!(back, reply);
        }
    }
}
