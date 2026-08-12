//! The `/ac/manifest/2.0.0` and `/ac/blob/1.0.0` protocols.
//!
//! The **only** module in this crate permitted to name `libp2p`. The store, the paths, the
//! conflict rules and the sync policy are all free of networking types, which is what lets
//! them be tested against a temp directory with no socket.
//!
//! # Two protocols, because they carry different things
//!
//! **The manifest** is small, structured, and request-response: "what do you have?" answered
//! by a page of catalogue rows. It is capped like any other message and buffered whole.
//!
//! **A blob** is a file, possibly gigabytes of it, and request-response cannot carry that —
//! `request_response` holds an entire message in memory, so a chunked version would need
//! out-of-order reassembly, a second hashing pass, and blocking disk reads inside the event
//! loop. Blobs travel over a **stream** instead, opened per transfer. Only the header types
//! live here; the stream itself is `ac-node`'s, because it needs a runtime and a spawned task.

use ac_groups::id::GroupId;
use libp2p::StreamProtocol;
use libp2p::request_response::{self, ProtocolSupport};
use serde::{Deserialize, Serialize};

use crate::path::RelPath;
use crate::store::FileRow;

/// Bumped on any incompatible change to the types below. The version lives in the name because
/// multistream-select negotiates on it, so an incompatible peer fails cleanly at negotiation
/// rather than misreading a message — the same convention as `ac_net::proto`.
///
/// `2.0.0` added [`ManifestRequest::Holdings`]. Adding a request variant is not backward
/// compatible — an older peer cannot decode it — so the name carries the bump rather than a
/// feature flag, and an old peer fails at negotiation instead of on a message it cannot read.
pub const MANIFEST_PROTOCOL: &str = "/ac/manifest/2.0.0";

/// Versioned separately from the manifest: the two change for different reasons, and a peer
/// that cannot exchange catalogues has no use for a blob stream either way.
pub const BLOB_PROTOCOL: &str = "/ac/blob/1.0.0";

/// Ceiling on how many groups one `Offer` may name.
///
/// Matches `ac_groups::wire`, and for the same reason: without a cap an offer is an unbounded
/// allocation on the receiving side.
pub const MAX_HEADS_PER_OFFER: usize = 128;

/// Rows one `Changes` response may carry.
///
/// Not a limit on how large a catalogue may be — a peer that has more says so with `more` and
/// is asked again from the position it reported. That is what makes a node returning after a
/// year converge over several rounds instead of hitting a ceiling it cannot get past.
pub const MAX_ENTRIES_PER_RESPONSE: usize = 2048;

/// Paths one [`ManifestRequest::Holdings`] may ask about.
///
/// A count cap alone does **not** bound the message — a path may be a kilobyte — so the
/// builder also stops when the encoded request approaches [`MAX_REQUEST_BYTES`]. This is the
/// friendlier of the two limits: it keeps a query to a round number of files rather than to
/// wherever the bytes happened to run out.
pub const MAX_HOLDINGS_QUERY: usize = 512;

/// Largest request we will decode. An `Offer` of 128 heads is ~7 KiB.
pub const MAX_REQUEST_BYTES: u64 = 64 * 1024;

/// Largest response we will decode.
///
/// A denial-of-service backstop, not a page size: `request_response` buffers whole messages,
/// so an unbounded response is a memory attack. [`MAX_ENTRIES_PER_RESPONSE`] is what actually
/// bounds a page, and `a_full_page_fits_in_a_response` checks the two agree.
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

/// What one peer believes about one group's catalogue.
///
/// The digest answers "are our lists identical?" and nothing else: equal means there is
/// nothing to do and no rows are exchanged at all, which is the common case on every
/// reconnection. `count` is advisory, for reporting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileHead {
    #[serde(with = "ac_groups::bytes::group_id")]
    pub group: GroupId,
    #[serde(with = "ac_groups::bytes::digest")]
    pub digest: [u8; 32],
    pub count: u64,
}

/// One catalogue row, as it crosses the wire.
///
/// Deliberately **not** a `FileRow`: `have` and `seen_seq` are local facts that would be
/// meaningless or actively wrong on another node, and leaving them out of the type is what
/// stops either being sent by accident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub path: String,
    /// Raw content hash, not the hex the store keeps. Hex would double the dominant field of
    /// every entry — 32 bytes against 64 — and this is what a catalogue is mostly made of.
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
    /// "These are the catalogues I believe we share." Built only from
    /// `ac_groups::store::Groups::shared_with`, which is the one thing allowed to name a group
    /// to a peer.
    Offer(Vec<FileHead>),
    /// Everything past our position in *this peer's own* change log.
    ///
    /// `after` is a position the peer itself reported, never a timestamp and never a number we
    /// invented. A row created long ago but learned by them recently sits at the end of their
    /// log, so it is still delivered — which a cursor over `added_at` would miss.
    Changes { group: GroupId, after: u64 },
    /// "Of these paths, which do you actually hold?"
    ///
    /// A **pull**, not an advertisement: nothing is volunteered, holdings never enter the
    /// digest, and the answer only ever describes the files that were asked about.
    ///
    /// It exists because the blob protocol answers one file at a time and has no way to say
    /// *"nothing else here for you"*. Without this, concluding that a peer cannot help would
    /// mean opening a stream per missing file — five hundred round trips to learn that a peer
    /// holds none of them. This answers it in one.
    ///
    /// It cannot ride on [`ManifestResponse::Changes`] instead, which is the cheaper-looking
    /// design: in a mirror two members usually have *identical catalogues and different
    /// holdings*, so their digests match, no entries are exchanged, and there is nothing to
    /// carry a `have` bit on. The case that matters transfers nothing to piggyback on.
    Holdings { group: GroupId, paths: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManifestResponse {
    Offer(Vec<FileHead>),
    Changes {
        group: GroupId,
        entries: Vec<ManifestEntry>,
        /// The highest log position in this batch, which becomes the asker's new cursor.
        next: u64,
        /// Whether anything remains past `next`.
        more: bool,
        /// The responder's digest as of now, so the asker can tell convergence from
        /// "there is more to come".
        #[serde(with = "ac_groups::bytes::digest")]
        digest: [u8; 32],
    },
    /// One bit per path of the request, in the order asked: set means "I hold this".
    ///
    /// A bitmap rather than a list of paths, because the asker already knows what it asked
    /// and echoing the strings back would multiply a 512-path query by the length of its
    /// paths for no information.
    Holdings {
        group: GroupId,
        #[serde(with = "ac_groups::bytes::blob")]
        held: Vec<u8>,
    },
    /// Refused, with **no reason given, deliberately**.
    ///
    /// Distinguishing "I have never heard of that group" from "you are not a member of it"
    /// would turn guessing a `GroupId` into a membership oracle — the same argument as
    /// `ac_groups::wire::GroupResponse::Unavailable`.
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
///
/// Out of range reads `false`, so a peer returning a short bitmap withholds files rather than
/// inventing them — the safe direction, since the cost is asking someone else.
pub fn holds(bitmap: &[u8], i: usize) -> bool {
    bitmap
        .get(i / 8)
        .is_some_and(|byte| byte & (1 << (i % 8)) != 0)
}

/// Sent by the opener of a blob stream, length-prefixed, before any bytes flow.
///
/// `hash` names the content rather than trusting the path, so the receiver can verify what
/// arrived is what it asked for even if the catalogue moved underneath it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobRequest {
    #[serde(with = "ac_groups::bytes::group_id")]
    pub group: GroupId,
    pub path: String,
    #[serde(with = "ac_groups::bytes::digest")]
    pub hash: [u8; 32],
    /// Where to start. Non-zero resumes a transfer that was cut off — which is routine rather
    /// than exceptional, because a relayed transfer is cut every `MAX_CIRCUIT_BYTES`.
    pub offset: u64,
}

/// The answer to a [`BlobRequest`], before the bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlobReply {
    /// Bytes follow: `size` of them, counting from the requested offset.
    Sending { size: u64 },
    /// Refused or absent, and which is not said — same reasoning as
    /// [`ManifestResponse::Unavailable`].
    Unavailable,
}

pub type Behaviour = request_response::cbor::Behaviour<ManifestRequest, ManifestResponse>;

/// Build the manifest behaviour that `ac-node` mounts alongside the group one.
///
/// `ProtocolSupport::Full` because the exchange is symmetric: either side offers, either side
/// may be asked. Size maxima are set explicitly — the codec defaults are 1 MiB request and
/// 10 MiB response, far more than this protocol should accept.
pub fn behaviour() -> Behaviour {
    let codec = request_response::cbor::codec::Codec::default()
        .set_request_size_maximum(MAX_REQUEST_BYTES)
        .set_response_size_maximum(MAX_RESPONSE_BYTES);

    Behaviour::with_codec(
        codec,
        [(
            StreamProtocol::new(MANIFEST_PROTOCOL),
            ProtocolSupport::Full,
        )],
        request_response::Config::default(),
    )
}

impl ManifestEntry {
    /// What we would tell a peer about one of our rows.
    pub fn of(row: &FileRow) -> Option<Self> {
        let mut hash = [0u8; 32];
        // A row whose hash is not 32 bytes of hex cannot have come from `Content::stage`.
        // Skipped rather than sent, so one damaged row does not poison a whole page.
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
    ///
    /// Everything a peer controls is validated here, at the edge: the path becomes a
    /// [`RelPath`] before anything joins it to a directory, and the peer id must parse. A row
    /// arriving from the network never claims `have` — bytes are fetched separately, and a
    /// peer does not get to tell us what is on our own disk.
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
            // Assigned by our own store when the row is written.
            seen_seq: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ac_net::PeerId;
    use libp2p::identity::Keypair;
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
        // Measured, not assumed. serde encodes `[u8; 32]` as a sequence of integers unless
        // told otherwise, costing ~2 bytes per random byte — the mistake `ac_groups::bytes`
        // exists to document. Dropping the adapter would put `hash` at ~64 bytes instead of
        // 34 and inflate every entry of every catalogue.
        //
        // An entry is ~164 bytes today, and the shape of that is worth knowing before anyone
        // tries to shrink it: roughly 53 in CBOR field names, 52 in the base58 peer id, 34 in
        // the hash, and the rest in the path and three timestamps. The peer id and the field
        // names are the fat, not the hash.
        let size = encoded(&entry("a.jpg")).len();
        assert!(
            size <= 175,
            "a manifest entry costs {size} bytes; the byte-string adapters have probably \
             been dropped from `hash`"
        );
    }

    #[test]
    fn an_offer_of_the_maximum_fits_in_a_request() {
        let heads: Vec<_> = (0..MAX_HEADS_PER_OFFER)
            .map(|i| FileHead {
                group: GroupId::from_str(&hex::encode([i as u8; 32])).unwrap(),
                digest: [200u8; 32],
                count: 10_000,
            })
            .collect();

        let size = encoded(&ManifestRequest::Offer(heads)).len() as u64;
        assert!(size < MAX_REQUEST_BYTES, "an offer is {size} bytes");
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
            ManifestRequest::Offer(vec![head.clone()]),
            ManifestRequest::Changes { group, after: 412 },
        ] {
            let bytes = encoded(&request);
            let back: ManifestRequest = ciborium::from_reader(&bytes[..]).unwrap();
            assert_eq!(back, request);
        }

        for response in [
            ManifestResponse::Offer(vec![head]),
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
