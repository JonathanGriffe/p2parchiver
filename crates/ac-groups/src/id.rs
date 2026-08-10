//! Content-addressed identifiers for groups and entries.
//!
//! Both are sha-256 over signed bytes, and both are domain-separated by a leading tag byte so
//! a group id can never be mistaken for an entry hash even though the two are the same width
//! and both derived from the same genesis body.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Tag for a group id. Domain separation: the genesis body hashes to both a `GroupId` and an
/// [`EntryHash`], and they must not collide.
const TAG_GROUP: u8 = 0x01;

/// Tag for an entry hash.
const TAG_ENTRY: u8 = 0x00;

/// A group's permanent name.
///
/// `sha256(0x01 || <genesis body bytes>)`. The genesis body carries the admin's peer id and 16
/// random bytes, so the id **commits to its admin** and cannot be squatted: a hostile peer
/// cannot offer a different genesis under the same id, because the id is a function of that
/// genesis. Recomputable by anyone holding the first entry, so it needs no registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GroupId([u8; 32]);

/// The hash of one entry's body.
///
/// Over the **body only**, never the signature, so it stays a pure function of the bytes that
/// were signed — the same reason `ac_net::attest` carries its statement verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EntryHash([u8; 32]);

/// The `prev` of a genesis entry, which has no predecessor.
pub const NO_PARENT: EntryHash = EntryHash([0u8; 32]);

impl GroupId {
    /// The placeholder a genesis body carries in its own `group` field.
    ///
    /// A genesis cannot name the id derived from it, so the field is zeroed and the id is the
    /// hash of the body containing that zero. Every later entry carries the real id, and a
    /// non-genesis entry claiming `ZERO` is refused.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Derive the id from a genesis entry's encoded body.
    pub fn of_genesis(body: &[u8]) -> Self {
        Self(tagged(TAG_GROUP, body))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// For [`crate::bytes`], which reconstructs one from a CBOR byte string.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The first 8 hex characters, for logs and `ac group list`.
    pub fn short(&self) -> String {
        hex::encode(&self.0[..4])
    }
}

impl EntryHash {
    /// Hash an entry's encoded body.
    pub fn of_body(body: &[u8]) -> Self {
        Self(tagged(TAG_ENTRY, body))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// For [`crate::bytes`], which reconstructs one from a CBOR byte string.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

fn tagged(tag: u8, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([tag]);
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Both types are 32 bytes of hex in every human-facing surface: the CLI, logs, and the
/// database. On the wire they travel as bytes, which is what the `Serialize` derive gives.
macro_rules! hex_repr {
    ($t:ty, $what:literal) => {
        impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&hex::encode(self.0))
            }
        }

        impl FromStr for $t {
            type Err = BadHex;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let mut out = [0u8; 32];
                hex::decode_to_slice(s, &mut out).map_err(|_| BadHex { what: $what })?;
                Ok(Self(out))
            }
        }
    };
}

hex_repr!(GroupId, "group id");
hex_repr!(EntryHash, "entry hash");

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not a valid {what}: expected 64 hex characters")]
pub struct BadHex {
    pub what: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_group_id_round_trips_through_hex() {
        let id = GroupId::of_genesis(b"genesis");
        assert_eq!(id.to_string().parse::<GroupId>().unwrap(), id);
        assert_eq!(id.to_string().len(), 64);
        assert_eq!(id.short().len(), 8);
    }

    #[test]
    fn an_entry_hash_round_trips_through_hex() {
        let h = EntryHash::of_body(b"body");
        assert_eq!(h.to_string().parse::<EntryHash>().unwrap(), h);
    }

    #[test]
    fn the_tags_keep_the_two_apart() {
        // The genesis body is hashed as both. Without domain separation an entry hash would
        // equal its own group id, and a `prev` field could be confused for a group.
        let body = b"the same bytes";
        assert_ne!(
            GroupId::of_genesis(body).as_bytes(),
            EntryHash::of_body(body).as_bytes(),
        );
    }

    #[test]
    fn different_bodies_hash_differently() {
        assert_ne!(GroupId::of_genesis(b"a"), GroupId::of_genesis(b"b"));
    }

    #[test]
    fn junk_hex_is_refused() {
        for junk in ["", "zz", &"a".repeat(63), &"a".repeat(65)] {
            assert!(junk.parse::<GroupId>().is_err(), "{junk:?}");
        }
    }
}
