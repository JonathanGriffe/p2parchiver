//! Serde adapters that put binary on the wire as CBOR **byte strings**.
//!
//! # Why these exist
//!
//! serde encodes `[u8; N]` and `Vec<u8>` as *sequences of integers*. CBOR spends one byte on an
//! integer up to 23 and two above it, so uniformly random binary — hashes, signatures, signed
//! bodies — costs close to two bytes per byte. Measured on a real chain, that was 590 bytes per
//! entry, of which roughly half was this inflation: an ed25519 signature alone went from 64
//! bytes to ~121.
//!
//! # Why they are applied at field sites, not to the types
//!
//! Two different rules apply, and conflating them would be a serious bug.
//!
//! **Signed bodies must never be re-encoded.** [`crate::chain::EntryBody`] and
//! [`crate::standing::StandingBody`] are signed and hashed as their exact CBOR bytes. Changing
//! how *they* serialise would change every entry hash and invalidate every signature ever
//! written. So [`crate::id::GroupId`] and [`crate::id::EntryHash`] keep their derived
//! `Serialize`, which is what those bodies use, and these adapters are applied only where a
//! hash appears in a **wire** type.
//!
//! **Their wrappers are just transport.** [`crate::chain::Entry`] and
//! [`crate::standing::Standing`] carry `body: Vec<u8>` — the signed bytes, opaque at this
//! level. How that blob is framed for transmission has no bearing on what was signed, because
//! verification reads the bytes back out and checks them directly. It has no bearing on storage
//! either: entries live in SQLite `BLOB` columns and never pass through serde on the way to
//! disk. So the wrappers may be encoded as efficiently as we like.
//!
//! The split is the whole point: transient framing is free to change and is versioned by the
//! protocol name; signed bytes are permanent.

use std::fmt;

use serde::{Deserializer, Serializer};

use crate::id::{EntryHash, GroupId};

/// Read exactly `N` bytes from a CBOR byte string.
fn read_array<'de, D: Deserializer<'de>, const N: usize>(
    deserializer: D,
) -> Result<[u8; N], D::Error> {
    struct Exactly<const N: usize>;

    impl<const N: usize> serde::de::Visitor<'_> for Exactly<N> {
        type Value = [u8; N];

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{N} bytes")
        }

        fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
            v.try_into().map_err(|_| E::invalid_length(v.len(), &self))
        }
    }

    deserializer.deserialize_bytes(Exactly::<N>)
}

/// Read a variable-length CBOR byte string.
fn read_blob<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    struct Blob;

    impl serde::de::Visitor<'_> for Blob {
        type Value = Vec<u8>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a byte string")
        }

        fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
            Ok(v.to_vec())
        }

        fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
            Ok(v)
        }
    }

    deserializer.deserialize_byte_buf(Blob)
}

/// `#[serde(with = "crate::bytes::group_id")]` on a wire field holding a [`GroupId`].
pub mod group_id {
    use super::{Deserializer, GroupId, Serializer, read_array};

    pub fn serialize<S: Serializer>(id: &GroupId, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(id.as_bytes())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<GroupId, D::Error> {
        read_array::<D, 32>(d).map(GroupId::from_bytes)
    }
}

/// `#[serde(with = "crate::bytes::entry_hash")]` on a wire field holding an [`EntryHash`].
pub mod entry_hash {
    use super::{Deserializer, EntryHash, Serializer, read_array};

    pub fn serialize<S: Serializer>(hash: &EntryHash, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(hash.as_bytes())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<EntryHash, D::Error> {
        read_array::<D, 32>(d).map(EntryHash::from_bytes)
    }
}

/// `#[serde(with = "crate::bytes::digest")]` on a wire field holding a bare `[u8; 32]`.
pub mod digest {
    use super::{Deserializer, Serializer, read_array};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        read_array::<D, 32>(d)
    }
}

/// `#[serde(with = "crate::bytes::blob")]` on a field holding opaque bytes — a signed body or
/// a signature.
pub mod blob {
    use super::{Deserializer, Serializer, read_blob};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        read_blob(d)
    }
}
