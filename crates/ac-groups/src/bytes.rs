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

pub mod group_id {
    use super::{Deserializer, GroupId, Serializer, read_array};

    pub fn serialize<S: Serializer>(id: &GroupId, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(id.as_bytes())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<GroupId, D::Error> {
        read_array::<D, 32>(d).map(GroupId::from_bytes)
    }
}

pub mod entry_hash {
    use super::{Deserializer, EntryHash, Serializer, read_array};

    pub fn serialize<S: Serializer>(hash: &EntryHash, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(hash.as_bytes())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<EntryHash, D::Error> {
        read_array::<D, 32>(d).map(EntryHash::from_bytes)
    }
}

pub mod digest {
    use super::{Deserializer, Serializer, read_array};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        read_array::<D, 32>(d)
    }
}

pub mod blob {
    use super::{Deserializer, Serializer, read_blob};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        read_blob(d)
    }
}
