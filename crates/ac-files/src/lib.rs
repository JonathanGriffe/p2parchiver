//! Files: what a group actually holds, on this node's disk.
//!
//! `ac-net` answers "can we talk, and should we". `ac-groups` answers "what about" — which
//! peers belong to which group. This crate answers "what": the bytes themselves, where they
//! sit, and what this node knows about them.
//!
//! # The bytes are the truth
//!
//! This is the inverse of [`ac_groups`], where signed bytes are authoritative and every table
//! is a cache. Here the **filesystem** is authoritative and the SQLite index is the cache: a
//! file exists because it is on disk, and the row describes it. That ordering decides how
//! every write is sequenced — bytes land first, then the row commits (see [`content`]).
//!
//! It follows that the index can be wrong in exactly two ways, both recoverable and both
//! reported by `ac file verify`: a row whose bytes are missing, and bytes with no row. The
//! second is benign and is what a crash mid-write leaves behind. The first is not, which is
//! why nothing here ever writes a row before the bytes it promises.
//!
//! # Layout
//!
//! ```text
//! <storage_root>/<group-dir>/<path>
//! ```
//!
//! `<group-dir>` is **allocated once and recorded** in `file_roots`, never recomputed from the
//! group's name. Three things force that. A name is unvalidated beyond its length, so
//! `../../.ssh` is a legal group name and arrives from a *remote* admin. Two groups may
//! legitimately share a name. And sanitising is lossy, so distinct names can collapse onto one
//! directory. Deciding once, writing it down, and never revisiting it turns all three into a
//! single allocation-time question — see [`dirname`].
//!
//! `<path>` is a [`path::RelPath`], which is the only type the store and the content layer
//! accept. Making it a type rather than a check at each call site is what stops one forgotten
//! validation from writing outside the root.
//!
//! # Removal is recorded, not performed
//!
//! [`store::Files::remove`] sets `removed_at` and deletes the bytes; the row stays. A group
//! syncs automatically, so a row that simply vanished would be re-fetched from a peer that
//! still holds it — the same reason `ac_groups::State::Left` is local and permanent. The
//! timestamp is also what the next milestone transmits: an add/remove conflict resolves by
//! comparing `removed_at` against `added_at`, later wins.
//!
//! That is a timestamp used for ordering, which `ac_groups::chain` deliberately avoids. The
//! exposure is narrower: it decides whether one file is present, not who may reach anything,
//! so a skewed clock costs a wrong file state rather than an access-control failure.
//!
//! # Layering
//!
//! Nothing here may name a libp2p networking type. `PeerId` is fine. `tests/layering.rs`
//! enforces it by reading the source, because a reviewer will not catch a re-added `use`.

// The workspace warns on unwrap/expect because a panic in the event loop takes the whole
// daemon down. In tests a panic *is* the failure report, so let them through.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod content;
pub mod dirname;
pub mod path;
pub mod store;
pub mod sync;
pub mod wire;

pub use content::{Content, Staged};
pub use path::{PathError, RelPath};
pub use store::{FileRow, Files, FilesError, Merged, Recorded};
pub use sync::{FileAction, FileEvent, FileSync, Notice};
pub use wire::{
    BLOB_PROTOCOL, BlobReply, BlobRequest, FileHead, MANIFEST_PROTOCOL, ManifestEntry,
    ManifestRequest, ManifestResponse,
};
