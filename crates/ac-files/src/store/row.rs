//! One file as this node knows it, the rules for choosing between two of them, and the
//! reading of one back out of sqlite.
//!
//! Which of two rows wins is a question about the rows themselves rather than about storage,
//! and keeping it here means it can be read — and argued with — without a schema around it.
//! The decoder sits beside them because what it builds is this file's business: everything
//! that reads a `files` row goes through it.

use std::str::FromStr;

use ac_net::PeerId;

use crate::path::RelPath;
use crate::store::FilesError;

/// What this node knows about one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRow {
    pub path: RelPath,
    pub size: u64,
    pub hash: String,
    pub modified: i64,
    pub added_at: i64,
    pub added_by: PeerId,
    pub removed_at: Option<i64>,
    pub have: bool,
    pub seen_seq: u64,
}

impl FileRow {
    pub fn is_removed(&self) -> bool {
        self.removed_at.is_some()
    }

    /// When this row last changed, in the clock of whoever changed it.
    pub fn changed_at(&self) -> i64 {
        self.removed_at.unwrap_or(self.added_at).max(self.added_at)
    }
}

/// What one [`Files::merge`] did with a row from a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Merged {
    Unchanged,
    Rejected,
    Applied,
    Conflicted { moved: RelPath },
    Deduplicated { kept: RelPath, dropped: RelPath },
}

/// Which of two versions of one path is true.
pub(super) fn wins_path(a: &FileRow, b: &FileRow) -> bool {
    (a.changed_at(), &a.hash) > (b.changed_at(), &b.hash)
}

/// Which of two paths keeps content the group holds twice.
pub(super) fn wins_hash(a: &FileRow, b: &FileRow) -> bool {
    (a.added_at, &a.path) < (b.added_at, &b.path)
}

/// What one [`Files::record`] changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recorded {
    Added,
    Unchanged,
    Replaced,
}

pub(super) type RowResult = rusqlite::Result<Result<FileRow, FilesError>>;

pub(super) fn row_to_file(row: &rusqlite::Row<'_>) -> RowResult {
    let path: String = row.get(0)?;
    let size: i64 = row.get(1)?;
    let hash: String = row.get(2)?;
    let modified: i64 = row.get(3)?;
    let added_at: i64 = row.get(4)?;
    let added_by: String = row.get(5)?;
    let removed_at: Option<i64> = row.get(6)?;
    let have: i64 = row.get(7)?;
    let seen_seq: i64 = row.get(8)?;

    Ok((|| {
        Ok(FileRow {
            path: RelPath::parse(&path).map_err(|_| FilesError::CorruptRow)?,
            size: u64::try_from(size).map_err(|_| FilesError::CorruptRow)?,
            hash,
            modified,
            added_at,
            added_by: PeerId::from_str(&added_by).map_err(|_| FilesError::CorruptRow)?,
            removed_at,
            have: have != 0,
            seen_seq: u64::try_from(seen_seq).map_err(|_| FilesError::CorruptRow)?,
        })
    })())
}
