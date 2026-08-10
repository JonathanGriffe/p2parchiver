//! The file index, in the node's existing `state.sqlite`.
//!
//! The bytes on disk are the truth and this is the cache — the inverse of `ac_groups`, where
//! signed bytes are authoritative. So a row here is a claim about the filesystem, and the one
//! rule that keeps the claim honest is that **nothing writes a row before the bytes it
//! describes exist**. `crate::content` is what makes that possible.
//!
//! # Sharing the database
//!
//! This file already has three writers across two processes — `contacts`, `ac_groups`, and the
//! server's own store in its own directory. A fourth inherits the same two disciplines, for
//! the reasons `ac_groups::store` sets out at length: `BEGIN IMMEDIATE` rather than deferred,
//! so the write lock is taken before the work rather than after it, and a `busy_timeout`, so a
//! concurrent writer is a short wait rather than an immediate `SQLITE_BUSY`.

use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use ac_groups::id::GroupId;
use ac_net::PeerId;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::dirname::sanitize;
use crate::path::RelPath;

/// How long to wait for another process's write lock before giving up.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// What this node knows about one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRow {
    pub path: RelPath,
    pub size: u64,
    /// sha256 of the content, hex. Computed while the bytes are copied in.
    pub hash: String,
    /// The source file's mtime, unix seconds. Advisory: it describes where the file came
    /// from, and nothing orders by it.
    pub modified: i64,
    pub added_at: i64,
    pub added_by: PeerId,
    /// Set once removed. The row survives so that an automatic sync cannot resurrect the
    /// file, and so the next milestone has a timestamp to compare against `added_at`.
    pub removed_at: Option<i64>,
}

impl FileRow {
    pub fn is_removed(&self) -> bool {
        self.removed_at.is_some()
    }
}

/// What one [`Files::record`] changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recorded {
    Added,
    /// Same path, same content: nothing to do. Makes re-running a bulk add cheap and safe.
    Unchanged,
    /// Same path, different content. Only reached when the caller asked to replace.
    Replaced,
}

pub struct Files {
    db: Connection,
    me: PeerId,
}

impl Files {
    /// Open (creating if absent) the file tables at `path`.
    ///
    /// Takes a plain path rather than `ac_net::config::Paths` so this crate stays independent
    /// of how a node lays out its directories; `ac-node` passes `paths.db_file()`.
    pub fn open(path: &Path, me: PeerId) -> Result<Self, FilesError> {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        Self::from_connection(Connection::open(path)?, me)
    }

    pub fn in_memory(me: PeerId) -> Result<Self, FilesError> {
        Self::from_connection(Connection::open_in_memory()?, me)
    }

    fn from_connection(db: Connection, me: PeerId) -> Result<Self, FilesError> {
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.busy_timeout(BUSY_TIMEOUT)?;
        // Table names are prefixed or plural-distinct because this file is shared with
        // `contacts` and the `group_*` tables.
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS file_roots (
                 group_id TEXT PRIMARY KEY NOT NULL,
                 dir      TEXT NOT NULL UNIQUE
             );
             CREATE TABLE IF NOT EXISTS files (
                 group_id   TEXT NOT NULL,
                 path       TEXT NOT NULL,
                 size       INTEGER NOT NULL,
                 hash       TEXT NOT NULL,
                 modified   INTEGER NOT NULL,
                 added_at   INTEGER NOT NULL,
                 added_by   TEXT NOT NULL,
                 removed_at INTEGER,
                 PRIMARY KEY (group_id, path)
             );
             CREATE INDEX IF NOT EXISTS files_hash ON files(hash);",
        )?;
        Ok(Self { db, me })
    }

    pub fn me(&self) -> PeerId {
        self.me
    }

    /// The directory holding `group`'s files, allocating one on first use.
    ///
    /// Recorded rather than recomputed, which is what makes the whole scheme work: a group
    /// name is unvalidated, not unique, and reaches us from a remote admin. Deciding once and
    /// writing the answer down means a collision is resolved a single time, and a directory
    /// never moves under files already in it.
    pub fn dir_for(&mut self, group: GroupId, name: &str) -> Result<String, FilesError> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        let existing: Option<String> = tx
            .query_row(
                "SELECT dir FROM file_roots WHERE group_id = ?1",
                params![group.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(dir) = existing {
            return Ok(dir);
        }

        // Falling back to the id covers a name that sanitises to nothing at all.
        let base = sanitize(name).unwrap_or_else(|| group.short());
        let mut candidate = base.clone();

        // Widening hex prefixes rather than a counter: the suffix then says *which group* the
        // directory belongs to, which is the question someone reading a backup will have.
        let full = group.to_string();
        let mut width = 8;
        while dir_taken(&tx, &candidate)? {
            if width > full.len() {
                return Err(FilesError::NoDirectory { group });
            }
            candidate = format!("{base}-{}", &full[..width]);
            width += 4;
        }

        tx.execute(
            "INSERT INTO file_roots (group_id, dir) VALUES (?1, ?2)",
            params![group.to_string(), candidate],
        )?;
        tx.commit()?;
        Ok(candidate)
    }

    /// The directory recorded for `group`, if one has been allocated.
    pub fn dir_of(&self, group: GroupId) -> Result<Option<String>, FilesError> {
        Ok(self
            .db
            .query_row(
                "SELECT dir FROM file_roots WHERE group_id = ?1",
                params![group.to_string()],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Record a file whose bytes are already in place.
    ///
    /// `replace` decides what happens when the path is held by *different* content; identical
    /// content is always [`Recorded::Unchanged`], so re-running a bulk add is free.
    ///
    /// Re-recording a removed path clears `removed_at`. That is the one place a removal is
    /// undone, and it is deliberate: it takes a local `ac file add` naming the path again.
    pub fn record(
        &mut self,
        group: GroupId,
        row: &FileRow,
        replace: bool,
    ) -> Result<Recorded, FilesError> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        let existing: Option<(String, Option<i64>)> = tx
            .query_row(
                "SELECT hash, removed_at FROM files WHERE group_id = ?1 AND path = ?2",
                params![group.to_string(), row.path.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;

        let outcome = match existing {
            Some((hash, None)) if hash == row.hash => return Ok(Recorded::Unchanged),
            Some((hash, None)) => {
                if !replace {
                    return Err(FilesError::Conflict {
                        path: row.path.clone(),
                        existing: hash,
                    });
                }
                Recorded::Replaced
            }
            // Previously removed, or never seen.
            Some((_, Some(_))) | None => Recorded::Added,
        };

        tx.execute(
            "INSERT INTO files (group_id, path, size, hash, modified, added_at, added_by, removed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)
             ON CONFLICT(group_id, path) DO UPDATE SET
                 size       = excluded.size,
                 hash       = excluded.hash,
                 modified   = excluded.modified,
                 added_at   = excluded.added_at,
                 added_by   = excluded.added_by,
                 removed_at = NULL",
            params![
                group.to_string(),
                row.path.as_str(),
                // SQLite integers are signed. No real file reaches 8 exabytes, but a silent
                // wrap would store a negative size, so say so instead.
                i64::try_from(row.size).map_err(|_| FilesError::CorruptRow)?,
                row.hash,
                row.modified,
                row.added_at,
                row.added_by.to_base58(),
            ],
        )?;
        tx.commit()?;
        Ok(outcome)
    }

    pub fn get(&self, group: GroupId, path: &RelPath) -> Result<Option<FileRow>, FilesError> {
        let row = self
            .db
            .query_row(
                "SELECT path, size, hash, modified, added_at, added_by, removed_at
                 FROM files WHERE group_id = ?1 AND path = ?2",
                params![group.to_string(), path.as_str()],
                row_to_file,
            )
            .optional()?;
        row.transpose()
    }

    /// Every file in `group`, in path order.
    ///
    /// Removed rows are excluded unless asked for: they are history, and a listing that mixed
    /// them in would misrepresent what the group holds.
    pub fn list(
        &self,
        group: GroupId,
        prefix: Option<&str>,
        include_removed: bool,
    ) -> Result<Vec<FileRow>, FilesError> {
        let mut stmt = self.db.prepare(
            "SELECT path, size, hash, modified, added_at, added_by, removed_at
             FROM files
             WHERE group_id = ?1
               AND (?2 = 1 OR removed_at IS NULL)
               AND (?3 IS NULL OR path LIKE ?3 ESCAPE '\\')
             ORDER BY path",
        )?;

        let pattern = prefix.map(|p| format!("{}%", escape_like(p)));
        let rows = stmt.query_map(
            params![group.to_string(), include_removed as i64, pattern],
            row_to_file,
        )?;

        let mut out = Vec::new();
        for row in rows {
            match row? {
                Ok(file) => out.push(file),
                // A row we cannot interpret is skipped rather than failing the listing: one
                // bad row must not hide every good one.
                Err(e) => tracing::warn!(error = %e, "skipping an unreadable file row"),
            }
        }
        Ok(out)
    }

    /// Mark a file removed. The row stays; the caller deletes the bytes.
    ///
    /// Returns whether anything changed, so the CLI can tell "removed" from "was not there".
    pub fn remove(&mut self, group: GroupId, path: &RelPath, at: i64) -> Result<bool, FilesError> {
        let changed = self.db.execute(
            "UPDATE files SET removed_at = ?3
             WHERE group_id = ?1 AND path = ?2 AND removed_at IS NULL",
            params![group.to_string(), path.as_str(), at],
        )?;
        Ok(changed > 0)
    }

    /// Drop everything this node records about a group's files, for `ac group forget`.
    ///
    /// Local only, and it does not touch the bytes — deleting a user's content as a
    /// side effect of forgetting a group is not something to do without being asked.
    pub fn forget_group(&mut self, group: GroupId) -> Result<(), FilesError> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM files WHERE group_id = ?1",
            params![group.to_string()],
        )?;
        tx.execute(
            "DELETE FROM file_roots WHERE group_id = ?1",
            params![group.to_string()],
        )?;
        tx.commit()?;
        Ok(())
    }
}

fn dir_taken(tx: &rusqlite::Transaction<'_>, dir: &str) -> Result<bool, FilesError> {
    Ok(tx
        .query_row(
            "SELECT 1 FROM file_roots WHERE dir = ?1",
            params![dir],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// `LIKE` treats `%` and `_` as wildcards, so a path containing either would match more than
/// the user asked for.
fn escape_like(raw: &str) -> String {
    raw.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

type RowResult = rusqlite::Result<Result<FileRow, FilesError>>;

fn row_to_file(row: &rusqlite::Row<'_>) -> RowResult {
    let path: String = row.get(0)?;
    let size: i64 = row.get(1)?;
    let hash: String = row.get(2)?;
    let modified: i64 = row.get(3)?;
    let added_at: i64 = row.get(4)?;
    let added_by: String = row.get(5)?;
    let removed_at: Option<i64> = row.get(6)?;

    Ok((|| {
        Ok(FileRow {
            path: RelPath::parse(&path).map_err(|_| FilesError::CorruptRow)?,
            size: u64::try_from(size).map_err(|_| FilesError::CorruptRow)?,
            hash,
            modified,
            added_at,
            added_by: PeerId::from_str(&added_by).map_err(|_| FilesError::CorruptRow)?,
            removed_at,
        })
    })())
}

#[derive(Debug, thiserror::Error)]
pub enum FilesError {
    #[error(transparent)]
    Db(#[from] rusqlite::Error),
    #[error(transparent)]
    Path(#[from] crate::path::PathError),
    #[error("a stored row could not be read")]
    CorruptRow,
    #[error("{path} already holds different content ({existing})")]
    Conflict { path: RelPath, existing: String },
    #[error("could not find an unused directory name for group {group}")]
    NoDirectory { group: GroupId },
}

#[cfg(test)]
mod tests {
    use super::*;
    use ac_groups::store::Groups;
    use libp2p::identity::Keypair;

    const AT: i64 = 1_000_000;

    fn peer() -> PeerId {
        Keypair::generate_ed25519().public().to_peer_id()
    }

    fn group_id(seed: u8) -> GroupId {
        GroupId::from_str(&hex::encode([seed; 32])).unwrap()
    }

    /// A store and the peer it belongs to, kept apart so a row can be built while the store
    /// is borrowed mutably.
    fn store() -> (Files, PeerId) {
        let me = peer();
        (Files::in_memory(me).unwrap(), me)
    }

    fn row(me: PeerId, path: &str, hash: &str) -> FileRow {
        FileRow {
            path: RelPath::parse(path).unwrap(),
            size: 3,
            hash: hash.to_owned(),
            modified: AT,
            added_at: AT,
            added_by: me,
            removed_at: None,
        }
    }

    #[test]
    fn a_file_round_trips() {
        let (mut files, me) = store();
        let g = group_id(1);
        let r = row(me, "photos/beach.jpg", "aa");

        assert_eq!(files.record(g, &r, false).unwrap(), Recorded::Added);
        assert_eq!(files.get(g, &r.path).unwrap().as_ref(), Some(&r));
        assert_eq!(files.list(g, None, false).unwrap(), vec![r]);
    }

    #[test]
    fn re_adding_identical_content_is_free() {
        let (mut files, me) = store();
        let g = group_id(1);
        let r = row(me, "a.jpg", "aa");

        files.record(g, &r, false).unwrap();
        assert_eq!(files.record(g, &r, false).unwrap(), Recorded::Unchanged);
    }

    #[test]
    fn different_content_at_one_path_needs_asking() {
        let (mut files, me) = store();
        let g = group_id(1);
        files.record(g, &row(me, "a.jpg", "aa"), false).unwrap();

        let changed = row(me, "a.jpg", "bb");
        assert!(matches!(
            files.record(g, &changed, false),
            Err(FilesError::Conflict { .. })
        ));
        assert_eq!(files.record(g, &changed, true).unwrap(), Recorded::Replaced);
        assert_eq!(files.get(g, &changed.path).unwrap().unwrap().hash, "bb");
    }

    #[test]
    fn removal_keeps_the_row_and_hides_it() {
        let (mut files, me) = store();
        let g = group_id(1);
        let r = row(me, "a.jpg", "aa");
        files.record(g, &r, false).unwrap();

        assert!(files.remove(g, &r.path, AT + 5).unwrap());
        assert!(files.list(g, None, false).unwrap().is_empty());

        let kept = files.list(g, None, true).unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].removed_at, Some(AT + 5));
    }

    #[test]
    fn removing_twice_reports_nothing_changed() {
        let (mut files, me) = store();
        let g = group_id(1);
        let r = row(me, "a.jpg", "aa");
        files.record(g, &r, false).unwrap();

        assert!(files.remove(g, &r.path, AT).unwrap());
        assert!(!files.remove(g, &r.path, AT).unwrap());
    }

    #[test]
    fn re_adding_a_removed_path_revives_it() {
        // The one way a removal is undone, and it takes a local `ac file add` to do it.
        let (mut files, me) = store();
        let g = group_id(1);
        let r = row(me, "a.jpg", "aa");
        files.record(g, &r, false).unwrap();
        files.remove(g, &r.path, AT).unwrap();

        let again = FileRow {
            added_at: AT + 10,
            ..r.clone()
        };
        assert_eq!(files.record(g, &again, false).unwrap(), Recorded::Added);

        let live = files.get(g, &r.path).unwrap().unwrap();
        assert_eq!(live.removed_at, None);
        assert!(
            live.added_at > AT,
            "added_at must beat the removal it undoes"
        );
    }

    #[test]
    fn listing_filters_by_prefix() {
        let (mut files, me) = store();
        let g = group_id(1);
        for path in ["a.jpg", "photos/1.jpg", "photos/2.jpg", "raw/3.jpg"] {
            files.record(g, &row(me, path, "aa"), false).unwrap();
        }

        let found = files.list(g, Some("photos/"), false).unwrap();
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|f| f.path.as_str().starts_with("photos/")));
    }

    #[test]
    fn a_prefix_containing_a_wildcard_is_taken_literally() {
        let (mut files, me) = store();
        let g = group_id(1);
        files.record(g, &row(me, "100%.jpg", "aa"), false).unwrap();
        files.record(g, &row(me, "1000.jpg", "bb"), false).unwrap();

        let found = files.list(g, Some("100%"), false).unwrap();
        assert_eq!(found.len(), 1, "`%` is a character, not a wildcard");
        assert_eq!(found[0].path.as_str(), "100%.jpg");
    }

    #[test]
    fn files_are_scoped_to_their_group() {
        let (mut files, me) = store();
        let (a, b) = (group_id(1), group_id(2));
        files.record(a, &row(me, "x.jpg", "aa"), false).unwrap();

        assert!(files.list(b, None, false).unwrap().is_empty());
        assert!(
            files
                .get(b, &RelPath::parse("x.jpg").unwrap())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_directory_is_allocated_once_and_remembered() {
        let (mut files, _me) = store();
        let g = group_id(1);

        let first = files.dir_for(g, "holiday").unwrap();
        assert_eq!(first, "holiday");
        // Even asked under a different name, the recorded answer wins.
        assert_eq!(files.dir_for(g, "something else").unwrap(), "holiday");
        assert_eq!(files.dir_of(g).unwrap().as_deref(), Some("holiday"));
    }

    #[test]
    fn a_second_group_of_the_same_name_gets_a_suffix() {
        let (mut files, _me) = store();
        let (a, b) = (group_id(1), group_id(2));

        assert_eq!(files.dir_for(a, "holiday").unwrap(), "holiday");
        let second = files.dir_for(b, "holiday").unwrap();

        assert_ne!(second, "holiday");
        assert!(second.starts_with("holiday-"), "{second}");
        assert!(second.contains(&b.short()), "the suffix names the group");
        // And the first is undisturbed, which is the point of recording it.
        assert_eq!(files.dir_of(a).unwrap().as_deref(), Some("holiday"));
    }

    #[test]
    fn a_hostile_group_name_cannot_escape() {
        // The name arrives inside a log signed by a remote admin.
        let (mut files, _me) = store();
        let dir = files.dir_for(group_id(1), "../../.ssh").unwrap();

        assert!(!dir.contains('/'), "{dir}");
        assert!(!dir.starts_with('.'), "{dir}");
    }

    #[test]
    fn a_name_that_sanitises_to_nothing_falls_back_to_the_id() {
        let (mut files, _me) = store();
        let g = group_id(7);

        assert_eq!(files.dir_for(g, "...").unwrap(), g.short());
    }

    #[test]
    fn forgetting_a_group_drops_its_rows_and_its_directory() {
        let (mut files, me) = store();
        let g = group_id(1);
        files.record(g, &row(me, "a.jpg", "aa"), false).unwrap();
        files.dir_for(g, "holiday").unwrap();

        files.forget_group(g).unwrap();

        assert!(files.list(g, None, true).unwrap().is_empty());
        assert_eq!(files.dir_of(g).unwrap(), None);
    }

    #[test]
    fn changes_are_visible_to_a_separate_connection() {
        // The CLI writes; a running daemon reads the same file without restarting.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite");
        let me = peer();

        let mut writer = Files::open(&path, me).unwrap();
        let g = group_id(1);
        writer.record(g, &row(me, "a.jpg", "aa"), false).unwrap();

        let reader = Files::open(&path, me).unwrap();
        assert_eq!(reader.list(g, None, false).unwrap().len(), 1);
    }

    #[test]
    fn the_file_tables_coexist_with_the_group_and_contact_ones() {
        // One `state.sqlite`, several owners. Opening either must not disturb the other.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite");
        let me = peer();

        let mut files = Files::open(&path, me).unwrap();
        let groups = Groups::open(&path, me).unwrap();

        let g = group_id(1);
        files.record(g, &row(me, "a.jpg", "aa"), false).unwrap();

        assert_eq!(files.list(g, None, false).unwrap().len(), 1);
        assert!(groups.list().unwrap().is_empty());
    }
}
