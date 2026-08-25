use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use ac_groups::id::GroupId;
use ac_net::PeerId;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::content::Content;
use crate::dirname::sanitize;
use crate::path::RelPath;

/// How long to wait for another process's write lock before giving up.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

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
fn wins_path(a: &FileRow, b: &FileRow) -> bool {
    (a.changed_at(), &a.hash) > (b.changed_at(), &b.hash)
}

/// Which of two paths keeps content the group holds twice.
fn wins_hash(a: &FileRow, b: &FileRow) -> bool {
    (a.added_at, &a.path) < (b.added_at, &b.path)
}

/// What one [`Files::record`] changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recorded {
    Added,
    Unchanged,
    Replaced,
}

pub struct Files {
    db: Connection,
    me: PeerId,
}

impl Files {
    /// Open (creating if absent) the file tables at `path`.
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
                 have       INTEGER NOT NULL DEFAULT 0,
                 seen_seq   INTEGER NOT NULL DEFAULT 0,
                 PRIMARY KEY (group_id, path)
             );
             CREATE INDEX IF NOT EXISTS files_hash ON files(hash);
             CREATE TABLE IF NOT EXISTS file_sync (
                 group_id TEXT NOT NULL,
                 peer     TEXT NOT NULL,
                 cursor   INTEGER NOT NULL,
                 PRIMARY KEY (group_id, peer)
             );
             CREATE TABLE IF NOT EXISTS file_wants (
                 group_id TEXT NOT NULL,
                 path     TEXT NOT NULL,
                 PRIMARY KEY (group_id, path)
             );
             CREATE INDEX IF NOT EXISTS files_seen ON files(group_id, seen_seq);
             CREATE TABLE IF NOT EXISTS file_state (
                 group_id    TEXT PRIMARY KEY NOT NULL,
                 digest      BLOB,
                 digest_seq  INTEGER NOT NULL DEFAULT 0,
                 noticed_seq INTEGER NOT NULL DEFAULT 0,
                 last_change INTEGER NOT NULL DEFAULT 0
             );",
        )?;

        Ok(Self { db, me })
    }

    pub fn me(&self) -> PeerId {
        self.me
    }

    /// The directory holding `group`'s files, allocating one on first use.
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

    /// Every group that has a directory allocated, for a sweep that has to visit all of them.
    pub fn group_dirs(&self) -> Result<Vec<(GroupId, String)>, FilesError> {
        let mut stmt = self.db.prepare("SELECT group_id, dir FROM file_roots")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;

        let mut out = Vec::new();
        for row in rows {
            let (id, dir) = row?;
            if let Ok(group) = id.parse() {
                out.push((group, dir));
            }
        }
        Ok(out)
    }

    /// Live rows whose bytes we do not hold.
    pub fn unfinished(&self, group: GroupId) -> Result<Vec<RelPath>, FilesError> {
        let mut stmt = self.db.prepare(
            "SELECT path FROM files
             WHERE group_id = ?1 AND removed_at IS NULL AND have = 0",
        )?;
        let rows = stmt.query_map(params![group.to_string()], |row| row.get::<_, String>(0))?;

        let mut out = Vec::new();
        for row in rows {
            // An unparseable path cannot name a staging file either, since the name is derived
            // from the path we would have parsed.
            if let Ok(path) = RelPath::parse(&row?) {
                out.push(path);
            }
        }
        Ok(out)
    }

    /// Record a file whose bytes are already in place.
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

        write_row(&tx, group, row, row.have)?;
        tx.commit()?;
        Ok(outcome)
    }

    /// Take in a row from a peer, resolving both kinds of collision it can cause.
    pub fn merge(
        &mut self,
        group: GroupId,
        incoming: &FileRow,
        content: &Content,
        dir: &str,
    ) -> Result<Merged, FilesError> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        let local = read_row(&tx, group, &incoming.path)?;

        let mut settled = FileRow {
            path: incoming.path.clone(),
            ..incoming.clone()
        };
        let mut outcome = Merged::Applied;
        let mut displaced = None;

        match &local {
            None => {}

            Some(local) if local.hash == incoming.hash => {
                settled.added_at = local.added_at.min(incoming.added_at);
                settled.removed_at = match (local.removed_at, incoming.removed_at) {
                    (Some(a), Some(b)) => Some(a.max(b)),
                    (a, b) => a.or(b),
                };
                if settled.added_at == local.added_at && settled.removed_at == local.removed_at {
                    outcome = Merged::Unchanged;
                }
            }

            Some(local) if !local.is_removed() && !incoming.is_removed() => {
                if wins_path(incoming, local) {
                    displaced = Some(local.clone());
                } else {
                    // Ours keeps the name; theirs arrives under its own derived one.
                    settled.path = incoming.path.conflict_name(&incoming.hash);
                }
            }

            Some(local) if !wins_path(incoming, local) => return Ok(Merged::Rejected),
            Some(_) => {}
        }

        if let Some(loser) = &displaced {
            let moved = loser.path.conflict_name(&loser.hash);
            let held = loser.have && move_bytes(content, dir, &loser.path, &moved)?;
            write_row(
                &tx,
                group,
                &FileRow {
                    path: moved.clone(),
                    ..loser.clone()
                },
                held,
            )?;
            outcome = Merged::Conflicted { moved };
        }

        if outcome != Merged::Unchanged {
            let have = local
                .as_ref()
                .is_some_and(|l| l.have && l.hash == settled.hash && l.path == settled.path);
            write_row(&tx, group, &settled, have)?;
        }

        if !settled.is_removed()
            && let Some(twin) = read_twin(&tx, group, &settled)?
        {
            let (keep, drop) = if wins_hash(&settled, &twin) {
                (&settled, &twin)
            } else {
                (&twin, &settled)
            };

            let keep_have = read_row(&tx, group, &keep.path)?.is_some_and(|r| r.have);
            let drop_have = read_row(&tx, group, &drop.path)?.is_some_and(|r| r.have);
            if drop_have && !keep_have {
                if move_bytes(content, dir, &drop.path, &keep.path)? {
                    write_row(&tx, group, keep, true)?;
                }
            } else if drop_have {
                content
                    .remove(dir, &drop.path)
                    .map_err(|source| FilesError::Io {
                        path: drop.path.to_string(),
                        source,
                    })?;
            }

            let seq = next_seq(&tx, group)?;
            tx.execute(
                "UPDATE files SET removed_at = ?3, have = 0, seen_seq = ?4
                 WHERE group_id = ?1 AND path = ?2",
                params![
                    group.to_string(),
                    drop.path.as_str(),
                    drop.added_at.max(keep.added_at),
                    i64::try_from(seq).map_err(|_| FilesError::CorruptRow)?,
                ],
            )?;

            outcome = Merged::Deduplicated {
                kept: keep.path.clone(),
                dropped: drop.path.clone(),
            };
        }

        tx.commit()?;
        Ok(outcome)
    }

    pub fn path_of_hash(&self, group: GroupId, hash: &str) -> Result<Option<RelPath>, FilesError> {
        let found: Option<String> = self
            .db
            .query_row(
                "SELECT path FROM files
                 WHERE group_id = ?1 AND hash = ?2 AND removed_at IS NULL
                 ORDER BY added_at, path LIMIT 1",
                params![group.to_string(), hash],
                |row| row.get(0),
            )
            .optional()?;

        found
            .map(|p| RelPath::parse(&p).map_err(|_| FilesError::CorruptRow))
            .transpose()
    }

    pub fn mark_have(
        &mut self,
        group: GroupId,
        path: &RelPath,
        have: bool,
    ) -> Result<(), FilesError> {
        self.db.execute(
            "UPDATE files SET have = ?3 WHERE group_id = ?1 AND path = ?2",
            params![group.to_string(), path.as_str(), have as i64],
        )?;
        Ok(())
    }

    pub fn changes_since(
        &self,
        group: GroupId,
        cursor: u64,
        limit: usize,
    ) -> Result<(Vec<FileRow>, u64), FilesError> {
        let mut stmt = self.db.prepare(
            "SELECT path, size, hash, modified, added_at, added_by, removed_at, have, seen_seq
             FROM files
             WHERE group_id = ?1 AND seen_seq > ?2
             ORDER BY seen_seq
             LIMIT ?3",
        )?;
        let rows = stmt.query_map(
            params![
                group.to_string(),
                i64::try_from(cursor).unwrap_or(i64::MAX),
                i64::try_from(limit).unwrap_or(i64::MAX),
            ],
            row_to_file,
        )?;

        let mut out = Vec::new();
        let mut highest = cursor;
        for row in rows {
            match row? {
                Ok(file) => {
                    highest = highest.max(file.seen_seq);
                    out.push(file);
                }
                Err(e) => tracing::warn!(error = %e, "skipping an unreadable file row"),
            }
        }
        Ok((out, highest))
    }

    pub fn has_changes_after(&self, group: GroupId, cursor: u64) -> Result<bool, FilesError> {
        Ok(self
            .db
            .query_row(
                "SELECT 1 FROM files WHERE group_id = ?1 AND seen_seq > ?2 LIMIT 1",
                params![group.to_string(), i64::try_from(cursor).unwrap_or(i64::MAX)],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    pub fn cursor(&self, group: GroupId, peer: &PeerId) -> Result<u64, FilesError> {
        let found: Option<i64> = self
            .db
            .query_row(
                "SELECT cursor FROM file_sync WHERE group_id = ?1 AND peer = ?2",
                params![group.to_string(), peer.to_base58()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.unwrap_or(0).max(0) as u64)
    }

    pub fn set_cursor(
        &mut self,
        group: GroupId,
        peer: &PeerId,
        cursor: u64,
    ) -> Result<(), FilesError> {
        self.db.execute(
            "INSERT INTO file_sync (group_id, peer, cursor) VALUES (?1, ?2, ?3)
             ON CONFLICT(group_id, peer) DO UPDATE SET cursor = excluded.cursor",
            params![
                group.to_string(),
                peer.to_base58(),
                i64::try_from(cursor).unwrap_or(i64::MAX),
            ],
        )?;
        Ok(())
    }

    pub fn want(&mut self, group: GroupId, path: &RelPath) -> Result<(), FilesError> {
        self.db.execute(
            "INSERT INTO file_wants (group_id, path) VALUES (?1, ?2)
             ON CONFLICT(group_id, path) DO NOTHING",
            params![group.to_string(), path.as_str()],
        )?;
        Ok(())
    }

    /// Stop wanting a file: it arrived, or it went away.
    pub fn unwant(&mut self, group: GroupId, path: &RelPath) -> Result<(), FilesError> {
        self.db.execute(
            "DELETE FROM file_wants WHERE group_id = ?1 AND path = ?2",
            params![group.to_string(), path.as_str()],
        )?;
        Ok(())
    }

    /// Everything asked for and not yet held.
    pub fn wants(&self) -> Result<Vec<(GroupId, RelPath)>, FilesError> {
        let mut stmt = self
            .db
            .prepare("SELECT group_id, path FROM file_wants ORDER BY group_id, path")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;

        let mut out = Vec::new();
        for row in rows {
            let (group, path) = row?;
            match (GroupId::from_str(&group), RelPath::parse(&path)) {
                (Ok(group), Ok(path)) => out.push((group, path)),
                _ => tracing::warn!(%group, %path, "skipping an unreadable want"),
            }
        }
        Ok(out)
    }

    /// Fingerprint of a group's whole catalogue: "are our lists identical?", nothing more.
    pub fn digest(&self, group: GroupId) -> Result<[u8; 32], FilesError> {
        let tx = self.db.unchecked_transaction()?;

        let seq = seq_in(&tx, group)?;
        let cached: Option<(Option<Vec<u8>>, i64)> = tx
            .query_row(
                "SELECT digest, digest_seq FROM file_state WHERE group_id = ?1",
                params![group.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;

        if let Some((Some(bytes), at_seq)) = cached
            && at_seq as u64 == seq
            && let Ok(digest) = <[u8; 32]>::try_from(bytes.as_slice())
        {
            return Ok(digest);
        }

        let mut stmt = tx.prepare(
            "SELECT path, hash, added_at, removed_at FROM files
             WHERE group_id = ?1 ORDER BY path",
        )?;
        let mut rows = stmt.query(params![group.to_string()])?;

        let mut hasher = Sha256::new();
        hasher.update([0x03u8]);

        while let Some(row) = rows.next()? {
            let path: String = row.get(0)?;
            let hash: String = row.get(1)?;
            let added_at: i64 = row.get(2)?;
            let removed_at: Option<i64> = row.get(3)?;

            hasher.update((path.len() as u64).to_be_bytes());
            hasher.update(path.as_bytes());
            hasher.update((hash.len() as u64).to_be_bytes());
            hasher.update(hash.as_bytes());
            hasher.update(added_at.to_be_bytes());
            hasher.update(removed_at.unwrap_or(0).to_be_bytes());
        }

        let digest: [u8; 32] = hasher.finalize().into();
        drop(rows);
        drop(stmt);
        drop(tx);

        if let Ok(seq) = i64::try_from(seq) {
            let stored = self.db.execute(
                "INSERT INTO file_state (group_id, digest, digest_seq) VALUES (?1, ?2, ?3)
                 ON CONFLICT(group_id) DO UPDATE SET
                     digest = excluded.digest, digest_seq = excluded.digest_seq",
                params![group.to_string(), digest.as_slice(), seq],
            );
            if let Err(e) = stored {
                tracing::debug!(%group, error = %e, "could not cache the catalogue digest");
            }
        }

        Ok(digest)
    }

    /// This group's change counter: the highest position handed out in its log.
    pub fn seq(&self, group: GroupId) -> Result<u64, FilesError> {
        let tx = self.db.unchecked_transaction()?;
        seq_in(&tx, group)
    }

    /// Stamp when this group's catalogue last moved, and answer when that was.
    pub fn note_change(&mut self, group: GroupId, at: i64) -> Result<i64, FilesError> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        let seq = seq_in(&tx, group)?;
        let state: Option<(i64, i64)> = tx
            .query_row(
                "SELECT noticed_seq, last_change FROM file_state WHERE group_id = ?1",
                params![group.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;

        let (noticed, last) = state.unwrap_or((0, 0));
        if noticed as u64 == seq {
            return Ok(last);
        }

        tx.execute(
            "INSERT INTO file_state (group_id, noticed_seq, last_change) VALUES (?1, ?2, ?3)
             ON CONFLICT(group_id) DO UPDATE SET
                 noticed_seq = excluded.noticed_seq, last_change = excluded.last_change",
            params![
                group.to_string(),
                i64::try_from(seq).map_err(|_| FilesError::CorruptRow)?,
                at,
            ],
        )?;
        tx.commit()?;
        Ok(at)
    }

    /// How many live rows in this group we do not hold the bytes for.
    pub fn missing_count(&self, group: GroupId) -> Result<u64, FilesError> {
        let n: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM files
             WHERE group_id = ?1 AND have = 0 AND removed_at IS NULL",
            params![group.to_string()],
            |row| row.get(0),
        )?;
        Ok(n.max(0) as u64)
    }

    /// How many bytes of content this node holds, across every group.
    pub fn held_bytes(&self) -> Result<u64, FilesError> {
        let total: i64 = self.db.query_row(
            "SELECT COALESCE(SUM(size), 0) FROM files WHERE have = 1 AND removed_at IS NULL",
            [],
            |row| row.get(0),
        )?;
        Ok(total.max(0) as u64)
    }

    /// The next rows worth asking a peer for, wanted ones first.
    pub fn missing(&self, group: GroupId, limit: usize) -> Result<Vec<FileRow>, FilesError> {
        let mut stmt = self.db.prepare(
            "SELECT f.path, f.size, f.hash, f.modified, f.added_at, f.added_by,
                    f.removed_at, f.have, f.seen_seq
             FROM files f
             LEFT JOIN file_wants w ON w.group_id = f.group_id AND w.path = f.path
             WHERE f.group_id = ?1 AND f.have = 0 AND f.removed_at IS NULL
             ORDER BY (w.path IS NULL), f.path
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(
            params![group.to_string(), i64::try_from(limit).unwrap_or(i64::MAX)],
            row_to_file,
        )?;

        let mut out = Vec::new();
        for row in rows {
            match row? {
                Ok(file) => out.push(file),
                Err(e) => tracing::warn!(error = %e, "skipping an unreadable file row"),
            }
        }
        Ok(out)
    }

    /// How many rows the catalogue holds, tombstones included.
    pub fn count(&self, group: GroupId) -> Result<u64, FilesError> {
        let n: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM files WHERE group_id = ?1",
            params![group.to_string()],
            |row| row.get(0),
        )?;
        Ok(n.max(0) as u64)
    }

    pub fn get(&self, group: GroupId, path: &RelPath) -> Result<Option<FileRow>, FilesError> {
        let row = self
            .db
            .query_row(
                "SELECT path, size, hash, modified, added_at, added_by, removed_at, have, seen_seq
                 FROM files WHERE group_id = ?1 AND path = ?2",
                params![group.to_string(), path.as_str()],
                row_to_file,
            )
            .optional()?;
        row.transpose()
    }

    /// Every file in `group`, in path order.
    pub fn list(
        &self,
        group: GroupId,
        prefix: Option<&str>,
        include_removed: bool,
    ) -> Result<Vec<FileRow>, FilesError> {
        let mut stmt = self.db.prepare(
            "SELECT path, size, hash, modified, added_at, added_by, removed_at, have, seen_seq
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
    pub fn remove(&mut self, group: GroupId, path: &RelPath, at: i64) -> Result<bool, FilesError> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        let seq = next_seq(&tx, group)?;
        let changed = tx.execute(
            "UPDATE files SET removed_at = ?3, have = 0, seen_seq = ?4
             WHERE group_id = ?1 AND path = ?2 AND removed_at IS NULL",
            params![
                group.to_string(),
                path.as_str(),
                at,
                i64::try_from(seq).map_err(|_| FilesError::CorruptRow)?,
            ],
        )?;
        tx.commit()?;
        Ok(changed > 0)
    }

    /// Drop everything this node records about a group's files, for `ac group forget`.
    pub fn forget_group(&mut self, group: GroupId) -> Result<(), FilesError> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for table in [
            "files",
            "file_roots",
            "file_sync",
            "file_wants",
            "file_state",
        ] {
            tx.execute(
                &format!("DELETE FROM {table} WHERE group_id = ?1"),
                params![group.to_string()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}

/// Write a row and give it the next position in this group's change log.
fn write_row(
    tx: &rusqlite::Transaction<'_>,
    group: GroupId,
    row: &FileRow,
    have: bool,
) -> Result<u64, FilesError> {
    let seq = next_seq(tx, group)?;

    tx.execute(
        "INSERT INTO files
             (group_id, path, size, hash, modified, added_at, added_by, removed_at, have, seen_seq)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT(group_id, path) DO UPDATE SET
             size       = excluded.size,
             hash       = excluded.hash,
             modified   = excluded.modified,
             added_at   = excluded.added_at,
             added_by   = excluded.added_by,
             removed_at = excluded.removed_at,
             have       = excluded.have,
             seen_seq   = excluded.seen_seq",
        params![
            group.to_string(),
            row.path.as_str(),
            i64::try_from(row.size).map_err(|_| FilesError::CorruptRow)?,
            row.hash,
            row.modified,
            row.added_at,
            row.added_by.to_base58(),
            row.removed_at,
            have as i64,
            i64::try_from(seq).map_err(|_| FilesError::CorruptRow)?,
        ],
    )?;
    Ok(seq)
}

/// Move a file, reporting whether there was anything there.
fn move_bytes(
    content: &Content,
    dir: &str,
    from: &RelPath,
    to: &RelPath,
) -> Result<bool, FilesError> {
    match content.rename(dir, from, to) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(%from, "the index claimed bytes that are not on disk");
            Ok(false)
        }
        Err(source) => Err(FilesError::Io {
            path: from.to_string(),
            source,
        }),
    }
}

fn read_row(
    tx: &rusqlite::Transaction<'_>,
    group: GroupId,
    path: &RelPath,
) -> Result<Option<FileRow>, FilesError> {
    tx.query_row(
        "SELECT path, size, hash, modified, added_at, added_by, removed_at, have, seen_seq
         FROM files WHERE group_id = ?1 AND path = ?2",
        params![group.to_string(), path.as_str()],
        row_to_file,
    )
    .optional()?
    .transpose()
}

/// Another live path in this group holding the same content.
fn read_twin(
    tx: &rusqlite::Transaction<'_>,
    group: GroupId,
    row: &FileRow,
) -> Result<Option<FileRow>, FilesError> {
    tx.query_row(
        "SELECT path, size, hash, modified, added_at, added_by, removed_at, have, seen_seq
         FROM files
         WHERE group_id = ?1 AND hash = ?2 AND path <> ?3 AND removed_at IS NULL
         ORDER BY added_at, path LIMIT 1",
        params![group.to_string(), row.hash, row.path.as_str()],
        row_to_file,
    )
    .optional()?
    .transpose()
}

fn next_seq(tx: &rusqlite::Transaction<'_>, group: GroupId) -> Result<u64, FilesError> {
    Ok(seq_in(tx, group)? + 1)
}

/// The highest position this group has handed out, or zero.
fn seq_in(tx: &rusqlite::Transaction<'_>, group: GroupId) -> Result<u64, FilesError> {
    let highest: i64 = tx.query_row(
        "SELECT COALESCE(MAX(seen_seq), 0) FROM files WHERE group_id = ?1",
        params![group.to_string()],
        |row| row.get(0),
    )?;
    Ok(highest.max(0) as u64)
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

#[derive(Debug, thiserror::Error)]
pub enum FilesError {
    #[error(transparent)]
    Db(#[from] rusqlite::Error),
    #[error(transparent)]
    Path(#[from] crate::path::PathError),
    #[error("a stored row could not be read")]
    CorruptRow,
    #[error("could not move the bytes of {path}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{path} already holds different content ({existing})")]
    Conflict { path: RelPath, existing: String },
    #[error("could not find an unused directory name for group {group}")]
    NoDirectory { group: GroupId },
}

#[cfg(test)]
mod tests {
    use super::*;
    use ac_groups::store::Groups;
    use ac_net::identity::Keypair;

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
            have: true,
            // Assigned by the store on write, so what a caller puts here is ignored.
            seen_seq: 0,
        }
    }

    #[test]
    fn a_file_round_trips() {
        let (mut files, me) = store();
        let g = group_id(1);
        let r = row(me, "photos/beach.jpg", "aa");

        assert_eq!(files.record(g, &r, false).unwrap(), Recorded::Added);

        // `seen_seq` is the store's to assign, so compare everything the caller supplied and
        // then that the row took a real position in the log.
        let stored = files.get(g, &r.path).unwrap().unwrap();
        assert_eq!(
            (
                &stored.path,
                stored.size,
                &stored.hash,
                stored.added_at,
                stored.have
            ),
            (&r.path, r.size, &r.hash, r.added_at, r.have)
        );
        assert_eq!(
            stored.seen_seq, 1,
            "the first row in a group starts the log"
        );
        assert_eq!(files.list(g, None, false).unwrap(), vec![stored]);
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
    fn a_forgotten_group_does_not_leave_its_digest_behind() {
        let (mut files, me) = store();
        let g = group_id(1);
        files.record(g, &row(me, "a.jpg", "aa"), false).unwrap();
        let before = files.digest(g).unwrap();

        files.forget_group(g).unwrap();
        files.record(g, &row(me, "b.jpg", "bb"), false).unwrap();

        assert_eq!(files.seq(g).unwrap(), 1, "the counter did restart");
        assert_ne!(
            files.digest(g).unwrap(),
            before,
            "a different catalogue at the same counter position"
        );
    }

    #[test]
    fn the_cached_digest_is_invalidated_by_the_writes_it_covers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.db");
        let me = peer();
        let mut files = Files::open(&path, me).unwrap();
        let g = group_id(1);

        files.record(g, &row(me, "a.jpg", "aa"), false).unwrap();
        let first = files.digest(g).unwrap();
        assert_eq!(
            files.digest(g).unwrap(),
            first,
            "served again from the cache"
        );

        // Another process entirely.
        let mut other = Files::open(&path, me).unwrap();
        other.record(g, &row(me, "b.jpg", "bb"), false).unwrap();

        assert_ne!(
            files.digest(g).unwrap(),
            first,
            "the writer advanced the counter, which is all the invalidation there is"
        );
    }

    #[test]
    fn taking_a_copy_does_not_count_as_a_catalogue_change() {
        // `have` is local and excluded from the digest, and `mark_have` is the one write that
        // does not advance the counter. The two facts have to agree: if fetching bytes moved the
        // counter, every download would look like news and be announced to the whole group.
        let (mut files, me) = store();
        let g = group_id(1);
        let path = RelPath::parse("a.jpg").unwrap();
        files.record(g, &row(me, "a.jpg", "aa"), false).unwrap();

        let (digest, seq) = (files.digest(g).unwrap(), files.seq(g).unwrap());
        files.mark_have(g, &path, false).unwrap();

        assert_eq!(files.seq(g).unwrap(), seq, "not a change to the catalogue");
        assert_eq!(files.digest(g).unwrap(), digest);
    }

    #[test]
    fn the_pause_is_measured_from_the_change_not_from_noticing_twice() {
        let (mut files, me) = store();
        let g = group_id(1);

        files.record(g, &row(me, "a.jpg", "aa"), false).unwrap();
        assert_eq!(files.note_change(g, 100).unwrap(), 100, "the edit is news");
        assert_eq!(
            files.note_change(g, 160).unwrap(),
            100,
            "still the same edit sixty seconds later, so the pause has sixty seconds on it"
        );

        files.record(g, &row(me, "b.jpg", "bb"), false).unwrap();
        assert_eq!(files.note_change(g, 200).unwrap(), 200, "a second edit");
    }

    #[test]
    fn held_bytes_counts_only_what_is_here_and_live() {
        let (mut files, me) = store();
        let g = group_id(1);

        let mut held = row(me, "here.jpg", "aa");
        held.size = 100;
        files.record(g, &held, true).unwrap();

        let mut known = row(me, "elsewhere.jpg", "bb");
        known.size = 900;
        files.record(g, &known, true).unwrap();
        files
            .mark_have(g, &RelPath::parse("elsewhere.jpg").unwrap(), false)
            .unwrap();

        assert_eq!(files.held_bytes().unwrap(), 100, "only what we hold");

        // Across groups, not per group: the limit is about the volume, and three groups under
        // their own ceilings can still fill one disk.
        let other = group_id(2);
        let mut more = row(me, "second.jpg", "cc");
        more.size = 50;
        files.record(other, &more, true).unwrap();
        assert_eq!(files.held_bytes().unwrap(), 150);

        // A removal deletes the bytes, so it stops counting.
        files
            .remove(g, &RelPath::parse("here.jpg").unwrap(), AT)
            .unwrap();
        assert_eq!(files.held_bytes().unwrap(), 50);
    }

    #[test]
    fn forgetting_a_group_leaves_no_work_behind() {
        let (mut files, me) = store();
        let g = group_id(1);
        let path = RelPath::parse("a.jpg").unwrap();

        files.record(g, &row(me, "a.jpg", "aa"), false).unwrap();
        files.want(g, &path).unwrap();
        files.set_cursor(g, &me, 42).unwrap();

        files.forget_group(g).unwrap();

        assert!(
            files.wants().unwrap().is_empty(),
            "a want for a forgotten group is work nobody can ever finish"
        );
        assert_eq!(
            files.cursor(g, &me).unwrap(),
            0,
            "and a cursor into a log we no longer hold would skip rows on re-joining"
        );
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
    fn every_write_takes_a_new_position_in_the_log() {
        let (mut files, me) = store();
        let g = group_id(1);

        files.record(g, &row(me, "a.jpg", "aa"), false).unwrap();
        files.record(g, &row(me, "b.jpg", "bb"), false).unwrap();
        let (changes, next) = files.changes_since(g, 0, 100).unwrap();

        assert_eq!(changes.len(), 2);
        assert_eq!(next, 2);
        assert!(
            changes[0].seen_seq < changes[1].seen_seq,
            "the log is ordered"
        );
    }

    #[test]
    fn a_removal_is_news_and_advances_the_log() {
        // A peer already past this row must still hear that the file went.
        let (mut files, me) = store();
        let g = group_id(1);
        let r = row(me, "a.jpg", "aa");
        files.record(g, &r, false).unwrap();
        let (_, after_add) = files.changes_since(g, 0, 100).unwrap();

        files.remove(g, &r.path, AT + 5).unwrap();

        let (changes, next) = files.changes_since(g, after_add, 100).unwrap();
        assert_eq!(changes.len(), 1, "the removal is a change");
        assert!(changes[0].is_removed());
        assert!(next > after_add);
    }

    #[test]
    fn a_row_learned_late_still_travels() {
        let (mut files, me) = store();
        let g = group_id(1);

        files
            .record(g, &row(me, "recent.jpg", "rr"), false)
            .unwrap();
        let (_, caught_up) = files.changes_since(g, 0, 100).unwrap();

        let ancient = FileRow {
            added_at: AT - 100_000,
            ..row(me, "ancient.jpg", "an")
        };
        files.record(g, &ancient, false).unwrap();

        let (changes, _) = files.changes_since(g, caught_up, 100).unwrap();
        assert_eq!(
            changes.iter().map(|c| c.path.as_str()).collect::<Vec<_>>(),
            vec!["ancient.jpg"],
            "an old file learned late is still new to a peer"
        );
    }

    #[test]
    fn changes_are_paginated_and_report_where_to_resume() {
        let (mut files, me) = store();
        let g = group_id(1);
        for i in 0..10 {
            files
                .record(g, &row(me, &format!("f{i}.jpg"), "aa"), false)
                .unwrap();
        }

        let (first, next) = files.changes_since(g, 0, 4).unwrap();
        assert_eq!(first.len(), 4);
        assert!(files.has_changes_after(g, next).unwrap());

        let (second, next) = files.changes_since(g, next, 4).unwrap();
        assert_eq!(second.len(), 4);

        let (third, next) = files.changes_since(g, next, 4).unwrap();
        assert_eq!(third.len(), 2);
        assert!(!files.has_changes_after(g, next).unwrap(), "drained");
    }

    #[test]
    fn a_cursor_defaults_to_the_beginning() {
        let (mut files, _me) = store();
        let g = group_id(1);
        let them = peer();

        assert_eq!(files.cursor(g, &them).unwrap(), 0);
        files.set_cursor(g, &them, 412).unwrap();
        assert_eq!(files.cursor(g, &them).unwrap(), 412);
    }

    #[test]
    fn cursors_are_per_peer_and_per_group() {
        let (mut files, _me) = store();
        let (a, b) = (group_id(1), group_id(2));
        let (p, q) = (peer(), peer());

        files.set_cursor(a, &p, 10).unwrap();
        assert_eq!(files.cursor(a, &q).unwrap(), 0, "another peer's log");
        assert_eq!(files.cursor(b, &p).unwrap(), 0, "another group's log");
    }

    #[test]
    fn identical_catalogues_agree_on_a_digest() {
        let (mut one, me) = store();
        let (mut two, _) = store();
        let g = group_id(1);

        // Inserted in opposite orders, so the digest cannot depend on insertion order.
        for path in ["a.jpg", "b.jpg", "c.jpg"] {
            one.record(g, &row(me, path, path), false).unwrap();
        }
        for path in ["c.jpg", "b.jpg", "a.jpg"] {
            two.record(g, &row(me, path, path), false).unwrap();
        }

        assert_eq!(one.digest(g).unwrap(), two.digest(g).unwrap());
    }

    #[test]
    fn a_digest_ignores_what_is_local() {
        // `have` and `seen_seq` are this node's business. If either reached the digest, two
        // peers with the same catalogue and different downloads would resync for ever.
        let (mut one, me) = store();
        let (mut two, _) = store();
        let g = group_id(1);

        one.record(g, &row(me, "a.jpg", "aa"), false).unwrap();
        two.record(g, &row(me, "a.jpg", "aa"), false).unwrap();
        // Diverge both local columns.
        two.mark_have(g, &RelPath::parse("a.jpg").unwrap(), false)
            .unwrap();
        two.record(g, &row(me, "a.jpg", "aa"), false).unwrap();

        assert_eq!(one.digest(g).unwrap(), two.digest(g).unwrap());
    }

    #[test]
    fn a_digest_notices_a_removal() {
        // A tombstone is shared state. If it were left out, a peer that has seen a deletion
        // would disagree with one that has not, and neither could tell why.
        let (mut files, me) = store();
        let g = group_id(1);
        let r = row(me, "a.jpg", "aa");
        files.record(g, &r, false).unwrap();
        let before = files.digest(g).unwrap();

        files.remove(g, &r.path, AT + 1).unwrap();
        assert_ne!(files.digest(g).unwrap(), before);
    }

    #[test]
    fn a_digest_notices_content_changing_under_one_path() {
        let (mut files, me) = store();
        let g = group_id(1);
        files.record(g, &row(me, "a.jpg", "aa"), false).unwrap();
        let before = files.digest(g).unwrap();

        files.record(g, &row(me, "a.jpg", "bb"), true).unwrap();
        assert_ne!(files.digest(g).unwrap(), before);
    }

    #[test]
    fn a_digest_is_scoped_to_its_group() {
        let (mut files, me) = store();
        let (a, b) = (group_id(1), group_id(2));
        files.record(a, &row(me, "x.jpg", "aa"), false).unwrap();

        assert_ne!(files.digest(a).unwrap(), files.digest(b).unwrap());
        assert_eq!(files.count(a).unwrap(), 1);
        assert_eq!(files.count(b).unwrap(), 0);
    }

    #[test]
    fn content_already_held_is_found_by_hash() {
        let (mut files, me) = store();
        let g = group_id(1);
        files
            .record(g, &row(me, "albums/2024/beach.jpg", "d89c"), false)
            .unwrap();

        assert_eq!(
            files.path_of_hash(g, "d89c").unwrap().unwrap().as_str(),
            "albums/2024/beach.jpg"
        );
        assert_eq!(files.path_of_hash(g, "nope").unwrap(), None);
        assert_eq!(
            files.path_of_hash(group_id(2), "d89c").unwrap(),
            None,
            "another group keeps its own copy"
        );
    }

    #[test]
    fn a_removed_path_no_longer_holds_its_content() {
        let (mut files, me) = store();
        let g = group_id(1);
        let r = row(me, "a.jpg", "aa");
        files.record(g, &r, false).unwrap();
        files.remove(g, &r.path, AT).unwrap();

        assert_eq!(files.path_of_hash(g, "aa").unwrap(), None);
    }

    #[test]
    fn removing_clears_have() {
        let (mut files, me) = store();
        let g = group_id(1);
        let r = row(me, "a.jpg", "aa");
        files.record(g, &r, false).unwrap();
        files.remove(g, &r.path, AT).unwrap();

        let stored = files.list(g, None, true).unwrap();
        assert!(!stored[0].have, "the bytes went with the row");
    }

    #[test]
    fn only_live_rows_we_lack_are_unfinished() {
        // The keep-set a staging sweep is built from: everything else has no transfer that
        // could still resume into it.
        let (mut files, me) = store();
        let g = group_id(1);

        let missing = row(me, "want.mp4", "aa");
        let held = row(me, "have.mp4", "bb");
        let gone = row(me, "removed.mp4", "cc");

        files.record(g, &missing, false).unwrap();
        files.record(g, &held, false).unwrap();
        files.record(g, &gone, false).unwrap();
        // `record` is for bytes already in place, so the row that stands for one learned from
        // a peer has to give its `have` back.
        files.mark_have(g, &missing.path, false).unwrap();
        files.remove(g, &gone.path, AT).unwrap();

        let unfinished = files.unfinished(g).unwrap();
        assert_eq!(unfinished, vec![missing.path]);
    }

    #[test]
    fn a_forgotten_group_has_no_directory_left_to_sweep() {
        let (mut files, _me) = store();
        let g = group_id(1);
        let dir = files.dir_for(g, "holiday").unwrap();

        assert_eq!(files.group_dirs().unwrap(), vec![(g, dir)]);

        files.forget_group(g).unwrap();
        assert!(files.group_dirs().unwrap().is_empty());
    }

    /// A store, its peer, and a content root the merge can move bytes in.
    fn merging() -> (Files, PeerId, Content, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let me = peer();
        (
            Files::in_memory(me).unwrap(),
            me,
            Content::new(dir.path().join("files")),
            dir,
        )
    }

    /// Put real bytes at a path, so a merge that moves them can be checked on disk.
    fn place(content: &Content, path: &RelPath, bytes: &[u8]) {
        let dest = content.locate("g", path);
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        std::fs::write(dest, bytes).unwrap();
    }

    #[test]
    fn a_row_we_already_agree_with_changes_nothing() {
        let (mut files, me, content, _tmp) = merging();
        let g = group_id(1);
        let r = row(me, "a.jpg", "aa");
        files.record(g, &r, false).unwrap();

        assert_eq!(
            files.merge(g, &r, &content, "g").unwrap(),
            Merged::Unchanged
        );
    }

    #[test]
    fn two_different_files_at_one_path_both_survive() {
        let (mut files, me, content, _tmp) = merging();
        let g = group_id(1);

        let mine = FileRow {
            added_at: AT,
            ..row(me, "photos/beach.jpg", "aaaaaaaa")
        };
        files.record(g, &mine, false).unwrap();
        place(&content, &mine.path, b"mine");

        let theirs = FileRow {
            added_at: AT + 10,
            have: false,
            ..row(peer(), "photos/beach.jpg", "bbbbbbbb")
        };
        let outcome = files.merge(g, &theirs, &content, "g").unwrap();

        let moved = mine.path.conflict_name(&mine.hash);
        assert_eq!(
            outcome,
            Merged::Conflicted {
                moved: moved.clone()
            }
        );

        // Theirs took the name, and is not claimed to be here.
        let at_path = files.get(g, &mine.path).unwrap().unwrap();
        assert_eq!(at_path.hash, "bbbbbbbb");
        assert!(!at_path.have);

        // Ours kept its content, under the derived name, with the bytes actually moved.
        let renamed = files.get(g, &moved).unwrap().unwrap();
        assert_eq!(renamed.hash, "aaaaaaaa");
        assert!(renamed.have);
        assert_eq!(std::fs::read(content.locate("g", &moved)).unwrap(), b"mine");
        assert!(!content.exists("g", &mine.path), "the old name was vacated");
    }

    #[test]
    fn the_loser_of_a_path_is_the_same_on_both_sides() {
        // Neither peer coordinates, so the rule has to be a pure function of the two rows.
        let g = group_id(1);
        let (a_key, b_key) = (peer(), peer());
        let early = FileRow {
            added_at: AT,
            ..row(a_key, "p.jpg", "11111111")
        };
        let late = FileRow {
            added_at: AT + 5,
            ..row(b_key, "p.jpg", "22222222")
        };

        // The node that holds `early` receives `late`, and vice versa.
        let (mut one, _, c1, _t1) = merging();
        one.record(g, &early, false).unwrap();
        one.merge(g, &late, &c1, "g").unwrap();

        let (mut two, _, c2, _t2) = merging();
        two.record(g, &late, false).unwrap();
        two.merge(g, &early, &c2, "g").unwrap();

        assert_eq!(one.digest(g).unwrap(), two.digest(g).unwrap());
        assert_eq!(one.get(g, &late.path).unwrap().unwrap().hash, "22222222");
        assert_eq!(two.get(g, &late.path).unwrap().unwrap().hash, "22222222");
    }

    #[test]
    fn duplicate_content_collapses_onto_the_earliest_path() {
        let (mut files, me, content, _tmp) = merging();
        let g = group_id(1);

        let first = FileRow {
            added_at: AT,
            ..row(me, "albums/2024/beach.jpg", "d89ccb96")
        };
        files.record(g, &first, false).unwrap();
        place(&content, &first.path, b"photo");

        let second = FileRow {
            added_at: AT + 10,
            ..row(me, "favourites/beach.jpg", "d89ccb96")
        };
        let outcome = files.merge(g, &second, &content, "g").unwrap();

        assert_eq!(
            outcome,
            Merged::Deduplicated {
                kept: first.path.clone(),
                dropped: second.path.clone(),
            }
        );
        assert!(
            files.get(g, &second.path).unwrap().unwrap().is_removed(),
            "the later path gives way"
        );
        assert!(files.get(g, &first.path).unwrap().unwrap().have);
        assert_eq!(files.path_of_hash(g, "d89ccb96").unwrap(), Some(first.path));
    }

    #[test]
    fn dedup_never_deletes_the_only_copy() {
        // The node holds the *later* path's bytes and not the earlier one's. Collapsing must
        // move the content onto the surviving name, not throw it away and re-download it.
        let (mut files, me, content, _tmp) = merging();
        let g = group_id(1);

        // Known about, not held.
        let earlier = FileRow {
            added_at: AT,
            have: false,
            ..row(me, "albums/beach.jpg", "d89ccb96")
        };
        files.record(g, &earlier, false).unwrap();
        files.mark_have(g, &earlier.path, false).unwrap();

        // Held, but added later.
        let later = FileRow {
            added_at: AT + 10,
            ..row(me, "favourites/beach.jpg", "d89ccb96")
        };
        files.record(g, &later, false).unwrap();
        place(&content, &later.path, b"photo");

        files.merge(g, &later, &content, "g").unwrap();

        let kept = files.get(g, &earlier.path).unwrap().unwrap();
        assert!(!kept.is_removed(), "the earliest path survives");
        assert!(kept.have, "and it now holds the content");
        assert_eq!(
            std::fs::read(content.locate("g", &earlier.path)).unwrap(),
            b"photo",
            "the bytes moved rather than being deleted"
        );
        assert!(
            files.get(g, &later.path).unwrap().unwrap().is_removed(),
            "the later path is tombstoned"
        );
    }

    #[test]
    fn a_deduped_path_is_tombstoned_so_a_peer_cannot_recreate_it() {
        // A hard delete would let a peer that has not yet deduped re-offer the row on every
        // connection, and we would recreate it every time.
        let (mut files, me, content, _tmp) = merging();
        let g = group_id(1);

        let first = FileRow {
            added_at: AT,
            ..row(me, "a.jpg", "cafebabe")
        };
        files.record(g, &first, false).unwrap();
        place(&content, &first.path, b"x");

        let second = FileRow {
            added_at: AT + 10,
            ..row(me, "b.jpg", "cafebabe")
        };

        // Three deliveries, as a reconnection or a re-offer would produce.
        for _ in 0..3 {
            files.merge(g, &second, &content, "g").unwrap();
            assert!(
                files.get(g, &second.path).unwrap().unwrap().is_removed(),
                "stays removed however many times it is offered"
            );
        }
        assert_eq!(files.list(g, None, false).unwrap().len(), 1);
    }

    #[test]
    fn dedup_does_not_cross_a_group() {
        // Two groups are two membership boundaries. Dropping a file from one because another
        // held it earlier would destroy content across a line that matters.
        let (mut files, me, content, _tmp) = merging();
        let (a, b) = (group_id(1), group_id(2));

        let shared = row(me, "beach.jpg", "d89ccb96");
        files.record(a, &shared, false).unwrap();
        files.merge(b, &shared, &content, "g").unwrap();

        assert!(!files.get(a, &shared.path).unwrap().unwrap().is_removed());
        assert!(!files.get(b, &shared.path).unwrap().unwrap().is_removed());
    }

    #[test]
    fn an_older_row_for_a_path_we_have_is_rejected() {
        let (mut files, me, content, _tmp) = merging();
        let g = group_id(1);
        let r = row(me, "a.jpg", "aa");
        files.record(g, &r, false).unwrap();
        files.remove(g, &r.path, AT + 100).unwrap();

        // A re-add stamped before the removal must not resurrect it.
        let stale = FileRow {
            added_at: AT + 1,
            ..row(me, "a.jpg", "aa")
        };
        files.merge(g, &stale, &content, "g").unwrap();

        assert!(files.get(g, &r.path).unwrap().unwrap().is_removed());
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
