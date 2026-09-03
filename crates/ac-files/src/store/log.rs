//! The per-group log: what has changed here, how far each peer has read, and the digest
//! that says whether two nodes agree.
//!
//! Three tables, because the answer to "what has this group done lately" is spread over all
//! of them: the position each row was stamped with in `files`, how far each peer has read in
//! `file_sync`, and the digest and the unsent counts in `file_state`.
//!
//! `file_state` is this module's alone: the parent names it in the schema and when a group is
//! forgotten, and otherwise never reads or writes a column of it. The handful of `pub(super)`
//! helpers at the bottom are what it goes through instead — a position in the log is the log's
//! to hand out, so a writer asks for one rather than reaching for the table. That keeps the
//! calls running from the parent into here, and one module answerable for the counters.

use ac_groups::id::GroupId;
use ac_net::PeerId;
use rusqlite::{OptionalExtension, params};
use sha2::{Digest, Sha256};

use crate::store::row::{FileRow, row_to_file};
use crate::store::{Files, FilesError};

impl Files {
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

    /// What this node has changed here since the group was last told: how many, and when last.
    pub fn local_news(&self, group: GroupId) -> Result<(u64, i64), FilesError> {
        let row: Option<(i64, i64)> = self
            .db
            .query_row(
                "SELECT changes, last_change FROM file_state WHERE group_id = ?1",
                params![group.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (changes, last) = row.unwrap_or((0, 0));
        Ok((changes.max(0) as u64, last))
    }

    /// Rows this group has gained that we do not hold, since the count was last taken.
    pub fn wanted_news(&self, group: GroupId) -> Result<u64, FilesError> {
        let n: Option<i64> = self
            .db
            .query_row(
                "SELECT wanted FROM file_state WHERE group_id = ?1",
                params![group.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        Ok(n.unwrap_or(0).max(0) as u64)
    }

    /// Taken account of: the group may ask around again.
    pub fn wanted_seen(&mut self, group: GroupId) -> Result<(), FilesError> {
        self.db.execute(
            "UPDATE file_state SET wanted = 0 WHERE group_id = ?1",
            params![group.to_string()],
        )?;
        Ok(())
    }

    /// The group has been told. Anything after this is a fresh change.
    pub fn news_told(&mut self, group: GroupId) -> Result<(), FilesError> {
        self.db.execute(
            "INSERT INTO file_state (group_id, changes) VALUES (?1, 0)
             ON CONFLICT(group_id) DO UPDATE SET changes = 0",
            params![group.to_string()],
        )?;
        Ok(())
    }

    /// Say this group wants bytes it was not waiting for a moment ago.
    ///
    /// Merging a catalogue notes this for itself. Marking a row unheld does not, so anything
    /// that discovers bytes have gone has to say so here, or the content loop will sit on its
    /// backoff with a file it now wants and no reason to go asking.
    pub fn wanted_again(&mut self, group: GroupId) -> Result<(), FilesError> {
        let tx = self.db.unchecked_transaction()?;
        note_wanted(&tx, group)?;
        tx.commit()?;
        Ok(())
    }
}
/// Record that this group gained a row we do not hold.
pub(super) fn note_wanted(
    tx: &rusqlite::Transaction<'_>,
    group: GroupId,
) -> Result<(), FilesError> {
    tx.execute(
        "INSERT INTO file_state (group_id, wanted) VALUES (?1, 1)
         ON CONFLICT(group_id) DO UPDATE SET wanted = file_state.wanted + 1",
        params![group.to_string()],
    )?;
    Ok(())
}

/// Record that this node changed this group's catalogue.
pub(super) fn note_local(
    tx: &rusqlite::Transaction<'_>,
    group: GroupId,
    at: i64,
) -> Result<(), FilesError> {
    tx.execute(
        "INSERT INTO file_state (group_id, last_change, changes) VALUES (?1, ?2, 1)
         ON CONFLICT(group_id) DO UPDATE SET
             last_change = excluded.last_change,
             changes     = file_state.changes + 1",
        params![group.to_string(), at],
    )?;
    Ok(())
}

pub(super) fn next_seq(tx: &rusqlite::Transaction<'_>, group: GroupId) -> Result<u64, FilesError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::Content;
    use crate::path::RelPath;
    use crate::store::fixtures::{AT, group_id, peer, row, store};

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
    fn the_pause_is_measured_from_the_change_not_from_reading_it_twice() {
        let (mut files, me) = store();
        let g = group_id(1);

        let mut edit = row(me, "a.jpg", "aa");
        edit.added_at = 100;
        files.record(g, &edit, false).unwrap();
        assert_eq!(
            files.local_news(g).unwrap(),
            (1, 100),
            "the edit is news, stamped when it was made"
        );
        assert_eq!(
            files.local_news(g).unwrap(),
            (1, 100),
            "and reading it again does not push the pause forward"
        );

        let mut second = row(me, "b.jpg", "bb");
        second.added_at = 200;
        files.record(g, &second, false).unwrap();
        assert_eq!(files.local_news(g).unwrap(), (2, 200), "a second edit");

        files.news_told(g).unwrap();
        assert_eq!(
            files.local_news(g).unwrap().0,
            0,
            "and nothing is owed once the group has been told"
        );
    }

    #[test]
    fn a_row_from_a_peer_is_not_our_news() {
        // The whole reason the writer stamps this rather than the supervisor inferring it: the
        // group's sequence moves for a merged row exactly as it does for an edit, so telling the
        // group about what it just told us would be one message per member per member.
        let (mut files, _me) = store();
        let g = group_id(1);
        let dir = files.dir_for(g, "holiday").unwrap();
        let content = Content::new(tempfile::tempdir().unwrap().path().to_path_buf());

        let theirs = row(PeerId::random(), "theirs.jpg", "cc");
        files.merge(g, &theirs, &content, &dir).unwrap();

        assert_eq!(
            files.local_news(g).unwrap().0,
            0,
            "we did not change anything; they did"
        );
        assert!(files.seq(g).unwrap() > 0, "though the log did move");
    }

    #[test]
    fn a_removal_is_news_like_any_other_change() {
        let (mut files, me) = store();
        let g = group_id(1);

        files.record(g, &row(me, "a.jpg", "aa"), false).unwrap();
        files.news_told(g).unwrap();

        assert!(
            files
                .remove(g, &RelPath::parse("a.jpg").unwrap(), 500)
                .unwrap(),
            "the row was there to remove"
        );
        assert_eq!(
            files.local_news(g).unwrap(),
            (1, 500),
            "taking a file out is a change the group has to hear about"
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

    /// Wanting a file again is not a catalogue change either, but it does have to reach the
    /// content loop: bytes that went missing locally are wanted from this moment, and the
    /// group would otherwise sit on whatever backoff it was already on.
    #[test]
    fn wanting_bytes_again_is_news_to_the_content_loop_and_nobody_else() {
        let (mut files, me) = store();
        let g = group_id(1);
        let path = RelPath::parse("a.jpg").unwrap();
        files.record(g, &row(me, "a.jpg", "aa"), true).unwrap();
        files.wanted_seen(g).unwrap();

        let (digest, seq) = (files.digest(g).unwrap(), files.seq(g).unwrap());
        assert_eq!(files.wanted_news(g).unwrap(), 0, "nothing is wanted yet");

        // What verify does when the bytes have gone from disk.
        files.mark_have(g, &path, false).unwrap();
        files.wanted_again(g).unwrap();

        assert!(files.wanted_news(g).unwrap() > 0, "the loop gets told");
        assert_eq!(files.seq(g).unwrap(), seq, "but the catalogue did not move");
        assert_eq!(files.digest(g).unwrap(), digest, "so peers hear nothing");
    }
}
