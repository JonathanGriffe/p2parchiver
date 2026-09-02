use std::path::Path;
use std::time::Duration;

use rusqlite::{
    Connection, OptionalExtension, TransactionBehavior, params, params_from_iter, types::Value,
};

use crate::config::Fields;
use crate::source::{Checksum, Digest, Item, SourceError, SourceType};

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Seconds between scans
pub const SCAN_INTERVAL: i64 = 16 * 3600;

pub const FETCH_RETRY_DELAY: i64 = 3600;

pub const MAX_FETCH_ATTEMPTS: i64 = 3;

const REFS_PER_QUERY: usize = 900;

pub fn due(kind: SourceType, scanned_at: i64, backoff: i64, at: i64) -> bool {
    kind.polled() && scanned_at.saturating_add(SCAN_INTERVAL.max(backoff)) <= at
}

/// What became of one imported content. Only ever moves forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Unsorted,
    Sorted,
    Dropped,
}

impl State {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unsorted => "unsorted",
            Self::Sorted => "sorted",
            Self::Dropped => "dropped",
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "unsorted" => Some(Self::Unsorted),
            "sorted" => Some(Self::Sorted),
            "dropped" => Some(Self::Dropped),
            _ => None,
        }
    }
}

/// One source the user configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRow {
    pub dir: String,
    pub name: String,
    pub source: String,
    pub config: Fields,
    pub added_at: i64,
    pub scanned_at: i64,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owed {
    pub source_dir: String,
    pub source_ref: String,
    pub folder: String,
    pub name: String,
    pub size: Option<u64>,
    pub checksum: Option<Checksum>,
}

impl Owed {
    /// What the source offered, as it was written down. What a fetch is handed back.
    pub fn item(&self) -> Item {
        Item {
            reference: self.source_ref.clone(),
            folder: self.folder.clone(),
            name: self.name.clone(),
            size: self.size,
            checksum: self.checksum.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Imported {
    pub hash: String,
    pub state: State,
    pub name: String,
    pub size: u64,
    pub at: i64,
    pub group_id: Option<String>,
    pub source_dir: String,
    pub source_name: String,
    pub source_ref: String,
    pub folder: String,
}

/// What one source has brought in over its whole life.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tally {
    pub waiting: u64,
    pub sorted: u64,
    pub dropped: u64,
}

pub struct Ledger {
    db: Connection,
}

impl Ledger {
    pub fn open(path: &Path) -> Result<Self, LedgerError> {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        Self::from_connection(Connection::open(path)?)
    }

    fn from_connection(db: Connection) -> Result<Self, LedgerError> {
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.busy_timeout(BUSY_TIMEOUT)?;
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS sources (
                 dir        TEXT PRIMARY KEY NOT NULL,
                 name       TEXT NOT NULL UNIQUE,
                 source     TEXT NOT NULL,
                 config     TEXT NOT NULL,
                 added_at   INTEGER NOT NULL,
                 scanned_at INTEGER NOT NULL DEFAULT 0,
                 last_error TEXT
             );
             CREATE TABLE IF NOT EXISTS source_settings (
                 source TEXT NOT NULL,
                 key    TEXT NOT NULL,
                 value  TEXT NOT NULL,
                 PRIMARY KEY (source, key)
             );
             CREATE TABLE IF NOT EXISTS import_refs (
                 source_dir TEXT NOT NULL,
                 source_ref TEXT NOT NULL,
                 folder     TEXT NOT NULL,
                 name       TEXT NOT NULL,
                 size       INTEGER,
                 -- What the source said the bytes would come to, kept from the scan that
                 -- heard it: the fetch that has to check it happens much later.
                 algo       TEXT,
                 checksum   TEXT,
                 -- What they came to. Set once the file is in, which is what settles the row.
                 hash       TEXT,
                 tried_at   INTEGER NOT NULL DEFAULT 0,
                 fails      INTEGER NOT NULL DEFAULT 0,
                 PRIMARY KEY (source_dir, source_ref)
             );
             CREATE INDEX IF NOT EXISTS import_refs_owed
                 ON import_refs(tried_at, fails) WHERE hash IS NULL;
             CREATE INDEX IF NOT EXISTS import_refs_source_owed
                 ON import_refs(source_dir) WHERE hash IS NULL;
             CREATE TABLE IF NOT EXISTS imported (
                 hash        TEXT PRIMARY KEY NOT NULL,
                 state       TEXT NOT NULL,
                 name        TEXT NOT NULL,
                 size        INTEGER NOT NULL,
                 at          INTEGER NOT NULL,
                 group_id    TEXT,
                 source_dir  TEXT NOT NULL,
                 source_name TEXT NOT NULL,
                 source_ref  TEXT NOT NULL,
                 folder      TEXT NOT NULL,
                 CHECK ((state = 'sorted') = (group_id IS NOT NULL))
             );
             CREATE INDEX IF NOT EXISTS imported_at
                 ON imported(at, hash, size) WHERE state = 'unsorted';
             CREATE INDEX IF NOT EXISTS imported_open
                 ON imported(source_dir, folder) WHERE state = 'unsorted';
             CREATE INDEX IF NOT EXISTS imported_by_source
                 ON imported(source_dir, state);",
        )?;

        Ok(Self { db })
    }

    pub fn add_source(&self, row: &SourceRow) -> Result<(), LedgerError> {
        self.db.execute(
            "INSERT INTO sources (dir, name, source, config, added_at, scanned_at, last_error)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                row.dir,
                row.name,
                row.source,
                row.config.encode(),
                row.added_at,
                row.scanned_at,
                row.last_error,
            ],
        )?;
        Ok(())
    }

    pub fn sources(&self) -> Result<Vec<SourceRow>, LedgerError> {
        self.read_sources("ORDER BY name", [])
    }

    pub fn stalest(&self) -> Result<Vec<SourceRow>, LedgerError> {
        self.read_sources("ORDER BY scanned_at, name", [])
    }

    pub fn source(&self, dir: &str) -> Result<Option<SourceRow>, LedgerError> {
        Ok(self
            .read_sources("WHERE dir = ?1", params![dir])?
            .into_iter()
            .next())
    }

    pub fn source_named(&self, name: &str) -> Result<Option<SourceRow>, LedgerError> {
        Ok(self
            .read_sources("WHERE name = ?1", params![name])?
            .into_iter()
            .next())
    }

    pub fn dir_taken(&self, dir: &str) -> Result<bool, LedgerError> {
        let found: Option<i64> = self
            .db
            .query_row(
                "SELECT 1 WHERE EXISTS (SELECT 1 FROM sources WHERE dir = ?1)
                           OR EXISTS (SELECT 1 FROM imported
                                       WHERE source_dir = ?1 AND state = 'unsorted')",
                params![dir],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    pub fn scanned(&self, dir: &str, at: i64) -> Result<(), LedgerError> {
        self.db.execute(
            "UPDATE sources SET scanned_at = ?2, last_error = NULL WHERE dir = ?1",
            params![dir, at],
        )?;
        Ok(())
    }

    /// What is wrong with this source, for the list to show. Cleared by a scan that finishes,
    /// so it is always the last thing that went wrong rather than the first.
    pub fn failed(&self, dir: &str, why: &str) -> Result<(), LedgerError> {
        self.db.execute(
            "UPDATE sources SET last_error = ?2 WHERE dir = ?1",
            params![dir, why],
        )?;
        Ok(())
    }

    pub fn remove_source(&mut self, dir: &str) -> Result<bool, LedgerError> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM import_refs WHERE source_dir = ?1",
            params![dir],
        )?;
        let gone = tx.execute("DELETE FROM sources WHERE dir = ?1", params![dir])?;
        tx.commit()?;
        Ok(gone > 0)
    }

    fn read_sources(
        &self,
        tail: &str,
        args: impl rusqlite::Params,
    ) -> Result<Vec<SourceRow>, LedgerError> {
        let mut stmt = self.db.prepare(&format!(
            "SELECT dir, name, source, config, added_at, scanned_at, last_error
               FROM sources {tail}"
        ))?;
        let rows = stmt.query_map(args, |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, Option<String>>(6)?,
            ))
        })?;

        let mut out = Vec::new();
        for row in rows {
            let (dir, name, source, config, added_at, scanned_at, last_error) = row?;
            out.push(SourceRow {
                dir,
                name,
                source,
                config: Fields::parse(&config)?,
                added_at,
                scanned_at,
                last_error,
            });
        }
        Ok(out)
    }

    pub fn settings(&self, source: &str) -> Result<Fields, LedgerError> {
        let mut stmt = self
            .db
            .prepare("SELECT key, value FROM source_settings WHERE source = ?1 ORDER BY key")?;
        let rows = stmt.query_map(params![source], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;

        let mut fields = Fields::new();
        for row in rows {
            let (key, value) = row?;
            fields.push(&key, &value);
        }
        Ok(fields)
    }

    pub fn set_setting(&self, source: &str, key: &str, value: &str) -> Result<(), LedgerError> {
        self.db.execute(
            "INSERT INTO source_settings (source, key, value) VALUES (?1, ?2, ?3)
             ON CONFLICT (source, key) DO UPDATE SET value = excluded.value",
            params![source, key, value],
        )?;
        Ok(())
    }

    pub fn known_refs(
        &self,
        source_dir: &str,
        refs: &[&str],
    ) -> Result<Vec<(String, i64)>, LedgerError> {
        let mut out = Vec::new();
        for chunk in refs.chunks(REFS_PER_QUERY) {
            let holes = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(",");
            let mut stmt = self.db.prepare(&format!(
                "SELECT source_ref, fails FROM import_refs
                  WHERE source_dir = ?1 AND source_ref IN ({holes})"
            ))?;

            let args = std::iter::once(Value::from(source_dir.to_owned()))
                .chain(chunk.iter().map(|r| Value::from((*r).to_owned())));
            let rows = stmt.query_map(params_from_iter(args), |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            for row in rows {
                out.push(row?);
            }
        }
        Ok(out)
    }

    pub fn owe(&self, source_dir: &str, item: &Item) -> Result<(), LedgerError> {
        self.db.execute(
            "INSERT INTO import_refs (source_dir, source_ref, folder, name, size, algo, checksum)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT (source_dir, source_ref) DO UPDATE
                 SET folder = excluded.folder, name = excluded.name, size = excluded.size,
                     algo = excluded.algo, checksum = excluded.checksum",
            params![
                source_dir,
                item.reference,
                item.folder,
                item.name,
                item.size.map(|size| size as i64),
                item.checksum.as_ref().map(|sum| sum.algo.as_str()),
                item.checksum.as_ref().map(|sum| sum.value.as_str()),
            ],
        )?;
        Ok(())
    }

    pub fn offer_again(&self, source_dir: &str, refs: &[&str]) -> Result<usize, LedgerError> {
        let mut reset = 0;
        for source_ref in refs {
            reset += self.db.execute(
                "UPDATE import_refs SET fails = 0, tried_at = 0
                  WHERE source_dir = ?1 AND source_ref = ?2 AND hash IS NULL",
                params![source_dir, source_ref],
            )?;
        }
        Ok(reset)
    }

    pub fn retire_gone(&self, source_dir: &str) -> Result<usize, LedgerError> {
        Ok(self.db.execute(
            "DELETE FROM import_refs
              WHERE source_dir = ?1 AND hash IS NULL AND fails >= ?2",
            params![source_dir, MAX_FETCH_ATTEMPTS],
        )?)
    }

    /// Take up to `limit` owed references, counting the attempt in the same write.
    pub fn claim(&mut self, at: i64, limit: usize) -> Result<Vec<Owed>, LedgerError> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        let taken = {
            let mut stmt = tx.prepare(
                "SELECT source_dir, source_ref, folder, name, size, algo, checksum
                   FROM import_refs
                  WHERE hash IS NULL AND fails < ?1 AND tried_at < ?2
                  ORDER BY tried_at LIMIT ?3",
            )?;
            let rows = stmt.query_map(
                params![
                    MAX_FETCH_ATTEMPTS,
                    at.saturating_sub(FETCH_RETRY_DELAY),
                    limit as i64
                ],
                |row| {
                    Ok(Owed {
                        source_dir: row.get(0)?,
                        source_ref: row.get(1)?,
                        folder: row.get(2)?,
                        name: row.get(3)?,
                        size: row.get::<_, Option<i64>>(4)?.map(|size| size.max(0) as u64),
                        checksum: checksum(row.get(5)?, row.get(6)?),
                    })
                },
            )?;
            rows.collect::<Result<Vec<_>, _>>()?
        };

        for owed in &taken {
            tx.execute(
                "UPDATE import_refs SET tried_at = ?3, fails = fails + 1
                  WHERE source_dir = ?1 AND source_ref = ?2",
                params![owed.source_dir, owed.source_ref, at],
            )?;
        }
        tx.commit()?;
        Ok(taken)
    }

    pub fn settled(
        &self,
        source_dir: &str,
        source_ref: &str,
        hash: &str,
    ) -> Result<(), LedgerError> {
        self.db.execute(
            "UPDATE import_refs SET hash = ?3 WHERE source_dir = ?1 AND source_ref = ?2",
            params![source_dir, source_ref, hash],
        )?;
        Ok(())
    }

    /// Drop a reference the source has answered for by saying it is gone. The next scan
    /// writes it down again if it ever comes back.
    pub fn forget(&self, source_dir: &str, source_ref: &str) -> Result<bool, LedgerError> {
        let gone = self.db.execute(
            "DELETE FROM import_refs WHERE source_dir = ?1 AND source_ref = ?2 AND hash IS NULL",
            params![source_dir, source_ref],
        )?;
        Ok(gone > 0)
    }

    pub fn owed(&self, source_dir: &str) -> Result<u64, LedgerError> {
        let count: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM import_refs WHERE source_dir = ?1 AND hash IS NULL",
            params![source_dir],
            |row| row.get(0),
        )?;
        Ok(count.max(0) as u64)
    }

    pub fn seen(&self, hash: &str) -> Result<Option<State>, LedgerError> {
        let state: Option<String> = self
            .db
            .query_row(
                "SELECT state FROM imported WHERE hash = ?1",
                params![hash],
                |row| row.get(0),
            )
            .optional()?;
        match state {
            None => Ok(None),
            Some(raw) => State::parse(&raw).map(Some).ok_or(LedgerError::CorruptRow),
        }
    }

    /// Whether some other reference is already waiting under this name, in this folder, from
    /// this source. Only `unsorted` counts: a sorted file has been moved into its group and a
    /// dropped one is gone, so neither is still holding the name.
    pub fn name_taken(
        &self,
        source_dir: &str,
        folder: &str,
        name: &str,
        except: &str,
    ) -> Result<bool, LedgerError> {
        let found: Option<i64> = self
            .db
            .query_row(
                "SELECT 1 FROM imported
                  WHERE source_dir = ?1 AND folder = ?2 AND name = ?3 AND source_ref <> ?4
                    AND state = 'unsorted' LIMIT 1",
                params![source_dir, folder, name, except],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    pub fn keep(&self, row: &Imported) -> Result<(), LedgerError> {
        self.db.execute(
            "INSERT INTO imported
                 (hash, state, name, size, at, group_id,
                  source_dir, source_name, source_ref, folder)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                row.hash,
                row.state.as_str(),
                row.name,
                row.size as i64,
                row.at,
                row.group_id,
                row.source_dir,
                row.source_name,
                row.source_ref,
                row.folder,
            ],
        )?;
        Ok(())
    }

    /// Filed into a group. Only from `unsorted`, which is what keeps the state moving one way.
    pub fn sorted(&self, hash: &str, group: &str) -> Result<bool, LedgerError> {
        let moved = self.db.execute(
            "UPDATE imported SET state = 'sorted', group_id = ?2
              WHERE hash = ?1 AND state = 'unsorted'",
            params![hash, group],
        )?;
        Ok(moved > 0)
    }

    /// Thrown away, permanently. The row stays: it is the only thing that remembers we decided.
    pub fn dropped(&self, hash: &str) -> Result<bool, LedgerError> {
        let moved = self.db.execute(
            "UPDATE imported SET state = 'dropped', group_id = NULL
              WHERE hash = ?1 AND state = 'unsorted'",
            params![hash],
        )?;
        Ok(moved > 0)
    }

    pub fn unsorted(
        &self,
        after: Option<(i64, &str)>,
        len: usize,
    ) -> Result<Vec<Imported>, LedgerError> {
        let (at, hash) = after.unwrap_or((i64::MIN, ""));
        let mut stmt = self.db.prepare(
            "SELECT hash, state, name, size, at, group_id,
                    source_dir, source_name, source_ref, folder
               FROM imported
              WHERE state = 'unsorted' AND (at, hash) > (?1, ?2)
              ORDER BY at, hash LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![at, hash, len as i64], read_imported)?;
        collect(rows)
    }

    /// Everything that came from one source folder: what a bulk action counts and then acts on.
    pub fn in_folder(&self, source_dir: &str, folder: &str) -> Result<Vec<Imported>, LedgerError> {
        let mut stmt = self.db.prepare(
            "SELECT hash, state, name, size, at, group_id,
                    source_dir, source_name, source_ref, folder
               FROM imported
              WHERE source_dir = ?1 AND folder = ?2 AND state = 'unsorted'
              ORDER BY at, hash",
        )?;
        let rows = stmt.query_map(params![source_dir, folder], read_imported)?;
        collect(rows)
    }

    pub fn get(&self, hash: &str) -> Result<Option<Imported>, LedgerError> {
        let mut stmt = self.db.prepare(
            "SELECT hash, state, name, size, at, group_id,
                    source_dir, source_name, source_ref, folder
               FROM imported WHERE hash = ?1",
        )?;
        let rows = stmt.query_map(params![hash], read_imported)?;
        Ok(collect(rows)?.into_iter().next())
    }

    pub fn waiting(&self) -> Result<u64, LedgerError> {
        let count: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM imported WHERE state = 'unsorted'",
            [],
            |row| row.get(0),
        )?;
        Ok(count.max(0) as u64)
    }

    pub fn waiting_in(&self, source_dir: &str, folder: &str) -> Result<u64, LedgerError> {
        let count: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM imported
              WHERE source_dir = ?1 AND folder = ?2 AND state = 'unsorted'",
            params![source_dir, folder],
            |row| row.get(0),
        )?;
        Ok(count.max(0) as u64)
    }

    pub fn unsorted_bytes(&self) -> Result<u64, LedgerError> {
        let total: i64 = self.db.query_row(
            "SELECT COALESCE(SUM(size), 0) FROM imported WHERE state = 'unsorted'",
            [],
            |row| row.get(0),
        )?;
        Ok(total.max(0) as u64)
    }

    pub fn tallies(&self) -> Result<Vec<(String, Tally)>, LedgerError> {
        let mut stmt = self.db.prepare(
            "SELECT source_dir, state, COUNT(*) FROM imported GROUP BY source_dir, state",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;

        let mut out: Vec<(String, Tally)> = Vec::new();
        for row in rows {
            let (dir, state, count) = row?;
            let count = count.max(0) as u64;
            let tally = match out.iter_mut().find(|(seen, _)| *seen == dir) {
                Some((_, tally)) => tally,
                None => {
                    out.push((dir, Tally::default()));
                    let last = out.len() - 1;
                    &mut out[last].1
                }
            };
            match State::parse(&state) {
                Some(State::Unsorted) => tally.waiting = count,
                Some(State::Sorted) => tally.sorted = count,
                Some(State::Dropped) => tally.dropped = count,
                None => return Err(LedgerError::CorruptRow),
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }
}

/// The promise as it was stored. An algorithm this build no longer has is no promise at all:
/// there is nothing to check the bytes against, and refusing them would be worse.
fn checksum(algo: Option<String>, value: Option<String>) -> Option<Checksum> {
    let (algo, value) = (algo?, value?);
    Some(Checksum {
        algo: Digest::parse(&algo)?,
        value,
    })
}

fn read_imported(row: &rusqlite::Row<'_>) -> rusqlite::Result<Imported> {
    Ok(Imported {
        hash: row.get(0)?,
        // A guess rather than a check: nothing here writes a fourth state, so an unreadable
        // one came from outside this code. `seen` and `tallies` call the same thing corrupt.
        state: State::parse(&row.get::<_, String>(1)?).unwrap_or(State::Unsorted),
        name: row.get(2)?,
        size: row.get::<_, i64>(3)?.max(0) as u64,
        at: row.get(4)?,
        group_id: row.get(5)?,
        source_dir: row.get(6)?,
        source_name: row.get(7)?,
        source_ref: row.get(8)?,
        folder: row.get(9)?,
    })
}

fn collect<I>(rows: I) -> Result<Vec<Imported>, LedgerError>
where
    I: Iterator<Item = rusqlite::Result<Imported>>,
{
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error(transparent)]
    Db(#[from] rusqlite::Error),
    #[error("a stored row could not be read")]
    CorruptRow,
    #[error(transparent)]
    Config(#[from] SourceError),
}

#[cfg(test)]
mod tests {
    use super::*;

    const AT: i64 = 1_000_000;

    fn ledger() -> Ledger {
        Ledger::from_connection(Connection::open_in_memory().unwrap()).unwrap()
    }

    fn source(dir: &str, name: &str) -> SourceRow {
        let mut config = Fields::new();
        config.push("path", "/home/a/pictures");
        SourceRow {
            dir: dir.to_owned(),
            name: name.to_owned(),
            source: "folder".to_owned(),
            config,
            added_at: AT,
            scanned_at: 0,
            last_error: None,
        }
    }

    fn item(reference: &str) -> Item {
        let (folder, name) = reference.rsplit_once('/').unwrap_or(("", reference));
        Item {
            reference: reference.to_owned(),
            folder: folder.to_owned(),
            name: name.to_owned(),
            size: Some(10),
            checksum: None,
        }
    }

    fn imported(hash: &str, dir: &str, at: i64) -> Imported {
        Imported {
            hash: hash.to_owned(),
            state: State::Unsorted,
            name: format!("{hash}.jpg"),
            size: 100,
            at,
            group_id: None,
            source_dir: dir.to_owned(),
            source_name: "Pictures".to_owned(),
            source_ref: format!("DCIM/{hash}.jpg"),
            folder: "DCIM".to_owned(),
        }
    }

    #[test]
    fn a_source_comes_back_as_it_went_in() {
        let ledger = ledger();
        ledger.add_source(&source("pictures", "Pictures")).unwrap();

        let back = ledger.source("pictures").unwrap().unwrap();
        assert_eq!(back, source("pictures", "Pictures"));
        assert_eq!(back.config.get("path"), Some("/home/a/pictures"));
        assert_eq!(ledger.source_named("Pictures").unwrap(), Some(back));
        assert_eq!(ledger.source("nothing").unwrap(), None);
    }

    #[test]
    fn a_finished_scan_clears_the_error_the_last_one_left() {
        let ledger = ledger();
        ledger.add_source(&source("pictures", "Pictures")).unwrap();

        ledger.failed("pictures", "the disk went away").unwrap();
        assert!(
            ledger
                .source("pictures")
                .unwrap()
                .unwrap()
                .last_error
                .is_some()
        );

        ledger.scanned("pictures", AT).unwrap();
        let row = ledger.source("pictures").unwrap().unwrap();
        assert_eq!(row.scanned_at, AT);
        assert_eq!(row.last_error, None);
    }

    #[test]
    fn removing_a_source_takes_its_queue_and_leaves_its_files() {
        let mut ledger = ledger();
        ledger.add_source(&source("pictures", "Pictures")).unwrap();
        ledger.owe("pictures", &item("DCIM/a.jpg")).unwrap();
        ledger.keep(&imported("aa", "pictures", AT)).unwrap();

        assert!(ledger.remove_source("pictures").unwrap());
        assert_eq!(ledger.source("pictures").unwrap(), None);
        assert_eq!(ledger.owed("pictures").unwrap(), 0, "nothing is owed now");

        // What was downloaded is still here, still unsorted, still knowing where it came from.
        let still = ledger.get("aa").unwrap().unwrap();
        assert_eq!(still.state, State::Unsorted);
        assert_eq!(still.source_name, "Pictures");
        assert_eq!(ledger.waiting().unwrap(), 1);
    }

    #[test]
    fn a_directory_stays_taken_while_unsorted_files_live_in_it() {
        let mut ledger = ledger();
        ledger.add_source(&source("pictures", "Pictures")).unwrap();
        ledger.keep(&imported("aa", "pictures", AT)).unwrap();
        ledger.remove_source("pictures").unwrap();

        assert!(
            ledger.dir_taken("pictures").unwrap(),
            "re-adding must not land on top of files that are still there"
        );

        ledger.dropped("aa").unwrap();
        assert!(
            !ledger.dir_taken("pictures").unwrap(),
            "the name frees itself once the last file is sorted or dropped"
        );
    }

    #[test]
    fn settings_outlive_every_source_that_ever_used_them() {
        let mut ledger = ledger();
        // Set before any source of that implementation exists, which is how it actually goes.
        ledger.set_setting("drive", "client_id", "abc").unwrap();
        ledger.set_setting("drive", "client_secret", "shh").unwrap();

        ledger.add_source(&source("work", "Work")).unwrap();
        ledger.remove_source("work").unwrap();

        let settings = ledger.settings("drive").unwrap();
        assert_eq!(settings.get("client_id"), Some("abc"));
        assert_eq!(settings.get("client_secret"), Some("shh"));
        assert!(ledger.settings("folder").unwrap().is_empty());
    }

    #[test]
    fn a_setting_is_replaced_rather_than_repeated() {
        let ledger = ledger();
        ledger.set_setting("drive", "client_id", "first").unwrap();
        ledger.set_setting("drive", "client_id", "second").unwrap();

        let settings = ledger.settings("drive").unwrap();
        assert_eq!(settings.all("client_id").count(), 1);
        assert_eq!(settings.get("client_id"), Some("second"));
    }

    #[test]
    fn a_scan_asks_once_which_of_a_page_it_already_knows() {
        let ledger = ledger();
        ledger.owe("pictures", &item("a.jpg")).unwrap();
        ledger.owe("pictures", &item("b.jpg")).unwrap();
        ledger.owe("other", &item("c.jpg")).unwrap();

        let known = ledger
            .known_refs("pictures", &["a.jpg", "b.jpg", "c.jpg", "d.jpg"])
            .unwrap();
        let mut names: Vec<&str> = known.iter().map(|(r, _)| r.as_str()).collect();
        names.sort_unstable();

        assert_eq!(
            names,
            ["a.jpg", "b.jpg"],
            "another source's rows are not ours"
        );
        assert!(known.iter().all(|(_, fails)| *fails == 0));
    }

    #[test]
    fn the_queue_is_read_through_its_index_rather_than_by_reading_it_all() {
        let ledger = ledger();
        let plan: String = ledger
            .db
            .query_row(
                "EXPLAIN QUERY PLAN
                 SELECT source_dir, source_ref, folder, name, size FROM import_refs
                  WHERE hash IS NULL AND fails < 3 AND tried_at < 0
                  ORDER BY tried_at LIMIT 8",
                [],
                |row| row.get(3),
            )
            .unwrap();

        assert!(plan.contains("import_refs_owed"), "{plan}");
        assert!(!plan.contains("SCAN import_refs"), "{plan}");
    }

    #[test]
    fn two_claims_never_take_the_same_row() {
        let mut ledger = ledger();
        for reference in ["a.jpg", "b.jpg", "c.jpg", "d.jpg"] {
            ledger.owe("pictures", &item(reference)).unwrap();
        }

        let first = ledger.claim(AT, 2).unwrap();
        let second = ledger.claim(AT, 2).unwrap();
        assert_eq!(first.len(), 2);
        assert_eq!(second.len(), 2);
        for taken in &first {
            assert!(
                !second
                    .iter()
                    .any(|other| other.source_ref == taken.source_ref),
                "{taken:?} was claimed twice"
            );
        }
        assert!(ledger.claim(AT, 2).unwrap().is_empty(), "all four are out");
    }

    #[test]
    fn an_abandoned_claim_comes_back_by_itself() {
        let mut ledger = ledger();
        ledger.owe("pictures", &item("a.jpg")).unwrap();

        let taken = ledger.claim(AT, 8).unwrap();
        assert_eq!(taken.len(), 1);
        assert!(
            ledger
                .claim(AT + FETCH_RETRY_DELAY - 1, 8)
                .unwrap()
                .is_empty()
        );

        // Nothing was cleaned up at startup: the lease simply expired.
        let again = ledger.claim(AT + FETCH_RETRY_DELAY + 1, 8).unwrap();
        assert_eq!(again, taken);
    }

    #[test]
    fn a_row_out_of_attempts_waits_for_a_scan_to_offer_it_again() {
        let mut ledger = ledger();
        ledger.owe("pictures", &item("a.jpg")).unwrap();

        let mut at = AT;
        for _ in 0..MAX_FETCH_ATTEMPTS {
            assert_eq!(ledger.claim(at, 8).unwrap().len(), 1);
            at += FETCH_RETRY_DELAY + 1;
        }
        assert!(
            ledger.claim(at, 8).unwrap().is_empty(),
            "an unreadable file must not spin the pump"
        );

        assert_eq!(ledger.offer_again("pictures", &["a.jpg"]).unwrap(), 1);
        assert_eq!(ledger.claim(at, 8).unwrap().len(), 1, "a scan resets it");
    }

    #[test]
    fn retiring_takes_only_what_is_exhausted_and_still_owed() {
        let mut ledger = ledger();
        ledger.owe("pictures", &item("gone.jpg")).unwrap();
        ledger.owe("pictures", &item("fresh.jpg")).unwrap();
        ledger.owe("pictures", &item("done.jpg")).unwrap();
        ledger.settled("pictures", "done.jpg", "aa").unwrap();

        let mut at = AT;
        for _ in 0..MAX_FETCH_ATTEMPTS {
            for taken in ledger.claim(at, 8).unwrap() {
                // Only `gone.jpg` keeps failing; the other is settled the first time round.
                if taken.source_ref == "fresh.jpg" {
                    ledger.settled("pictures", "fresh.jpg", "bb").unwrap();
                }
            }
            at += FETCH_RETRY_DELAY + 1;
        }

        assert_eq!(ledger.retire_gone("pictures").unwrap(), 1);
        assert_eq!(ledger.owed("pictures").unwrap(), 0);
        assert_eq!(
            ledger
                .known_refs("pictures", &["fresh.jpg", "done.jpg"])
                .unwrap()
                .len(),
            2,
            "a settled row is history and is not retired"
        );
    }

    #[test]
    fn a_promise_about_the_bytes_survives_until_something_fetches_them() {
        let mut ledger = ledger();
        let mut promised = item("a.jpg");
        promised.checksum = Some(Checksum {
            algo: Digest::Md5,
            value: "5d41402abc4b2a76b9719d911017c592".to_owned(),
        });
        ledger.owe("pictures", &promised).unwrap();
        ledger.owe("pictures", &item("b.jpg")).unwrap();

        let taken = ledger.claim(AT, 8).unwrap();
        let checked = |reference: &str| {
            taken
                .iter()
                .find(|owed| owed.source_ref == reference)
                .unwrap()
                .clone()
        };

        // What comes back out is what `fetch` is handed, promise and all.
        assert_eq!(checked("a.jpg").item(), promised);
        assert_eq!(checked("b.jpg").checksum, None, "most sources promise none");
    }

    #[test]
    fn a_reference_the_source_says_is_gone_stops_being_owed_at_once() {
        let ledger = ledger();
        ledger.owe("pictures", &item("gone.jpg")).unwrap();
        ledger.owe("pictures", &item("here.jpg")).unwrap();
        ledger.settled("pictures", "here.jpg", "aa").unwrap();

        assert!(ledger.forget("pictures", "gone.jpg").unwrap());
        assert_eq!(ledger.owed("pictures").unwrap(), 0);

        assert!(!ledger.forget("pictures", "never.jpg").unwrap());
        assert!(!ledger.forget("pictures", "here.jpg").unwrap());
        assert_eq!(
            ledger.known_refs("pictures", &["here.jpg"]).unwrap().len(),
            1
        );
    }

    #[test]
    fn a_name_is_taken_by_the_reference_that_is_still_waiting_under_it() {
        let ledger = ledger();
        let mut row = imported("aa", "pictures", AT);
        row.folder = "DCIM".to_owned();
        row.name = "IMG_1.jpg".to_owned();
        row.source_ref = "DCIM/IMG_1.jpg".to_owned();
        ledger.keep(&row).unwrap();

        let taken = |reference: &str| {
            ledger
                .name_taken("pictures", "DCIM", "IMG_1.jpg", reference)
                .unwrap()
        };
        assert!(taken("other-id"), "someone else is waiting under that name");
        assert!(
            !taken("DCIM/IMG_1.jpg"),
            "but it does not take it from itself"
        );
        assert!(
            !ledger.name_taken("pictures", "", "IMG_1.jpg", "x").unwrap(),
            "the same name in another folder is a different name"
        );

        // Sorted into a group, the file left `.unsorted`, so the name is free again.
        assert!(ledger.sorted("aa", "g").unwrap());
        assert!(!taken("other-id"));
    }

    #[test]
    fn settling_takes_a_reference_off_the_queue_for_good() {
        let mut ledger = ledger();
        ledger.owe("pictures", &item("a.jpg")).unwrap();
        ledger.settled("pictures", "a.jpg", "aa").unwrap();

        assert_eq!(ledger.owed("pictures").unwrap(), 0);
        assert!(
            ledger
                .claim(AT + FETCH_RETRY_DELAY * 10, 8)
                .unwrap()
                .is_empty()
        );
        // Re-offering it in a later scan changes nothing: the fetch already happened.
        assert_eq!(ledger.offer_again("pictures", &["a.jpg"]).unwrap(), 0);
    }

    #[test]
    fn what_became_of_a_file_only_ever_moves_forward() {
        let ledger = ledger();
        ledger.keep(&imported("aa", "pictures", AT)).unwrap();
        ledger.keep(&imported("bb", "pictures", AT)).unwrap();

        assert!(ledger.sorted("aa", "group-1").unwrap());
        assert!(!ledger.sorted("aa", "group-2").unwrap(), "already filed");
        assert!(
            !ledger.dropped("aa").unwrap(),
            "a sorted file is not droppable"
        );
        assert_eq!(ledger.seen("aa").unwrap(), Some(State::Sorted));

        assert!(ledger.dropped("bb").unwrap());
        assert!(
            !ledger.sorted("bb", "group-1").unwrap(),
            "you threw it away"
        );
        assert_eq!(ledger.seen("bb").unwrap(), Some(State::Dropped));
        assert_eq!(ledger.seen("cc").unwrap(), None);
    }

    #[test]
    fn a_page_of_the_backlog_reads_the_same_however_long_it_is() {
        let ledger = ledger();
        // Every row at the same instant, which a fast local import really does produce: if the
        // page resumed on `at` alone it would step over the rest of the second.
        for n in 0..20 {
            ledger
                .keep(&imported(&format!("{n:02}"), "pictures", AT))
                .unwrap();
        }
        ledger.keep(&imported("zz", "pictures", AT + 1)).unwrap();

        let all: Vec<String> = ledger
            .unsorted(None, 100)
            .unwrap()
            .into_iter()
            .map(|row| row.hash)
            .collect();
        assert_eq!(all.len(), 21);

        let mut paged: Vec<String> = Vec::new();
        let mut after: Option<(i64, String)> = None;
        loop {
            let resume = after.as_ref().map(|(at, hash)| (*at, hash.as_str()));
            let page = ledger.unsorted(resume, 3).unwrap();
            if page.is_empty() {
                break;
            }
            after = page.last().map(|row| (row.at, row.hash.clone()));
            paged.extend(page.into_iter().map(|row| row.hash));
        }
        assert_eq!(paged, all, "paging lost or repeated something");
    }

    #[test]
    fn a_bulk_action_sees_one_source_folder_and_only_what_is_waiting() {
        let ledger = ledger();
        for n in 0..3 {
            ledger
                .keep(&imported(&format!("a{n}"), "pictures", AT))
                .unwrap();
        }
        let mut elsewhere = imported("bb", "pictures", AT);
        elsewhere.folder = "DCIM/2024-07".to_owned();
        ledger.keep(&elsewhere).unwrap();
        ledger.keep(&imported("cc", "other", AT)).unwrap();
        ledger.sorted("a0", "group-1").unwrap();

        assert_eq!(ledger.waiting_in("pictures", "DCIM").unwrap(), 2);
        let acting_on = ledger.in_folder("pictures", "DCIM").unwrap();
        assert_eq!(acting_on.len(), 2);
        assert!(acting_on.iter().all(|row| row.state == State::Unsorted));
    }

    #[test]
    fn the_storage_budget_counts_what_is_waiting_and_nothing_else() {
        let ledger = ledger();
        ledger.keep(&imported("aa", "pictures", AT)).unwrap();
        ledger.keep(&imported("bb", "pictures", AT)).unwrap();
        assert_eq!(ledger.unsorted_bytes().unwrap(), 200);

        // Sorting moves the bytes into a group, where `files.held_bytes()` counts them, and
        // dropping deletes them. Either way they stop being ours to count.
        ledger.sorted("aa", "group-1").unwrap();
        ledger.dropped("bb").unwrap();
        assert_eq!(ledger.unsorted_bytes().unwrap(), 0);
    }

    #[test]
    fn a_tally_splits_a_sources_whole_life_three_ways() {
        let ledger = ledger();
        for n in 0..4 {
            ledger
                .keep(&imported(&format!("a{n}"), "pictures", AT))
                .unwrap();
        }
        ledger.keep(&imported("bb", "other", AT)).unwrap();
        ledger.sorted("a0", "group-1").unwrap();
        ledger.sorted("a1", "group-1").unwrap();
        ledger.dropped("a2").unwrap();

        let tallies = ledger.tallies().unwrap();
        assert_eq!(
            tallies,
            vec![
                (
                    "other".to_owned(),
                    Tally {
                        waiting: 1,
                        sorted: 0,
                        dropped: 0
                    }
                ),
                (
                    "pictures".to_owned(),
                    Tally {
                        waiting: 1,
                        sorted: 2,
                        dropped: 1
                    }
                ),
            ]
        );
    }

    #[test]
    fn a_one_shot_source_is_never_due_and_a_backoff_holds_the_rest() {
        assert!(
            !due(SourceType::OneShot, 0, 0, AT),
            "one-shot runs when asked"
        );

        assert!(due(SourceType::Remote, 0, 0, AT));
        assert!(!due(SourceType::Remote, AT, 0, AT + SCAN_INTERVAL - 1));
        assert!(due(SourceType::Remote, AT, 0, AT + SCAN_INTERVAL));

        // A backoff can only ever hold a source back, never bring it forward.
        assert!(!due(
            SourceType::Intermittent,
            AT,
            SCAN_INTERVAL * 2,
            AT + SCAN_INTERVAL
        ));
        assert!(due(
            SourceType::Intermittent,
            AT,
            SCAN_INTERVAL / 2,
            AT + SCAN_INTERVAL
        ));
    }

    #[test]
    fn an_interrupted_scan_leaves_its_source_overdue() {
        let ledger = ledger();
        let mut row = source("pictures", "Pictures");
        row.scanned_at = AT;
        ledger.add_source(&row).unwrap();

        // The scan is cut short, so `scanned` is never called and the stamp does not move.
        ledger.failed("pictures", "the process went away").unwrap();

        let back = ledger.source("pictures").unwrap().unwrap();
        assert!(due(
            SourceType::Remote,
            back.scanned_at,
            0,
            AT + SCAN_INTERVAL
        ));
    }
}
