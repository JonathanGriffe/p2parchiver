//! What the running daemon is waiting on, published so another process can read it.
//!
//! # Why this exists at all
//!
//! Everything else `ac` reports is a fact in the database: what files exist, who is in a group,
//! who this node has met. The supervisor's reasons are not. A dial that is not happening is
//! being *not done* because of a backoff that has not expired, a member believed offline, or a
//! content pull suspended after a rotation in which nobody could help — and every one of those
//! lives in memory in a process the CLI cannot see.
//!
//! So the daemon writes a snapshot on each housekeeping tick and `ac peer status` reads it.
//! SQLite is the channel because it already is: `ac file add` in one process reaches a running
//! daemon the same way, and adding a second mechanism for one command would be worse than the
//! staleness this accepts.
//!
//! # It is a snapshot, and says so
//!
//! [`Snapshot::at`] is when the daemon last wrote. A reader that finds it minutes old is
//! looking at a stopped daemon, and that is by far the commonest answer to "why is it not doing
//! anything" — so it is reported first and never silently.
//!
//! Nothing reads this back into the supervisor. It is a diagnostic, and a corrupt or absent
//! snapshot costs a person one confusing command rather than a node that behaves differently.

use std::path::Path;

use std::str::FromStr;

use ac_groups::id::GroupId;
use ac_net::PeerId;
use ac_peers::sync::{GroupStatus, PeerStatus, Status};
use rusqlite::{Connection, OptionalExtension, params};

/// A snapshot, plus when it was taken.
pub struct Snapshot {
    /// Unix seconds. `None` when the daemon has never written one.
    pub at: Option<i64>,
    pub groups: Vec<GroupStatus>,
    pub peers: Vec<PeerStatus>,
}

/// The published view of the supervisor, backed by SQLite.
pub struct Published {
    db: Connection,
}

impl Published {
    pub fn open(path: &Path) -> Result<Self, rusqlite::Error> {
        let db = Connection::open(path)?;
        // The same pragmas every other store here opens with: several processes write this
        // file, so WAL and a busy timeout are not optional.
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "foreign_keys", "ON")?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;

        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS supervisor_at (
                 id INTEGER PRIMARY KEY CHECK (id = 0),
                 at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS supervisor_groups (
                 group_id         TEXT PRIMARY KEY,
                 missing          INTEGER NOT NULL,
                 owed          INTEGER NOT NULL,
                 next_peer        TEXT,
                 source           TEXT,
                 content_until    INTEGER NOT NULL,
                 heartbeat_at     INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS supervisor_peers (
                 peer      TEXT PRIMARY KEY,
                 connected INTEGER NOT NULL,
                 online    INTEGER NOT NULL,
                 retry_at  INTEGER NOT NULL,
                 rounds    INTEGER NOT NULL,
                 transfers INTEGER NOT NULL,
                 closing   INTEGER NOT NULL
             );",
        )?;
        Ok(Self { db })
    }

    /// Replace the snapshot wholesale.
    ///
    /// One transaction, and a delete before every insert: a group we have left or a member who
    /// was removed must vanish from the report rather than linger as a row nothing updates.
    /// `BEGIN IMMEDIATE` because a reader in another process may be mid-query.
    pub fn publish(&mut self, status: &Status, at: i64) -> Result<(), rusqlite::Error> {
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        tx.execute("DELETE FROM supervisor_groups", [])?;
        tx.execute("DELETE FROM supervisor_peers", [])?;

        for group in &status.groups {
            tx.execute(
                "INSERT INTO supervisor_groups
                     (group_id, missing, owed, next_peer, source,
                      content_until, heartbeat_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    group.group.to_string(),
                    group.missing as i64,
                    group.owed as i64,
                    group.next.map(|p| p.to_base58()),
                    group.source.map(|p| p.to_base58()),
                    group.content_until,
                    group.heartbeat_at,
                ],
            )?;
        }

        for peer in &status.peers {
            tx.execute(
                "INSERT INTO supervisor_peers
                     (peer, connected, online, retry_at, rounds, transfers, closing)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    peer.peer.to_base58(),
                    peer.connected,
                    peer.online,
                    peer.retry_at,
                    peer.rounds as i64,
                    peer.transfers as i64,
                    peer.closing,
                ],
            )?;
        }

        tx.execute(
            "INSERT INTO supervisor_at (id, at) VALUES (0, ?1)
             ON CONFLICT(id) DO UPDATE SET at = excluded.at",
            params![at],
        )?;
        tx.commit()
    }

    /// Whatever the daemon last published, or an empty snapshot if it never has.
    ///
    /// A row that will not parse is dropped rather than failing the command: this is a
    /// diagnostic, and refusing to print anything because one peer id is malformed would be
    /// exactly the wrong trade.
    pub fn read(&self) -> Result<Snapshot, rusqlite::Error> {
        let at: Option<i64> = self
            .db
            .query_row("SELECT at FROM supervisor_at WHERE id = 0", [], |r| {
                r.get(0)
            })
            .optional()?;

        let mut groups = self.db.prepare(
            "SELECT group_id, missing, owed, next_peer, source,
                    content_until, heartbeat_at
             FROM supervisor_groups ORDER BY group_id",
        )?;
        let groups = groups
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, u32>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            })?
            .filter_map(|row| {
                let (id, missing, owed, next, source, content_until, heartbeat_at) = row.ok()?;
                Some(GroupStatus {
                    group: GroupId::from_str(&id).ok()?,
                    // SQLite has one integer type and it is signed, so the counts round-trip
                    // through `i64`. A negative one is a corrupt row, not a small number.
                    missing: u64::try_from(missing).ok()?,
                    owed: usize::try_from(owed).ok()?,
                    next: next.and_then(|p| p.parse().ok()),
                    source: source.and_then(|p| p.parse().ok()),
                    content_until,
                    heartbeat_at,
                })
            })
            .collect();

        let mut peers = self.db.prepare(
            "SELECT peer, connected, online, retry_at, rounds, transfers, closing
             FROM supervisor_peers ORDER BY peer",
        )?;
        let peers = peers
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, bool>(1)?,
                    row.get::<_, bool>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, bool>(6)?,
                ))
            })?
            .filter_map(|row| {
                let (peer, connected, online, retry_at, rounds, transfers, closing) = row.ok()?;
                Some(PeerStatus {
                    peer: peer.parse::<PeerId>().ok()?,
                    connected,
                    online,
                    retry_at,
                    rounds: usize::try_from(rounds).ok()?,
                    transfers: usize::try_from(transfers).ok()?,
                    closing,
                })
            })
            .collect();

        Ok(Snapshot { at, groups, peers })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> PeerId {
        libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id()
    }

    fn published() -> (Published, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite");
        (Published::open(&path).unwrap(), dir)
    }

    fn sample(group: GroupId, next: PeerId) -> Status {
        Status {
            groups: vec![GroupStatus {
                group,
                missing: 7,
                owed: 2,
                next: Some(next),
                source: None,
                content_until: 1_000_030,
                heartbeat_at: 1_014_400,
            }],
            peers: vec![PeerStatus {
                peer: next,
                connected: false,
                online: true,
                retry_at: 1_000_060,
                rounds: 0,
                transfers: 0,
                closing: false,
            }],
        }
    }

    #[test]
    fn nothing_published_yet_is_not_an_error() {
        // The state a person hits first: they installed this, ran the CLI, and no daemon has
        // ever started. Reporting "no snapshot" is the answer; failing to open is not.
        let (store, _dir) = published();
        let snapshot = store.read().unwrap();

        assert_eq!(snapshot.at, None);
        assert!(snapshot.groups.is_empty());
        assert!(snapshot.peers.is_empty());
    }

    #[test]
    fn a_snapshot_survives_a_separate_connection() {
        // The whole point: the writer is the daemon and the reader is a different process.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite");
        let group = GroupId::from_bytes([3u8; 32]);
        let member = peer();

        let mut writer = Published::open(&path).unwrap();
        writer.publish(&sample(group, member), 1_000_000).unwrap();

        let reader = Published::open(&path).unwrap();
        let snapshot = reader.read().unwrap();

        assert_eq!(snapshot.at, Some(1_000_000));
        assert_eq!(snapshot.groups.len(), 1);
        assert_eq!(snapshot.groups[0].missing, 7);
        assert_eq!(snapshot.groups[0].next, Some(member));
        assert_eq!(snapshot.peers.len(), 1);
        assert!(snapshot.peers[0].online);
        assert!(!snapshot.peers[0].connected);
    }

    #[test]
    fn a_group_that_is_gone_does_not_linger() {
        // Written wholesale rather than upserted, so leaving a group removes it from the
        // report. An accumulating snapshot would show work outstanding for a group this node
        // is no longer in, which is precisely the confusion the command exists to prevent.
        let (mut store, _dir) = published();
        let member = peer();
        store
            .publish(&sample(GroupId::from_bytes([3u8; 32]), member), 1_000_000)
            .unwrap();
        store
            .publish(
                &Status {
                    groups: Vec::new(),
                    peers: Vec::new(),
                },
                1_000_005,
            )
            .unwrap();

        let snapshot = store.read().unwrap();
        assert_eq!(snapshot.at, Some(1_000_005), "and the clock moved on");
        assert!(snapshot.groups.is_empty());
        assert!(snapshot.peers.is_empty());
    }
}
