use std::path::Path;

use std::str::FromStr;

use ac_groups::id::GroupId;
use ac_net::PeerId;
use ac_peers::sync::{GroupStatus, PeerStatus, Status};
use rusqlite::{Connection, OptionalExtension, params};

pub struct Snapshot {
    pub at: Option<i64>,
    pub groups: Vec<GroupStatus>,
    pub peers: Vec<PeerStatus>,
    pub bandwidth: Bandwidth,
}

/// Content bytes this node has moved, and how fast it moved them over the last tick.
///
/// Blob payload only. Manifests, attestation, discovery and the transport's own framing all
/// travel beside this and none of it is counted, so these are the bytes of files transferred,
/// not the bytes put on the wire.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Bandwidth {
    /// Totals since the node started. A restart puts them back to zero.
    pub down: u64,
    pub up: u64,
    /// Bytes a second, measured across the gap between the last two publishes.
    pub down_rate: u64,
    pub up_rate: u64,
}

pub struct Published {
    db: Connection,
}

impl Published {
    pub fn open(path: &Path) -> Result<Self, rusqlite::Error> {
        let db = Connection::open(path)?;
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "foreign_keys", "ON")?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;

        // `CREATE TABLE IF NOT EXISTS` leaves a table that predates a column exactly as it
        // found it, and every write would then fail against a shape nothing here expects. The
        // snapshot is derived state, rewritten every tick, so the old one is thrown away
        // rather than migrated: the cost is one stale reading, and it is paid once.
        let mut shape = db.prepare("SELECT name FROM pragma_table_info('supervisor_at')")?;
        let columns: Vec<String> = shape
            .query_map([], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        drop(shape);
        if !columns.is_empty() && !columns.iter().any(|name| name == "down") {
            db.execute_batch("DROP TABLE supervisor_at")?;
        }

        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS supervisor_at (
                 id INTEGER PRIMARY KEY CHECK (id = 0),
                 at INTEGER NOT NULL,
                 down      INTEGER NOT NULL,
                 up        INTEGER NOT NULL,
                 down_rate INTEGER NOT NULL,
                 up_rate   INTEGER NOT NULL
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
    pub fn publish(
        &mut self,
        status: &Status,
        at: i64,
        bandwidth: &Bandwidth,
    ) -> Result<(), rusqlite::Error> {
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
            "INSERT INTO supervisor_at (id, at, down, up, down_rate, up_rate)
                 VALUES (0, ?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET
                 at        = excluded.at,
                 down      = excluded.down,
                 up        = excluded.up,
                 down_rate = excluded.down_rate,
                 up_rate   = excluded.up_rate",
            params![
                at,
                bandwidth.down as i64,
                bandwidth.up as i64,
                bandwidth.down_rate as i64,
                bandwidth.up_rate as i64,
            ],
        )?;
        tx.commit()
    }

    /// Whatever the daemon last published, or an empty snapshot if it never has.
    pub fn read(&self) -> Result<Snapshot, rusqlite::Error> {
        let published: Option<(i64, i64, i64, i64, i64)> = self
            .db
            .query_row(
                "SELECT at, down, up, down_rate, up_rate FROM supervisor_at WHERE id = 0",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?;

        let at = published.map(|row| row.0);
        // SQLite has one integer type and it is signed, so the counters round-trip through
        // `i64`. A negative one is a corrupt row, not a small number.
        let bandwidth = published
            .map(|(_, down, up, down_rate, up_rate)| Bandwidth {
                down: u64::try_from(down).unwrap_or(0),
                up: u64::try_from(up).unwrap_or(0),
                down_rate: u64::try_from(down_rate).unwrap_or(0),
                up_rate: u64::try_from(up_rate).unwrap_or(0),
            })
            .unwrap_or_default();

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

        Ok(Snapshot {
            at,
            groups,
            peers,
            bandwidth,
        })
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
        writer
            .publish(&sample(group, member), 1_000_000, &Bandwidth::default())
            .unwrap();

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
    fn the_bandwidth_counters_cross_the_process_boundary_intact() {
        let (mut store, _dir) = published();
        let moved = Bandwidth {
            // Past what an i32 holds, since a long-lived node will be.
            down: 9_000_000_000,
            up: 12,
            down_rate: 1024,
            up_rate: 0,
        };
        store
            .publish(&sample(GroupId::from_bytes([3u8; 32]), peer()), 1, &moved)
            .unwrap();

        assert_eq!(store.read().unwrap().bandwidth, moved);
    }

    /// A home written before the bandwidth columns existed. Without the discard in `open`,
    /// every publish against it fails and the Status page silently freezes.
    #[test]
    fn a_snapshot_table_from_before_the_counters_is_thrown_away_not_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite");

        let old = Connection::open(&path).unwrap();
        old.execute_batch(
            "CREATE TABLE supervisor_at (
                 id INTEGER PRIMARY KEY CHECK (id = 0),
                 at INTEGER NOT NULL
             );
             INSERT INTO supervisor_at (id, at) VALUES (0, 42);",
        )
        .unwrap();
        drop(old);

        let mut store = Published::open(&path).unwrap();
        store
            .publish(
                &sample(GroupId::from_bytes([3u8; 32]), peer()),
                99,
                &Bandwidth::default(),
            )
            .unwrap();

        let snapshot = store.read().unwrap();
        assert_eq!(snapshot.at, Some(99), "the new snapshot took hold");
        assert_eq!(snapshot.bandwidth, Bandwidth::default());
    }

    #[test]
    fn a_node_that_has_never_published_reports_no_traffic_rather_than_failing() {
        let (store, _dir) = published();

        assert_eq!(store.read().unwrap().bandwidth, Bandwidth::default());
    }

    #[test]
    fn a_group_that_is_gone_does_not_linger() {
        // Written wholesale rather than upserted, so leaving a group removes it from the
        // report. An accumulating snapshot would show work outstanding for a group this node
        // is no longer in, which is precisely the confusion the command exists to prevent.
        let (mut store, _dir) = published();
        let member = peer();
        store
            .publish(
                &sample(GroupId::from_bytes([3u8; 32]), member),
                1_000_000,
                &Bandwidth::default(),
            )
            .unwrap();
        store
            .publish(
                &Status {
                    groups: Vec::new(),
                    peers: Vec::new(),
                },
                1_000_005,
                &Bandwidth::default(),
            )
            .unwrap();

        let snapshot = store.read().unwrap();
        assert_eq!(snapshot.at, Some(1_000_005), "and the clock moved on");
        assert!(snapshot.groups.is_empty());
        assert!(snapshot.peers.is_empty());
    }
}
