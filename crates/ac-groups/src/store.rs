use std::path::Path;
use std::time::Duration;

use ac_net::PeerId;
use ac_net::identity::Keypair;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::chain::{Chain, ChainError, Entry, Op};
use crate::id::{EntryHash, GroupId};
use crate::members::Members;
use crate::standing::{Position, Standing, StandingError, StandingSet};
use crate::wire::GroupHead;

/// How long to wait for another process's write lock before giving up.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// This node's consent for one group. Written only by us
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Pending,
    Active,
    Left,
}

impl State {
    fn as_str(self) -> &'static str {
        match self {
            State::Pending => "pending",
            State::Active => "active",
            State::Left => "left",
        }
    }

    fn parse(raw: &str) -> Self {
        match raw {
            "active" => State::Active,
            "left" => State::Left,
            _ => State::Pending,
        }
    }
}

/// What this node holds about one group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRow {
    pub id: GroupId,
    pub name: String,
    pub admin: PeerId,
    pub state: State,
    pub head_seq: u64,
    pub head_hash: EntryHash,
    pub standings_digest: [u8; 32],
    pub first_seen: i64,
    pub last_synced: i64,
}

impl GroupRow {
    pub fn head(&self) -> GroupHead {
        GroupHead {
            group: self.id,
            head_seq: self.head_seq,
            head_hash: self.head_hash,
            standings: self.standings_digest,
        }
    }
}

/// What one [`Groups::put`] changed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Applied {
    pub accepted: usize,
    pub head_seq: u64,
    pub added: Vec<PeerId>,
    pub removed: Vec<PeerId>,
    pub we_joined: bool,
    pub we_lost: bool,
    pub departed: Vec<PeerId>,
}

pub struct Groups {
    db: Connection,
    me: PeerId,
}

impl Groups {
    /// Open (creating if absent) the group tables at `path`.
    pub fn open(path: &Path, me: PeerId) -> Result<Self, StoreError> {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        Self::from_connection(Connection::open(path)?, me)
    }

    /// An in-memory store. **Public, not test-only**: the sync machine's tests live in a
    /// sibling crate and cannot see a `cfg(test)` item.
    pub fn in_memory(me: PeerId) -> Result<Self, StoreError> {
        Self::from_connection(Connection::open_in_memory()?, me)
    }

    fn from_connection(db: Connection, me: PeerId) -> Result<Self, StoreError> {
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.busy_timeout(BUSY_TIMEOUT)?;
        // Table names are prefixed because this file is shared with `contacts`.
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS groups (
                 group_id         TEXT PRIMARY KEY NOT NULL,
                 name             TEXT NOT NULL,
                 admin            TEXT NOT NULL,
                 state            TEXT NOT NULL,
                 head_seq         INTEGER NOT NULL,
                 head_hash        TEXT NOT NULL,
                 standings_digest TEXT NOT NULL,
                 first_seen       INTEGER NOT NULL,
                 last_synced      INTEGER NOT NULL,
                 news             INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS group_entries (
                 group_id  TEXT NOT NULL,
                 seq       INTEGER NOT NULL,
                 hash      TEXT NOT NULL,
                 body      BLOB NOT NULL,
                 signature BLOB NOT NULL,
                 PRIMARY KEY (group_id, seq)
             );
             CREATE TABLE IF NOT EXISTS group_standings (
                 group_id  TEXT NOT NULL,
                 peer      TEXT NOT NULL,
                 seq       INTEGER NOT NULL,
                 position  TEXT NOT NULL,
                 body      BLOB NOT NULL,
                 signature BLOB NOT NULL,
                 PRIMARY KEY (group_id, peer)
             );
             CREATE TABLE IF NOT EXISTS group_members (
                 group_id  TEXT NOT NULL,
                 peer      TEXT NOT NULL,
                 username  TEXT NOT NULL,
                 is_admin  INTEGER NOT NULL,
                 PRIMARY KEY (group_id, peer)
             );
             CREATE INDEX IF NOT EXISTS group_members_peer ON group_members(peer);",
        )?;
        Ok(Self { db, me })
    }

    pub fn me(&self) -> PeerId {
        self.me
    }

    // ---- reads ----

    pub fn get(&self, group: GroupId) -> Result<Option<GroupRow>, StoreError> {
        self.db
            .query_row(
                "SELECT group_id, name, admin, state, head_seq, head_hash, standings_digest,
                        first_seen, last_synced
                 FROM groups WHERE group_id = ?1",
                params![group.to_string()],
                row_to_group,
            )
            .optional()?
            .transpose()
    }

    fn require(&self, group: GroupId) -> Result<GroupRow, StoreError> {
        self.get(group)?.ok_or(StoreError::UnknownGroup { group })
    }

    pub fn list(&self) -> Result<Vec<GroupRow>, StoreError> {
        let mut stmt = self.db.prepare(
            "SELECT group_id, name, admin, state, head_seq, head_hash, standings_digest,
                    first_seen, last_synced
             FROM groups ORDER BY name, group_id",
        )?;
        let rows = stmt.query_map([], row_to_group)?;

        let mut out = Vec::new();
        for row in rows {
            // A row we cannot parse is corrupt rather than merely absent; skip it instead of
            // failing the whole listing, as `contacts::list` does.
            match row? {
                Ok(group) => out.push(group),
                Err(e) => tracing::warn!(error = %e, "skipping an unreadable group row"),
            }
        }
        Ok(out)
    }

    /// Load and re-verify the whole chain.
    pub fn chain(&self, group: GroupId) -> Result<Chain, StoreError> {
        let mut stmt = self.db.prepare(
            "SELECT body, signature FROM group_entries WHERE group_id = ?1 ORDER BY seq",
        )?;
        let entries = stmt
            .query_map(params![group.to_string()], |r| {
                Ok(Entry {
                    body: r.get(0)?,
                    signature: r.get(1)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        if entries.is_empty() {
            return Err(StoreError::UnknownGroup { group });
        }
        Ok(Chain::load(entries)?)
    }

    pub fn standings(&self, group: GroupId) -> Result<Vec<Standing>, StoreError> {
        let mut stmt = self.db.prepare(
            "SELECT body, signature FROM group_standings WHERE group_id = ?1 ORDER BY peer",
        )?;
        let out = stmt
            .query_map(params![group.to_string()], |r| {
                Ok(Standing {
                    body: r.get(0)?,
                    signature: r.get(1)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(out)
    }

    /// Membership from the cache, which `put` keeps in step with the chain.
    pub fn members(&self, group: GroupId) -> Result<Members, StoreError> {
        let mut stmt = self
            .db
            .prepare("SELECT peer, username, is_admin FROM group_members WHERE group_id = ?1")?;
        let rows = stmt.query_map(params![group.to_string()], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;

        let mut members = Members::default();
        for row in rows {
            let (peer, username, is_admin) = row?;
            if let Ok(peer) = peer.parse() {
                members.insert(peer, username, is_admin != 0);
            }
        }
        Ok(members)
    }

    /// **Groups whose content we share with `peer`.** Active only: naming a group here is what
    /// lets its files be offered, and that needs our consent.
    pub fn shared_with(&self, peer: &PeerId) -> Result<Vec<GroupHead>, StoreError> {
        self.heads_shared(peer, "'active'")
    }

    pub fn log_shared_with(&self, peer: &PeerId) -> Result<Vec<GroupHead>, StoreError> {
        self.heads_shared(peer, "'active', 'pending'")
    }

    fn heads_shared(&self, peer: &PeerId, states: &str) -> Result<Vec<GroupHead>, StoreError> {
        let mut stmt = self.db.prepare(&format!(
            "SELECT g.group_id, g.name, g.admin, g.state, g.head_seq, g.head_hash,
                    g.standings_digest, g.first_seen, g.last_synced
             FROM groups g
             JOIN group_members them ON them.group_id = g.group_id AND them.peer = ?1
             JOIN group_members us   ON us.group_id   = g.group_id AND us.peer   = ?2
             WHERE g.state IN ({states})
             ORDER BY g.group_id"
        ))?;
        let rows = stmt.query_map(params![peer.to_base58(), self.me.to_base58()], row_to_group)?;

        let mut out = Vec::new();
        for row in rows {
            if let Ok(group) = row? {
                out.push(group.head());
            }
        }
        Ok(out)
    }

    /// How much of a group we may serve `peer`, if any. `Some(limit)` means entries
    /// `0..limit`.
    pub fn serve_up_to(&self, group: GroupId, peer: &PeerId) -> Result<Option<u64>, StoreError> {
        let Some(row) = self.get(group)? else {
            return Ok(None);
        };
        // A group we are not in ourselves is not ours to serve.
        let members = self.members(group)?;
        if !members.contains(&self.me) {
            return Ok(None);
        }
        if members.contains(peer) {
            return Ok(Some(row.head_seq));
        }

        // Not a member now. Were they ever? The chain is only loaded on this rarer path.
        Ok(self
            .chain(group)?
            .departure_seq(peer)
            .map(|removed_at| removed_at + 1))
    }

    /// Whether we may answer this peer's `Fetch` at all.
    pub fn serves(&self, group: GroupId, peer: &PeerId) -> Result<bool, StoreError> {
        Ok(self.serve_up_to(group, peer)?.is_some())
    }

    /// The entries to send in answer to `Fetch { group, from }`, or `None` to refuse.
    pub fn entries_for(
        &self,
        group: GroupId,
        peer: &PeerId,
        from: u64,
    ) -> Result<Option<Vec<Entry>>, StoreError> {
        let Some(limit) = self.serve_up_to(group, peer)? else {
            return Ok(None);
        };
        Ok(Some(
            self.chain(group)?
                .entries_between(from, limit)
                .cloned()
                .collect(),
        ))
    }

    /// Resolve a full id, a unique hex prefix, or an exact name.
    pub fn resolve(&self, needle: &str) -> Result<Resolved, StoreError> {
        if needle.trim().is_empty() {
            return Ok(Resolved::None);
        }

        let all = self.list()?;
        let needle_lower = needle.to_lowercase();

        let mut hits: Vec<GroupId> = all
            .iter()
            .filter(|g| g.id.to_string().starts_with(&needle_lower) || g.name == needle)
            .map(|g| g.id)
            .collect();
        hits.dedup();

        Ok(match hits.len() {
            0 => Resolved::None,
            1 => Resolved::One(hits[0]),
            _ => Resolved::Ambiguous(hits),
        })
    }

    /// Peers whose own latest statement is that they have left.
    pub fn departed(&self, group: GroupId) -> Result<Vec<PeerId>, StoreError> {
        let mut stmt = self.db.prepare(
            "SELECT peer FROM group_standings
             WHERE group_id = ?1 AND position = 'out' ORDER BY peer",
        )?;
        let rows = stmt.query_map(params![group.to_string()], |r| r.get::<_, String>(0))?;

        let mut out = Vec::new();
        for row in rows {
            if let Ok(peer) = row?.parse() {
                out.push(peer);
            }
        }
        Ok(out)
    }

    /// The highest standing seq we hold for ourselves, so the next one climbs past it.
    pub fn my_standing_seq(&self, group: GroupId) -> Result<Option<u64>, StoreError> {
        Ok(self
            .db
            .query_row(
                "SELECT seq FROM group_standings WHERE group_id = ?1 AND peer = ?2",
                params![group.to_string(), self.me.to_base58()],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .map(|seq| seq as u64))
    }

    // ---- writes ----

    /// Create a group with this node as its admin.
    pub fn create(
        &mut self,
        key: &Keypair,
        name: &str,
        username: &str,
        at: i64,
    ) -> Result<GroupId, StoreError> {
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| StoreError::Entropy)?;

        let chain = Chain::create(key, name, username, nonce, at)?;
        let id = chain.id();
        if self.get(id)?.is_some() {
            return Err(StoreError::Duplicate { group: id });
        }

        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO groups (group_id, name, admin, state, head_seq, head_hash,
                                 standings_digest, first_seen, last_synced)
             VALUES (?1, ?2, ?3, 'active', 0, ?4, ?5, ?6, ?6)",
            params![
                id.to_string(),
                chain.name(),
                chain.admin().to_base58(),
                EntryHash::of_body(&[]).to_string(),
                hex::encode([0u8; 32]),
                at,
            ],
        )?;
        write_entries(&tx, id, 0, chain.entries())?;
        set_head(&tx, id, 0, chain.len(), chain.head())?;
        rebuild_caches(&tx, id, &chain, &StandingSet::default())?;
        tx.commit()?;
        Ok(id)
    }

    /// Ingest a batch of entries and standings.
    pub fn put(
        &mut self,
        group: GroupId,
        from: u64,
        entries: &[Entry],
        standings: &[Standing],
        now: i64,
    ) -> Result<Applied, StoreError> {
        self.require(group)?; // refuse a group we do not hold, before any verification work
        let mut chain = self.chain(group)?;
        let members_before = chain.fold();
        let head_seq = chain.len();

        let overlap = head_seq.saturating_sub(from).min(entries.len() as u64);
        for i in 0..overlap {
            let seq = from + i;
            let theirs = entries[i as usize].hash();
            if chain.hash_at(seq) != Some(theirs) {
                return Err(StoreError::Diverged { group, seq });
            }
        }
        if from > head_seq {
            return Err(StoreError::Gap {
                want: head_seq,
                got: from,
            });
        }

        let fresh = &entries[overlap as usize..];
        let accepted = if fresh.is_empty() {
            0
        } else {
            chain.extend(fresh)?
        };

        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        if accepted > 0 {
            write_entries(&tx, group, head_seq, fresh.iter())?;
            if set_head(&tx, group, head_seq, chain.len(), chain.head())? == 0 {
                return Err(StoreError::Raced { group });
            }
        }

        let members_after = chain.fold();
        let mut set = load_standings(&tx, group)?;
        let mut departed = Vec::new();

        for standing in standings {
            let Ok(body) = standing.verify(group) else {
                continue;
            };
            let Ok(peer) = body.peer.parse::<PeerId>() else {
                continue;
            };
            if !ever_mentioned(&chain, &peer) {
                continue;
            }
            if !set.insert(peer, standing.clone(), body.seq, body.position) {
                continue;
            }
            tx.execute(
                "INSERT INTO group_standings (group_id, peer, seq, position, body, signature)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(group_id, peer) DO UPDATE SET
                     seq = excluded.seq, position = excluded.position,
                     body = excluded.body, signature = excluded.signature",
                params![
                    group.to_string(),
                    peer.to_base58(),
                    body.seq as i64,
                    position_str(body.position),
                    standing.body,
                    standing.signature,
                ],
            )?;

            // Only a departure. An unanswered invitation is not one, and ratifying it would
            // write a `Remove` against someone who has merely not replied yet.
            if body.position.is_departure() && members_after.contains(&peer) {
                departed.push(peer);
            }
        }

        rebuild_caches(&tx, group, &chain, &set)?;
        tx.execute(
            "UPDATE groups SET name = ?2, last_synced = ?3 WHERE group_id = ?1",
            params![group.to_string(), chain.name(), now],
        )?;
        tx.commit()?;

        Ok(Applied {
            accepted,
            head_seq: chain.len(),
            added: diff(&members_after, &members_before),
            removed: diff(&members_before, &members_after),
            we_joined: !members_before.contains(&self.me) && members_after.contains(&self.me),
            we_lost: members_before.contains(&self.me) && !members_after.contains(&self.me),
            departed,
        })
    }

    /// Append an entry. Admin only.
    pub fn author(
        &mut self,
        key: &Keypair,
        group: GroupId,
        op: Op,
        at: i64,
    ) -> Result<Entry, StoreError> {
        self.require(group)?;
        let mut chain = self.chain(group)?;
        let head_seq = chain.len();
        let entry = chain.author(key, op, at)?;

        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        write_entries(&tx, group, head_seq, std::iter::once(&entry))?;
        if set_head(&tx, group, head_seq, chain.len(), chain.head())? == 0 {
            return Err(StoreError::Raced { group });
        }
        let set = load_standings(&tx, group)?;
        rebuild_caches(&tx, group, &chain, &set)?;
        tx.execute(
            "UPDATE groups SET name = ?2, last_synced = ?3 WHERE group_id = ?1",
            params![group.to_string(), chain.name(), at],
        )?;
        note_news(&tx, group)?;
        tx.commit()?;
        Ok(entry)
    }

    /// Sign and store this node's own position, and set the matching local state.
    pub fn author_standing(
        &mut self,
        key: &Keypair,
        group: GroupId,
        position: Position,
        at: i64,
    ) -> Result<Standing, StoreError> {
        let seq = Standing::next_seq(self.my_standing_seq(group)?);
        let standing = Standing::author(key, group, seq, position, at)?;
        let body = standing.verify(group)?;

        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO group_standings (group_id, peer, seq, position, body, signature)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(group_id, peer) DO UPDATE SET
                 seq = excluded.seq, position = excluded.position,
                 body = excluded.body, signature = excluded.signature",
            params![
                group.to_string(),
                self.me.to_base58(),
                body.seq as i64,
                position_str(position),
                standing.body,
                standing.signature,
            ],
        )?;
        let state = match position {
            Position::Unanswered => State::Pending,
            Position::In => State::Active,
            Position::Out => State::Left,
        };
        tx.execute(
            "UPDATE groups SET state = ?2 WHERE group_id = ?1",
            params![group.to_string(), state.as_str()],
        )?;
        note_news(&tx, group)?;
        tx.commit()?;

        // The digest changed, so recompute it outside the write path's hot loop.
        self.refresh_digest(group)?;
        Ok(standing)
    }

    /// Membership changes this node made that the group has not been told about.
    pub fn news(&self, group: GroupId) -> Result<u64, StoreError> {
        let n: Option<i64> = self
            .db
            .query_row(
                "SELECT news FROM groups WHERE group_id = ?1",
                params![group.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        Ok(n.unwrap_or(0).max(0) as u64)
    }

    /// The group has been told. Anything after this is a fresh change.
    pub fn news_told(&mut self, group: GroupId) -> Result<(), StoreError> {
        self.db.execute(
            "UPDATE groups SET news = 0 WHERE group_id = ?1",
            params![group.to_string()],
        )?;
        Ok(())
    }

    pub fn set_state(&mut self, group: GroupId, state: State) -> Result<(), StoreError> {
        self.db.execute(
            "UPDATE groups SET state = ?2 WHERE group_id = ?1",
            params![group.to_string(), state.as_str()],
        )?;
        Ok(())
    }

    /// Forget a group locally. Writes nothing to any chain and tells nobody.
    pub fn forget(&mut self, group: GroupId) -> Result<(), StoreError> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for table in [
            "group_members",
            "group_standings",
            "group_entries",
            "groups",
        ] {
            tx.execute(
                &format!("DELETE FROM {table} WHERE group_id = ?1"),
                params![group.to_string()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Store a group we have never seen, from someone else's offer.
    pub fn adopt(
        &mut self,
        entries: &[Entry],
        standings: &[Standing],
        now: i64,
    ) -> Result<Applied, StoreError> {
        let chain = Chain::load(entries.to_vec())?;
        let id = chain.id();
        if self.get(id)?.is_some() {
            return self.put(id, 0, entries, standings, now);
        }

        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO groups (group_id, name, admin, state, head_seq, head_hash,
                                 standings_digest, first_seen, last_synced)
             VALUES (?1, ?2, ?3, 'pending', 0, ?4, ?5, ?6, ?6)",
            params![
                id.to_string(),
                chain.name(),
                chain.admin().to_base58(),
                EntryHash::of_body(&[]).to_string(),
                hex::encode([0u8; 32]),
                now,
            ],
        )?;
        write_entries(&tx, id, 0, chain.entries())?;
        set_head(&tx, id, 0, chain.len(), chain.head())?;
        rebuild_caches(&tx, id, &chain, &StandingSet::default())?;
        tx.commit()?;

        let mut applied = self.put(id, chain.len(), &[], standings, now)?;
        applied.head_seq = chain.len();
        applied.accepted = chain.len() as usize;
        applied.we_joined = chain.fold().contains(&self.me);
        Ok(applied)
    }

    fn refresh_digest(&mut self, group: GroupId) -> Result<(), StoreError> {
        let chain = self.chain(group)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let set = load_standings(&tx, group)?;
        rebuild_caches(&tx, group, &chain, &set)?;
        tx.commit()?;
        Ok(())
    }
}

/// Whether a peer is named by any `Add` anywhere in the chain.
fn ever_mentioned(chain: &Chain, peer: &PeerId) -> bool {
    if chain.admin() == *peer {
        return true;
    }
    chain.entries().any(|e| match e.body().map(|b| b.op) {
        Ok(Op::Add { peer: named, .. }) => named.parse::<PeerId>().ok().as_ref() == Some(peer),
        _ => false,
    })
}

fn diff(a: &Members, b: &Members) -> Vec<PeerId> {
    a.iter()
        .filter(|m| !b.contains(&m.peer))
        .map(|m| m.peer)
        .collect()
}

fn write_entries<'a>(
    tx: &rusqlite::Transaction<'_>,
    group: GroupId,
    from: u64,
    entries: impl Iterator<Item = &'a Entry>,
) -> Result<(), StoreError> {
    for (offset, entry) in entries.enumerate() {
        tx.execute(
            "INSERT OR IGNORE INTO group_entries (group_id, seq, hash, body, signature)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                group.to_string(),
                (from + offset as u64) as i64,
                entry.hash().to_string(),
                entry.body,
                entry.signature,
            ],
        )?;
    }
    Ok(())
}

/// Compare-and-swap the head. Returns rows changed; 0 means another writer won.
fn set_head(
    tx: &rusqlite::Transaction<'_>,
    group: GroupId,
    observed: u64,
    head_seq: u64,
    head_hash: EntryHash,
) -> Result<usize, StoreError> {
    Ok(tx.execute(
        "UPDATE groups SET head_seq = ?3, head_hash = ?4
         WHERE group_id = ?1 AND head_seq = ?2",
        params![
            group.to_string(),
            observed as i64,
            head_seq as i64,
            head_hash.to_string(),
        ],
    )?)
}

fn load_standings(
    tx: &rusqlite::Transaction<'_>,
    group: GroupId,
) -> Result<StandingSet, StoreError> {
    let mut stmt = tx.prepare(
        "SELECT peer, seq, position, body, signature FROM group_standings WHERE group_id = ?1",
    )?;
    let rows = stmt.query_map(params![group.to_string()], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, Vec<u8>>(3)?,
            r.get::<_, Vec<u8>>(4)?,
        ))
    })?;

    let mut set = StandingSet::default();
    for row in rows {
        let (peer, seq, position, body, signature) = row?;
        if let Ok(peer) = peer.parse() {
            set.insert(
                peer,
                Standing { body, signature },
                seq as u64,
                position_of(&position),
            );
        }
    }
    Ok(set)
}

/// Rewrite the derived tables from the chain. Always inside the transaction that changed it.
fn rebuild_caches(
    tx: &rusqlite::Transaction<'_>,
    group: GroupId,
    chain: &Chain,
    standings: &StandingSet,
) -> Result<(), StoreError> {
    let members = chain.fold();

    tx.execute(
        "DELETE FROM group_members WHERE group_id = ?1",
        params![group.to_string()],
    )?;
    for member in members.iter() {
        tx.execute(
            "INSERT INTO group_members (group_id, peer, username, is_admin)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                group.to_string(),
                member.peer.to_base58(),
                member.username,
                i64::from(member.is_admin),
            ],
        )?;
    }
    tx.execute(
        "DELETE FROM group_standings
          WHERE group_id = ?1
            AND peer NOT IN (SELECT peer FROM group_members WHERE group_id = ?1)",
        params![group.to_string()],
    )?;
    tx.execute(
        "UPDATE groups SET standings_digest = ?2 WHERE group_id = ?1",
        params![
            group.to_string(),
            hex::encode(members.standings_digest(standings))
        ],
    )?;
    Ok(())
}

/// Record that this node changed this group's membership.
fn note_news(tx: &rusqlite::Transaction<'_>, group: GroupId) -> Result<(), StoreError> {
    tx.execute(
        "UPDATE groups SET news = news + 1 WHERE group_id = ?1",
        params![group.to_string()],
    )?;
    Ok(())
}

fn position_str(position: Position) -> &'static str {
    match position {
        Position::Unanswered => "unanswered",
        Position::In => "in",
        Position::Out => "out",
    }
}

fn position_of(raw: &str) -> Position {
    match raw {
        "in" => Position::In,
        "out" => Position::Out,
        _ => Position::Unanswered,
    }
}

type RowResult = Result<GroupRow, StoreError>;

fn row_to_group(r: &rusqlite::Row<'_>) -> rusqlite::Result<RowResult> {
    let parse = || -> RowResult {
        let mut digest = [0u8; 32];
        hex::decode_to_slice(r.get::<_, String>(6)?, &mut digest)
            .map_err(|_| StoreError::CorruptRow)?;

        Ok(GroupRow {
            id: r
                .get::<_, String>(0)?
                .parse()
                .map_err(|_| StoreError::CorruptRow)?,
            name: r.get(1)?,
            admin: r
                .get::<_, String>(2)?
                .parse()
                .map_err(|_| StoreError::CorruptRow)?,
            state: State::parse(&r.get::<_, String>(3)?),
            head_seq: r.get::<_, i64>(4)? as u64,
            head_hash: r
                .get::<_, String>(5)?
                .parse()
                .map_err(|_| StoreError::CorruptRow)?,
            standings_digest: digest,
            first_seen: r.get(7)?,
            last_synced: r.get(8)?,
        })
    };
    Ok(parse())
}

/// The outcome of resolving a user-typed group reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    One(GroupId),
    None,
    Ambiguous(Vec<GroupId>),
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Db(#[from] rusqlite::Error),
    #[error(transparent)]
    Chain(#[from] ChainError),
    #[error(transparent)]
    Standing(#[from] StandingError),
    #[error("a stored row could not be read")]
    CorruptRow,
    #[error("no entropy available to mint a group nonce")]
    Entropy,
    #[error("this node does not know group {group}")]
    UnknownGroup { group: GroupId },
    #[error("group {group} is already known")]
    Duplicate { group: GroupId },
    #[error("entries start at {got}, but {want} is needed to continue")]
    Gap { want: u64, got: u64 },
    #[error("group {group} disagrees with us at entry {seq}; the batch was refused")]
    Diverged { group: GroupId, seq: u64 },
    #[error("another writer moved the head of {group} mid-batch")]
    Raced { group: GroupId },
}

#[cfg(test)]
mod tests {
    use super::*;

    const AT: i64 = 1_000_000;

    fn key() -> Keypair {
        Keypair::generate_ed25519()
    }

    fn peer_of(k: &Keypair) -> PeerId {
        k.public().to_peer_id()
    }

    /// A store owned by `admin`, holding one group they created.
    fn admin_store() -> (Groups, Keypair, GroupId) {
        let admin = key();
        let mut store = Groups::in_memory(peer_of(&admin)).unwrap();
        let id = store.create(&admin, "family", "alice", AT).unwrap();
        (store, admin, id)
    }

    #[test]
    fn a_membership_change_of_ours_is_news_and_one_we_adopt_is_not() {
        // The head moves for an entry adopted from a peer exactly as it does for an op of ours,
        // so a supervisor watching it cannot tell them apart. Re-telling a group what it just
        // told us is one message per member per member, which is why the writer stamps this.
        let (mut store, admin, id) = admin_store();
        store.news_told(id).unwrap();

        add(&mut store, &admin, id, peer_of(&key()), "bob");
        assert_eq!(store.news(id).unwrap(), 1, "our own op is news");

        store.news_told(id).unwrap();
        assert_eq!(
            store.news(id).unwrap(),
            0,
            "and is settled once the group is told"
        );

        // The same chain, arriving from somewhere else.
        let entries: Vec<Entry> = store.chain(id).unwrap().entries().cloned().collect();
        let mut theirs = Groups::in_memory(peer_of(&key())).unwrap();
        theirs.adopt(&entries, &[], AT).unwrap();
        assert_eq!(
            theirs.news(id).unwrap(),
            0,
            "they did not change anything; the admin did"
        );
        assert!(
            theirs.get(id).unwrap().is_some_and(|g| g.head_seq > 0),
            "though the head did move"
        );
    }

    #[test]
    fn answering_an_invitation_is_news_the_group_must_hear() {
        let member = key();
        let (mut store, admin, id) = admin_store();
        add(&mut store, &admin, id, peer_of(&member), "bob");

        let entries: Vec<Entry> = store.chain(id).unwrap().entries().cloned().collect();
        let mut theirs = Groups::in_memory(peer_of(&member)).unwrap();
        theirs.adopt(&entries, &[], AT).unwrap();
        assert_eq!(theirs.news(id).unwrap(), 0, "receiving it says nothing");

        theirs
            .author_standing(&member, id, Position::In, AT)
            .unwrap();
        assert_eq!(
            theirs.news(id).unwrap(),
            1,
            "but accepting is ours to tell, or nobody learns we are in"
        );
    }

    fn add(store: &mut Groups, admin: &Keypair, id: GroupId, peer: PeerId, name: &str) {
        store
            .author(
                admin,
                id,
                Op::Add {
                    peer: peer.to_base58(),
                    username: name.into(),
                },
                AT,
            )
            .unwrap();
    }

    #[test]
    fn creating_a_group_makes_us_its_active_admin() {
        let (store, admin, id) = admin_store();
        let row = store.get(id).unwrap().unwrap();

        assert_eq!(row.admin, peer_of(&admin));
        assert_eq!(row.state, State::Active);
        assert_eq!(row.name, "family");
        assert!(store.members(id).unwrap().contains(&peer_of(&admin)));
    }

    #[test]
    fn entries_are_stored_and_returned_byte_for_byte() {
        // Re-encoding would break every signature and every hash in the chain.
        let (mut store, admin, id) = admin_store();
        add(&mut store, &admin, id, peer_of(&key()), "bob");

        let original: Vec<Entry> = store.chain(id).unwrap().entries().cloned().collect();
        let reloaded: Vec<Entry> = store.chain(id).unwrap().entries().cloned().collect();
        assert_eq!(original, reloaded);
    }

    #[test]
    fn a_replayed_batch_changes_nothing() {
        let (mut store, admin, id) = admin_store();
        add(&mut store, &admin, id, peer_of(&key()), "bob");
        let entries: Vec<Entry> = store.chain(id).unwrap().entries().cloned().collect();

        let applied = store.put(id, 0, &entries, &[], AT).unwrap();
        assert_eq!(applied.accepted, 0);
        assert_eq!(applied.head_seq, 2);
    }

    #[test]
    fn a_gap_reports_what_is_needed() {
        let (mut store, admin, id) = admin_store();

        // Build a longer chain elsewhere and offer only its tail.
        let mut source = store.chain(id).unwrap();
        let mut tail = Vec::new();
        for name in ["bob", "carol"] {
            tail.push(
                source
                    .author(
                        &admin,
                        Op::Add {
                            peer: peer_of(&key()).to_base58(),
                            username: name.into(),
                        },
                        AT,
                    )
                    .unwrap(),
            );
        }

        assert!(matches!(
            store.put(id, 2, &tail[1..], &[], AT),
            Err(StoreError::Gap { want: 1, got: 2 })
        ));
    }

    #[test]
    fn a_divergent_batch_is_refused_and_writes_nothing() {
        let (mut store, admin, id) = admin_store();
        add(&mut store, &admin, id, peer_of(&key()), "bob");

        // A divergent history: same genesis, different entry at seq 1.
        let genesis = store.chain(id).unwrap().entries().next().unwrap().clone();
        let mut divergent = Chain::load(vec![genesis]).unwrap();
        let other = divergent
            .author(
                &admin,
                Op::Add {
                    peer: peer_of(&key()).to_base58(),
                    username: "mallory".into(),
                },
                AT,
            )
            .unwrap();

        let before = store.chain(id).unwrap();
        assert!(matches!(
            store.put(id, 1, &[other], &[], AT),
            Err(StoreError::Diverged { seq: 1, .. })
        ));

        let after = store.chain(id).unwrap();
        assert_eq!(after.head(), before.head(), "nothing was written");
    }

    #[test]
    fn a_group_is_named_only_to_someone_it_contains() {
        // The non-leak rule, and the single place it is enforced.
        let (mut store, admin, id) = admin_store();
        let (bob, stranger) = (key(), key());
        add(&mut store, &admin, id, peer_of(&bob), "bob");

        assert_eq!(store.shared_with(&peer_of(&bob)).unwrap().len(), 1);
        assert!(
            store.shared_with(&peer_of(&stranger)).unwrap().is_empty(),
            "a non-member must learn nothing, not even that the group exists"
        );
        assert!(!store.serves(id, &peer_of(&stranger)).unwrap());
    }

    #[test]
    fn a_removed_member_is_not_offered_but_may_still_learn_they_were_removed() {
        let (mut store, admin, id) = admin_store();
        let bob = key();
        add(&mut store, &admin, id, peer_of(&bob), "bob");
        store
            .author(
                &admin,
                id,
                Op::Remove {
                    peer: peer_of(&bob).to_base58(),
                },
                AT,
            )
            .unwrap();
        // One more entry, which Bob must never see.
        add(&mut store, &admin, id, peer_of(&key()), "carol");

        assert!(
            store.shared_with(&peer_of(&bob)).unwrap().is_empty(),
            "we do not chase someone we removed"
        );
        assert_eq!(
            store.serve_up_to(id, &peer_of(&bob)).unwrap(),
            Some(3),
            "everything up to and including the entry that removed them"
        );

        let served = store
            .entries_for(id, &peer_of(&bob), 0)
            .unwrap()
            .expect("a removed member may still ask");
        assert_eq!(served.len(), 3, "genesis, their add, their removal");

        // What Bob makes of it: he is out, and knows it.
        let bobs_view = Chain::load(served).unwrap();
        assert!(!bobs_view.fold().contains(&peer_of(&bob)));
        assert_eq!(bobs_view.len(), 3, "nothing after the removal");
    }

    #[test]
    fn a_peer_removed_twice_is_served_up_to_the_last_removal() {
        let (mut store, admin, id) = admin_store();
        let bob = key();
        let remove = |s: &mut Groups| {
            s.author(
                &admin,
                id,
                Op::Remove {
                    peer: peer_of(&bob).to_base58(),
                },
                AT,
            )
            .unwrap();
        };

        add(&mut store, &admin, id, peer_of(&bob), "bob"); // 1
        remove(&mut store); // 2
        add(&mut store, &admin, id, peer_of(&bob), "bob"); // 3
        remove(&mut store); // 4

        assert_eq!(store.serve_up_to(id, &peer_of(&bob)).unwrap(), Some(5));
    }

    #[test]
    fn a_peer_re_added_after_their_removal_gets_everything() {
        let (mut store, admin, id) = admin_store();
        let bob = key();
        add(&mut store, &admin, id, peer_of(&bob), "bob");
        store
            .author(
                &admin,
                id,
                Op::Remove {
                    peer: peer_of(&bob).to_base58(),
                },
                AT,
            )
            .unwrap();
        add(&mut store, &admin, id, peer_of(&bob), "bob");

        let head = store.get(id).unwrap().unwrap().head_seq;
        assert_eq!(store.serve_up_to(id, &peer_of(&bob)).unwrap(), Some(head));
        assert_eq!(store.shared_with(&peer_of(&bob)).unwrap().len(), 1);
    }

    #[test]
    fn a_stranger_is_served_nothing_however_they_ask() {
        // The distinction that keeps a guessed group id from becoming a membership oracle.
        let (mut store, admin, id) = admin_store();
        add(&mut store, &admin, id, peer_of(&key()), "bob");
        let stranger = peer_of(&key());

        assert_eq!(store.serve_up_to(id, &stranger).unwrap(), None);
        assert!(store.entries_for(id, &stranger, 0).unwrap().is_none());
    }

    #[test]
    fn a_group_we_have_not_accepted_is_served_to_nobody() {
        // `pending` means we have not consented, so we do not act on the group's behalf.
        let admin = key();
        let me = key();
        let mut theirs = Groups::in_memory(peer_of(&admin)).unwrap();
        let id = theirs.create(&admin, "family", "alice", AT).unwrap();
        add(&mut theirs, &admin, id, peer_of(&me), "bob");
        let entries: Vec<Entry> = theirs.chain(id).unwrap().entries().cloned().collect();

        let mut mine = Groups::in_memory(peer_of(&me)).unwrap();
        mine.adopt(&entries, &[], AT).unwrap();

        assert_eq!(mine.get(id).unwrap().unwrap().state, State::Pending);
        assert!(
            mine.shared_with(&peer_of(&admin)).unwrap().is_empty(),
            "we do not advertise the content of a group we have not accepted"
        );
        assert_eq!(
            mine.log_shared_with(&peer_of(&admin)).unwrap().len(),
            1,
            "but we do name its log, or our silence reads as a refusal forever"
        );
        assert!(
            mine.serves(id, &peer_of(&admin)).unwrap(),
            "and we still answer a member asking for the log, which is not data"
        );

        mine.author_standing(&me, id, Position::In, AT).unwrap();
        assert_eq!(mine.get(id).unwrap().unwrap().state, State::Active);
        assert_eq!(mine.shared_with(&peer_of(&admin)).unwrap().len(), 1);
    }

    #[test]
    fn a_group_we_have_left_is_named_to_nobody() {
        // The boundary of `log_shared_with`: pending is a delay, left is a decision.
        let (mut store, admin, id) = admin_store();
        let bob = key();
        add(&mut store, &admin, id, peer_of(&bob), "bob");
        assert_eq!(store.log_shared_with(&peer_of(&bob)).unwrap().len(), 1);

        store.set_state(id, State::Left).unwrap();
        assert!(store.log_shared_with(&peer_of(&bob)).unwrap().is_empty());
        assert!(store.shared_with(&peer_of(&bob)).unwrap().is_empty());
    }

    #[test]
    fn leaving_sets_the_local_state_and_a_re_add_does_not_undo_it() {
        // The stickiness that matters is local: no entry the admin writes can put us back.
        let admin = key();
        let me = key();
        let mut theirs = Groups::in_memory(peer_of(&admin)).unwrap();
        let id = theirs.create(&admin, "family", "alice", AT).unwrap();
        add(&mut theirs, &admin, id, peer_of(&me), "bob");

        let mut mine = Groups::in_memory(peer_of(&me)).unwrap();
        mine.adopt(
            &theirs
                .chain(id)
                .unwrap()
                .entries()
                .cloned()
                .collect::<Vec<_>>(),
            &[],
            AT,
        )
        .unwrap();
        mine.author_standing(&me, id, Position::In, AT).unwrap();
        mine.author_standing(&me, id, Position::Out, AT).unwrap();
        assert_eq!(mine.get(id).unwrap().unwrap().state, State::Left);

        // The admin removes and re-adds us; we ingest both.
        theirs
            .author(
                &admin,
                id,
                Op::Remove {
                    peer: peer_of(&me).to_base58(),
                },
                AT,
            )
            .unwrap();
        add(&mut theirs, &admin, id, peer_of(&me), "bob");
        let all: Vec<Entry> = theirs.chain(id).unwrap().entries().cloned().collect();
        mine.put(id, 0, &all, &[], AT).unwrap();

        assert!(mine.members(id).unwrap().contains(&peer_of(&me)));
        assert_eq!(
            mine.get(id).unwrap().unwrap().state,
            State::Left,
            "only `ac group accept` may put us back"
        );
        assert!(mine.shared_with(&peer_of(&admin)).unwrap().is_empty());
        assert!(
            mine.serves(id, &peer_of(&admin)).unwrap(),
            "a node that has left still answers, or its own departure could never reach the \
             admin and leaving would be invisible to everyone but the leaver"
        );
    }

    #[test]
    fn a_standing_survives_until_ratified_and_no_longer() {
        // The window it exists for is exactly "they said so, the admin has not acted yet". While
        // the chain still lists them the statement has work to do; once the `Remove` lands the
        // entry is the record, and a stale `Out` at some high seq would beat the seq-1 standing
        // of the same peer re-added after an `ac group forget`.
        let (mut store, admin, id) = admin_store();
        let bob = key();
        add(&mut store, &admin, id, peer_of(&bob), "bob");

        let leaving = Standing::author(&bob, id, 1, Position::Out, AT).unwrap();
        store.put(id, 1, &[], &[leaving], AT).unwrap();
        assert_eq!(
            store.standings(id).unwrap().len(),
            1,
            "still a member, so their word still travels"
        );
        assert_eq!(store.departed(id).unwrap(), vec![peer_of(&bob)]);

        store
            .author(
                &admin,
                id,
                Op::Remove {
                    peer: peer_of(&bob).to_base58(),
                },
                AT,
            )
            .unwrap();

        assert!(
            store.standings(id).unwrap().is_empty(),
            "ratified, so the entry is the record and the standing is dropped"
        );
        assert!(store.departed(id).unwrap().is_empty());
    }

    #[test]
    fn a_departure_is_reported_to_the_admin_once_per_departure() {
        // The trigger for ratification. Re-ingesting the same standing must not report it
        // again, or the admin appends a `Remove` per delivery and the chain grows without end.
        let (mut store, admin, id) = admin_store();
        let bob = key();
        add(&mut store, &admin, id, peer_of(&bob), "bob");

        let standing = Standing::author(&bob, id, 1, Position::Out, AT).unwrap();
        let first = store
            .put(id, 2, &[], std::slice::from_ref(&standing), AT)
            .unwrap();
        assert_eq!(first.departed, vec![peer_of(&bob)]);

        let again = store
            .put(id, 2, &[], std::slice::from_ref(&standing), AT)
            .unwrap();
        assert!(again.departed.is_empty(), "already superseded");

        // Once ratified, the peer is out of the chain, so it is not reported even if the
        // standing arrives afresh from a peer that had not seen the removal.
        store
            .author(
                &admin,
                id,
                Op::Remove {
                    peer: peer_of(&bob).to_base58(),
                },
                AT,
            )
            .unwrap();
        let after = store.put(id, 3, &[], &[standing], AT).unwrap();
        assert!(after.departed.is_empty());
    }

    #[test]
    fn a_standing_for_a_peer_the_chain_never_mentions_is_dropped() {
        // Otherwise an enrolled peer could grow our database with statements about strangers.
        let (mut store, _admin, id) = admin_store();
        let stranger = key();
        let junk = Standing::author(&stranger, id, 1, Position::Out, AT).unwrap();

        store.put(id, 1, &[], &[junk], AT).unwrap();
        assert!(store.standings(id).unwrap().is_empty());
    }

    #[test]
    fn a_standing_arriving_before_its_add_is_accepted_afterwards() {
        let (mut store, admin, id) = admin_store();
        let bob = key();
        let early = Standing::author(&bob, id, 1, Position::Out, AT).unwrap();

        store
            .put(id, 1, &[], std::slice::from_ref(&early), AT)
            .unwrap();
        assert!(store.standings(id).unwrap().is_empty(), "not a member yet");

        add(&mut store, &admin, id, peer_of(&bob), "bob");
        let applied = store.put(id, 2, &[], &[early], AT).unwrap();
        assert_eq!(store.standings(id).unwrap().len(), 1);
        assert_eq!(applied.departed, vec![peer_of(&bob)]);
    }

    #[test]
    fn the_member_cache_matches_a_recomputed_fold() {
        let (mut store, admin, id) = admin_store();
        let peers: Vec<_> = (0..5).map(|_| key()).collect();
        for (i, k) in peers.iter().enumerate() {
            add(&mut store, &admin, id, peer_of(k), &format!("user{i}"));
        }
        store
            .author(
                &admin,
                id,
                Op::Remove {
                    peer: peer_of(&peers[2]).to_base58(),
                },
                AT,
            )
            .unwrap();

        // Every field, not just the peer ids: a cache that defaulted the rest would be a
        // quiet trap for whoever reads `is_admin` back.
        assert_eq!(store.members(id).unwrap(), store.chain(id).unwrap().fold());
        assert_eq!(store.members(id).unwrap().len(), 5); // admin + 5 added - 1 removed

        let admin_peer = peer_of(&admin);
        assert!(
            store
                .members(id)
                .unwrap()
                .get(&admin_peer)
                .unwrap()
                .is_admin
        );
    }

    #[test]
    fn the_digest_changes_when_a_standing_does() {
        let (mut store, admin, id) = admin_store();
        let bob = key();
        add(&mut store, &admin, id, peer_of(&bob), "bob");
        let before = store.get(id).unwrap().unwrap().standings_digest;

        let standing = Standing::author(&bob, id, 1, Position::Out, AT).unwrap();
        store.put(id, 2, &[], &[standing], AT).unwrap();

        assert_ne!(store.get(id).unwrap().unwrap().standings_digest, before);
    }

    #[test]
    fn resolve_accepts_a_prefix_or_a_name_and_reports_ambiguity() {
        let (mut store, admin, id) = admin_store();
        assert_eq!(store.resolve("family").unwrap(), Resolved::One(id));
        assert_eq!(
            store.resolve(&id.to_string()[..8]).unwrap(),
            Resolved::One(id)
        );
        assert_eq!(store.resolve("nope").unwrap(), Resolved::None);

        let second = store.create(&admin, "family", "alice", AT).unwrap();
        assert!(matches!(
            store.resolve("family").unwrap(),
            Resolved::Ambiguous(ids) if ids.len() == 2 && ids.contains(&second)
        ));
    }

    #[test]
    fn an_empty_needle_resolves_to_nothing_even_with_one_group() {
        // `starts_with("")` matches every group, so the ambiguity check that makes prefix
        // matching safe does not fire: on a node holding exactly one group it would collapse
        // to a single hit and resolve. A command whose argument went missing would then act
        // on the only group, and `ac group remove` is among the callers.
        let (mut store, admin, _id) = admin_store();

        assert_eq!(store.resolve("").unwrap(), Resolved::None);
        assert_eq!(store.resolve("   ").unwrap(), Resolved::None);

        // Not merely a side effect of ambiguity once a second group exists.
        store.create(&admin, "other", "alice", AT).unwrap();
        assert_eq!(store.resolve("").unwrap(), Resolved::None);
    }

    #[test]
    fn forgetting_removes_every_trace_locally() {
        let (mut store, admin, id) = admin_store();
        add(&mut store, &admin, id, peer_of(&key()), "bob");

        store.forget(id).unwrap();
        assert!(store.get(id).unwrap().is_none());
        assert!(matches!(
            store.chain(id),
            Err(StoreError::UnknownGroup { .. })
        ));
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn our_own_standing_seq_climbs_and_never_repeats() {
        let (mut store, admin, id) = admin_store();
        assert_eq!(store.my_standing_seq(id).unwrap(), None);

        store
            .author_standing(&admin, id, Position::Out, AT)
            .unwrap();
        assert_eq!(store.my_standing_seq(id).unwrap(), Some(1));
        store.author_standing(&admin, id, Position::In, AT).unwrap();
        assert_eq!(store.my_standing_seq(id).unwrap(), Some(2));
    }

    #[test]
    fn two_connections_to_one_file_see_each_others_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite");
        let admin = key();

        let mut writer = Groups::open(&path, peer_of(&admin)).unwrap();
        let reader = Groups::open(&path, peer_of(&admin)).unwrap();

        let id = writer.create(&admin, "family", "alice", AT).unwrap();
        assert!(reader.get(id).unwrap().is_some());

        add(&mut writer, &admin, id, peer_of(&key()), "bob");
        assert_eq!(reader.chain(id).unwrap().len(), 2);
    }

    #[test]
    fn groups_and_contacts_share_one_file() {
        // They are separate tables in the node's single `state.sqlite`; opening both must not
        // have either clobbering the other's schema.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite");
        let admin = key();

        let contacts = Connection::open(&path).unwrap();
        contacts
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS contacts (
                     peer_id TEXT PRIMARY KEY NOT NULL, label TEXT NOT NULL);
                 INSERT INTO contacts VALUES ('somepeer', 'bob');",
            )
            .unwrap();

        let mut groups = Groups::open(&path, peer_of(&admin)).unwrap();
        let id = groups.create(&admin, "family", "alice", AT).unwrap();

        assert!(groups.get(id).unwrap().is_some());
        let label: String = contacts
            .query_row("SELECT label FROM contacts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(label, "bob");
    }
}
