//! The contact list: peers this node wants to find and stay connected to.
//!
//! **This is not an access-control list.** It never decides who may connect — clients
//! accept anyone, and data is authorized per group (see `ac_net::authz`). What it does is
//! answer "who am I looking for", which drives rendezvous lookups (stage 8) and
//! reconnection (stage 10).
//!
//! The distinction matters because the two are easy to conflate and the consequences
//! differ sharply: a contact list that is out of date means slower discovery, while an
//! access list that is out of date means a member returning from an absence can be
//! refused by peers that have not heard of them yet.
//!
//! Entries are added by hand and only by hand. When groups arrive, a group's signed
//! membership log is itself the record of who belongs, and discovery reads that log
//! directly rather than copying peers in here — one fact, one place.

use std::path::Path;

use ac_net::PeerId;
use rusqlite::{Connection, OptionalExtension, params};

/// A peer id is unreadable; the label is how a person refers to a contact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contact {
    pub peer: PeerId,
    pub label: String,
}

/// The contact list, backed by SQLite.
pub struct Contacts {
    db: Connection,
}

impl Contacts {
    /// Open (creating if absent) the contact list at `path`.
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        Self::from_connection(Connection::open(path)?)
    }

    #[cfg(test)]
    fn in_memory() -> rusqlite::Result<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(db: Connection) -> rusqlite::Result<Self> {
        // WAL lets `ac peer add` write while `ac run` reads, which is the whole point of
        // querying SQLite live rather than caching in the daemon.
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS contacts (
                 peer_id TEXT PRIMARY KEY NOT NULL,
                 label   TEXT NOT NULL
             );",
        )?;
        Ok(Self { db })
    }

    /// Add a contact, or relabel one already present.
    ///
    /// Returns whether this was a new contact, so the CLI can say which happened.
    pub fn add(&self, peer: &PeerId, label: &str) -> rusqlite::Result<bool> {
        let existed = self.get(peer)?.is_some();
        self.db.execute(
            "INSERT INTO contacts (peer_id, label) VALUES (?1, ?2)
             ON CONFLICT(peer_id) DO UPDATE SET label = excluded.label",
            params![peer.to_string(), label],
        )?;
        Ok(!existed)
    }

    /// Remove a contact. Returns whether anything was removed.
    pub fn remove(&self, peer: &PeerId) -> rusqlite::Result<bool> {
        let n = self.db.execute(
            "DELETE FROM contacts WHERE peer_id = ?1",
            params![peer.to_string()],
        )?;
        Ok(n > 0)
    }

    pub fn get(&self, peer: &PeerId) -> rusqlite::Result<Option<Contact>> {
        self.db
            .query_row(
                "SELECT peer_id, label FROM contacts WHERE peer_id = ?1",
                params![peer.to_string()],
                row_to_contact,
            )
            .optional()
            .map(Option::flatten)
    }

    /// Every contact, by label — the order a person reading the list expects.
    pub fn list(&self) -> rusqlite::Result<Vec<Contact>> {
        let mut stmt = self
            .db
            .prepare("SELECT peer_id, label FROM contacts ORDER BY label, peer_id")?;
        let rows = stmt.query_map([], row_to_contact)?;

        let mut out = Vec::new();
        for row in rows {
            // A row whose peer id no longer parses is corrupt rather than merely absent;
            // skip it instead of failing the whole listing.
            if let Some(contact) = row? {
                out.push(contact);
            }
        }
        Ok(out)
    }
}

/// `None` when the stored peer id cannot be parsed.
fn row_to_contact(row: &rusqlite::Row<'_>) -> rusqlite::Result<Option<Contact>> {
    let raw: String = row.get(0)?;
    let Ok(peer) = raw.parse::<PeerId>() else {
        tracing::warn!(peer_id = %raw, "skipping contact with an unparseable peer id");
        return Ok(None);
    };

    Ok(Some(Contact {
        peer,
        label: row.get(1)?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> PeerId {
        libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id()
    }

    #[test]
    fn add_then_get_round_trips() {
        let c = Contacts::in_memory().unwrap();
        let p = peer();

        assert!(c.add(&p, "bob").unwrap());

        let got = c.get(&p).unwrap().expect("contact present");
        assert_eq!(got.peer, p);
        assert_eq!(got.label, "bob");
    }

    #[test]
    fn re_adding_relabels_and_reports_not_new() {
        let c = Contacts::in_memory().unwrap();
        let p = peer();

        assert!(c.add(&p, "bob").unwrap());
        assert!(!c.add(&p, "bobs-laptop").unwrap());

        assert_eq!(c.get(&p).unwrap().unwrap().label, "bobs-laptop");
    }

    #[test]
    fn remove_reports_whether_it_did_anything() {
        let c = Contacts::in_memory().unwrap();
        let p = peer();

        assert!(!c.remove(&p).unwrap(), "removing an absent peer is a no-op");
        c.add(&p, "bob").unwrap();
        assert!(c.remove(&p).unwrap());
        assert!(c.get(&p).unwrap().is_none());
    }

    #[test]
    fn list_is_ordered_by_label() {
        let c = Contacts::in_memory().unwrap();
        c.add(&peer(), "carol").unwrap();
        c.add(&peer(), "alice").unwrap();
        c.add(&peer(), "bob").unwrap();

        let labels: Vec<_> = c.list().unwrap().into_iter().map(|x| x.label).collect();
        assert_eq!(labels, ["alice", "bob", "carol"]);
    }

    #[test]
    fn a_corrupt_row_does_not_break_the_listing() {
        let c = Contacts::in_memory().unwrap();
        c.add(&peer(), "good").unwrap();
        c.db.execute(
            "INSERT INTO contacts (peer_id, label) VALUES ('not-a-peer-id', 'bad')",
            [],
        )
        .unwrap();

        assert_eq!(
            c.list().unwrap().len(),
            1,
            "the good row should survive a bad one"
        );
    }

    #[test]
    fn changes_are_visible_to_a_separate_connection() {
        // The daemon and `ac peer add` are different processes. If this did not hold,
        // adding a contact would require restarting the daemon.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite");
        let p = peer();

        let writer = Contacts::open(&path).unwrap();
        let reader = Contacts::open(&path).unwrap();

        assert!(reader.get(&p).unwrap().is_none());
        writer.add(&p, "bob").unwrap();
        assert!(
            reader.get(&p).unwrap().is_some(),
            "a second connection should see the write immediately"
        );
    }
}
