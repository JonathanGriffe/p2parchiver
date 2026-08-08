//! The server's database: who may use it, and the invites that let them in.
//!
//! # What the connection-level gate actually checks
//!
//! It refuses **revoked** peers, not un-enrolled ones. That looks inconsistent with
//! "the server has an allowlist" until you notice that enrolling *requires a
//! connection* — gating connections on enrollment would be the same bootstrapping
//! deadlock as the client-side trust list, one layer down.
//!
//! So the split is:
//!
//! - **Connection**: refuse peers explicitly revoked. Everyone else may connect, because
//!   they might be about to enroll.
//! - **Service** (relay reservation, rendezvous registration, stage 6): require
//!   enrollment. This is where the server's bandwidth is actually spent — a connection
//!   that never opens a circuit costs a handshake and a slot, nothing more.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use ac_net::PeerId;
use ac_net::authz::PeerAuthorizer;
use rusqlite::{Connection, OptionalExtension, params};

use crate::invite::InviteCode;

/// Unix seconds. Passed in explicitly rather than read inside queries so that TTL and
/// expiry can be tested without waiting or faking a clock.
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The outcome of presenting an invite code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Redemption {
    Enrolled,
    UnknownCode,
    AlreadyRedeemed,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteRecord {
    pub code_hash: String,
    pub label: String,
    pub expires_at: i64,
    pub redeemed_by: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRecord {
    pub peer: PeerId,
    pub label: String,
    pub enrolled_at: i64,
    /// `None` while the client is active. Kept as a timestamp rather than a flag so a
    /// revocation stays visible after the fact — the row is evidence, not just state.
    pub revoked_at: Option<i64>,
}

impl ClientRecord {
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }
}

pub struct Store {
    db: Connection,
}

impl Store {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        Self::from_connection(Connection::open(path)?)
    }

    #[cfg(test)]
    pub(crate) fn in_memory() -> rusqlite::Result<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(db: Connection) -> rusqlite::Result<Self> {
        // WAL so the admin CLI can revoke a client while the daemon is reading, which is
        // what makes revocation take effect without a restart.
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS invites (
                 code_hash   TEXT PRIMARY KEY NOT NULL,
                 label       TEXT NOT NULL,
                 expires_at  INTEGER NOT NULL,
                 redeemed_by TEXT,
                 redeemed_at INTEGER
             );
             CREATE TABLE IF NOT EXISTS clients (
                 peer_id     TEXT PRIMARY KEY NOT NULL,
                 label       TEXT NOT NULL,
                 enrolled_at INTEGER NOT NULL,
                 revoked_at  INTEGER
             );",
        )?;
        Ok(Self { db })
    }

    // ---- invites ----

    /// Record a new invite. Only its hash is stored.
    pub fn create_invite(
        &self,
        code: &InviteCode,
        label: &str,
        expires_at: i64,
    ) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT INTO invites (code_hash, label, expires_at) VALUES (?1, ?2, ?3)",
            params![code.hash(), label, expires_at],
        )?;
        Ok(())
    }

    pub fn list_invites(&self) -> rusqlite::Result<Vec<InviteRecord>> {
        let mut stmt = self.db.prepare(
            "SELECT code_hash, label, expires_at, redeemed_by FROM invites ORDER BY expires_at",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(InviteRecord {
                code_hash: r.get(0)?,
                label: r.get(1)?,
                expires_at: r.get(2)?,
                redeemed_by: r.get(3)?,
            })
        })?;
        rows.collect()
    }

    /// Spend an invite and enroll `peer`.
    ///
    /// The read and both writes share one transaction, so two clients racing on the same
    /// code cannot both win — single use is enforced by the database, not by timing.
    pub fn redeem(
        &self,
        code: &InviteCode,
        peer: &PeerId,
        now: i64,
    ) -> rusqlite::Result<Redemption> {
        let tx = self.db.unchecked_transaction()?;
        let hash = code.hash();

        let found: Option<(i64, Option<String>, String)> = tx
            .query_row(
                "SELECT expires_at, redeemed_by, label FROM invites WHERE code_hash = ?1",
                params![hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;

        let Some((expires_at, redeemed_by, label)) = found else {
            return Ok(Redemption::UnknownCode);
        };
        if redeemed_by.is_some() {
            return Ok(Redemption::AlreadyRedeemed);
        }
        if expires_at <= now {
            return Ok(Redemption::Expired);
        }

        // `redeemed_by IS NULL` repeats what the SELECT above already established, on
        // purpose. Without it, single use would rest on transaction isolation — correct
        // in WAL mode, but by way of a snapshot-conflict error rather than a clean
        // refusal. With it, the statement itself carries the invariant: it either finds
        // an unspent invite or changes nothing.
        let spent = tx.execute(
            "UPDATE invites SET redeemed_by = ?1, redeemed_at = ?2
             WHERE code_hash = ?3 AND redeemed_by IS NULL",
            params![peer.to_string(), now, hash],
        )?;
        if spent != 1 {
            // Another redemption committed between our read and this write.
            return Ok(Redemption::AlreadyRedeemed);
        }
        // Deliberately does *not* clear `revoked_at`. A revoked peer is refused at
        // connection establishment, so it can never reach this code — a clause here that
        // "brings them back" would be unreachable, and would describe behaviour the
        // server does not have. Reversing a revocation is [`Self::unrevoke`], an explicit
        // admin action, matching the explicit action that caused it.
        tx.execute(
            "INSERT INTO clients (peer_id, label, enrolled_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(peer_id) DO UPDATE SET label = excluded.label",
            params![peer.to_string(), label, now],
        )?;
        tx.commit()?;

        Ok(Redemption::Enrolled)
    }

    // ---- clients ----

    pub fn list_clients(&self) -> rusqlite::Result<Vec<ClientRecord>> {
        let mut stmt = self.db.prepare(
            "SELECT peer_id, label, enrolled_at, revoked_at FROM clients ORDER BY label",
        )?;
        let rows = stmt.query_map([], |r| {
            let raw: String = r.get(0)?;
            Ok(raw.parse::<PeerId>().ok().map(|peer| ClientRecord {
                peer,
                label: r.get(1).unwrap_or_default(),
                enrolled_at: r.get(2).unwrap_or_default(),
                revoked_at: r.get(3).unwrap_or_default(),
            }))
        })?;

        let mut out = Vec::new();
        for row in rows {
            if let Some(record) = row? {
                out.push(record);
            }
        }
        Ok(out)
    }

    /// Returns whether a client was there to revoke.
    pub fn revoke(&self, peer: &PeerId, now: i64) -> rusqlite::Result<bool> {
        let n = self.db.execute(
            "UPDATE clients SET revoked_at = ?1 WHERE peer_id = ?2 AND revoked_at IS NULL",
            params![now, peer.to_string()],
        )?;
        Ok(n > 0)
    }

    /// Reverse a revocation. Returns whether there was one to reverse.
    pub fn unrevoke(&self, peer: &PeerId) -> rusqlite::Result<bool> {
        let n = self.db.execute(
            "UPDATE clients SET revoked_at = NULL WHERE peer_id = ?1 AND revoked_at IS NOT NULL",
            params![peer.to_string()],
        )?;
        Ok(n > 0)
    }

    pub fn is_enrolled(&self, peer: &PeerId) -> bool {
        self.db
            .query_row(
                "SELECT 1 FROM clients WHERE peer_id = ?1 AND revoked_at IS NULL",
                params![peer.to_string()],
                |_| Ok(()),
            )
            .optional()
            .unwrap_or(None)
            .is_some()
    }

    pub fn is_revoked(&self, peer: &PeerId) -> bool {
        self.db
            .query_row(
                "SELECT 1 FROM clients WHERE peer_id = ?1 AND revoked_at IS NOT NULL",
                params![peer.to_string()],
                |_| Ok(()),
            )
            .optional()
            .unwrap_or(None)
            .is_some()
    }
}

/// The service listener's policy: **enrolled peers only**.
///
/// This is the gate that could not exist while one listener served both enrolment and
/// services — a stranger refused here could never have enrolled. With enrolment on its own
/// listener, the two policies stop contradicting each other, and everything the service
/// listener speaks is behind this one check rather than being gated protocol by protocol.
pub struct Enrolled(pub Store);

impl PeerAuthorizer for Enrolled {
    fn is_allowed(&self, peer: &PeerId) -> bool {
        // `is_enrolled` already excludes revoked clients.
        self.0.is_enrolled(peer)
    }
}

impl PeerAuthorizer for Store {
    /// Refuse only peers that were explicitly revoked — see the module docs for why this
    /// is not "is enrolled".
    ///
    /// A database error reads as "not revoked". Failing open is deliberate: a corrupt or
    /// locked database should degrade the server to an open relay, not silently cut off
    /// every legitimate client, and the service-level checks in stage 6 still apply.
    fn is_allowed(&self, peer: &PeerId) -> bool {
        !self.is_revoked(peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: i64 = 3600;

    fn peer() -> PeerId {
        libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id()
    }

    fn store_with_invite(expires_at: i64) -> (Store, InviteCode) {
        let store = Store::in_memory().unwrap();
        let code = InviteCode::generate().unwrap();
        store
            .create_invite(&code, "bobs-laptop", expires_at)
            .unwrap();
        (store, code)
    }

    #[test]
    fn a_valid_code_enrolls_the_peer() {
        let (store, code) = store_with_invite(now() + HOUR);
        let p = peer();

        assert_eq!(
            store.redeem(&code, &p, now()).unwrap(),
            Redemption::Enrolled
        );
        assert!(store.is_enrolled(&p));
        assert!(!store.is_revoked(&p));
    }

    #[test]
    fn the_label_carries_from_invite_to_client() {
        let (store, code) = store_with_invite(now() + HOUR);
        let p = peer();
        store.redeem(&code, &p, now()).unwrap();

        let clients = store.list_clients().unwrap();
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0].label, "bobs-laptop");
    }

    #[test]
    fn a_code_cannot_be_used_twice() {
        let (store, code) = store_with_invite(now() + HOUR);

        assert_eq!(
            store.redeem(&code, &peer(), now()).unwrap(),
            Redemption::Enrolled
        );
        assert_eq!(
            store.redeem(&code, &peer(), now()).unwrap(),
            Redemption::AlreadyRedeemed,
            "a replayed code must not enroll a second peer"
        );
    }

    #[test]
    fn an_expired_code_is_refused() {
        let (store, code) = store_with_invite(now() - 1);
        let p = peer();

        assert_eq!(store.redeem(&code, &p, now()).unwrap(), Redemption::Expired);
        assert!(!store.is_enrolled(&p));
    }

    #[test]
    fn expiry_is_checked_against_the_moment_of_redemption() {
        let issued = 1_000_000;
        let (store, code) = store_with_invite(issued + HOUR);

        assert_eq!(
            store.redeem(&code, &peer(), issued + HOUR - 1).unwrap(),
            Redemption::Enrolled
        );
    }

    #[test]
    fn an_unknown_code_is_refused() {
        let store = Store::in_memory().unwrap();
        let never_issued = InviteCode::generate().unwrap();

        assert_eq!(
            store.redeem(&never_issued, &peer(), now()).unwrap(),
            Redemption::UnknownCode
        );
    }

    #[test]
    fn only_the_hash_reaches_the_database() {
        let (store, code) = store_with_invite(now() + HOUR);
        let stored = &store.list_invites().unwrap()[0];

        assert_eq!(stored.code_hash, code.hash());
        assert!(
            !stored
                .code_hash
                .contains(&code.to_string().replace('-', "")),
            "a leaked backup must not contain live invite codes"
        );
    }

    #[test]
    fn revocation_takes_the_client_out() {
        let (store, code) = store_with_invite(now() + HOUR);
        let p = peer();
        store.redeem(&code, &p, now()).unwrap();

        assert!(store.revoke(&p, now()).unwrap());
        assert!(!store.is_enrolled(&p));
        assert!(store.is_revoked(&p));
    }

    #[test]
    fn revoking_twice_reports_nothing_to_do() {
        let (store, code) = store_with_invite(now() + HOUR);
        let p = peer();
        store.redeem(&code, &p, now()).unwrap();

        assert!(store.revoke(&p, now()).unwrap());
        assert!(!store.revoke(&p, now()).unwrap());
    }

    #[test]
    fn revocation_is_recorded_not_erased() {
        let (store, code) = store_with_invite(now() + HOUR);
        let p = peer();
        store.redeem(&code, &p, now()).unwrap();
        store.revoke(&p, 1_234_567).unwrap();

        let clients = store.list_clients().unwrap();
        assert_eq!(clients[0].revoked_at, Some(1_234_567));
        assert!(clients[0].is_revoked());
    }

    #[test]
    fn unrevoke_restores_a_revoked_client() {
        let (store, code) = store_with_invite(now() + HOUR);
        let p = peer();
        store.redeem(&code, &p, now()).unwrap();
        store.revoke(&p, now()).unwrap();

        assert!(store.unrevoke(&p).unwrap());
        assert!(store.is_enrolled(&p));
        assert!(!store.is_revoked(&p));
        assert!(store.is_allowed(&p), "they may connect again");
    }

    #[test]
    fn unrevoke_reports_when_there_was_nothing_to_undo() {
        let (store, code) = store_with_invite(now() + HOUR);
        let p = peer();
        store.redeem(&code, &p, now()).unwrap();

        assert!(!store.unrevoke(&p).unwrap(), "this client is not revoked");
        assert!(!store.unrevoke(&peer()).unwrap(), "this one does not exist");
    }

    #[test]
    fn redeeming_again_does_not_quietly_undo_a_revocation() {
        // Unreachable in practice — a revoked peer cannot connect, so it can never
        // redeem — but if that gate ever changes, re-enrolment must not become a back
        // door around an admin's decision.
        let store = Store::in_memory().unwrap();
        let first = InviteCode::generate().unwrap();
        store.create_invite(&first, "bob", now() + HOUR).unwrap();
        let p = peer();
        store.redeem(&first, &p, now()).unwrap();
        store.revoke(&p, now()).unwrap();

        let second = InviteCode::generate().unwrap();
        store.create_invite(&second, "bob", now() + HOUR).unwrap();
        store.redeem(&second, &p, now()).unwrap();

        assert!(
            store.is_revoked(&p),
            "only `unrevoke` may reverse a revocation"
        );
    }

    #[test]
    fn the_connection_gate_refuses_revoked_peers_only() {
        let (store, code) = store_with_invite(now() + HOUR);
        let enrolled = peer();
        let stranger = peer();
        store.redeem(&code, &enrolled, now()).unwrap();

        assert!(store.is_allowed(&enrolled));
        assert!(
            store.is_allowed(&stranger),
            "an un-enrolled peer must be able to connect, or it could never enroll"
        );

        store.revoke(&enrolled, now()).unwrap();
        assert!(!store.is_allowed(&enrolled));
    }

    #[test]
    fn revocation_is_visible_to_a_separate_connection() {
        // `ac-server client revoke` runs in a different process from the daemon.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite");

        let admin = Store::open(&path).unwrap();
        let daemon = Store::open(&path).unwrap();

        let code = InviteCode::generate().unwrap();
        admin.create_invite(&code, "bob", now() + HOUR).unwrap();
        let p = peer();
        admin.redeem(&code, &p, now()).unwrap();

        assert!(daemon.is_allowed(&p));
        admin.revoke(&p, now()).unwrap();
        assert!(
            !daemon.is_allowed(&p),
            "the daemon must see a revocation without restarting"
        );
    }
}
