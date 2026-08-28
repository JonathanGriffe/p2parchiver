use std::collections::HashMap;

use ac_groups::id::GroupId;
use ac_net::PeerId;
use ac_net::attest;
use ac_net::config::Paths;
use anyhow::{Context, Result, anyhow};

use super::{Known, now, open};
use crate::contacts::Contacts;
use crate::directory;
use crate::status::Published;

/// How stale a snapshot may be before it is reported as a stopped daemon.
pub const STALE_AFTER: i64 = 60;

pub struct Labelled {
    pub label: String,
    pub peer: PeerId,
    /// False when the peer was already known and only the label changed.
    pub was_new: bool,
}

fn contacts(paths: &Paths) -> Result<Contacts> {
    let path = paths.db_file();
    Contacts::open(&path).with_context(|| format!("opening contacts at {}", path.display()))
}

pub fn add(paths: &Paths, peer: &PeerId, label: &str) -> Result<Labelled> {
    let label =
        attest::normalise_username(label).map_err(|e| anyhow!("unusable label {label:?}: {e}"))?;

    let was_new = contacts(paths)?
        .add(peer, &label)
        .with_context(|| format!("adding contact {peer}"))?;

    Ok(Labelled {
        label,
        peer: *peer,
        was_new,
    })
}

/// Whether there was a contact to remove.
pub fn remove(paths: &Paths, peer: &PeerId) -> Result<bool> {
    contacts(paths)?
        .remove(peer)
        .with_context(|| format!("removing contact {peer}"))
}

/// Everyone this node has a name for: contacts, plus fellow members of its groups.
pub fn list(paths: &Paths) -> Result<Vec<Known>> {
    let (identity, groups) = open(paths)?;
    directory::everyone(&contacts(paths)?, &groups, identity.peer_id())
}

/// Whether the daemon is running, as far as its last published snapshot can say.
pub enum Liveness {
    /// No snapshot has ever been written.
    Never,
    /// The last one is older than [`STALE_AFTER`].
    Stale {
        seconds: i64,
    },
    Live,
}

pub struct GroupProgress {
    pub group: GroupId,
    /// The group's name, falling back to its short id when it has none yet.
    pub label: String,
    pub missing: u64,
    pub owed: usize,
    pub source: Option<String>,
    pub next: Option<String>,
    pub content_until: i64,
    pub heartbeat_at: i64,
}

pub struct PeerProgress {
    pub peer: PeerId,
    pub name: String,
    pub connected: bool,
    pub online: bool,
    pub retry_at: i64,
    pub rounds: usize,
    pub transfers: usize,
    pub closing: bool,
}

pub struct StatusReport {
    pub liveness: Liveness,
    /// The clock the rest of this report is relative to.
    pub now: i64,
    pub groups: Vec<GroupProgress>,
    pub peers: Vec<PeerProgress>,
}

/// Why the supervisor is, or is not, doing anything.
pub fn status(paths: &Paths) -> Result<StatusReport> {
    let (identity, groups) = open(paths)?;

    let db = paths.db_file();
    let published = Published::open(&db).with_context(|| format!("opening {}", db.display()))?;
    let snapshot = published
        .read()
        .context("reading the supervisor's status")?;

    let at = now();
    let liveness = match snapshot.at {
        None => Liveness::Never,
        Some(published_at) if at - published_at > STALE_AFTER => Liveness::Stale {
            seconds: at - published_at,
        },
        Some(_) => Liveness::Live,
    };

    let names: HashMap<PeerId, String> =
        directory::everyone(&contacts(paths)?, &groups, identity.peer_id())?
            .into_iter()
            .map(|entry| (entry.peer, entry.name))
            .collect();
    let name = |peer: &PeerId| {
        names
            .get(peer)
            .cloned()
            .unwrap_or_else(|| peer.to_base58()[..8].to_owned())
    };

    let group_rows = snapshot
        .groups
        .iter()
        .map(|group| GroupProgress {
            group: group.group,
            label: groups
                .get(group.group)
                .ok()
                .flatten()
                .map(|row| row.name)
                .unwrap_or_else(|| group.group.short()),
            missing: group.missing,
            owed: group.owed,
            source: group.source.as_ref().map(&name),
            next: group.next.as_ref().map(&name),
            content_until: group.content_until,
            heartbeat_at: group.heartbeat_at,
        })
        .collect();

    let peer_rows = snapshot
        .peers
        .iter()
        .map(|peer| PeerProgress {
            peer: peer.peer,
            name: name(&peer.peer),
            connected: peer.connected,
            online: peer.online,
            retry_at: peer.retry_at,
            rounds: peer.rounds,
            transfers: peer.transfers,
            closing: peer.closing,
        })
        .collect();

    Ok(StatusReport {
        liveness,
        now: at,
        groups: group_rows,
        peers: peer_rows,
    })
}
