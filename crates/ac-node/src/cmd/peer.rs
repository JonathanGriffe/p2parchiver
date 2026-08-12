//! `ac peer` — the contact list, and what the supervisor is doing.
//!
//! `add` and `remove` edit the hand-written list, and only ever that. `list` shows the wider
//! view from [`crate::directory`]: contacts *and* fellow group members, since both are people
//! this node knows a name for, and a person looking for someone does not care which table the
//! name came from. The `via` column keeps the distinction visible, because the two names come
//! from different places and are trustworthy in different ways.

use std::collections::HashMap;

use ac_groups::store::Groups;
use ac_net::PeerId;
use ac_net::attest;
use ac_net::config::Paths;
use ac_net::identity::Identity;
use anyhow::{Context, Result};

use crate::contacts::Contacts;
use crate::directory::{self, Source};
use crate::status::Published;

/// How stale a snapshot may be before it is reported as a stopped daemon.
///
/// The daemon publishes on the 5-second housekeeping tick, so anything past a minute means it
/// is not running — which is the commonest answer to "why is nothing happening" and deserves
/// to be the first line rather than something a person infers from empty columns.
const STALE_AFTER: i64 = 60;

fn open(paths: &Paths) -> Result<Contacts> {
    let path = paths.db_file();
    Contacts::open(&path).with_context(|| format!("opening contacts at {}", path.display()))
}

pub fn add(paths: &Paths, peer: &PeerId, label: &str) -> Result<()> {
    let added = open(paths)?
        .add(peer, label)
        .with_context(|| format!("adding contact {peer}"))?;

    if added {
        println!("added {label} ({peer})");
    } else {
        println!("relabelled {peer} to {label}");
    }
    Ok(())
}

pub fn remove(paths: &Paths, peer: &PeerId) -> Result<()> {
    if open(paths)?
        .remove(peer)
        .with_context(|| format!("removing contact {peer}"))?
    {
        println!("removed {peer}");
    } else {
        println!("no such contact: {peer}");
    }
    Ok(())
}

pub fn list(paths: &Paths) -> Result<()> {
    let key_path = paths.identity_file();
    let (identity, _) = Identity::load_or_generate(&key_path)
        .with_context(|| format!("loading identity from {}", key_path.display()))?;

    let db = paths.db_file();
    let groups = Groups::open(&db, identity.peer_id())
        .with_context(|| format!("opening the group store at {}", db.display()))?;

    let known = directory::everyone(&open(paths)?, &groups, identity.peer_id())?;

    if known.is_empty() {
        println!("nobody yet. add someone with: ac peer add <peer-id> --label <name>");
        println!("fellow members of your groups appear here too.");
        return Ok(());
    }

    let widest = known.iter().map(|k| k.name.len()).max().unwrap_or(0);
    for entry in known {
        // Which kind of name this is, not decoration: a contact label was typed here, while a
        // group username is whatever that group's admin wrote and can name anyone at all.
        let via = match entry.source {
            Source::Contact => "contact",
            Source::Group => "group",
        };
        println!("{:<widest$}  {:<7}  {}", entry.name, via, entry.peer);
    }
    Ok(())
}

/// `ac peer status` — why the supervisor is, or is not, doing anything.
///
/// Read from the snapshot the running daemon publishes, because none of it exists anywhere
/// else: a backoff, a member believed offline and a suspended content pull are all in memory
/// in another process. Names come from the same [`crate::directory`] view `list` uses, since a
/// bare peer id answers nothing.
pub fn status(paths: &Paths) -> Result<()> {
    let key_path = paths.identity_file();
    let (identity, _) = Identity::load_or_generate(&key_path)
        .with_context(|| format!("loading identity from {}", key_path.display()))?;

    let db = paths.db_file();
    let published = Published::open(&db).with_context(|| format!("opening {}", db.display()))?;
    let snapshot = published
        .read()
        .context("reading the supervisor's status")?;

    let now = attest::now();
    match snapshot.at {
        None => {
            println!("the node has never run. start it with: ac run");
            return Ok(());
        }
        Some(at) if now - at > STALE_AFTER => {
            println!("last seen {}s ago — the node is not running.", now - at);
            println!("  start it with: ac run");
            println!();
        }
        Some(_) => {}
    }

    let groups = Groups::open(&db, identity.peer_id())
        .with_context(|| format!("opening the group store at {}", db.display()))?;
    let contacts = open(paths)?;
    let names: HashMap<PeerId, String> =
        directory::everyone(&contacts, &groups, identity.peer_id())?
            .into_iter()
            .map(|entry| (entry.peer, entry.name))
            .collect();
    let name = |peer: &PeerId| {
        names
            .get(peer)
            .cloned()
            .unwrap_or_else(|| peer.to_base58()[..8].to_owned())
    };

    if snapshot.groups.is_empty() {
        println!("no groups. create one with: ac group create --name <name>");
    }
    for group in &snapshot.groups {
        let label = groups
            .get(group.group)
            .ok()
            .flatten()
            .map(|row| row.name)
            .unwrap_or_else(|| group.group.short());

        println!("{label} ({})", group.group.short());
        println!("  missing   {}", group.missing);
        println!(
            "  news      {}",
            match group.unheard {
                0 => "everyone has it".to_owned(),
                1 => "1 member still to tell".to_owned(),
                n => format!("{n} members still to tell"),
            }
        );
        match group.source {
            Some(peer) => println!("  pulling   from {}", name(&peer)),
            // Two different silences, and telling them apart is the point of the command: a
            // suspended pull is working as designed after a fruitless rotation, while an idle
            // one with files missing means nobody reachable has them.
            None if now < group.content_until => {
                println!("  pulling   paused for {}s", group.content_until - now);
            }
            None if group.missing > 0 => println!("  pulling   nobody has offered them"),
            None => println!("  pulling   nothing to fetch"),
        }
        if let Some(peer) = group.next {
            println!("  next      {}", name(&peer));
        }
        println!("  heartbeat in {}s", (group.heartbeat_at - now).max(0));
    }

    if snapshot.peers.is_empty() {
        return Ok(());
    }
    println!();
    let widest = snapshot
        .peers
        .iter()
        .map(|p| name(&p.peer).len())
        .max()
        .unwrap_or(0);

    for peer in &snapshot.peers {
        let state = if peer.connected {
            let mut busy = Vec::new();
            if peer.rounds > 0 {
                busy.push(format!("{} round(s)", peer.rounds));
            }
            if peer.transfers > 0 {
                busy.push(format!("{} transfer(s)", peer.transfers));
            }
            if peer.closing {
                busy.push("closing".to_owned());
            }
            if busy.is_empty() {
                "connected, idle".to_owned()
            } else {
                format!("connected, {}", busy.join(", "))
            }
        } else if now < peer.retry_at {
            format!("backed off for {}s", peer.retry_at - now)
        } else if peer.online {
            "online, not connected".to_owned()
        } else {
            "not seen".to_owned()
        };
        println!("{:<widest$}  {}", name(&peer.peer), state);
    }
    Ok(())
}
