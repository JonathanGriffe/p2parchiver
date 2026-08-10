//! `ac peer` — manage the contact list.
//!
//! `add` and `remove` edit the hand-written list, and only ever that. `list` shows the wider
//! view from [`crate::directory`]: contacts *and* fellow group members, since both are people
//! this node knows a name for, and a person looking for someone does not care which table the
//! name came from. The `via` column keeps the distinction visible, because the two names come
//! from different places and are trustworthy in different ways.

use ac_groups::store::Groups;
use ac_net::PeerId;
use ac_net::config::Paths;
use ac_net::identity::Identity;
use anyhow::{Context, Result};

use crate::contacts::Contacts;
use crate::directory::{self, Source};

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
