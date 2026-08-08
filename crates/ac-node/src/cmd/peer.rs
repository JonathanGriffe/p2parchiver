//! `ac peer` — manage the contact list.
//!
//! These edit who this node looks for, not who it accepts. See [`crate::contacts`].

use ac_net::PeerId;
use ac_net::config::Paths;
use anyhow::{Context, Result};

use crate::contacts::Contacts;

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
    let contacts = open(paths)?.list().context("listing contacts")?;

    if contacts.is_empty() {
        println!("no contacts. add one with: ac peer add <peer-id> --label <name>");
        return Ok(());
    }

    let widest = contacts.iter().map(|c| c.label.len()).max().unwrap_or(0);
    for contact in contacts {
        println!("{:<widest$}  {}", contact.label, contact.peer);
    }
    Ok(())
}
