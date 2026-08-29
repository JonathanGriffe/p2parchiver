use ac_net::PeerId;
use ac_net::config::Paths;
use anyhow::Result;

use crate::ops::format::state_name;
use crate::ops::group::{Accepted, Departed, LogLine};
use crate::ops::{self};

pub fn create(paths: &Paths, name: &str) -> Result<()> {
    let created = ops::group::create(paths, name)?;

    println!("created {} ({})", created.name, created.id.short());
    println!("id    {}", created.id);
    println!("admin {} (this node)", created.admin);
    println!();
    println!("You are this group's only admin: nobody else can add or remove members, and");
    println!("that cannot be transferred, so losing this node's key freezes the group.");
    println!();
    println!(
        "Add someone with: ac group add {} <peer-id>",
        created.id.short()
    );
    Ok(())
}

pub fn list(paths: &Paths) -> Result<()> {
    let rows = ops::group::list(paths)?;

    if rows.is_empty() {
        println!("no groups. create one with: ac group create --name <name>");
        return Ok(());
    }

    let widest = rows.iter().map(|r| r.name.len()).max().unwrap_or(0);
    for row in rows {
        let mut notes = Vec::new();
        if row.is_admin {
            notes.push("admin".to_owned());
        }
        if row.removed_by_admin {
            notes.push("removed by admin".to_owned());
        }

        let note = if notes.is_empty() {
            String::new()
        } else {
            format!("  ({})", notes.join(", "))
        };
        println!(
            "{:<widest$}  {}  {:<7}  {} member(s){note}",
            row.name,
            row.id.short(),
            state_name(row.state),
            row.members,
        );
    }
    Ok(())
}

pub fn show(paths: &Paths, needle: &str, log: bool) -> Result<()> {
    let detail = ops::group::show(paths, needle, log)?;
    let row = &detail.row;

    println!("id      {}", row.id);
    println!("name    {}", row.name);
    println!(
        "admin   {}{}",
        row.admin,
        if detail.is_admin { "  (this node)" } else { "" }
    );
    println!("state   {}", state_name(row.state));
    println!("entries {}", row.head_seq);

    println!();
    println!("members");
    // A member who has not published a standing yet has told us no name at all.
    let named = |m: &ops::group::MemberView| m.username.clone().unwrap_or_else(|| "?".to_owned());
    let widest = detail
        .members
        .iter()
        .map(|m| named(m).len())
        .max()
        .unwrap_or(0);
    for member in &detail.members {
        let mut notes = Vec::new();
        if member.is_admin {
            notes.push("admin");
        }
        if member.is_me {
            notes.push("this node");
        }
        if member.departed {
            notes.push("has left, awaiting removal");
        }
        let note = if notes.is_empty() {
            String::new()
        } else {
            format!("  ({})", notes.join(", "))
        };
        println!("  {:<widest$}  {}{note}", named(member), member.peer);
    }

    if let Some(log) = detail.log {
        println!();
        println!("log");
        for (seq, line) in log.iter().enumerate() {
            match line {
                LogLine::Said(said) => println!("  {seq:>3}  {said}"),
                LogLine::Unreadable(why) => println!("  {seq:>3}  <unreadable: {why}>"),
            }
        }
    }
    Ok(())
}

pub fn add(paths: &Paths, needle: &str, peer: &PeerId) -> Result<()> {
    let added = ops::group::add(paths, needle, peer)?;

    println!("added {}", added.peer);
    println!();
    println!("They will be told the next time this node and theirs are both online and");
    println!("connected. Being added is an invitation: they choose whether to accept.");
    Ok(())
}

pub fn remove(paths: &Paths, needle: &str, peer: &PeerId) -> Result<()> {
    ops::group::remove(paths, needle, peer)?;

    println!("removed {peer}");
    println!();
    println!("They stop being served by every member that has seen this, and will find out");
    println!("themselves next time they ask. It does not reach back: anything already shared");
    println!("with them is theirs, and no membership change can undo that.");
    Ok(())
}

pub fn accept(paths: &Paths, needle: &str) -> Result<()> {
    match ops::group::accept(paths, needle)? {
        Accepted::Already(name) => println!("already a member of {name}"),
        Accepted::Joined(name) => println!("joined {name}"),
    }
    Ok(())
}

pub fn leave(paths: &Paths, needle: &str) -> Result<()> {
    match ops::group::leave(paths, needle)? {
        Departed::Already(name) => {
            println!("already left {name}");
            return Ok(());
        }
        Departed::Left(name) => println!("left {name}"),
    }

    println!();
    println!("This node stops sharing that group immediately, whatever anyone else believes.");
    println!("The others are told when they next connect, and the admin then makes it");
    println!("official. Being added again will not undo this, you would accept afresh.");
    Ok(())
}

pub fn forget(paths: &Paths, needle: &str) -> Result<()> {
    let forgotten = ops::group::forget(paths, needle)?;

    println!("forgot {} locally", forgotten.name);
    if forgotten.held > 0 {
        println!();
        println!(
            "{} file(s) were left on disk, no longer indexed:",
            forgotten.held
        );
        if let Some(dir) = forgotten.dir {
            println!("  {}", dir.display());
        }
    }
    if forgotten.was_admin {
        println!();
        println!("You were this group's admin, so nobody can change its membership again.");
        println!("Other members keep their copy and can still reach each other with it.");
    } else {
        println!();
        println!("Nothing was told to anyone. The others still list you, and will keep");
        println!("offering it, use `ac group leave` instead if you meant to tell them.");
    }
    Ok(())
}
