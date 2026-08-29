use ac_net::PeerId;
use ac_net::config::Paths;
use anyhow::Result;

use crate::ops::peer::Liveness;
use crate::ops::{self, Source};

pub fn add(paths: &Paths, peer: &PeerId, label: &str) -> Result<()> {
    let added = ops::peer::add(paths, peer, label)?;

    if added.was_new {
        println!("added {} ({})", added.label, added.peer);
    } else {
        println!("relabelled {} to {}", added.peer, added.label);
    }
    Ok(())
}

pub fn remove(paths: &Paths, peer: &PeerId) -> Result<()> {
    if ops::peer::remove(paths, peer)? {
        println!("removed {peer}");
    } else {
        println!("no such contact: {peer}");
    }
    Ok(())
}

pub fn list(paths: &Paths) -> Result<()> {
    let known = ops::peer::list(paths)?;

    if known.is_empty() {
        println!("nobody yet. add someone with: ac peer add <peer-id> --label <name>");
        println!("fellow members of your groups appear here too.");
        return Ok(());
    }

    // A peer met through a group who has published nothing is shown by the only thing this
    // node knows about them.
    let shown = |k: &crate::ops::Known| {
        k.name
            .clone()
            .unwrap_or_else(|| k.peer.to_base58()[..8].to_owned())
    };
    let widest = known.iter().map(|k| shown(k).len()).max().unwrap_or(0);
    for entry in known {
        let via = match entry.source {
            Source::Contact => "contact",
            Source::Group => "group",
        };
        println!("{:<widest$}  {:<7}  {}", shown(&entry), via, entry.peer);
    }
    Ok(())
}

/// `ac peer status`: why the supervisor is, or is not, doing anything.
pub fn status(paths: &Paths) -> Result<()> {
    let report = ops::peer::status(paths)?;
    let now = report.now;

    match report.liveness {
        Liveness::Never => {
            println!("the node has never run. start it with: ac run");
            return Ok(());
        }
        Liveness::Stale { seconds } => {
            println!("last seen {seconds}s ago, the node is not running.");
            println!("  start it with: ac run");
            println!();
        }
        Liveness::Live => {}
    }

    if report.groups.is_empty() {
        println!("no groups. create one with: ac group create --name <name>");
    }
    for group in &report.groups {
        println!("{} ({})", group.label, group.group.short());
        println!("  missing   {}", group.missing);
        println!(
            "  news      {}",
            match group.owed {
                0 => "nobody left to call".to_owned(),
                1 => "1 member to call".to_owned(),
                n => format!("{n} members to call"),
            }
        );
        match &group.source {
            Some(name) => println!("  pulling   from {name}"),
            None if now < group.content_until => {
                println!("  pulling   paused for {}s", group.content_until - now);
            }
            None if group.missing > 0 => println!("  pulling   nobody has offered them"),
            None => println!("  pulling   nothing to fetch"),
        }
        if let Some(name) = &group.next {
            println!("  next      {name}");
        }
        println!("  heartbeat in {}s", (group.heartbeat_at - now).max(0));
    }

    if report.peers.is_empty() {
        return Ok(());
    }
    println!();
    let widest = report.peers.iter().map(|p| p.name.len()).max().unwrap_or(0);

    for peer in &report.peers {
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
        println!("{:<widest$}  {}", peer.name, state);
    }
    Ok(())
}
