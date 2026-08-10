//! `ac group` — create groups and decide who is in them.
//!
//! Every command here writes to `state.sqlite` and returns. A running `ac run` picks the
//! change up on its next housekeeping tick and tells the peers that should hear about it —
//! the same arrangement `ac peer add` already uses, and the reason the store insists on
//! `BEGIN IMMEDIATE` and a busy timeout.
//!
//! Nothing here talks to the network, so every command works offline. What it cannot do
//! offline is *propagate*, which is a property of the design rather than a limitation of the
//! CLI: membership is a signed log, so a change is real the moment it is signed and merely
//! unseen until someone connects.

use ac_groups::chain::Op;
use ac_groups::store::{GroupRow, State};
use ac_net::PeerId;
use ac_net::attest;
use ac_net::config::Paths;
use ac_net::identity::Identity;
use anyhow::{Context, Result, anyhow, bail};

use super::{now, open, open_files, resolve};
use crate::contacts::Contacts;

pub fn create(paths: &Paths, name: &str) -> Result<()> {
    let (identity, mut groups) = open(paths)?;

    // The name we go by inside the group is the one the server attested, not one invented
    // here — so a member's advisory username and their attested one start out agreeing.
    let attestation = attest::load(&paths.attestation_file())
        .context("reading this node's attestation")?
        .ok_or_else(|| anyhow!("this node has not enrolled with a server; run `ac join` first"))?;
    let username = attestation
        .statement()
        .map_err(|e| anyhow!("{e}"))
        .context("reading the stored attestation")?
        .username;

    let id = groups
        .create(identity.keypair(), name, &username, now())
        .with_context(|| format!("creating group {name:?}"))?;

    println!("created {name} ({})", id.short());
    println!("id    {id}");
    println!("admin {} (this node)", identity.peer_id());
    println!();
    println!("You are this group's only admin: nobody else can add or remove members, and");
    println!("that cannot be transferred, so losing this node's key freezes the group.");
    println!();
    println!("Add someone with: ac group add {} <peer-id>", id.short());
    Ok(())
}

pub fn list(paths: &Paths) -> Result<()> {
    let (identity, groups) = open(paths)?;
    let rows = groups.list().context("listing groups")?;

    if rows.is_empty() {
        println!("no groups. create one with: ac group create --name <name>");
        return Ok(());
    }

    let widest = rows.iter().map(|r| r.name.len()).max().unwrap_or(0);
    for row in rows {
        let members = groups.members(row.id).unwrap_or_default();
        let mut notes = Vec::new();

        if row.admin == identity.peer_id() {
            notes.push("admin".to_owned());
        }
        if row.is_quarantined() {
            notes.push("FORKED — needs attention".to_owned());
        } else if !members.contains(&identity.peer_id()) {
            // We hold the group but the chain no longer lists us. Worth saying plainly:
            // `state` is our own consent and does not change when someone removes us.
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
            members.len(),
        );
    }
    Ok(())
}

pub fn show(paths: &Paths, needle: &str, log: bool) -> Result<()> {
    let (identity, groups) = open(paths)?;
    let (id, row) = resolve(&groups, needle)?;

    let members = groups.members(id).context("reading members")?;
    let departed = groups.departed(id).context("reading departures")?;

    println!("id      {}", row.id);
    println!("name    {}", row.name);
    println!(
        "admin   {}{}",
        row.admin,
        if row.admin == identity.peer_id() {
            "  (this node)"
        } else {
            ""
        }
    );
    println!("state   {}", state_name(row.state));
    println!("entries {}", row.head_seq);
    if let Some(seq) = row.forked_at {
        println!();
        println!("This group forked at entry {seq}: two different entries claim that position.");
        println!("Under a single admin that means a restored backup, a copied key, or two");
        println!("admin processes. It is now inert — no syncing, no serving. Nothing here can");
        println!("safely pick a winner, so recovery is to create a fresh group.");
    }

    println!();
    println!("members");
    let widest = members.iter().map(|m| m.username.len()).max().unwrap_or(0);
    for member in members.iter() {
        let mut notes = Vec::new();
        if member.is_admin {
            notes.push("admin");
        }
        if member.peer == identity.peer_id() {
            notes.push("this node");
        }
        if departed.contains(&member.peer) {
            notes.push("has left, awaiting removal");
        }
        let note = if notes.is_empty() {
            String::new()
        } else {
            format!("  ({})", notes.join(", "))
        };
        println!("  {:<widest$}  {}{note}", member.username, member.peer);
    }

    if log {
        println!();
        println!("log");
        let chain = groups.chain(id).context("reading the log")?;
        for (seq, entry) in chain.entries().enumerate() {
            match entry.body() {
                Ok(body) => println!("  {seq:>3}  {}", describe(&body.op)),
                Err(e) => println!("  {seq:>3}  <unreadable: {e}>"),
            }
        }
    }
    Ok(())
}

pub fn add(paths: &Paths, needle: &str, peer: &PeerId, username: Option<&str>) -> Result<()> {
    let (identity, mut groups) = open(paths)?;
    let (id, row) = resolve(&groups, needle)?;
    require_admin(&row, &identity, "add members")?;

    // Fall back to whatever this node already calls them. It is display text either way, and
    // making the flag mandatory would mean retyping a name the contact list already holds.
    let username = match username {
        Some(name) => name.to_owned(),
        None => Contacts::open(&paths.db_file())
            .ok()
            .and_then(|c| c.get(peer).ok().flatten())
            .map(|c| c.label)
            .ok_or_else(|| {
                anyhow!(
                    "no name for {peer}; pass --username, or add them first with \
                     `ac peer add {peer} --label <name>`"
                )
            })?,
    };

    groups
        .author(
            identity.keypair(),
            id,
            Op::Add {
                peer: peer.to_base58(),
                username: username.clone(),
            },
            now(),
        )
        .with_context(|| format!("adding {peer} to {needle}"))?;

    println!("added {username} ({peer})");
    println!();
    println!("They will be told the next time this node and theirs are both online and");
    println!("connected. Being added is an invitation: they choose whether to accept.");
    Ok(())
}

pub fn remove(paths: &Paths, needle: &str, peer: &PeerId) -> Result<()> {
    let (identity, mut groups) = open(paths)?;
    let (id, row) = resolve(&groups, needle)?;
    require_admin(&row, &identity, "remove members")?;

    groups
        .author(
            identity.keypair(),
            id,
            Op::Remove {
                peer: peer.to_base58(),
            },
            now(),
        )
        .with_context(|| format!("removing {peer} from {needle}"))?;

    println!("removed {peer}");
    println!();
    println!("They stop being served by every member that has seen this, and will find out");
    println!("themselves next time they ask. It does not reach back: anything already shared");
    println!("with them is theirs, and no membership change can undo that.");
    Ok(())
}

pub fn accept(paths: &Paths, needle: &str) -> Result<()> {
    let (identity, mut groups) = open(paths)?;
    let (id, row) = resolve(&groups, needle)?;

    if !groups
        .members(id)
        .context("reading members")?
        .contains(&identity.peer_id())
    {
        bail!(
            "this group does not list you; ask its admin to add you, then try again \
             (`ac group show {needle}` shows who is in it)"
        );
    }
    if row.state == State::Active {
        println!("already a member of {}", row.name);
        return Ok(());
    }

    groups
        .author_standing(identity.keypair(), id, true, now())
        .with_context(|| format!("accepting {needle}"))?;

    println!("joined {}", row.name);
    Ok(())
}

pub fn leave(paths: &Paths, needle: &str) -> Result<()> {
    let (identity, mut groups) = open(paths)?;
    let (id, row) = resolve(&groups, needle)?;

    if row.admin == identity.peer_id() {
        bail!(
            "you created {}, and a group cannot outlive its only admin. To stop holding it \
             on this node, use `ac group forget {needle}` — which tells nobody.",
            row.name
        );
    }
    if row.state == State::Left {
        println!("already left {}", row.name);
        return Ok(());
    }

    groups
        .author_standing(identity.keypair(), id, false, now())
        .with_context(|| format!("leaving {needle}"))?;

    println!("left {}", row.name);
    println!();
    println!("This node stops sharing that group immediately, whatever anyone else believes.");
    println!("The others are told when they next connect, and the admin then makes it");
    println!("official. Being added again will not undo this — you would accept afresh.");
    Ok(())
}

pub fn forget(paths: &Paths, needle: &str) -> Result<()> {
    let (identity, mut groups) = open(paths)?;
    let (id, row) = resolve(&groups, needle)?;
    let admin = row.admin == identity.peer_id();

    // The index goes; the bytes stay. Forgetting a group is a local bookkeeping act, and
    // deleting someone's photos as a side effect of it is not something to do unasked.
    let (mut files, content) = open_files(paths, &identity)?;
    let held = files.list(id, None, false).unwrap_or_default().len();
    let dir = files.dir_of(id).ok().flatten();
    files
        .forget_group(id)
        .with_context(|| format!("forgetting the files of {needle}"))?;

    groups
        .forget(id)
        .with_context(|| format!("forgetting {needle}"))?;

    println!("forgot {} locally", row.name);
    if held > 0 {
        println!();
        println!("{held} file(s) were left on disk, no longer indexed:");
        if let Some(dir) = dir {
            println!("  {}", content.group_dir(&dir).display());
        }
    }
    if admin {
        println!();
        println!("You were this group's admin, so nobody can change its membership again.");
        println!("Other members keep their copy and can still reach each other with it.");
    } else {
        println!();
        println!("Nothing was told to anyone. The others still list you, and will keep");
        println!("offering it — use `ac group leave` instead if you meant to tell them.");
    }
    Ok(())
}

fn require_admin(row: &GroupRow, identity: &Identity, what: &str) -> Result<()> {
    if row.admin != identity.peer_id() {
        bail!(
            "only {} can {what} in {}; this node is not its admin",
            row.admin,
            row.name
        );
    }
    Ok(())
}

fn state_name(state: State) -> &'static str {
    match state {
        State::Pending => "invited",
        State::Active => "member",
        State::Left => "left",
    }
}

fn describe(op: &Op) -> String {
    match op {
        Op::Create { name, admin, .. } => format!("created {name:?} by {admin}"),
        Op::Add { peer, username } => format!("added {username} ({peer})"),
        Op::Remove { peer } => format!("removed {peer}"),
    }
}
