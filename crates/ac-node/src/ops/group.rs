use std::path::PathBuf;

use ac_groups::chain::Op;
use ac_groups::id::GroupId;
use ac_groups::standing::Position;
use ac_groups::store::{GroupRow, State};
use ac_net::PeerId;
use ac_net::attest;
use ac_net::config::Paths;
use ac_net::identity::Identity;
use anyhow::{Context, Result, anyhow, bail};

use super::{now, open, open_files, resolve};

/// One group, as a list wants it.
pub struct GroupSummary {
    pub id: GroupId,
    pub name: String,
    pub state: State,
    pub members: usize,
    pub is_admin: bool,
    /// The admin's log no longer lists this node, so the group is over for it.
    pub removed_by_admin: bool,
}

/// One member, and what is worth saying about them beyond their name.
pub struct MemberView {
    pub peer: PeerId,
    /// What they call themselves, once their standing has reached this node. `None` until it
    /// does — the chain names nobody, so there is nothing else to fall back on.
    pub username: Option<String>,
    pub is_admin: bool,
    pub is_me: bool,
    /// Has said they are out, but the admin has not written the removal yet.
    pub departed: bool,
    /// Whether they have answered the invitation at all. False while this node holds the
    /// entry that names them but has heard nothing back from them.
    pub answered: bool,
}

/// One log entry, or the reason it could not be read. A corrupt entry is shown rather than
/// hidden: a gap in the log is exactly what someone opening it needs to see.
pub enum LogLine {
    Said(String),
    Unreadable(String),
}

pub struct GroupDetail {
    pub row: GroupRow,
    pub is_admin: bool,
    pub members: Vec<MemberView>,
    pub log: Option<Vec<LogLine>>,
}

pub struct Created {
    pub id: GroupId,
    pub name: String,
    pub admin: PeerId,
}

pub struct Added {
    pub peer: PeerId,
}

/// Accepting an invitation this node had already accepted is not an error.
pub enum Accepted {
    Joined(String),
    Already(String),
}

pub enum Departed {
    Left(String),
    Already(String),
}

pub struct Forgotten {
    pub name: String,
    pub was_admin: bool,
    /// Files left on disk, no longer indexed.
    pub held: usize,
    pub dir: Option<PathBuf>,
}

pub fn list(paths: &Paths) -> Result<Vec<GroupSummary>> {
    let (identity, groups) = open(paths)?;
    let me = identity.peer_id();

    Ok(groups
        .list()
        .context("listing groups")?
        .into_iter()
        .map(|row| {
            let members = groups.members(row.id).unwrap_or_default();
            GroupSummary {
                id: row.id,
                state: row.state,
                members: members.len(),
                is_admin: row.admin == me,
                removed_by_admin: !members.contains(&me),
                name: row.name,
            }
        })
        .collect())
}

pub fn show(paths: &Paths, needle: &str, log: bool) -> Result<GroupDetail> {
    let (identity, groups) = open(paths)?;
    let (id, row) = resolve(&groups, needle)?;
    let me = identity.peer_id();

    let members = groups.members(id).context("reading members")?;
    let departed = groups.departed(id).context("reading departures")?;
    let positions = groups.positions(id).context("reading positions")?;

    let members = members
        .iter()
        .map(|member| MemberView {
            peer: member.peer,
            username: member.username.clone(),
            is_admin: member.is_admin,
            is_me: member.peer == me,
            departed: departed.contains(&member.peer),
            // Anything other than silence counts as an answer, including "not yet": a member
            // who has published `Unanswered` has at least received the invitation.
            answered: matches!(
                positions.get(&member.peer),
                Some(Position::In) | Some(Position::Out)
            ),
        })
        .collect();

    let log = if log {
        let chain = groups.chain(id).context("reading the log")?;
        Some(
            chain
                .entries()
                .map(|entry| match entry.body() {
                    Ok(body) => LogLine::Said(super::format::describe(&body.op)),
                    Err(e) => LogLine::Unreadable(e.to_string()),
                })
                .collect(),
        )
    } else {
        None
    };

    Ok(GroupDetail {
        is_admin: row.admin == me,
        row,
        members,
        log,
    })
}

/// What this node calls itself, as the server that enrolled it recorded. Every standing this
/// node signs carries it, so joining a group at all depends on having one.
pub fn my_username(paths: &Paths) -> Result<String> {
    let attestation = attest::load(&paths.attestation_file())
        .context("reading this node's attestation")?
        .ok_or_else(|| anyhow!("this node has not enrolled with a server; run `ac join` first"))?;
    Ok(attestation
        .statement()
        .map_err(|e| anyhow!("{e}"))
        .context("reading the stored attestation")?
        .username)
}

pub fn create(paths: &Paths, name: &str) -> Result<Created> {
    let (identity, mut groups) = open(paths)?;
    let username = my_username(paths)?;

    let id = groups
        .create(identity.keypair(), name, &username, now())
        .with_context(|| format!("creating group {name:?}"))?;

    Ok(Created {
        id,
        name: name.to_owned(),
        admin: identity.peer_id(),
    })
}

pub fn add(paths: &Paths, needle: &str, peer: &PeerId) -> Result<Added> {
    let (identity, mut groups) = open(paths)?;
    let (id, row) = resolve(&groups, needle)?;
    require_admin(&row, &identity, "add members")?;

    groups
        .author(
            identity.keypair(),
            id,
            Op::Add {
                peer: peer.to_base58(),
            },
            now(),
        )
        .with_context(|| format!("adding {peer} to {needle}"))?;

    Ok(Added { peer: *peer })
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
    Ok(())
}

pub fn accept(paths: &Paths, needle: &str) -> Result<Accepted> {
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
        return Ok(Accepted::Already(row.name));
    }

    groups
        .author_standing(
            identity.keypair(),
            id,
            Position::In,
            &my_username(paths)?,
            now(),
        )
        .with_context(|| format!("accepting {needle}"))?;

    Ok(Accepted::Joined(row.name))
}

pub fn leave(paths: &Paths, needle: &str) -> Result<Departed> {
    let (identity, mut groups) = open(paths)?;
    let (id, row) = resolve(&groups, needle)?;

    if row.admin == identity.peer_id() {
        bail!(
            "you created {}, and a group cannot outlive its only admin. To stop holding it \
             on this node, use `ac group forget {needle}`, which tells nobody.",
            row.name
        );
    }
    if row.state == State::Left {
        return Ok(Departed::Already(row.name));
    }

    groups
        .author_standing(
            identity.keypair(),
            id,
            Position::Out,
            &my_username(paths)?,
            now(),
        )
        .with_context(|| format!("leaving {needle}"))?;

    Ok(Departed::Left(row.name))
}

pub fn forget(paths: &Paths, needle: &str) -> Result<Forgotten> {
    let (identity, mut groups) = open(paths)?;
    let (id, row) = resolve(&groups, needle)?;
    let was_admin = row.admin == identity.peer_id();

    let (mut files, content) = open_files(paths, &identity)?;
    let held = files.list(id, None, false).unwrap_or_default().len();
    let dir = files.dir_of(id).ok().flatten();

    if let Some(dir) = &dir {
        let _ = content.sweep_staging(dir, &[], std::time::Duration::ZERO);
    }

    files
        .forget_group(id)
        .with_context(|| format!("forgetting the files of {needle}"))?;

    groups
        .forget(id)
        .with_context(|| format!("forgetting {needle}"))?;

    Ok(Forgotten {
        name: row.name,
        was_admin,
        held,
        dir: dir.map(|d| content.group_dir(&d)),
    })
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
