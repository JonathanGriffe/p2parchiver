use ac_groups::chain::Op;
use ac_groups::id::GroupId;
use ac_groups::standing::Position;
use ac_groups::store::{GroupRow, Groups, State};
use ac_net::PeerId;
use ac_net::attest;
use ac_net::config::Paths;
use ac_net::identity::Identity;
use anyhow::{Context, Result, anyhow, bail};

use super::{now, open, resolve};

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
    pub username: Option<String>,
    pub is_admin: bool,
    pub is_me: bool,
    /// Has said they are out. The admin then writes their removal, except for its own: the
    /// chain cannot remove its admin, so an admin's `Out` stays a standing.
    pub departed: bool,
    /// Whether they have answered the invitation at all. False while this node holds the
    /// entry that names them but has heard nothing back from them.
    pub answered: bool,
}

impl MemberView {
    /// What `ac group show` and the desktop say after a member's name, in this order.
    pub fn notes(&self) -> Vec<&'static str> {
        let mut notes = Vec::new();
        if self.is_admin {
            notes.push("admin");
        }
        if self.is_me {
            notes.push("this node");
        }
        if self.departed {
            notes.push(if self.is_admin {
                "has left"
            } else {
                "has left, awaiting removal"
            });
        } else if !self.answered && !self.is_me {
            notes.push("invited, no answer yet");
        }
        notes
    }
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
    /// This node is the admin and has not left, so `add` would be allowed.
    pub can_add: bool,
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
    /// `admin` is set when this node is the group's admin, so nobody can be added any more.
    Left {
        name: String,
        admin: bool,
    },
    Already(String),
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
        can_add: row.admin == me && !left_as_admin(&groups, id, &row, &me)?,
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
    if left_as_admin(&groups, id, &row, &identity.peer_id())? {
        bail!("you left {}, so nobody can be added to it", row.name);
    }

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
    if left_as_admin(&groups, id, &row, &identity.peer_id())? {
        bail!(
            "you left {} as its admin, and an admin cannot come back",
            row.name
        );
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

    Ok(Departed::Left {
        name: row.name,
        admin: row.admin == identity.peer_id(),
    })
}

/// What leaving means, said by the desktop before it happens and by the CLI after.
pub fn leave_warning(admin: bool) -> &'static str {
    if admin {
        "This node stops sharing that group immediately. The others are told when they next \
         connect. You are its admin, so nobody can be added to it afterwards, and you cannot \
         come back."
    } else {
        "This node stops sharing that group immediately, whatever anyone else believes. The \
         others are told when they next connect, and the admin then makes it official. Being \
         added again will not undo this, you would accept afresh."
    }
}

/// This node is the group's admin, and its own signed standing says it left.
fn left_as_admin(groups: &Groups, id: GroupId, row: &GroupRow, me: &PeerId) -> Result<bool> {
    Ok(row.admin == *me
        && groups.positions(id).context("reading positions")?.get(me) == Some(&Position::Out))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A home that has enrolled, with an attestation written straight to disk.
    fn home() -> (tempfile::TempDir, Paths) {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::rooted_at(tmp.path());
        std::fs::create_dir_all(&paths.root).unwrap();

        let me = super::super::identity(&paths).unwrap();
        let server = ac_net::identity::Keypair::generate_ed25519();
        let attestation = attest::Attestation::issue(
            &server,
            &me.peer_id(),
            "alice",
            attest::now(),
            std::time::Duration::from_secs(3600),
        )
        .unwrap();
        attest::save(&paths.attestation_file(), &attestation).unwrap();
        (tmp, paths)
    }

    fn somebody_else() -> PeerId {
        ac_net::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id()
    }

    /// A group this node created and has left.
    fn created_and_left(paths: &Paths) -> String {
        let id = create(paths, "holiday").unwrap().id.to_string();
        leave(paths, &id).unwrap();
        id
    }

    #[test]
    fn an_admin_leaves_with_an_out_standing_and_only_once() {
        let (_tmp, paths) = home();
        let id = create(&paths, "holiday").unwrap().id.to_string();

        let Departed::Left { name, admin } = leave(&paths, &id).unwrap() else {
            panic!("the admin's leave is not refused");
        };
        assert_eq!(name, "holiday");
        assert!(admin);

        let (identity, groups) = open(&paths).unwrap();
        let (gid, row) = resolve(&groups, &id).unwrap();
        assert_eq!(row.state, State::Left);
        assert_eq!(
            groups.positions(gid).unwrap().get(&identity.peer_id()),
            Some(&Position::Out)
        );

        assert!(matches!(
            leave(&paths, &id).unwrap(),
            Departed::Already(name) if name == "holiday"
        ));
    }

    #[test]
    fn an_admin_that_has_left_cannot_accept_again() {
        let (_tmp, paths) = home();
        let id = created_and_left(&paths);

        assert!(accept(&paths, &id).is_err());

        let (_, groups) = open(&paths).unwrap();
        assert_eq!(resolve(&groups, &id).unwrap().1.state, State::Left);
    }

    #[test]
    fn an_admin_that_has_left_cannot_add_members() {
        let (_tmp, paths) = home();
        let id = created_and_left(&paths);
        let them = somebody_else();

        assert!(add(&paths, &id, &them).is_err());
        assert!(!show(&paths, &id, false).unwrap().can_add);

        let (_, groups) = open(&paths).unwrap();
        let (gid, _) = resolve(&groups, &id).unwrap();
        assert!(!groups.members(gid).unwrap().contains(&them));
    }

    /// As when the admin's own `Out` comes back from a peer: the row is `pending` again, but
    /// the standing still says it left.
    #[test]
    fn an_admin_whose_row_says_pending_but_who_has_left_cannot_add_members() {
        let (_tmp, paths) = home();
        let id = created_and_left(&paths);
        let them = somebody_else();
        {
            let (_, mut groups) = open(&paths).unwrap();
            let (gid, _) = resolve(&groups, &id).unwrap();
            groups.set_state(gid, State::Pending).unwrap();
        }

        assert!(add(&paths, &id, &them).is_err());
        assert!(!show(&paths, &id, false).unwrap().can_add);

        let (_, groups) = open(&paths).unwrap();
        let (gid, _) = resolve(&groups, &id).unwrap();
        assert!(!groups.members(gid).unwrap().contains(&them));
    }

    #[test]
    fn an_admin_that_has_not_left_can_add() {
        let (_tmp, paths) = home();
        let id = create(&paths, "holiday").unwrap().id.to_string();
        assert!(show(&paths, &id, false).unwrap().can_add);
    }

    fn member(is_admin: bool, is_me: bool, departed: bool, answered: bool) -> MemberView {
        MemberView {
            peer: somebody_else(),
            username: None,
            is_admin,
            is_me,
            departed,
            answered,
        }
    }

    #[test]
    fn an_admin_that_has_left_is_not_said_to_await_a_removal_that_never_comes() {
        assert_eq!(
            member(true, false, true, true).notes(),
            ["admin", "has left"]
        );
        assert_eq!(
            member(false, false, true, true).notes(),
            ["has left, awaiting removal"]
        );
    }

    #[test]
    fn a_silent_member_is_marked_as_unanswered_unless_it_is_this_node() {
        assert_eq!(
            member(false, false, false, false).notes(),
            ["invited, no answer yet"]
        );
        assert_eq!(
            member(true, true, false, false).notes(),
            ["admin", "this node"]
        );
        assert!(member(false, false, false, true).notes().is_empty());
    }
}
