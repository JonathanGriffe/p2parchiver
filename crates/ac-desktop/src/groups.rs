//! The Groups page: what `ac group` does, in the same words.
//!
//! Reading happens on the poller's thread and produces plain data; applying happens on the
//! event loop. Every action goes out to a thread of its own, because each one opens SQLite
//! and can wait on the daemon's writes.

use std::rc::Rc;
use std::str::FromStr;

use ac_net::config::Paths;
use ac_node::ops;
use ac_node::ops::format::state_name;
use ac_node::ops::group::LogLine;
use anyhow::{Context, Result};
use slint::{ComponentHandle, ModelRc, VecModel};

use crate::selection::Selection;
use crate::ui::{GroupItem, LogItem, MainWindow, MemberItem};
use crate::work::{self, Nudge};

/// Everything the page shows, read in one pass off the event loop.
#[derive(Default)]
pub struct Page {
    pub items: Vec<GroupItem>,
    pub detail: Option<Detail>,
}

pub struct Detail {
    pub name: String,
    pub id: String,
    pub state: String,
    pub entries: String,
    pub admin: bool,
    pub members: Vec<MemberItem>,
    pub log: Vec<LogItem>,
}

pub fn read(paths: &Paths, selected: &str) -> Page {
    let items = match ops::group::list(paths) {
        Ok(summaries) => summaries
            .iter()
            .map(|group| GroupItem {
                name: group.name.clone().into(),
                id: group.id.to_string().into(),
                short: group.id.short().into(),
                state: state_name(group.state).into(),
                members: format!("{} member(s)", group.members).into(),
                admin: group.is_admin,
                removed: group.removed_by_admin,
            })
            .collect(),
        Err(e) => {
            tracing::warn!(error = %e, "could not list groups");
            Vec::new()
        }
    };

    // A selected group that has just been forgotten is not an error worth showing: the list
    // beside it has already stopped mentioning it.
    let detail = (!selected.is_empty())
        .then(|| ops::group::show(paths, selected, true).ok())
        .flatten()
        .map(present);

    Page { items, detail }
}

fn present(detail: ops::group::GroupDetail) -> Detail {
    let members = detail
        .members
        .iter()
        .map(|member| {
            // The same notes `ac group show` puts after a member, in the same order.
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

            MemberItem {
                username: member.username.clone().into(),
                peer: member.peer.to_string().into(),
                note: notes.join(", ").into(),
                departed: member.departed,
            }
        })
        .collect();

    let log = detail
        .log
        .unwrap_or_default()
        .iter()
        .enumerate()
        .map(|(seq, line)| LogItem {
            seq: seq.to_string().into(),
            text: match line {
                LogLine::Said(said) => said.clone(),
                LogLine::Unreadable(why) => format!("<unreadable: {why}>"),
            }
            .into(),
        })
        .collect();

    Detail {
        name: detail.row.name.clone(),
        id: detail.row.id.to_string(),
        state: state_name(detail.row.state).to_owned(),
        entries: detail.row.head_seq.to_string(),
        admin: detail.is_admin,
        members,
        log,
    }
}

pub fn apply(window: &MainWindow, page: Page) {
    window.set_group_items(ModelRc::from(Rc::new(VecModel::from(page.items))));

    let Some(detail) = page.detail else {
        window.set_group_members(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        window.set_group_log(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        return;
    };

    window.set_group_name(detail.name.into());
    window.set_group_id(detail.id.into());
    window.set_group_state(detail.state.into());
    window.set_group_entries(detail.entries.into());
    window.set_group_admin(detail.admin);
    window.set_group_members(ModelRc::from(Rc::new(VecModel::from(detail.members))));
    window.set_group_log(ModelRc::from(Rc::new(VecModel::from(detail.log))));
}

/// Connect the page's buttons. Each one runs its `ops` call off the event loop, then says what
/// happened and asks the poller to read again so the change is on screen immediately.
pub fn wire(window: &MainWindow, paths: &Paths, selection: &Selection, nudge: &Nudge) {
    let weak = window.as_weak();

    window.on_select_group({
        let selection = selection.clone();
        let nudge = nudge.clone();
        move |id| {
            selection.set_group(&id);
            nudge.now();
        }
    });

    window.on_create_group(run(&weak, paths, nudge, |paths, name: &str, _| {
        let created = ops::group::create(paths, name)?;
        // `ac group create` says this too: it is the one fact about a new group that cannot
        // be undone later, so it is said at the moment it becomes true.
        Ok(format!(
            "created {} ({}). You are its only admin, and that cannot be transferred.",
            created.name,
            created.id.short()
        ))
    }));

    window.on_accept_group(run(&weak, paths, nudge, |paths, id: &str, _| {
        Ok(match ops::group::accept(paths, id)? {
            ops::group::Accepted::Already(name) => format!("already a member of {name}"),
            ops::group::Accepted::Joined(name) => format!("joined {name}"),
        })
    }));

    window.on_leave_group(run(&weak, paths, nudge, |paths, id: &str, _| {
        Ok(match ops::group::leave(paths, id)? {
            ops::group::Departed::Already(name) => format!("already left {name}"),
            ops::group::Departed::Left(name) => {
                format!("left {name}. The others are told when they next connect.")
            }
        })
    }));

    window.on_forget_group({
        let selection = selection.clone();
        let inner = run(&weak, paths, nudge, |paths, id: &str, _| {
            let forgotten = ops::group::forget(paths, id)?;
            let mut said = format!("forgot {} locally", forgotten.name);
            if forgotten.held > 0 {
                said += &format!(
                    ", {} file(s) left on disk and no longer indexed",
                    forgotten.held
                );
            }
            Ok(said)
        });
        move |id| {
            // The group is about to stop existing, so nothing should still be pointing at it.
            selection.set_group("");
            inner(id);
        }
    });

    window.on_add_member(run3(&weak, paths, nudge, |paths, id, peer, username| {
        let peer =
            ac_net::PeerId::from_str(peer).with_context(|| format!("{peer} is not a peer id"))?;
        let username = (!username.is_empty()).then_some(username);
        let added = ops::group::add(paths, id, &peer, username)?;
        Ok(format!(
            "added {}. They are told the next time both nodes are online; being added is an \
             invitation, and they choose whether to accept.",
            added.username
        ))
    }));

    window.on_remove_member(run2(&weak, paths, nudge, |paths, id, peer, _| {
        let peer =
            ac_net::PeerId::from_str(peer).with_context(|| format!("{peer} is not a peer id"))?;
        ops::group::remove(paths, id, &peer)?;
        Ok(format!("removed {peer}. It does not reach back."))
    }));
}

/// A button taking one field, the group's id.
fn run<F>(
    weak: &slint::Weak<MainWindow>,
    paths: &Paths,
    nudge: &Nudge,
    work: F,
) -> impl Fn(slint::SharedString) + 'static
where
    F: Fn(&Paths, &str, &str) -> Result<String> + Copy + Send + 'static,
{
    let inner = run3(weak, paths, nudge, move |paths, a, _, _| work(paths, a, ""));
    move |a| inner(a, Default::default(), Default::default())
}

/// A button taking two: the group, and something in it.
fn run2<F>(
    weak: &slint::Weak<MainWindow>,
    paths: &Paths,
    nudge: &Nudge,
    work: F,
) -> impl Fn(slint::SharedString, slint::SharedString) + 'static
where
    F: Fn(&Paths, &str, &str, &str) -> Result<String> + Copy + Send + 'static,
{
    let inner = run3(weak, paths, nudge, work);
    move |a, b| inner(a, b, Default::default())
}

/// The one that actually does it. The others are arities, not behaviour.
fn run3<F>(
    weak: &slint::Weak<MainWindow>,
    paths: &Paths,
    nudge: &Nudge,
    work: F,
) -> impl Fn(slint::SharedString, slint::SharedString, slint::SharedString) + 'static
where
    F: Fn(&Paths, &str, &str, &str) -> Result<String> + Copy + Send + 'static,
{
    let weak = weak.clone();
    let paths = paths.clone();
    let nudge = nudge.clone();

    move |a, b, c| {
        work::begin(&weak);

        let paths = paths.clone();
        let nudge = nudge.clone();
        work::action(
            &weak,
            move || work(&paths, a.as_str(), b.as_str(), c.as_str()),
            move |window, outcome| work::finish(window, outcome, &nudge),
        );
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A node that has enrolled, since `ac group create` refuses to run on one that has not.
    /// Enrolment is an attestation on disk, so the test writes one rather than running a
    /// server to be handed it.
    pub fn home(username: &str) -> (tempfile::TempDir, Paths) {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::rooted_at(tmp.path());
        std::fs::create_dir_all(&paths.root).unwrap();

        let (me, _) = ac_net::identity::Identity::load_or_generate(&paths.identity_file()).unwrap();
        let server = ac_net::identity::Keypair::generate_ed25519();
        let attestation = ac_net::attest::Attestation::issue(
            &server,
            &me.peer_id(),
            username,
            ac_net::attest::now(),
            std::time::Duration::from_secs(3600),
        )
        .unwrap();
        ac_net::attest::save(&paths.attestation_file(), &attestation).unwrap();

        (tmp, paths)
    }

    /// A peer id belonging to somebody else.
    pub fn somebody_else() -> ac_net::PeerId {
        let elsewhere = tempfile::tempdir().unwrap();
        let (them, _) =
            ac_net::identity::Identity::load_or_generate(&elsewhere.path().join("key")).unwrap();
        them.peer_id()
    }

    #[test]
    fn a_created_group_lists_with_this_node_as_its_admin() {
        let (_tmp, paths) = home("jonathan");
        let created = ops::group::create(&paths, "holiday").unwrap();

        let page = read(&paths, &created.id.to_string());

        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].name, "holiday");
        assert_eq!(page.items[0].short, created.id.short());
        assert!(page.items[0].admin, "whoever creates a group is its admin");
        assert!(!page.items[0].removed);
    }

    #[test]
    fn the_selected_group_is_the_one_described() {
        let (_tmp, paths) = home("jonathan");
        let first = ops::group::create(&paths, "first").unwrap();
        ops::group::create(&paths, "second").unwrap();

        let page = read(&paths, &first.id.to_string());

        assert_eq!(page.items.len(), 2, "both are listed");
        let detail = page.detail.expect("a selected group has a detail pane");
        assert_eq!(detail.name, "first");
        assert!(detail.admin);
    }

    #[test]
    fn nothing_selected_means_nothing_to_describe() {
        // What the page shows on first open, before anything is clicked.
        let (_tmp, paths) = home("jonathan");
        ops::group::create(&paths, "holiday").unwrap();

        let page = read(&paths, "");

        assert_eq!(page.items.len(), 1);
        assert!(page.detail.is_none());
    }

    #[test]
    fn an_added_member_appears_with_the_notes_the_cli_prints() {
        let (_tmp, paths) = home("jonathan");
        let created = ops::group::create(&paths, "holiday").unwrap();
        let them = somebody_else();
        ops::group::add(&paths, &created.id.to_string(), &them, Some("ana")).unwrap();

        let page = read(&paths, &created.id.to_string());
        let detail = page.detail.unwrap();

        assert_eq!(detail.members.len(), 2, "the admin and the one just added");
        let me = detail
            .members
            .iter()
            .find(|m| m.note.contains("this node"))
            .expect("this node is a member of a group it created");
        assert_eq!(me.note, "admin, this node");

        let ana = detail.members.iter().find(|m| m.username == "ana").unwrap();
        assert_eq!(ana.note, "", "a plain member carries no notes");
        assert!(!ana.departed);
    }

    #[test]
    fn a_forgotten_group_stops_being_listed() {
        let (_tmp, paths) = home("jonathan");
        let created = ops::group::create(&paths, "holiday").unwrap();
        ops::group::forget(&paths, &created.id.to_string()).unwrap();

        // Still "selected", because forgetting is what the selection was pointing at. The
        // page must cope rather than showing a stale pane.
        let page = read(&paths, &created.id.to_string());

        assert!(page.items.is_empty());
        assert!(page.detail.is_none());
    }
}
