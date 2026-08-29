//! The Groups page: what `ac group` does, in the same words.
//!
//! Reading happens on the poller's thread and produces plain data; applying happens on the
//! event loop. Every action goes out to a thread of its own, because each one opens SQLite
//! and can wait on the daemon's writes.

use std::rc::Rc;
use std::str::FromStr;

use ac_net::config::Paths;
use ac_node::ops;
use ac_node::ops::format::{State, state_name};
use anyhow::{Context, Result};
use slint::{ComponentHandle, ModelRc, VecModel};

use crate::peers;
use crate::selection::Selection;
use crate::ui::{GroupItem, MainWindow, MemberItem};
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
    /// Which actions apply, as [`INVITED`], [`MEMBER`] or [`GONE`].
    pub membership: i32,
    pub entries: String,
    pub admin: bool,
    pub members: Vec<MemberItem>,
}

const INVITED: i32 = 0;
const MEMBER: i32 = 1;
const GONE: i32 = 2;

/// What to call a member, by the same rule the Peers page uses: a name this node chose stands
/// plain, a name they chose for themselves is marked, and someone who has said nothing yet is
/// shown by the only thing known about them.
fn name_for(member: &ops::group::MemberView, known: &[ops::Known]) -> String {
    // Our own name is not somebody else's claim about us, so it is never marked. The directory
    // leaves this node out entirely, which is why it has to be handled before the lookup.
    if member.is_me {
        return member
            .username
            .clone()
            .unwrap_or_else(|| member.peer.to_base58()[..8].to_owned());
    }
    if let Some(entry) = known.iter().find(|k| k.peer == member.peer) {
        return peers::display_name(entry.name.as_deref(), entry.source, &entry.peer);
    }
    peers::display_name(member.username.as_deref(), ops::Source::Group, &member.peer)
}

fn membership(state: State) -> i32 {
    match state {
        State::Pending => INVITED,
        State::Active => MEMBER,
        State::Left => GONE,
    }
}

pub fn read(paths: &Paths, known: &[ops::Known], selected: &str) -> Page {
    let items = match ops::group::list(paths) {
        Ok(summaries) => summaries
            .iter()
            .map(|group| GroupItem {
                name: group.name.clone().into(),
                id: group.id.to_string().into(),
                short: group.id.short().into(),
                state: match group.state {
                    State::Active => String::new(),
                    other => state_name(other).to_owned(),
                }
                .into(),
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
        .then(|| ops::group::show(paths, selected, false).ok())
        .flatten()
        .map(|detail| present(detail, known));

    Page { items, detail }
}

fn present(detail: ops::group::GroupDetail, known: &[ops::Known]) -> Detail {
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
            } else if !member.answered && !member.is_me {
                // Named in the chain, silent so far. Either they have not been reached yet or
                // they have the invitation and have not decided.
                notes.push("invited, no answer yet");
            }

            MemberItem {
                username: name_for(member, known).into(),
                peer: member.peer.to_string().into(),
                note: notes.join(", ").into(),
                departed: member.departed,
                is_me: member.is_me,
            }
        })
        .collect();

    Detail {
        name: detail.row.name.clone(),
        id: detail.row.id.to_string(),
        state: state_name(detail.row.state).to_owned(),
        membership: membership(detail.row.state),
        entries: detail.row.head_seq.to_string(),
        admin: detail.is_admin,
        members,
    }
}

pub fn apply(window: &MainWindow, page: Page) {
    window.set_group_items(ModelRc::from(Rc::new(VecModel::from(page.items))));

    let Some(detail) = page.detail else {
        window.set_group_members(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        return;
    };

    window.set_group_name(detail.name.into());
    window.set_group_id(detail.id.into());
    window.set_group_state(detail.state.into());
    window.set_group_membership(detail.membership);
    window.set_group_entries(detail.entries.into());
    window.set_group_admin(detail.admin);
    window.set_group_members(ModelRc::from(Rc::new(VecModel::from(detail.members))));
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
            let mut said = format!("left {} on this node only, nobody was told", forgotten.name);
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

    window.on_add_member(run3(&weak, paths, nudge, |paths, id, peer, _| {
        let peer =
            ac_net::PeerId::from_str(peer).with_context(|| format!("{peer} is not a peer id"))?;
        let added = ops::group::add(paths, id, &peer)?;
        Ok(format!(
            "added {}. They are told the next time both nodes are online; being added is an \
             invitation, and they choose whether to accept. Their name is theirs to publish.",
            added.peer
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
        let paths = paths.clone();
        work::run(&weak, &nudge, move || {
            work(&paths, a.as_str(), b.as_str(), c.as_str())
        });
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

    /// The page as the poller builds it, directory and all.
    pub fn page(paths: &Paths, selected: &str) -> Page {
        let known = ops::peer::list(paths).unwrap_or_default();
        read(paths, &known, selected)
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

        let page = page(&paths, &created.id.to_string());

        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].name, "holiday");
        assert_eq!(page.items[0].short, created.id.short());
        assert!(page.items[0].admin, "whoever creates a group is its admin");
        assert!(!page.items[0].removed);
        assert_eq!(
            page.items[0].state, "",
            "being a member is what a listed group already means"
        );
    }

    #[test]
    fn every_membership_state_maps_to_its_own_set_of_buttons() {
        assert_eq!(membership(State::Pending), INVITED);
        assert_eq!(membership(State::Active), MEMBER);
        assert_eq!(membership(State::Left), GONE);
    }

    #[test]
    fn a_group_this_node_created_needs_no_accepting() {
        let (_tmp, paths) = home("jonathan");
        let created = ops::group::create(&paths, "holiday").unwrap();

        let detail = page(&paths, &created.id.to_string()).detail.unwrap();

        // Creating one makes you a member outright, so offering Accept would be nonsense.
        assert_eq!(detail.membership, MEMBER);
        assert_eq!(detail.state, "member", "and the word beside it agrees");
    }

    #[test]
    fn a_groups_own_admin_is_not_offered_a_leave_that_would_be_refused() {
        let (_tmp, paths) = home("jonathan");
        let created = ops::group::create(&paths, "holiday").unwrap();
        let id = created.id.to_string();

        let detail = page(&paths, &id).detail.unwrap();
        assert_eq!(detail.membership, MEMBER);
        assert!(detail.admin, "this is the case the branch turns on");

        // What the Leave button would have called, had it been offered.
        let Err(refused) = ops::group::leave(&paths, &id) else {
            panic!("leaving must be refused for a group's only admin");
        };
        assert!(
            format!("{refused:#}").contains("forget"),
            "and it points at the action that does apply: {refused:#}"
        );
    }

    #[test]
    fn this_node_is_marked_in_the_member_list_and_nobody_else_is() {
        let (_tmp, paths) = home("jonathan");
        let created = ops::group::create(&paths, "holiday").unwrap();
        ops::group::add(&paths, &created.id.to_string(), &somebody_else()).unwrap();

        let detail = page(&paths, &created.id.to_string()).detail.unwrap();
        let me = detail.members.iter().find(|m| m.is_me).unwrap();

        // Creating the group published this node's own standing, so it is named. Nobody else
        // has spoken yet, so nobody else is.
        assert_eq!(me.username, "jonathan");
        assert_eq!(detail.members.iter().filter(|m| m.is_me).count(), 1);
    }

    /// The chain says who is in a group; only the member says what they are called. Until the
    /// person who was added publishes a standing, this node has never been told a name for
    /// them and must not invent one.
    #[test]
    fn a_member_who_has_not_spoken_yet_is_shown_by_id_and_marked_as_unanswered() {
        let (_tmp, paths) = home("jonathan");
        let created = ops::group::create(&paths, "holiday").unwrap();
        let them = somebody_else();
        ops::group::add(&paths, &created.id.to_string(), &them).unwrap();

        let detail = page(&paths, &created.id.to_string()).detail.unwrap();
        let them = detail.members.iter().find(|m| !m.is_me).unwrap();

        assert_eq!(them.username, them.peer.to_string()[..8].to_string());
        assert_eq!(them.note, "invited, no answer yet");
    }

    /// A name this node chose for itself outranks silence, so someone added to a group who is
    /// also a contact is shown by the contact label, unmarked.
    #[test]
    fn a_member_this_node_has_a_name_for_is_shown_by_that_name() {
        let (_tmp, paths) = home("jonathan");
        let created = ops::group::create(&paths, "holiday").unwrap();
        let them = somebody_else();
        ops::group::add(&paths, &created.id.to_string(), &them).unwrap();
        ops::peer::add(&paths, &them, "ana").unwrap();

        let detail = page(&paths, &created.id.to_string()).detail.unwrap();
        let ana = detail.members.iter().find(|m| !m.is_me).unwrap();

        assert_eq!(ana.username, "ana", "a name we chose carries no mark");
    }

    #[test]
    fn the_selected_group_is_the_one_described() {
        let (_tmp, paths) = home("jonathan");
        let first = ops::group::create(&paths, "first").unwrap();
        ops::group::create(&paths, "second").unwrap();

        let page = page(&paths, &first.id.to_string());

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

        let page = page(&paths, "");

        assert_eq!(page.items.len(), 1);
        assert!(page.detail.is_none());
    }

    #[test]
    fn an_added_member_appears_with_the_notes_the_cli_prints() {
        let (_tmp, paths) = home("jonathan");
        let created = ops::group::create(&paths, "holiday").unwrap();
        let them = somebody_else();
        ops::group::add(&paths, &created.id.to_string(), &them).unwrap();

        let page = page(&paths, &created.id.to_string());
        let detail = page.detail.unwrap();

        assert_eq!(detail.members.len(), 2, "the admin and the one just added");
        let me = detail
            .members
            .iter()
            .find(|m| m.note.contains("this node"))
            .expect("this node is a member of a group it created");
        assert_eq!(me.note, "admin, this node");

        let them = detail.members.iter().find(|m| !m.is_me).unwrap();
        assert_eq!(them.note, "invited, no answer yet", "they have not replied");
        assert!(!them.departed);
    }

    #[test]
    fn a_forgotten_group_stops_being_listed() {
        let (_tmp, paths) = home("jonathan");
        let created = ops::group::create(&paths, "holiday").unwrap();
        ops::group::forget(&paths, &created.id.to_string()).unwrap();

        let page = page(&paths, &created.id.to_string());

        assert!(page.items.is_empty());
        assert!(page.detail.is_none());
    }
}
