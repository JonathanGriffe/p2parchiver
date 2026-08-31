//! The Groups page: what `ac group` does, in the same words.
//!
//! Reading happens on the poller's thread and produces plain data; applying happens on the
//! event loop. Every action goes out to a thread of its own, because each one opens SQLite
//! and can wait on the daemon's writes.

use std::rc::Rc;
use std::str::FromStr;

use ac_net::config::Paths;
use ac_node::ops;
use ac_node::ops::format::{State, human_size, state_name};
use anyhow::{Context, Result};
use slint::{ComponentHandle, ModelRc, VecModel};

use crate::peers;
use crate::selection::Selection;
use crate::ui::{GroupItem, MainWindow, MemberItem, PeerItem};
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
    /// How much the group holds, and where those bytes live on this node.
    pub content: String,
    pub dir: String,
    pub admin: bool,
    pub members: Vec<MemberItem>,
    /// Who the Add dialog offers, in the Peers page's two lists less this group's members.
    pub candidates: peers::Page,
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

/// What this node is to a group, in the words the page shows.
fn standing(state: State) -> &'static str {
    match state {
        State::Pending => "invited",
        State::Active => "member",
        State::Left => "left",
    }
}

/// What the group holds. Every file in it, not only the ones this node has fetched: the
/// question is what the group is, and the Status page answers what is on this disk.
fn describe_content(files: usize, bytes: u64) -> String {
    match files {
        0 => "no files".to_owned(),
        1 => format!("1 file, {}", human_size(bytes)),
        n => format!("{n} files, {}", human_size(bytes)),
    }
}

/// Whether the page has any business showing a group.
///
/// Leaving is this node's own decision and takes effect here at once, whatever the admin has
/// or has not written yet. Listing it until they ratify would be showing someone a group they
/// have already walked out of.
fn listed(state: State) -> bool {
    !matches!(state, State::Left)
}

pub fn read(paths: &Paths, known: &[ops::Known], directory: &peers::Page, selected: &str) -> Page {
    let items = match ops::group::list(paths) {
        Ok(summaries) => summaries
            .iter()
            .filter(|group| listed(group.state))
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
        // Left from another window or the CLI while this one was looking at it.
        .filter(|detail| listed(detail.row.state))
        .map(|detail| present(detail, known, directory, content(paths, selected)));

    Page { items, detail }
}

/// What the group holds and where, read off the file index rather than the chain.
fn content(paths: &Paths, selected: &str) -> (String, String) {
    match ops::file::list(paths, selected, None, false) {
        Ok(listing) => (
            describe_content(
                listing.rows.len(),
                listing.rows.iter().map(|r| r.size).sum(),
            ),
            listing.dir.display().to_string(),
        ),
        Err(e) => {
            tracing::debug!(error = %e, "could not list a group's files");
            (describe_content(0, 0), String::new())
        }
    }
}

fn present(
    detail: ops::group::GroupDetail,
    known: &[ops::Known],
    directory: &peers::Page,
    (content, dir): (String, String),
) -> Detail {
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
        state: standing(detail.row.state).to_owned(),
        membership: membership(detail.row.state),
        content,
        dir,
        admin: detail.is_admin,
        candidates: candidates(directory, &detail.members),
        members,
    }
}

/// Everyone this node knows of who is not in the group already. Offering a member again
/// would only earn them the refusal the CLI gives.
fn candidates(directory: &peers::Page, members: &[ops::group::MemberView]) -> peers::Page {
    let mine = |item: &PeerItem| members.iter().any(|m| item.peer == m.peer.to_string());
    let without_members = |list: &[PeerItem]| -> Vec<PeerItem> {
        list.iter().filter(|item| !mine(item)).cloned().collect()
    };

    peers::Page {
        contacts: without_members(&directory.contacts),
        discovered: without_members(&directory.discovered),
    }
}

pub fn apply(window: &MainWindow, page: Page) {
    window.set_group_items(ModelRc::from(Rc::new(VecModel::from(page.items))));

    let Some(detail) = page.detail else {
        window.set_group_members(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        window.set_group_add_contacts(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        window.set_group_add_discovered(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        return;
    };

    window.set_group_name(detail.name.into());
    window.set_group_id(detail.id.into());
    window.set_group_state(detail.state.into());
    window.set_group_membership(detail.membership);
    window.set_group_content(detail.content.into());
    window.set_group_dir(detail.dir.into());
    window.set_group_admin(detail.admin);
    window.set_group_members(ModelRc::from(Rc::new(VecModel::from(detail.members))));
    window.set_group_add_contacts(ModelRc::from(Rc::new(VecModel::from(
        detail.candidates.contacts,
    ))));
    window.set_group_add_discovered(ModelRc::from(Rc::new(VecModel::from(
        detail.candidates.discovered,
    ))));
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

    window.on_leave_group({
        let selection = selection.clone();
        let inner = run(&weak, paths, nudge, |paths, id: &str, _| {
            Ok(match ops::group::leave(paths, id)? {
                ops::group::Departed::Already(name) => format!("already left {name}"),
                ops::group::Departed::Left(name) => {
                    format!("left {name}. The others are told when they next connect.")
                }
            })
        });
        move |id| {
            // The list is about to stop offering it, so nothing should still be pointing at it.
            selection.set_group("");
            inner(id);
        }
    });

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

    window.on_open_group_folder({
        let weak = weak.clone();
        let nudge = nudge.clone();
        move |dir| {
            let dir = std::path::PathBuf::from(dir.as_str());
            let outcome = crate::shell::open(&dir).map(|()| format!("opened {}", dir.display()));
            if let Some(window) = weak.upgrade() {
                work::finish(&window, outcome, &nudge);
            }
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
        let directory = peers::read(&known, None);
        read(paths, &known, &directory, selected)
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

    /// The dialog is a list of people to add, so it must not list someone already in the
    /// group: the only thing pressing that could earn is the refusal the CLI gives.
    #[test]
    fn the_add_dialog_offers_everyone_who_is_not_in_the_group_yet() {
        let (_tmp, paths) = home("jonathan");
        let created = ops::group::create(&paths, "holiday").unwrap();
        let id = created.id.to_string();

        let (ana, bob) = (somebody_else(), somebody_else());
        ops::peer::add(&paths, &ana, "ana").unwrap();
        ops::peer::add(&paths, &bob, "bob").unwrap();
        ops::group::add(&paths, &id, &bob).unwrap();

        let detail = page(&paths, &id).detail.unwrap();
        let offered: Vec<&str> = detail
            .candidates
            .contacts
            .iter()
            .map(|peer| peer.name.as_str())
            .collect();

        assert_eq!(offered, ["ana"], "bob is in the group already");
        assert_eq!(detail.candidates.contacts[0].peer, ana.to_string());
        assert!(detail.candidates.discovered.is_empty());
        assert!(
            detail.members.iter().any(|m| m.peer == bob.to_string()),
            "bob is offered nowhere because he is a member, not because he is unknown"
        );
    }

    /// Every peer id opens with the same handful of characters, so a box too narrow for one
    /// has to drop the front and keep the tail.
    #[test]
    fn a_peer_id_too_wide_for_its_box_loses_its_beginning() {
        use std::rc::Rc;

        use i_slint_backend_testing::ElementHandle;

        const PEER: &str = "12D3KooWDmPLKCjUV7snQBQVod5bNQnDmZ5X4MYNnPx8NM95zxke";

        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().unwrap();
        window.set_tab(1);
        window.set_selected_group("holiday-id".into());
        window.set_group_membership(MEMBER);
        window.set_group_members(ModelRc::from(Rc::new(VecModel::from(vec![MemberItem {
            username: "ana".into(),
            peer: PEER.into(),
            note: "".into(),
            departed: false,
            is_me: false,
        }]))));

        // Cut or not, the id keeps the whole of itself for anything reading the window.
        let shown = || {
            let handle = ElementHandle::find_by_accessible_label(&window, PEER)
                .next()
                .unwrap();
            (handle.absolute_position().x, handle.size().width)
        };
        // The box it was given, which the columns either side of it keep put.
        let box_of = || {
            let handle = ElementHandle::find_by_element_id(&window, "IdText::root")
                .next()
                .unwrap();
            (handle.absolute_position().x, handle.size().width)
        };

        window
            .window()
            .set_size(slint::LogicalSize::new(1600., 800.));
        let (roomy, room) = box_of();
        let (text, whole) = shown();
        assert!(room > whole, "room enough for all of it");
        assert_eq!(text, roomy, "so it is not moved");

        window
            .window()
            .set_size(slint::LogicalSize::new(900., 800.));
        let (left, narrow) = box_of();
        let (moved, width) = shown();
        assert_eq!(left, roomy, "the columns beside it have not moved");
        assert!(narrow < width, "the box is now narrower than the id");
        assert!(
            moved < left,
            "the front is what hangs outside the box: {moved} is not left of {left}"
        );
        assert_eq!(
            moved + width,
            left + narrow,
            "and the last character sits at the right edge"
        );
    }

    /// Adding is the admin's, and every row offers to add the person on it: what travels is
    /// the peer id, never the name beside it.
    #[test]
    fn only_an_admin_is_offered_the_dialog_and_its_rows_add_who_they_name() {
        use std::cell::RefCell;
        use std::rc::Rc;

        use i_slint_backend_testing::ElementHandle;

        fn candidate(name: &str, id: &str) -> PeerItem {
            PeerItem {
                name: name.into(),
                peer: id.into(),
                state: "no contact yet".into(),
                tone: crate::view::QUIET,
            }
        }
        fn model(items: Vec<PeerItem>) -> ModelRc<PeerItem> {
            ModelRc::from(Rc::new(VecModel::from(items)))
        }

        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().unwrap();
        let showing = |label: &str| ElementHandle::find_by_accessible_label(&window, label).count();

        window.set_tab(1);
        window.set_selected_group("holiday-id".into());
        window.set_group_name("holiday".into());
        window.set_group_membership(MEMBER);
        window.set_group_add_contacts(model(vec![candidate("ana", "12D3-ana")]));
        window.set_group_add_discovered(model(vec![candidate("~ bo", "12D3-bo")]));

        window.set_group_admin(false);
        assert_eq!(showing("Add member"), 0, "not this node's group to add to");

        window.set_group_admin(true);
        assert_eq!(showing("Add member"), 1);
        assert_eq!(showing("Add to holiday"), 0, "not until it is asked for");

        ElementHandle::find_by_accessible_label(&window, "Add member")
            .next()
            .unwrap()
            .invoke_accessible_default_action();

        assert_eq!(showing("Add to holiday"), 1);
        assert_eq!(showing("ana"), 1, "a contact");
        assert_eq!(showing("~ bo"), 1, "and someone met through a group");

        let row = ElementHandle::find_by_accessible_label(&window, "ana")
            .next()
            .unwrap()
            .size();
        assert!(
            row.width > 0. && row.height > 0.,
            "the rows are laid out rather than collapsed: {row:?}"
        );

        let asked = Rc::new(RefCell::new(Vec::new()));
        window.on_add_member({
            let asked = asked.clone();
            move |group, peer, name| {
                asked
                    .borrow_mut()
                    .push((group.to_string(), peer.to_string(), name.to_string()))
            }
        });

        // In tree order: the field's own button, then a row for each person.
        let buttons: Vec<_> = ElementHandle::find_by_accessible_label(&window, "Add").collect();
        assert_eq!(buttons.len(), 3, "one to add a pasted id, one per person");
        buttons[1].invoke_accessible_default_action();

        assert_eq!(
            *asked.borrow(),
            [(
                "holiday-id".to_owned(),
                "12D3-ana".to_owned(),
                String::new()
            )],
            "the id of the row pressed, under no name of the admin's invention"
        );
        assert_eq!(showing("Add to holiday"), 0, "and the dialog is done with");
    }

    /// Leaving takes effect on this node at once. Holding the group on the page until the
    /// admin ratifies would offer a way back into something already walked out of.
    #[test]
    fn a_group_this_node_has_left_is_not_listed_before_the_admin_ratifies() {
        assert!(listed(State::Pending), "an invitation is still to answer");
        assert!(listed(State::Active));
        assert!(!listed(State::Left));
    }

    /// The line under a group's name says what this node is to it and what is in it. The log
    /// length it used to carry answered neither question.
    #[test]
    fn the_group_line_says_what_this_node_is_and_what_the_group_holds() {
        assert_eq!(standing(State::Active), "member");
        assert_eq!(standing(State::Pending), "invited");

        assert_eq!(describe_content(0, 0), "no files");
        assert_eq!(describe_content(1, 2_000), "1 file, 2.0 KB");
        assert_eq!(describe_content(12, 3_400_000_000), "12 files, 3.4 GB");
    }

    /// Everything on that line comes from the file index, and the folder button opens the
    /// same group's bytes.
    #[test]
    fn a_group_reports_its_files_and_where_they_are_kept() {
        let (_tmp, paths) = home("jonathan");
        let created = ops::group::create(&paths, "holiday").unwrap();
        let id = created.id.to_string();

        let detail = page(&paths, &id).detail.unwrap();
        assert_eq!(detail.state, "member", "whoever creates a group is in it");
        assert_eq!(detail.content, "no files");
        assert!(
            detail.dir.ends_with("/holiday") || detail.dir.ends_with("\\holiday"),
            "the folder is this group's: {}",
            detail.dir
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
