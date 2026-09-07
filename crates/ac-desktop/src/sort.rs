use std::path::PathBuf;
use std::rc::Rc;

use ac_net::config::Paths;
use ac_node::ops;
use ac_node::ops::format::{ago, human_size};
use ac_node::ops::import::Waiting;
use slint::{ComponentHandle, ModelRc, VecModel};

use crate::selection::{Selection, Sorting};

/// How the group's own root reads in the folder picker: a path, because that is what it is.
pub const ROOT: &str = "/";
use crate::ui::MainWindow;
use crate::work::{self, Nudge};

/// Everything the Sort tab shows.
#[derive(Default)]
pub struct Page {
    /// The file on screen, or nothing when the backlog is empty.
    pub have: bool,
    pub name: String,
    pub size: String,
    pub arrived: String,
    pub source: String,
    pub folder: String,
    pub hash: String,
    /// Where it is on disk, for the Open button and the preview.
    pub path: String,
    /// True when a group has come to hold these bytes since it was imported.
    pub held: bool,
    /// "3 of 40,128", both numbers off indexed counts.
    pub position: String,
    /// What a bulk button is about to act on.
    pub in_folder: i32,

    pub group_names: Vec<slint::SharedString>,
    pub group_index: i32,
    pub group_id: String,

    /// The folders of the chosen group, with its root first. A name typed into "Add folder"
    /// is in here too, before any file has put it on disk.
    pub folder_names: Vec<slint::SharedString>,
    pub folder_index: i32,

    /// The file either side of the one on screen, as (hash, path): what the preview worker
    /// fetches ahead so stepping is instant rather than a spawn per keypress.
    pub neighbours: Vec<(String, String)>,
    /// Whether there is anywhere to step. Without these the ends are not ends: stepping
    /// past the last file would keep counting up while the backlog quietly began again.
    pub has_next: bool,
    pub has_previous: bool,
    /// What the Undo button would take back, or empty when there is nothing.
    pub undo: String,
}

pub fn read(paths: &Paths, looking_at: &Sorting) -> Page {
    let backlog = ops::import::backlog(paths, None).unwrap_or_default();
    let groups = ops::group::list(paths).unwrap_or_default();

    let mut page = Page {
        group_names: groups
            .iter()
            .map(|group| slint::SharedString::from(group.name.as_str()))
            .collect(),
        group_index: groups
            .iter()
            .position(|group| group.id.to_string() == looking_at.group)
            .map_or(-1, |at| at as i32),
        group_id: looking_at.group.clone(),
        ..Page::default()
    };

    // What it would take back, not which file: a name in a button cannot elide, so it sets
    // the width of the whole tab.
    page.undo = match looking_at.undo.last() {
        Some(last) => match last.dropped {
            true => "Undo delete".to_owned(),
            false => "Undo file".to_owned(),
        },
        None => String::new(),
    };

    let (folders, at) = destinations(paths, looking_at);
    page.folder_names = folders;
    page.folder_index = at;

    // Opened once for the whole read: the tab asks for the file on screen, and reopening the
    // ledger and the file index for each question is the bulk of what that costs.
    let opened = ops::import::Inbox::open(paths).ok();
    let found = opened.as_ref().and_then(|it| current_in(it, looking_at));
    let (Some(inbox), Some((file, here))) = (opened, found) else {
        page.position = match backlog.total {
            0 => String::new(),
            total => format!("{total} waiting"),
        };
        return page;
    };

    let in_folder = ops::import::backlog(paths, Some((&file.row.source_dir, &file.row.folder)))
        .unwrap_or_default();

    page.have = true;
    page.position = format!("{here} of {}", backlog.total);
    page.in_folder = in_folder.in_folder as i32;
    page.name = file.row.name.clone();
    page.size = human_size(file.row.size);
    page.arrived = ago(file.row.at);
    page.source = file.row.source_name.clone();
    page.folder = file.row.folder.clone();
    page.hash = file.row.hash.clone();
    page.held = file.held;
    page.path = located(paths, &file);
    page.has_previous = !looking_at.trail.is_empty();
    page.has_next = ahead(&inbox, &file).is_some();
    page.neighbours = neighbours(&inbox, paths, looking_at, &file);
    page
}

/// The one behind and the one ahead, which is the whole of what gets prefetched.
/// The folders a file may be filed into, and which one is chosen.
///
/// The group's root comes first and is not a folder — it is the absence of one — so it is
/// shown as `/` rather than given a name it does not have. A folder typed into "Add folder"
/// is included before any file has put it on disk, because until one does it exists only
/// as the choice that was made.
fn destinations(paths: &Paths, looking_at: &Sorting) -> (Vec<slint::SharedString>, i32) {
    let mut folders = match looking_at.group.is_empty() {
        true => Vec::new(),
        false => ops::file::folders(paths, &looking_at.group).unwrap_or_default(),
    };
    if !looking_at.destination.is_empty() && !folders.contains(&looking_at.destination) {
        folders.push(looking_at.destination.clone());
        folders.sort();
    }

    let at = match looking_at.destination.is_empty() {
        true => 0,
        false => folders
            .iter()
            .position(|f| *f == looking_at.destination)
            .map_or(0, |at| at as i32 + 1),
    };

    let mut names = vec![slint::SharedString::from(ROOT)];
    names.extend(
        folders
            .iter()
            .map(|f| slint::SharedString::from(f.as_str())),
    );
    (names, at)
}

/// The file after this one, if the backlog has one.
fn ahead(inbox: &ops::import::Inbox, file: &Waiting) -> Option<Waiting> {
    inbox
        .page(Some((file.row.at, &file.row.hash)), 1)
        .unwrap_or_default()
        .into_iter()
        .next()
}

fn neighbours(
    inbox: &ops::import::Inbox,
    paths: &Paths,
    looking_at: &Sorting,
    file: &Waiting,
) -> Vec<(String, String)> {
    let mut out = Vec::new();

    let ahead = ahead(inbox, file);
    let behind = match looking_at.trail.len() {
        0 | 1 => Vec::new(),
        len => {
            let (at, hash) = &looking_at.trail[len - 2];
            inbox
                .page(Some((*at, hash.as_str())), 1)
                .unwrap_or_default()
        }
    };

    for file in ahead.iter().chain(behind.iter()) {
        out.push((file.row.hash.clone(), located(paths, file)));
    }
    out
}

/// The file on screen: the first row after the trail's last cursor.
///
/// A trail can point past the end — a bulk action just filed everything behind it — so an
/// empty answer is repaired by starting again rather than left as a blank page.
fn current_in(inbox: &ops::import::Inbox, looking_at: &Sorting) -> Option<(Waiting, u64)> {
    let page = inbox.page(looking_at.at(), 1).unwrap_or_default();
    if let Some(file) = page.into_iter().next() {
        return Some((file, looking_at.trail.len() as u64 + 1));
    }
    if looking_at.trail.is_empty() {
        return None;
    }
    // Started again, so the trail no longer says where this file is: it is the first one.
    let file = inbox.page(None, 1).unwrap_or_default().into_iter().next()?;
    Some((file, 1))
}

/// The same, opening the inbox for the one question. Only the tests ask that way.
#[cfg(test)]
fn current(paths: &Paths, looking_at: &Sorting) -> Option<Waiting> {
    Some(current_in(&ops::import::Inbox::open(paths).ok()?, looking_at)?.0)
}

/// Where the bytes are, absolute, for opening and previewing.
fn located(paths: &Paths, file: &Waiting) -> String {
    let Ok(config) = ac_net::config::Config::load(&paths.config_file()) else {
        return String::new();
    };
    config
        .storage_root(paths)
        .join(ops::import::UNSORTED)
        .join(file.path.as_str())
        .display()
        .to_string()
}

pub fn apply(window: &MainWindow, page: Page) {
    window.set_sort_have(page.have);
    window.set_sort_name(page.name.into());
    window.set_sort_size(page.size.into());
    window.set_sort_arrived(page.arrived.into());
    window.set_sort_source(page.source.into());
    window.set_sort_folder(page.folder.into());
    window.set_sort_hash(page.hash.as_str().into());
    window.set_sort_held(page.held);
    window.set_sort_position(page.position.into());
    window.set_sort_in_folder(page.in_folder);
    window.set_sort_has_next(page.has_next);
    window.set_sort_has_previous(page.has_previous);
    window.set_sort_undo(page.undo.into());

    window.set_sort_group_names(ModelRc::from(Rc::new(VecModel::from(page.group_names))));
    window.set_sort_group_index(page.group_index);
    window.set_sort_group_id(page.group_id.into());
    window.set_sort_folder_names(ModelRc::from(Rc::new(VecModel::from(page.folder_names))));
    window.set_sort_folder_index(page.folder_index);

    window.set_sort_path(page.path.clone().into());

    let previews = crate::preview::previews();
    previews.show(window, &page.hash, std::path::Path::new(&page.path));
    for (hash, path) in &page.neighbours {
        previews.prefetch(window, hash, std::path::Path::new(path));
    }
}

pub fn wire(window: &MainWindow, paths: &Paths, selection: &Selection, nudge: &Nudge) {
    let weak = window.as_weak();

    window.on_sort_pick_group({
        let weak = weak.clone();
        let paths = paths.clone();
        let selection = selection.clone();
        let nudge = nudge.clone();
        move |index| {
            let groups = ops::group::list(&paths).unwrap_or_default();
            let Some(group) = usize::try_from(index).ok().and_then(|at| groups.get(at)) else {
                return;
            };
            selection.set_sort_group(&group.id.to_string());
            if let Some(window) = weak.upgrade() {
                window.set_sort_group_id(group.id.to_string().into());
            }
            nudge.now();
        }
    });

    window.on_sort_pick_folder({
        let weak = weak.clone();
        let paths = paths.clone();
        let selection = selection.clone();
        let nudge = nudge.clone();
        move |index| {
            // The first entry is the group's root, which is no folder at all.
            let (folders, _) = destinations(&paths, &selection.get().sorting);
            let picked = match index {
                0 => String::new(),
                at => folders
                    .get(at as usize)
                    .map(|name| name.to_string())
                    .unwrap_or_default(),
            };
            selection.set_sort_destination(&picked);
            let _ = &weak;
            nudge.now();
        }
    });

    window.on_sort_add_folder({
        let selection = selection.clone();
        let nudge = nudge.clone();
        move |name| {
            // Not created anywhere: a folder in a group is the directory some file is
            // under, so it comes into being when the first file is filed into it.
            let name = name.trim().trim_matches('/').to_owned();
            if !name.is_empty() {
                selection.set_sort_destination(&name);
            }
            nudge.now();
        }
    });

    window.on_sort_step({
        let paths = paths.clone();
        let selection = selection.clone();
        let nudge = nudge.clone();
        move |forward| {
            match forward {
                true => {
                    // Only when something actually follows: stepping off the end would
                    // leave the trail pointing past the backlog, and the count with it.
                    let looking_at = selection.get().sorting;
                    if let Ok(inbox) = ops::import::Inbox::open(&paths)
                        && let Some(file) = current_in(&inbox, &looking_at)
                        && ahead(&inbox, &file).is_some()
                    {
                        selection.forward((file.row.at, file.row.hash));
                    }
                }
                false => selection.back(),
            }
            nudge.now();
        }
    });

    window.on_sort_file({
        let weak = weak.clone();
        let paths = paths.clone();
        let selection = selection.clone();
        let nudge = nudge.clone();
        move |hash, folder| {
            let (paths, nudge) = (paths.clone(), nudge.clone());
            let looking_at = selection.get().sorting;
            let (group, into) = (looking_at.group, looking_at.destination);
            let (hash, selection) = (hash.to_string(), selection.clone());
            // Taken now, while it is still the file on screen: once it is filed it is no
            // longer in the backlog to be looked up by.
            let named = weak.upgrade().map(|w| w.get_sort_name().to_string());

            work::run(&weak, &nudge, move || {
                let filed = match folder {
                    false => ops::import::sort(&paths, &hash, &group, &into)?,
                    true => {
                        let row = ops::import::find(&paths, &hash)?;
                        ops::import::sort_folder(
                            &paths,
                            &row.source_dir,
                            &row.folder,
                            &group,
                            &into,
                        )?
                    }
                };
                // What was on screen has gone from the backlog, so the trail behind it no
                // longer points where it did.
                selection.rewind();
                // Only a single filing is offered back. A bulk one moves a whole folder,
                // and a button that reversed forty without saying which would be worse to
                // have than none.
                if !folder && let Some(name) = named {
                    remember(&paths, &selection, &hash, &name, false);
                }
                Ok(said(&filed, "filed"))
            });
        }
    });

    window.on_sort_delete({
        let weak = weak.clone();
        let paths = paths.clone();
        let selection = selection.clone();
        let nudge = nudge.clone();
        move |hash, folder| {
            let (paths, nudge) = (paths.clone(), nudge.clone());
            let (hash, selection) = (hash.to_string(), selection.clone());
            let named = weak.upgrade().map(|w| w.get_sort_name().to_string());

            work::run(&weak, &nudge, move || {
                let filed = match folder {
                    false => ops::import::drop(&paths, &hash)?,
                    true => {
                        let row = ops::import::find(&paths, &hash)?;
                        ops::import::drop_folder(&paths, &row.source_dir, &row.folder)?
                    }
                };
                selection.rewind();
                match (folder, named) {
                    (false, Some(name)) => remember(&paths, &selection, &hash, &name, true),
                    // A whole folder at once cannot be taken back, so it is finished with
                    // straight away rather than left waiting on disk.
                    _ => {
                        if let Err(error) = ops::import::sweep_dropped(&paths) {
                            tracing::warn!(
                                error = %format!("{error:#}"),
                                "could not finish with what was deleted"
                            );
                        }
                    }
                }
                Ok(said(&filed, "deleted"))
            });
        }
    });

    window.on_sort_open({
        let weak = weak.clone();
        let nudge = nudge.clone();
        move |path| {
            if path.is_empty() {
                return;
            }
            let path = PathBuf::from(path.as_str());
            let outcome = crate::shell::open(&path).map(|()| format!("opened {}", path.display()));
            if let Some(window) = weak.upgrade() {
                work::finish(&window, outcome, &nudge);
            }
        }
    });

    window.on_sort_undo_last({
        let weak = weak.clone();
        let paths = paths.clone();
        let selection = selection.clone();
        let nudge = nudge.clone();
        move || {
            let Some(taken) = selection.take_back() else {
                return;
            };
            let (paths, nudge, selection) = (paths.clone(), nudge.clone(), selection.clone());

            work::run(&weak, &nudge, move || {
                ops::import::undo(&paths, &taken.hash)?;
                // It is back in the backlog, and wherever the reader had got to no longer
                // describes where it is — so the file itself comes back on screen, which is
                // the whole of what taking it back means.
                selection.rewind();
                Ok(String::new())
            });
        }
    });

    window.on_sort_reveal({
        let weak = weak.clone();
        let nudge = nudge.clone();
        move |path| {
            if path.is_empty() {
                return;
            }
            let path = PathBuf::from(path.as_str());
            // A file manager opening is its own confirmation; only its refusal to is news.
            let outcome = crate::shell::reveal(&path).map(|()| String::new());
            if let Some(window) = weak.upgrade() {
                work::finish(&window, outcome, &nudge);
            }
        }
    });
}

/// Put one decision on the stack, and finish with whatever falls off the far end — nothing
/// can take that one back any more, so its bytes may go.
fn remember(paths: &Paths, selection: &Selection, hash: &str, name: &str, dropped: bool) {
    let fell_off = selection.did(crate::selection::Undoable {
        hash: hash.to_owned(),
        name: name.to_owned(),
        dropped,
    });

    if let Some(done_with) = fell_off
        && done_with.dropped
        && let Err(error) = ops::import::forget(paths, &done_with.hash)
    {
        tracing::warn!(error = %format!("{error:#}"), "could not finish with a deleted file");
    }
}

/// One line for what a filing or a deletion did.
/// What to say about a filing, and nothing at all for the ordinary one.
///
/// See [`crate::work::finish`] for why an empty message is the usual answer.
///
/// Filing the photograph on screen moves to the next one, which has already said it happened.
/// A count is worth a line only when it is a count nobody could have seen — a bulk action, or
/// one where something did not go through.
fn said(filed: &ops::import::Filed, did: &str) -> String {
    if filed.done <= 1 && filed.missing == 0 && filed.failed.is_empty() {
        return String::new();
    }

    let mut out = format!("{} {did}", filed.done);
    if filed.missing > 0 {
        out += &format!(", {} already gone from disk", filed.missing);
    }
    for note in &filed.failed {
        out += &format!("\n{note}");
    }
    out
}

#[cfg(test)]
mod tests {
    /// Filing the photograph on screen moves to the next one, which has already said what
    /// happened. A line under it saying "1 filed" is furniture that has to be read to be
    /// dismissed — so the ordinary success is silent, and only what cannot be seen is said.
    #[test]
    fn an_ordinary_filing_says_nothing_and_a_bulk_one_says_how_many() {
        use ac_node::ops::import::Filed;

        let one = Filed {
            done: 1,
            ..Filed::default()
        };
        assert_eq!(super::said(&one, "filed"), "", "the tab already moved on");

        let none = Filed::default();
        assert_eq!(super::said(&none, "filed"), "", "nothing happened, quietly");

        // A count nobody could have arrived at by looking is worth the line.
        let many = Filed {
            done: 128,
            ..Filed::default()
        };
        assert_eq!(super::said(&many, "filed"), "128 filed");

        // And so is anything that did not go through.
        let partly = Filed {
            done: 1,
            missing: 2,
            ..Filed::default()
        };
        assert_eq!(
            super::said(&partly, "deleted"),
            "1 deleted, 2 already gone from disk"
        );
    }

    use super::*;
    use crate::groups::tests::home;
    use crate::selection::Sorting;

    /// An album imported and waiting to be sorted.
    pub fn waiting(files: &[&str]) -> (tempfile::TempDir, Paths) {
        let (tmp, paths) = home("jonathan");
        let album = tmp.path().join("album");
        for file in files {
            let path = album.join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, file.as_bytes()).unwrap();
        }

        let picked = ops::import::from_folder(&paths, Some("Summer"), &album).unwrap();
        ops::import::scan(&paths, &picked.row.dir).unwrap();
        ops::import::drain(&paths, None).unwrap();
        (tmp, paths)
    }

    #[test]
    fn the_tab_shows_one_file_and_says_where_it_is_in_the_backlog() {
        let (_tmp, paths) = waiting(&["DCIM/a.jpg", "DCIM/b.jpg", "other/c.jpg"]);

        let page = read(&paths, &Sorting::default());

        assert!(page.have);
        assert_eq!(page.position, "1 of 3");
        assert_eq!(page.source, "Summer");
        assert!(!page.path.is_empty(), "it says where the bytes are");
        assert!(!page.held, "no group has them");
    }

    #[test]
    fn stepping_forward_and_back_walks_the_backlog_once() {
        let (_tmp, paths) = waiting(&["a.jpg", "b.jpg", "c.jpg"]);
        let selection = Selection::new();

        let mut seen = Vec::new();
        for step in 1..=3 {
            let page = read(&paths, &selection.get().sorting);
            assert_eq!(page.position, format!("{step} of 3"));
            seen.push(page.name.clone());

            let file = current(&paths, &selection.get().sorting).unwrap();
            selection.forward((file.row.at, file.row.hash));
        }

        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), 3, "each file once");

        // And back the way it came.
        selection.back();
        assert_eq!(read(&paths, &selection.get().sorting).position, "3 of 3");
    }

    /// Pressing Next at the last file used to push the trail past the end: the count went
    /// on climbing while the backlog quietly started again underneath it.
    #[test]
    fn stepping_stops_at_the_ends_rather_than_running_past_them() {
        let (_tmp, paths) = waiting(&["a.jpg", "b.jpg", "c.jpg"]);
        let selection = Selection::new();

        let step = |forward: bool| {
            let looking_at = selection.get().sorting;
            match forward {
                true => {
                    if let Ok(inbox) = ops::import::Inbox::open(&paths)
                        && let Some(file) = current_in(&inbox, &looking_at)
                        && ahead(&inbox, &file).is_some()
                    {
                        selection.forward((file.row.at, file.row.hash));
                    }
                }
                false => selection.back(),
            }
        };

        // At the start there is nowhere back to go.
        assert!(!read(&paths, &selection.get().sorting).has_previous);
        step(false);
        assert_eq!(read(&paths, &selection.get().sorting).position, "1 of 3");

        // Forward to the last, and no further however hard it is pressed.
        for _ in 0..10 {
            step(true);
        }
        let end = read(&paths, &selection.get().sorting);
        assert_eq!(
            end.position, "3 of 3",
            "the count stops where the backlog does"
        );
        assert!(!end.has_next, "and the button says so");
        assert!(end.has_previous);

        // And it is genuinely the last file, not the first come round again.
        let first = read(&paths, &Sorting::default()).name;
        assert_ne!(end.name, first, "cycling is what the runaway looked like");
    }

    /// The two pickers: a group, and where in it. The root comes first and is not a folder.
    #[test]
    fn the_folder_picker_offers_the_group_root_and_a_name_not_yet_on_disk() {
        let (_tmp, paths) = waiting(&["a.jpg"]);
        let created = ops::group::create(&paths, "holiday").unwrap();
        let selection = Selection::new();

        // No group chosen, so nowhere to file into either.
        assert_eq!(read(&paths, &selection.get().sorting).folder_names, [ROOT]);

        selection.set_sort_group(&created.id.to_string());
        let page = read(&paths, &selection.get().sorting);
        assert_eq!(page.folder_names, [ROOT], "an empty group has no folders");
        assert_eq!(page.folder_index, 0, "and its root is what is chosen");

        // A name typed into "Add folder" is offered before any file has put it on disk.
        selection.set_sort_destination("2024");
        let page = read(&paths, &selection.get().sorting);
        assert_eq!(page.folder_names, [ROOT, "2024"]);
        assert_eq!(page.folder_index, 1, "and it is the one chosen");

        // Changing group forgets it: a folder belongs to the group it is in.
        selection.set_sort_group("");
        assert_eq!(read(&paths, &selection.get().sorting).folder_names, [ROOT]);
    }

    #[test]
    fn a_bulk_button_names_what_it_is_about_to_act_on() {
        let (_tmp, paths) = waiting(&["DCIM/a.jpg", "DCIM/b.jpg", "other/c.jpg"]);

        // The oldest is one of DCIM's two, so that is what the button would say.
        let page = read(&paths, &Sorting::default());
        assert_eq!(page.folder, "DCIM");
        assert_eq!(page.in_folder, 2);
    }

    #[test]
    fn an_empty_backlog_shows_no_file_at_all() {
        let (_tmp, paths) = waiting(&["a.jpg"]);
        let file = current(&paths, &Sorting::default()).unwrap();
        ops::import::drop(&paths, &file.row.hash).unwrap();

        let page = read(&paths, &Sorting::default());

        assert!(!page.have);
        assert!(page.name.is_empty());
        assert_eq!(page.position, "", "and says nothing about a backlog");
    }

    #[test]
    fn a_trail_pointing_past_the_end_starts_again_rather_than_going_blank() {
        let (_tmp, paths) = waiting(&["a.jpg", "b.jpg"]);
        let selection = Selection::new();

        // Walk to the second, then throw both away, as a bulk delete would.
        let first = current(&paths, &selection.get().sorting).unwrap();
        selection.forward((first.row.at, first.row.hash.clone()));
        let second = current(&paths, &selection.get().sorting).unwrap();
        ops::import::drop(&paths, &second.row.hash).unwrap();

        // The trail still points behind a file that is no longer there.
        let page = read(&paths, &selection.get().sorting);
        assert!(page.have, "it shows what is left rather than nothing");
        assert_eq!(page.name, first.row.name);
        // Starting again means starting at the first, so the count has to say so rather
        // than keep counting from where the trail had reached.
        assert_eq!(page.position, "1 of 1");
    }

    /// The tab as the window shows it: the bulk buttons have to name the count and the
    /// group, and neither number is worth trusting until slint has laid it out.
    #[test]
    fn the_bulk_buttons_name_what_they_are_about_to_do() {
        use crate::ui::MainWindow;
        use i_slint_backend_testing::ElementHandle;

        let (_tmp, paths) = waiting(&["DCIM/a.jpg", "DCIM/b.jpg", "other/c.jpg"]);
        ops::group::create(&paths, "holiday").unwrap();

        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().unwrap();
        window.set_tab(4);

        let selection = Selection::new();
        let groups = ops::group::list(&paths).unwrap();
        selection.set_sort_group(&groups[0].id.to_string());
        apply(&window, read(&paths, &selection.get().sorting));

        // The count comes off the ledger, so the button can say how many it will move.
        assert_eq!(window.get_sort_in_folder(), 2);
        assert_eq!(window.get_sort_folder(), "DCIM");
        assert_eq!(window.get_sort_position(), "1 of 3");
        assert_eq!(window.get_sort_group_id(), groups[0].id.to_string());

        // The count, but not the folder's name: which folder is on the line above, and a
        // path in a button cannot elide, so it would set the width of the whole tab.
        let filed = ElementHandle::find_by_accessible_label(&window, "File all 2 in this folder")
            .next()
            .expect("the bulk file button names its count");
        assert!(
            filed.accessible_enabled().unwrap_or(false),
            "a group is picked"
        );

        assert!(
            ElementHandle::find_by_accessible_label(&window, "Delete all 2 in this folder")
                .next()
                .is_some(),
            "and so does the bulk delete"
        );

        // The row that files a photo: which group, where in it, and a way to name a folder
        // that is not there yet.
        for control in ["Add folder", "File it"] {
            assert!(
                ElementHandle::find_by_accessible_label(&window, control)
                    .next()
                    .is_some(),
                "{control:?} should be on the filing row"
            );
        }
    }
}
