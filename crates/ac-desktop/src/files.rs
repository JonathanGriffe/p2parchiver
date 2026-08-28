use std::path::PathBuf;
use std::rc::Rc;

use ac_net::config::Paths;
use ac_node::ops;
use ac_node::ops::format::{ago, human_size};
use slint::{ComponentHandle, ModelRc, VecModel};

use crate::selection::{Selection, State};
use crate::ui::{FileItem, MainWindow};
use crate::work::{self, Nudge};

/// Everything the page shows.
#[derive(Default)]
pub struct Page {
    pub names: Vec<slint::SharedString>,
    pub index: i32,
    pub group: String,
    pub dir: String,
    pub files: Vec<FileItem>,
}

pub fn read(paths: &Paths, looking_at: &State) -> Page {
    let groups = ops::group::list(paths).unwrap_or_default();

    let names = groups
        .iter()
        .map(|group| slint::SharedString::from(group.name.as_str()))
        .collect();
    let index = groups
        .iter()
        .position(|group| group.id.to_string() == looking_at.group)
        .map_or(-1, |at| at as i32);

    if looking_at.group.is_empty() {
        return Page {
            names,
            index,
            ..Page::default()
        };
    }

    let prefix = (!looking_at.prefix.is_empty()).then_some(looking_at.prefix.as_str());
    let listing = match ops::file::list(paths, &looking_at.group, prefix, looking_at.removed) {
        Ok(listing) => listing,
        Err(e) => {
            tracing::debug!(error = %e, "could not list files");
            return Page {
                names,
                index,
                group: looking_at.group.clone(),
                ..Page::default()
            };
        }
    };

    let files = listing
        .rows
        .iter()
        .map(|row| FileItem {
            path: row.path.as_str().into(),
            size: human_size(row.size).into(),
            hash: row.hash[..8.min(row.hash.len())].into(),
            modified: ago(row.modified).into(),
            added_by: row.added_by.to_base58()[..8].into(),
            held: match (row.is_removed(), row.have) {
                (true, _) => "removed",
                (false, true) => "local",
                (false, false) => "remote",
            }
            .into(),
            removed: row.is_removed(),
            have: row.have,
        })
        .collect();

    Page {
        names,
        index,
        group: looking_at.group.clone(),
        dir: listing.dir.display().to_string(),
        files,
    }
}

pub fn apply(window: &MainWindow, page: Page) {
    window.set_file_group_names(ModelRc::from(Rc::new(VecModel::from(page.names))));
    window.set_file_group_index(page.index);
    window.set_file_group_id(page.group.into());
    window.set_file_dir(page.dir.into());
    window.set_files(ModelRc::from(Rc::new(VecModel::from(page.files))));
}

pub fn wire(window: &MainWindow, paths: &Paths, selection: &Selection, nudge: &Nudge) {
    let weak = window.as_weak();

    window.on_pick_group({
        let weak = weak.clone();
        let paths = paths.clone();
        let selection = selection.clone();
        let nudge = nudge.clone();
        move |index| {
            let groups = ops::group::list(&paths).unwrap_or_default();
            let Some(group) = usize::try_from(index).ok().and_then(|at| groups.get(at)) else {
                return;
            };
            selection.set_group(&group.id.to_string());
            if let Some(window) = weak.upgrade() {
                window.set_file_group_id(group.id.to_string().into());
            }
            nudge.now();
        }
    });

    window.on_filter({
        let selection = selection.clone();
        let nudge = nudge.clone();
        move |prefix, removed| {
            selection.set_filter(&prefix, removed);
            nudge.now();
        }
    });

    window.on_verify({
        let weak = weak.clone();
        let paths = paths.clone();
        let selection = selection.clone();
        let nudge = nudge.clone();
        move || {
            let (paths, nudge) = (paths.clone(), nudge.clone());
            let group = selection.get().group;
            work::run(&weak, &nudge, move || {
                Ok(describe_verify(&ops::file::verify(&paths, &group)?))
            });
        }
    });

    window.on_remove_file({
        let weak = weak.clone();
        let paths = paths.clone();
        let selection = selection.clone();
        let nudge = nudge.clone();
        move |path| {
            let (paths, nudge) = (paths.clone(), nudge.clone());
            let group = selection.get().group;
            let path = path.to_string();
            work::run(&weak, &nudge, move || {
                let gone = ops::file::remove(&paths, &group, &path)?;
                Ok(format!("removed {gone}"))
            });
        }
    });

    window.on_browse({
        let paths = paths.clone();
        let selection = selection.clone();
        let nudge = nudge.clone();
        move |folder| {
            let dialog = rfd::FileDialog::new().set_title(if folder {
                "Add a folder to this group"
            } else {
                "Add files to this group"
            });
            let chosen: Vec<PathBuf> = if folder {
                dialog.pick_folder().into_iter().collect()
            } else {
                dialog.pick_files().unwrap_or_default()
            };

            if chosen.is_empty() {
                return;
            }
            add(
                &weak,
                &paths,
                &selection.get().group,
                chosen,
                folder,
                &nudge,
            );
        }
    });
}

/// Copy files in, one at a time, saying which one as it goes.
fn add(
    weak: &slint::Weak<MainWindow>,
    paths: &Paths,
    group: &str,
    sources: Vec<PathBuf>,
    recursive: bool,
    nudge: &Nudge,
) {
    work::begin(weak);

    let (paths, group, nudge) = (paths.clone(), group.to_owned(), nudge.clone());
    let progress = weak.clone();

    work::action(
        weak,
        move || {
            let planned = ops::file::plan(&sources, None, None, recursive)?;
            let mut session = ops::file::session(&paths, &group)?;
            ops::file::writable(&session.row)?;

            let total = planned.items.len();
            let (mut added, mut failed) = (0usize, Vec::new());

            for (at, (src, dest)) in planned.items.iter().enumerate() {
                let say = format!("adding {} of {total}: {dest}", at + 1);
                let _ = progress.upgrade_in_event_loop(move |window| {
                    window.set_file_progress(say.into());
                });

                match ops::file::add_one(&mut session, src, dest, false) {
                    Ok(_) => added += 1,
                    Err(e) => failed.push(format!("{dest}: {e:#}")),
                }
            }

            let _ = progress.upgrade_in_event_loop(|window| window.set_file_progress("".into()));

            let mut said = format!("added {added} file(s)");
            for skipped in &planned.skipped {
                said += &format!("\nskipped {skipped}");
            }
            for failure in &failed {
                said += &format!("\n{failure}");
            }
            if failed.is_empty() {
                Ok(said)
            } else {
                Err(anyhow::anyhow!(said))
            }
        },
        move |window, outcome| work::finish(window, outcome, &nudge),
    );
}

/// The verify report as one line, keeping the CLI's names for the four ways a file can differ.
fn describe_verify(report: &ops::file::VerifyReport) -> String {
    if report.everything_matches() {
        return format!("checked {}, everything matches", report.checked);
    }

    let mut parts = Vec::new();
    if !report.missing.is_empty() {
        parts.push(format!("{} missing", report.missing.len()));
    }
    if !report.changed.is_empty() {
        parts.push(format!("{} changed", report.changed.len()));
    }
    if !report.untracked.is_empty() {
        parts.push(format!("{} untracked", report.untracked.len()));
    }
    if !report.unreadable.is_empty() {
        parts.push(format!("{} unreadable", report.unreadable.len()));
    }
    format!("checked {}: {}", report.checked, parts.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::tests::home;

    /// A group with one file in it, and the selection pointing at it.
    fn with_a_file() -> (tempfile::TempDir, Paths, State) {
        let (tmp, paths) = home("jonathan");
        let created = ops::group::create(&paths, "holiday").unwrap();

        let src = tmp.path().join("notes.txt");
        std::fs::write(&src, b"some notes").unwrap();

        let group = created.id.to_string();
        let planned = ops::file::plan(&[src], None, None, false).unwrap();
        let mut session = ops::file::session(&paths, &group).unwrap();
        for (from, to) in &planned.items {
            ops::file::add_one(&mut session, from, to, false).unwrap();
        }

        let looking_at = State {
            group,
            ..State::default()
        };
        (tmp, paths, looking_at)
    }

    #[test]
    fn an_added_file_is_listed_as_held_locally() {
        let (_tmp, paths, looking_at) = with_a_file();

        let page = read(&paths, &looking_at);

        assert_eq!(page.files.len(), 1);
        assert_eq!(page.files[0].path, "notes.txt");
        assert_eq!(
            page.files[0].held, "local",
            "this node added it, so it has it"
        );
        assert!(page.files[0].have);
        assert!(!page.files[0].removed);
        assert!(!page.dir.is_empty(), "the page says where the bytes live");
    }

    #[test]
    fn the_picker_marks_the_group_being_looked_at() {
        let (_tmp, paths, looking_at) = with_a_file();

        let page = read(&paths, &looking_at);

        assert_eq!(page.names.len(), 1);
        assert_eq!(page.index, 0);
    }

    #[test]
    fn no_group_chosen_lists_nothing_but_still_offers_the_groups() {
        let (_tmp, paths, _) = with_a_file();

        let page = read(&paths, &State::default());

        assert_eq!(page.names.len(), 1, "the picker still has something in it");
        assert_eq!(page.index, -1, "with nothing chosen");
        assert!(page.files.is_empty());
    }

    #[test]
    fn a_prefix_that_matches_nothing_empties_the_list() {
        let (_tmp, paths, looking_at) = with_a_file();
        let looking_at = State {
            prefix: "nowhere/".to_owned(),
            ..looking_at
        };

        assert!(read(&paths, &looking_at).files.is_empty());
    }

    #[test]
    fn a_removed_file_only_shows_when_asked_for() {
        let (_tmp, paths, looking_at) = with_a_file();
        ops::file::remove(&paths, &looking_at.group, "notes.txt").unwrap();

        assert!(read(&paths, &looking_at).files.is_empty());

        let asked = State {
            removed: true,
            ..looking_at
        };
        let page = read(&paths, &asked);
        assert_eq!(page.files.len(), 1);
        assert_eq!(page.files[0].held, "removed");
        assert!(page.files[0].removed);
    }

    #[test]
    fn a_clean_group_verifies_as_matching() {
        let (_tmp, paths, looking_at) = with_a_file();

        let report = ops::file::verify(&paths, &looking_at.group).unwrap();

        assert_eq!(describe_verify(&report), "checked 1, everything matches");
    }

    #[test]
    fn verify_names_what_differs_rather_than_just_failing() {
        let (_tmp, paths, looking_at) = with_a_file();

        // Delete the bytes behind the one file, which is what "missing" means.
        let page = read(&paths, &looking_at);
        std::fs::remove_file(PathBuf::from(&page.dir).join("notes.txt")).unwrap();

        let report = ops::file::verify(&paths, &looking_at.group).unwrap();

        assert_eq!(describe_verify(&report), "checked 1: 1 missing");
    }
}
