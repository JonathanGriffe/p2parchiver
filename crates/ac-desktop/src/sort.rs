use std::path::PathBuf;
use std::rc::Rc;

use ac_net::config::Paths;
use ac_node::ops;
use ac_node::ops::format::{ago, human_size};
use ac_node::ops::import::Waiting;
use slint::{ComponentHandle, ModelRc, VecModel};

use crate::selection::{Selection, Sorting};
use crate::ui::{FieldItem, MainWindow, SettingItem, SourceItem};
use crate::work::{self, Nudge};

/// What the picker offers when a source is being added, and what its fields are answered in.
pub const KIND_TEXT: i32 = 0;
pub const KIND_PATH: i32 = 1;
pub const KIND_PATHS: i32 = 2;
pub const KIND_SECRET: i32 = 3;
pub const KIND_TOGGLE: i32 = 4;

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

    /// The Sources section.
    pub sources: Vec<SourceItem>,
    /// What this build can import from, for the Add form's picker.
    pub implementations: Vec<slint::SharedString>,
    /// The Settings tab's Sources section, which is about the app rather than the accounts.
    pub settings: Vec<SettingItem>,
    /// The file either side of the one on screen, as (hash, path): what the preview worker
    /// fetches ahead so stepping is instant rather than a spawn per keypress.
    pub neighbours: Vec<(String, String)>,
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
        sources: sources(paths),
        implementations: ops::import::available()
            .iter()
            .map(|entry| slint::SharedString::from(entry.name))
            .collect(),
        settings: shared_settings(paths),
        ..Page::default()
    };

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
    page.neighbours = neighbours(&inbox, paths, looking_at, &file);
    page
}

/// The one behind and the one ahead, which is the whole of what gets prefetched.
fn neighbours(
    inbox: &ops::import::Inbox,
    paths: &Paths,
    looking_at: &Sorting,
    file: &Waiting,
) -> Vec<(String, String)> {
    let mut out = Vec::new();

    let ahead = inbox.page(Some((file.row.at, &file.row.hash)), 1);
    let behind = match looking_at.trail.len() {
        0 | 1 => Vec::new(),
        len => {
            let (at, hash) = &looking_at.trail[len - 2];
            inbox
                .page(Some((*at, hash.as_str())), 1)
                .unwrap_or_default()
        }
    };

    for file in ahead.unwrap_or_default().iter().chain(behind.iter()) {
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

/// The same, for a caller with only the one question to ask.
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

fn sources(paths: &Paths) -> Vec<SourceItem> {
    ops::import::sources(paths)
        .unwrap_or_default()
        .iter()
        .map(|entry| SourceItem {
            dir: entry.row.dir.as_str().into(),
            name: entry.row.name.as_str().into(),
            source: entry.row.source.as_str().into(),
            kind: match entry.kind {
                Some(kind) => kind.to_string(),
                None => format!("{} (not in this build)", entry.row.source),
            }
            .into(),
            scanned: match entry.row.scanned_at {
                0 => "never scanned".to_owned(),
                at => format!("scanned {}", ago(at)),
            }
            .into(),
            error: entry.row.last_error.clone().unwrap_or_default().into(),
            tally: format!(
                "{} waiting · {} sorted · {} deleted · {} owed",
                entry.tally.waiting, entry.tally.sorted, entry.tally.dropped, entry.owed
            )
            .into(),
        })
        .collect()
}

pub fn shared_settings(paths: &Paths) -> Vec<SettingItem> {
    let mut out = Vec::new();
    for entry in ops::import::available() {
        let Ok(settings) = ops::import::settings(paths, entry.name) else {
            continue;
        };
        for setting in settings {
            out.push(SettingItem {
                source: entry.name.into(),
                key: setting.field.key.into(),
                label: setting.field.label.into(),
                value: setting.value.unwrap_or_default().into(),
                secret: setting.field.kind == ac_import::config::FieldKind::Secret,
                set: setting.set,
            });
        }
    }
    out
}

/// The fields one implementation declares, as a form to fill in.
pub fn fields(source: &str) -> Vec<FieldItem> {
    let Ok(entry) = ops::import::implementation(source) else {
        return Vec::new();
    };
    entry
        .config
        .iter()
        .map(|field| FieldItem {
            key: field.key.into(),
            label: field.label.into(),
            kind: kind_of(field.kind),
            required: field.required,
            value: Default::default(),
        })
        .collect()
}

pub fn kind_of(kind: ac_import::config::FieldKind) -> i32 {
    use ac_import::config::FieldKind;
    match kind {
        FieldKind::Text => KIND_TEXT,
        FieldKind::Path => KIND_PATH,
        FieldKind::Paths => KIND_PATHS,
        FieldKind::Secret => KIND_SECRET,
        FieldKind::Toggle => KIND_TOGGLE,
    }
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

    window.set_sort_group_names(ModelRc::from(Rc::new(VecModel::from(page.group_names))));
    window.set_sort_group_index(page.group_index);
    window.set_sort_group_id(page.group_id.into());

    window.set_sources(ModelRc::from(Rc::new(VecModel::from(page.sources))));
    window.set_source_kinds(ModelRc::from(Rc::new(VecModel::from(page.implementations))));
    window.set_source_settings(ModelRc::from(Rc::new(VecModel::from(page.settings))));

    window.set_sort_path(page.path.clone().into());

    let previews = crate::preview::previews();
    previews.show(window, &page.hash, std::path::Path::new(&page.path));
    for (hash, path) in &page.neighbours {
        previews.prefetch(hash, std::path::Path::new(path));
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

    window.on_sort_step({
        let paths = paths.clone();
        let selection = selection.clone();
        let nudge = nudge.clone();
        move |forward| {
            match forward {
                true => {
                    let looking_at = selection.get().sorting;
                    if let Some(file) = current(&paths, &looking_at) {
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
            let group = selection.get().sorting.group;
            let (hash, selection) = (hash.to_string(), selection.clone());

            work::run(&weak, &nudge, move || {
                let filed = match folder {
                    false => ops::import::sort(&paths, &hash, &group)?,
                    true => {
                        let row = ops::import::find(&paths, &hash)?;
                        ops::import::sort_folder(&paths, &row.source_dir, &row.folder, &group)?
                    }
                };
                // What was on screen has gone from the backlog, so the trail behind it no
                // longer points where it did.
                selection.rewind();
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

            work::run(&weak, &nudge, move || {
                let filed = match folder {
                    false => ops::import::drop(&paths, &hash)?,
                    true => {
                        let row = ops::import::find(&paths, &hash)?;
                        ops::import::drop_folder(&paths, &row.source_dir, &row.folder)?
                    }
                };
                selection.rewind();
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

    window.on_import_pick({
        let weak = weak.clone();
        let paths = paths.clone();
        let selection = selection.clone();
        let nudge = nudge.clone();
        move |folder| {
            let dialog = rfd::FileDialog::new().set_title(match folder {
                true => "Import a folder",
                false => "Import files",
            });
            let picked: Vec<PathBuf> = match folder {
                true => dialog.pick_folder().into_iter().collect(),
                false => dialog.pick_files().unwrap_or_default(),
            };
            if picked.is_empty() {
                return;
            }
            import(&weak, &paths, picked, &selection, &nudge);
        }
    });

    window.on_scan_source({
        let weak = weak.clone();
        let paths = paths.clone();
        let nudge = nudge.clone();
        move |dir| {
            let (paths, nudge, dir) = (paths.clone(), nudge.clone(), dir.to_string());
            work::run(&weak, &nudge, move || {
                let scanned = ops::import::scan(&paths, &dir)?;
                if !scanned.reachable {
                    return Ok(format!("{} cannot be reached right now", scanned.name));
                }
                Ok(format!(
                    "{}: {} offered, {} new",
                    scanned.name, scanned.found, scanned.owed
                ))
            });
        }
    });

    window.on_remove_source({
        let weak = weak.clone();
        let paths = paths.clone();
        let nudge = nudge.clone();
        move |dir| {
            let (paths, nudge, dir) = (paths.clone(), nudge.clone(), dir.to_string());
            work::run(&weak, &nudge, move || {
                match ops::import::remove_source(&paths, &dir)? {
                    true => Ok(format!("removed {dir}")),
                    false => Err(anyhow::anyhow!("no source called {dir}")),
                }
            });
        }
    });

    window.on_pick_source_kind({
        let weak = weak.clone();
        move |source| {
            if let Some(window) = weak.upgrade() {
                let fields = fields(source.as_ref());
                window.set_source_fields(ModelRc::from(Rc::new(VecModel::from(fields))));
            }
        }
    });

    window.on_save_setting({
        let weak = weak.clone();
        let paths = paths.clone();
        let nudge = nudge.clone();
        move |source, key, value| {
            let (paths, nudge) = (paths.clone(), nudge.clone());
            let (source, key, value) = (source.to_string(), key.to_string(), value.to_string());
            work::run(&weak, &nudge, move || {
                ops::import::set_setting(&paths, &source, &key, &value)?;
                Ok(format!("set {source} {key}"))
            });
        }
    });

    window.on_field_edited({
        let weak = weak.clone();
        move |at, value| {
            if let Some(window) = weak.upgrade() {
                write_field(&window, at, |_| value.to_string());
            }
        }
    });

    // A path is chosen rather than typed, so what was chosen is written straight into the
    // model the Add button reads: the form never has to hand a value back.
    window.on_field_browse({
        let weak = weak.clone();
        move |at, several| {
            let dialog = rfd::FileDialog::new().set_title("Choose");
            let picked = match several {
                true => dialog.pick_folder(),
                false => dialog.pick_file(),
            };
            let Some(picked) = picked else {
                return;
            };
            let picked = picked.display().to_string();

            if let Some(window) = weak.upgrade() {
                write_field(&window, at, |had| match (several, had.is_empty()) {
                    (true, false) => format!("{had}\n{picked}"),
                    _ => picked.clone(),
                });
            }
        }
    });

    window.on_field_cleared({
        let weak = weak.clone();
        move |at| {
            if let Some(window) = weak.upgrade() {
                write_field(&window, at, |_| String::new());
            }
        }
    });

    window.on_add_source({
        let weak = weak.clone();
        let paths = paths.clone();
        let nudge = nudge.clone();
        move |source, name| {
            let Some(window) = weak.upgrade() else {
                return;
            };
            let answers = answers(&window);
            let (paths, nudge) = (paths.clone(), nudge.clone());
            let (source, name) = (source.to_string(), name.to_string());

            work::run(&weak, &nudge, move || {
                let row = ops::import::add_source(&paths, &source, &name, answers)?;
                Ok(format!("added {} ({})", row.name, row.source))
            });
        }
    });
}

/// Change one field's answer in the model the Add button reads.
fn write_field(window: &MainWindow, at: i32, to: impl FnOnce(&str) -> String) {
    use slint::Model;

    let fields = window.get_source_fields();
    let Some(at) = usize::try_from(at)
        .ok()
        .filter(|at| *at < fields.row_count())
    else {
        return;
    };
    let Some(mut field) = fields.row_data(at) else {
        return;
    };
    field.value = to(field.value.as_ref()).into();
    fields.set_row_data(at, field);
}

/// What the Add form was filled in with, in the shape the implementation declared.
fn answers(window: &MainWindow) -> ac_import::config::Fields {
    use slint::Model;

    let mut fields = ac_import::config::Fields::new();
    for field in window.get_source_fields().iter() {
        let value = field.value.to_string();
        if value.trim().is_empty() {
            continue;
        }
        // A repeatable field is one line per answer, which is how the form takes several
        // paths without growing a widget that can add rows.
        match field.kind == KIND_PATHS {
            true => {
                for line in value.lines().filter(|line| !line.trim().is_empty()) {
                    fields.push(&field.key, line.trim());
                }
            }
            false => {
                fields.push(&field.key, value.trim());
            }
        }
    }
    fields
}

/// Add the picked folders, scan them, and bring them in, saying which file as it goes.
fn import(
    weak: &slint::Weak<MainWindow>,
    paths: &Paths,
    picked: Vec<PathBuf>,
    selection: &Selection,
    nudge: &Nudge,
) {
    work::begin(weak);

    let (paths, nudge, selection) = (paths.clone(), nudge.clone(), selection.clone());
    let progress = weak.clone();

    work::action(
        weak,
        move || {
            let name = (picked.len() == 1)
                .then(|| {
                    picked[0]
                        .file_name()
                        .and_then(|name| name.to_str())
                        .map(str::to_owned)
                })
                .flatten();
            let picked = ops::import::from_folder(&paths, name.as_deref(), &picked)?;
            let scanned = ops::import::scan(&paths, &picked.row.dir)?;

            let mut pump = ops::import::pump(&paths, None)?;
            let mut fetched = ops::import::Fetched::default();
            while let Some(brought) = pump.next()? {
                let say = format!("importing {}: {}", fetched.tried + 1, brought.name);
                let _ = progress.upgrade_in_event_loop(move |window| {
                    window.set_sort_progress(say.into());
                });
                fetched.count(&brought);
            }
            pump.finish()?;

            let _ = progress.upgrade_in_event_loop(|window| window.set_sort_progress("".into()));
            selection.rewind();

            let mut said = format!(
                "{}: {} imported ({})",
                scanned.name,
                fetched.kept,
                human_size(fetched.bytes)
            );
            if fetched.known + fetched.held > 0 {
                said += &format!(", {} already had", fetched.known + fetched.held);
            }
            for note in &fetched.failed {
                said += &format!("\n{note}");
            }
            Ok(said)
        },
        move |window, outcome| work::finish(window, outcome, &nudge),
    );
}

/// One line for what a filing or a deletion did.
fn said(filed: &ops::import::Filed, did: &str) -> String {
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
    use super::*;
    use crate::groups::tests::home;
    use crate::selection::Sorting;

    /// An album imported and waiting to be sorted.
    fn waiting(files: &[&str]) -> (tempfile::TempDir, Paths) {
        let (tmp, paths) = home("jonathan");
        let album = tmp.path().join("album");
        for file in files {
            let path = album.join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, file.as_bytes()).unwrap();
        }

        let picked = ops::import::from_folder(&paths, Some("Summer"), &[album]).unwrap();
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
        assert_eq!(page.sources.len(), 1);
        assert_eq!(page.sources[0].name, "Summer");
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

    #[test]
    fn a_bulk_button_names_what_it_is_about_to_act_on() {
        let (_tmp, paths) = waiting(&["DCIM/a.jpg", "DCIM/b.jpg", "other/c.jpg"]);

        // The oldest is one of DCIM's two, so that is what the button would say.
        let page = read(&paths, &Sorting::default());
        assert_eq!(page.folder, "DCIM");
        assert_eq!(page.in_folder, 2);
    }

    #[test]
    fn an_empty_backlog_shows_no_file_but_still_lists_the_sources() {
        let (_tmp, paths) = waiting(&["a.jpg"]);
        let file = current(&paths, &Sorting::default()).unwrap();
        ops::import::drop(&paths, &file.row.hash).unwrap();

        let page = read(&paths, &Sorting::default());

        assert!(!page.have);
        assert!(page.name.is_empty());
        assert_eq!(page.sources.len(), 1, "the import is still listed");
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

        let filed = ElementHandle::find_by_accessible_label(&window, "File all 2 from DCIM")
            .next()
            .expect("the bulk file button names its count and its folder");
        assert!(
            filed.accessible_enabled().unwrap_or(false),
            "a group is picked"
        );

        assert!(
            ElementHandle::find_by_accessible_label(&window, "Delete all 2 from DCIM")
                .next()
                .is_some(),
            "and so does the bulk delete"
        );
    }

    /// The promise the registry makes, kept all the way to the window: a declaration this
    /// file has never heard of renders a form anyway.
    #[test]
    fn a_form_is_rendered_from_a_declaration_no_view_knows_about() {
        use crate::ui::MainWindow;
        use ac_import::config::{Field, FieldKind};
        use i_slint_backend_testing::ElementHandle;

        // One of every kind, as a `drive` or a `phone` would declare them.
        const DECLARED: &[Field] = &[
            Field::text("account", "Account"),
            Field::path("keyfile", "Key file"),
            Field::paths("path", "Folders"),
            Field::secret("token", "Refresh token"),
            Field::toggle("videos", "Include videos").optional(),
        ];

        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().unwrap();
        window.set_tab(4);

        let rendered: Vec<FieldItem> = DECLARED
            .iter()
            .map(|field| FieldItem {
                key: field.key.into(),
                label: field.label.into(),
                kind: kind_of(field.kind),
                required: field.required,
                value: Default::default(),
            })
            .collect();
        window.set_source_fields(ModelRc::from(Rc::new(VecModel::from(rendered))));

        for field in DECLARED {
            // A toggle carries its own label, so it is not given a second one above it.
            let looking_for = match (field.kind, field.required) {
                (FieldKind::Toggle, _) | (_, true) => field.label.to_owned(),
                (_, false) => format!("{} (optional)", field.label),
            };
            assert!(
                ElementHandle::find_by_accessible_label(&window, &looking_for)
                    .next()
                    .is_some(),
                "{} was declared and never drawn",
                field.label
            );
        }

        // A secret is written and never read back, whatever the model was given.
        write_field(&window, 3, |_| "shhh".to_owned());
        let secret = ElementHandle::find_by_accessible_label(&window, "Refresh token")
            .next()
            .expect("the secret field is drawn");
        assert_ne!(
            secret.accessible_value().unwrap_or_default(),
            "shhh",
            "a screenshot of this tab must not leak it"
        );
    }

    #[test]
    fn the_add_form_is_whatever_the_implementation_declared() {
        let declared = fields("folder");

        assert_eq!(declared.len(), 1, "one field, and no page knows its name");
        assert_eq!(declared[0].key, "path");
        assert_eq!(declared[0].kind, KIND_PATHS);
        assert!(declared[0].required);
        assert!(fields("nothing-like-this").is_empty());
    }
}
