use std::rc::Rc;

use ac_net::config::Paths;
use ac_node::ops;
use ac_node::ops::format::{ago, human_size};
use slint::{ComponentHandle, ModelRc, VecModel};

use crate::selection::Selection;
use crate::ui::{FieldItem, MainWindow, SettingItem, SourceItem};
use crate::work::{self, Nudge};

/// How a source is doing, which is also the colour its status is shown in. Shared with the
/// view, so the two cannot drift.
pub const AVAILABLE: i32 = 0;
pub const UNAVAILABLE: i32 = 1;
pub const BROKEN: i32 = 2;

/// What the Add form answers a declared field with. Mirrors `ac_import::config::FieldKind`,
/// because slint has no enums to share and a form is laid out by kind.
pub const KIND_TEXT: i32 = 0;
pub const KIND_PATH: i32 = 1;
pub const KIND_PATHS: i32 = 2;
pub const KIND_SECRET: i32 = 3;
pub const KIND_TOGGLE: i32 = 4;

/// Everything the Sources tab shows: what is configured, what this build can import from,
/// and the app-wide settings the Settings tab renders from the same read.
#[derive(Default)]
pub struct Page {
    pub sources: Vec<SourceItem>,
    /// What this build can import from, for the Add form's picker.
    pub implementations: Vec<slint::SharedString>,
    /// The Settings tab's Sources section, which is about the app rather than the accounts.
    pub settings: Vec<SettingItem>,
}

pub fn read(paths: &Paths) -> Page {
    Page {
        sources: sources(paths),
        implementations: ops::import::available()
            .iter()
            .map(|entry| slint::SharedString::from(entry.name))
            .collect(),
        settings: shared_settings(paths),
    }
}

fn sources(paths: &Paths) -> Vec<SourceItem> {
    ops::import::sources(paths)
        .unwrap_or_default()
        .iter()
        // A one-shot that has run is not a source to watch any more: it fetched what it
        // found and will do nothing further. Its files are on the Sort tab, which is where
        // there is still something to do about them.
        .filter(|entry| !entry.finished)
        .map(|entry| {
            let (state, status) = standing(entry);
            SourceItem {
                dir: entry.row.dir.as_str().into(),
                name: entry.row.name.as_str().into(),
                owed: entry.owed as i32,
                // Everything it ever brought in, whatever became of it since: a file that
                // was sorted into a group or thrown away was still downloaded once.
                downloaded: (entry.tally.waiting + entry.tally.sorted + entry.tally.dropped) as i32,
                size: human_size(entry.tally.bytes).into(),
                state,
                status: status.into(),
                polled: match entry.row.scanned_at {
                    0 => "never".to_owned(),
                    at => ago(at),
                }
                .into(),
                error: entry.row.last_error.clone().unwrap_or_default().into(),
                // An account, rather than something answerable by typing: it can be signed
                // in to again when its token stops working.
                signs_in: ops::import::implementation(&entry.row.source)
                    .is_ok_and(ac_import::Registered::signs_in),
            }
        })
        .collect()
}

/// How a source is doing, in one word and the colour that goes with it.
///
/// The three are not the same kind of thing, which is why they are told apart rather than
/// collapsed. A source that failed is *broken* and wants looking at. One that is simply
/// somewhere else is *unavailable*, which for a phone is the ordinary state and no cause
/// for red — only an Intermittent source can be that, and being absent is not a failure it
/// records an error for.
fn standing(entry: &ops::import::Configured) -> (i32, &'static str) {
    use ac_import::source::SourceType;

    if entry.row.last_error.is_some() {
        return (BROKEN, "broken");
    }
    match (entry.kind, entry.row.reachable) {
        (Some(SourceType::Intermittent), false) => (UNAVAILABLE, "unavailable"),
        _ => (AVAILABLE, "available"),
    }
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
            });
        }
    }
    out
}

/// The shared settings one implementation declares, as fields the Add dialog still has to ask.
///
/// Only the ones with no answer yet. These belong to the implementation rather than to the
/// source being added, so a second account of the same one is not asked for the application's
/// credentials again — and where they are all already stored, the dialog asks nothing extra
/// at all. Changing one afterwards is what the Settings tab is for.
pub fn settings_fields(paths: &Paths, source: &str) -> Vec<FieldItem> {
    let Ok(entry) = ops::import::implementation(source) else {
        return Vec::new();
    };
    let stored = ops::import::settings(paths, source).unwrap_or_default();

    entry
        .asked_settings()
        .filter(|field| !stored.iter().any(|s| s.field.key == field.key && s.set))
        .map(|field| FieldItem {
            key: field.key.into(),
            label: field.label.into(),
            kind: kind_of(field.kind),
            required: field.required,
            value: Default::default(),
            shown: Default::default(),
        })
        .collect()
}

/// The fields one implementation declares, as a form to fill in.
pub fn fields(source: &str) -> Vec<FieldItem> {
    let Ok(entry) = ops::import::implementation(source) else {
        return Vec::new();
    };
    entry
        .asked_config()
        .map(|field| FieldItem {
            key: field.key.into(),
            label: field.label.into(),
            kind: kind_of(field.kind),
            required: field.required,
            value: Default::default(),
            shown: Default::default(),
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

/// How many a scan passed over, for the end of the line that says what it did.
///
/// Which ones go to the log. A scan of a whole Drive can skip hundreds, and a bar that grows
/// a line per file stops being a bar; the count is what tells you whether to go and look.
fn also_skipped(notes: &[String]) -> String {
    for note in notes {
        tracing::info!("{note}");
    }
    match notes.len() {
        0 => String::new(),
        1 => ", 1 skipped".to_owned(),
        many => format!(", {many} skipped"),
    }
}

/// How many the source offered that are not pictures or video, for the end of the line.
fn also_ignored(ignored: u64) -> String {
    match ignored {
        0 => String::new(),
        1 => ", 1 not media".to_owned(),
        many => format!(", {many} not media"),
    }
}

pub fn apply(window: &MainWindow, page: Page) {
    window.set_sources(ModelRc::from(Rc::new(VecModel::from(page.sources))));
    window.set_source_kinds(ModelRc::from(Rc::new(VecModel::from(page.implementations))));
    window.set_source_settings(ModelRc::from(Rc::new(VecModel::from(page.settings))));
}

pub fn wire(window: &MainWindow, paths: &Paths, selection: &Selection, nudge: &Nudge) {
    let weak = window.as_weak();

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
                    "{}: {} offered, {} new{}",
                    scanned.name,
                    scanned.found,
                    scanned.owed,
                    also_ignored(scanned.ignored)
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
        let paths = paths.clone();
        move |source| {
            if let Some(window) = weak.upgrade() {
                let fields = fields(source.as_ref());
                window.set_source_fields(ModelRc::from(Rc::new(VecModel::from(fields))));

                let settings = settings_fields(&paths, source.as_ref());
                window.set_source_settings_fields(ModelRc::from(Rc::new(VecModel::from(settings))));
            }
        }
    });

    window.on_setting_edited({
        let weak = weak.clone();
        move |at, value| {
            if let Some(window) = weak.upgrade() {
                write_into(&window.get_source_settings_fields(), at, |_| {
                    value.to_string()
                });
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

    // Off the event loop like any other action, and for longer than most: it is waiting on
    // somebody to finish in a browser, which can take minutes or never happen at all.
    window.on_sign_in_source({
        let weak = weak.clone();
        let paths = paths.clone();
        let nudge = nudge.clone();
        move |source| {
            let (paths, nudge) = (paths.clone(), nudge.clone());
            let dir = source.to_string();
            work::run(&weak, &nudge, move || {
                let row = ops::import::authorize(&paths, &dir)?;
                Ok(format!("signed in again as {}", row.name))
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
        move |at, folder| {
            if let Some(window) = weak.upgrade() {
                browse_into(&window.get_source_fields(), at, folder);
            }
        }
    });

    window.on_field_cleared({
        let weak = weak.clone();
        move |at| {
            if let Some(window) = weak.upgrade() {
                write_into(&window.get_source_fields(), at, |_| String::new());
            }
        }
    });

    // The shared settings are a list of their own, counted from zero like the fields above.
    // Both sets of buttons reporting to the field handlers would mean browsing from a setting
    // wrote the picked path into whatever per-source field happened to sit at that number.
    window.on_setting_browse({
        let weak = weak.clone();
        move |at, folder| {
            if let Some(window) = weak.upgrade() {
                browse_into(&window.get_source_settings_fields(), at, folder);
            }
        }
    });

    window.on_setting_cleared({
        let weak = weak.clone();
        move |at| {
            if let Some(window) = weak.upgrade() {
                write_into(&window.get_source_settings_fields(), at, |_| String::new());
            }
        }
    });

    window.on_add_source({
        let weak = weak.clone();
        let paths = paths.clone();
        let nudge = nudge.clone();
        let selection = selection.clone();
        move |source, name| {
            let Some(window) = weak.upgrade() else {
                return;
            };
            let config = answers(&window.get_source_fields());
            let shared = answers(&window.get_source_settings_fields());
            let (paths, nudge) = (paths.clone(), nudge.clone());
            let (source, name) = (source.to_string(), name.to_string());

            let selection = selection.clone();

            // Not `work::run`: that shuts the whole tab until the action is done, and this
            // one can be waiting on somebody to finish in a browser. Only the Add button
            // waits, so a sign-in that stalls leaves the rest of the tab usable.
            window.set_source_adding(true);
            window.set_message(match ops::import::implementation(&source) {
                Ok(entry) if entry.signs_in() => "finish signing in, in your browser".into(),
                _ => slint::SharedString::from(""),
            });
            window.set_message_bad(false);

            work::action(
                &weak,
                move || {
                    // The settings go first: `add_source` refuses an implementation whose
                    // shared fields are not filled in, and refusing here would leave what was
                    // typed into the dialog with nowhere to have gone.
                    for (key, value) in shared.iter() {
                        ops::import::set_setting(&paths, &source, key, value)?;
                    }
                    let row = ops::import::add_source(&paths, &source, &name, config)?;

                    selection.rewind();

                    // A polled source is left to the daemon. It has never been scanned, which
                    // makes it the stalest thing there is and the next one picked up, and a whole
                    // Drive is not something to hold a window open for.
                    let one_shot = ops::import::implementation(&source)
                        .is_ok_and(|entry| !entry.kind.polled());
                    if !one_shot {
                        return Ok(format!("added {}, and it is being read now", row.name));
                    }

                    // A one-shot is never due, so nothing would ever come of it: this one scan is
                    // the whole of what it will ever offer.
                    let scanned = ops::import::scan(&paths, &row.dir)?;
                    let mut said = format!("added {}", row.name);
                    if !scanned.reachable {
                        said += ", which cannot be reached right now";
                        return Ok(said);
                    }
                    said += &format!(": {} to bring in", scanned.owed);
                    said += &also_ignored(scanned.ignored);
                    said += &also_skipped(&scanned.skipped);
                    Ok(said)
                },
                move |window, outcome| {
                    window.set_source_adding(false);
                    // Whatever the outcome, including the sign-in that never came back.
                    work::finish(window, outcome, &nudge);
                },
            );
        }
    });
}

/// How many characters of a path are worth showing. Chosen for the dialog's width at the
/// small monospace size, with room to spare rather than to the pixel.
const SHOWN: usize = 64;

/// A path cut to fit, keeping the end.
///
/// The front of a path is where the boilerplate is — everyone's home directory looks the
/// same — and the end is the album or the file that was actually picked. So what goes is
/// the front, which is the opposite of what eliding does.
pub fn shown(path: &str) -> String {
    if path.chars().count() <= SHOWN {
        return path.to_owned();
    }
    let tail: String = path
        .chars()
        .skip(path.chars().count().saturating_sub(SHOWN - 1))
        .collect();

    // Cut at a separator where there is one close by, so what is left reads as a path
    // rather than as the back half of a word.
    match tail.find('/') {
        Some(at) if at < 20 => format!("…{}", &tail[at..]),
        _ => format!("…{tail}"),
    }
}

/// What kind of field sits at `at`, which decides whether a chosen path is added to what
/// is there or replaces it.
/// Put a picked path into one row of whichever list is asking.
///
/// The list is handed in rather than reached for, so a row cannot end up writing into the
/// other one: `at` counts within a list and means nothing outside it.
fn browse_into(fields: &slint::ModelRc<FieldItem>, at: i32, folder: bool) {
    let dialog = rfd::FileDialog::new().set_title("Choose");
    let picked = match folder {
        true => dialog.pick_folder(),
        false => dialog.pick_file(),
    };
    let Some(picked) = picked else {
        return;
    };
    let picked = picked.display().to_string();

    write_into(fields, at, |had| match kind_in(fields, at) {
        // Several: one to a line, added to. Otherwise the one just chosen, replacing
        // whatever was there.
        KIND_PATHS if !had.is_empty() => format!("{had}\n{picked}"),
        _ => picked.clone(),
    });
}

fn kind_in(fields: &slint::ModelRc<FieldItem>, at: i32) -> i32 {
    use slint::Model;

    usize::try_from(at)
        .ok()
        .and_then(|at| fields.row_data(at))
        .map_or(KIND_TEXT, |field| field.kind)
}

/// Change one field's answer in the model the Add button reads.
fn write_field(window: &MainWindow, at: i32, to: impl FnOnce(&str) -> String) {
    write_into(&window.get_source_fields(), at, to);
}

fn write_into(fields: &slint::ModelRc<FieldItem>, at: i32, to: impl FnOnce(&str) -> String) {
    use slint::Model;

    let Some(at) = usize::try_from(at)
        .ok()
        .filter(|at| *at < fields.row_count())
    else {
        return;
    };
    let Some(mut field) = fields.row_data(at) else {
        return;
    };
    let value = to(field.value.as_ref());
    field.shown = shown(&value).into();
    field.value = value.into();
    fields.set_row_data(at, field);
}

/// What a form was filled in with, in the shape the implementation declared.
fn answers(model: &slint::ModelRc<FieldItem>) -> ac_import::config::Fields {
    use slint::Model;

    let mut fields = ac_import::config::Fields::new();
    for field in model.iter() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use ac_import::ledger::{SourceRow, Tally};
    use ac_import::source::SourceType;

    fn configured(
        kind: Option<SourceType>,
        reachable: bool,
        error: Option<&str>,
    ) -> ops::import::Configured {
        ops::import::Configured {
            row: SourceRow {
                dir: "phone".to_owned(),
                name: "Phone".to_owned(),
                source: "phone".to_owned(),
                config: Default::default(),
                added_at: 0,
                scanned_at: 0,
                last_error: error.map(str::to_owned),
                reachable,
            },
            kind,
            owed: 0,
            tally: Tally::default(),
            finished: false,
        }
    }

    /// The counts and the size come off the ledger, so the table can be trusted about how
    /// much a source has actually brought in.
    #[test]
    fn the_table_says_what_a_source_has_fetched_and_what_it_still_owes() {
        let (tmp, paths) = crate::groups::tests::home("jonathan");
        let album = tmp.path().join("album");
        for (name, bytes) in [("a.jpg", 1000usize), ("b.jpg", 2000), ("c.jpg", 3000)] {
            std::fs::create_dir_all(&album).unwrap();
            std::fs::write(album.join(name), vec![b'x'; bytes]).unwrap();
        }

        let picked = ops::import::from_folder(&paths, Some("Album"), &album).unwrap();
        ops::import::scan(&paths, &picked.row.dir).unwrap();

        // Scanned but not fetched: three owed, nothing downloaded.
        let before = &read(&paths).sources[0];
        assert_eq!(before.name, "Album");
        assert_eq!(before.owed, 3);
        assert_eq!(before.downloaded, 0);
        assert_eq!(before.size, "0 B");
        assert_eq!(before.state, AVAILABLE);
        assert_eq!(before.polled, "just now");

        // Two of them brought in.
        ops::import::drain(&paths, Some(2)).unwrap();
        let part = &read(&paths).sources[0];
        assert_eq!(part.owed, 1, "one still to fetch");
        assert_eq!(part.downloaded, 2);
        assert_eq!(part.size, "3.0 KB", "1000 + 2000 bytes");

        // And the rest — at which point a one-shot has run its course, and a table of
        // sources worth watching has nothing to say about it.
        ops::import::drain(&paths, None).unwrap();
        assert!(
            read(&paths).sources.is_empty(),
            "a finished one-shot leaves the table"
        );
    }

    /// The table on screen: its headings, and the two buttons that act on a picked row.
    #[test]
    fn the_table_is_drawn_and_its_buttons_wait_for_a_row() {
        use crate::ui::MainWindow;
        use i_slint_backend_testing::ElementHandle;

        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().unwrap();
        window.set_tab(5);

        for heading in ["Name", "To fetch", "Downloaded", "Size", "Status", "Polled"] {
            assert!(
                ElementHandle::find_by_accessible_label(&window, heading)
                    .next()
                    .is_some(),
                "the table should have a {heading:?} column"
            );
        }

        // Nothing is picked, so the two that act on a row are shut, and the one that does
        // not need one is open.
        for (label, ready) in [("Scan now", false), ("Remove", false), ("Add source", true)] {
            let button = ElementHandle::find_by_accessible_label(&window, label)
                .next()
                .unwrap_or_else(|| panic!("no {label:?} button"));
            assert_eq!(
                button.accessible_enabled().unwrap_or(false),
                ready,
                "{label:?} with nothing selected"
            );
        }
    }

    #[test]
    fn a_source_that_failed_reads_as_broken_whatever_else_is_true() {
        let (state, status) = standing(&configured(
            Some(SourceType::Intermittent),
            false,
            Some("no route to host"),
        ));
        assert_eq!(state, BROKEN);
        assert_eq!(status, "broken");
    }

    /// The distinction the three states exist for: a phone that is out of the house has not
    /// failed, and must not be shown in red.
    #[test]
    fn an_intermittent_source_that_is_simply_elsewhere_is_unavailable_not_broken() {
        let away = standing(&configured(Some(SourceType::Intermittent), false, None));
        assert_eq!(away, (UNAVAILABLE, "unavailable"));

        let home = standing(&configured(Some(SourceType::Intermittent), true, None));
        assert_eq!(home, (AVAILABLE, "available"));
    }

    /// Only an Intermittent source can be unavailable. A folder is either there or broken,
    /// and a folder that has never been polled is not "away".
    #[test]
    fn a_source_that_is_always_there_is_never_shown_as_away() {
        assert_eq!(
            standing(&configured(Some(SourceType::OneShot), false, None)),
            (AVAILABLE, "available")
        );
        assert_eq!(
            standing(&configured(Some(SourceType::Remote), false, None)),
            (AVAILABLE, "available")
        );
        // An implementation this build does not have cannot be asked, so it is not accused.
        assert_eq!(
            standing(&configured(None, false, None)),
            (AVAILABLE, "available")
        );
    }

    /// The dialog stacks two lists of boxes, each counting its rows from zero. A row in one
    /// reporting to the other's handlers would mean Clear on the first shared setting emptied
    /// whatever per-source field sat at that number instead — and Browse would have put a
    /// picked path there.
    #[test]
    fn a_button_on_a_shared_setting_acts_on_that_setting() {
        use crate::ui::MainWindow;
        use i_slint_backend_testing::ElementHandle;
        use slint::Model as _;

        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().unwrap();
        let (_tmp, paths) = crate::groups::tests::home("jonathan");
        let (nudge, _ticks) = crate::work::nudge();
        wire(&window, &paths, &Selection::new(), &nudge);
        window
            .window()
            .set_size(slint::PhysicalSize::new(1200, 2000));

        let one = |kind: i32, value: &str| {
            ModelRc::from(Rc::new(VecModel::from(vec![FieldItem {
                key: "k".into(),
                label: "A path".into(),
                kind,
                required: false,
                value: value.into(),
                shown: value.into(),
            }])))
        };
        window.set_tab(5);
        window.set_adding_source("folder".into());
        // Row zero of each list. The per-source one is plain text, so it draws no Clear of
        // its own and the only one on screen belongs to the shared setting.
        window.set_source_fields(one(KIND_TEXT, "the per-source one"));
        window.set_source_settings_fields(one(KIND_PATHS, "/somewhere"));

        ElementHandle::find_by_accessible_label(&window, "Clear")
            .next()
            .expect("the shared setting has a Clear button")
            .invoke_accessible_default_action();

        assert_eq!(
            window
                .get_source_settings_fields()
                .row_data(0)
                .unwrap()
                .value,
            "",
            "the setting it was pressed on"
        );
        assert_eq!(
            window.get_source_fields().row_data(0).unwrap().value,
            "the per-source one",
            "and not the field that shares its number"
        );
    }

    /// One button for a path, because no platform has a picker that takes both a file and
    /// a folder — `rfd::pick_file_or_folder` is macOS only. Which dialog to open is asked
    /// here instead.
    #[test]
    fn a_path_is_chosen_through_one_button_offering_both() {
        use crate::ui::MainWindow;
        use i_slint_backend_testing::ElementHandle;

        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().unwrap();
        window.set_tab(5);
        window.set_adding_source("folder".into());
        window.set_source_fields(ModelRc::from(Rc::new(VecModel::from(fields("folder")))));

        let showing = |label: &str| {
            ElementHandle::find_by_accessible_label(&window, label)
                .next()
                .is_some()
        };

        // One button, not two: the old pair was "Choose file…" and "Choose folder…".
        assert!(showing("Choose…"), "the one button is there");
        assert!(!showing("Choose file…") && !showing("Choose folder…"));
        assert!(!showing("File…"), "and it is shut to begin with");

        ElementHandle::find_by_accessible_label(&window, "Choose…")
            .next()
            .expect("no Choose button")
            .invoke_accessible_default_action();

        assert!(showing("File…") && showing("Folder…"), "both are offered");
    }

    #[test]
    fn a_long_path_is_cut_at_the_front_where_the_boilerplate_is() {
        // Short enough to stand as it is.
        let short = "/home/jo/Pictures/2024";
        assert_eq!(shown(short), short);

        // Long, so the front goes and the end — which is what was actually picked — stays.
        let long = format!(
            "/home/jonathan/{}/Pictures/holidays/2024/album",
            "deep/".repeat(12)
        );
        let cut = shown(&long);
        assert!(cut.starts_with('…'), "{cut}");
        assert!(cut.ends_with("/Pictures/holidays/2024/album"), "{cut}");
        assert!(
            cut.chars().count() <= SHOWN,
            "{} chars: {cut}",
            cut.chars().count()
        );

        // Cut at a separator, so what is left reads as a path.
        assert!(cut.starts_with("…/"), "{cut}");
    }

    #[test]
    fn cutting_a_path_never_splits_a_character() {
        // Multi-byte throughout, so a cut by bytes rather than characters would panic.
        let long = format!("/home/{}/álbum", "é".repeat(200));
        let cut = shown(&long);
        assert!(cut.chars().count() <= SHOWN);
        assert!(cut.ends_with("álbum"), "{cut}");
    }

    /// The row of buttons under the table. They sit in one row, so they have to be one
    /// height — and the one that carries the menu is wrapped, which is how it came to be a
    /// different size from the two beside it.
    #[test]
    fn the_buttons_under_the_table_are_all_one_height() {
        use crate::ui::MainWindow;
        use i_slint_backend_testing::ElementHandle;

        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().unwrap();
        window.set_tab(5);

        let height = |label: &str| {
            ElementHandle::find_by_accessible_label(&window, label)
                .next()
                .unwrap_or_else(|| panic!("no {label:?} button"))
                .size()
                .height
        };

        let (scan, remove, add) = (height("Scan now"), height("Remove"), height("Add source"));
        assert!(scan > 0.0, "a button with no height is not drawn at all");
        assert_eq!(scan, remove);
        assert_eq!(
            scan, add,
            "the wrapped one has to match the bare ones beside it"
        );
    }

    /// The two tabs are one page to a reader, so their buttons have to be one size. They
    /// are in different views, which is exactly how they would come to differ.
    #[test]
    fn the_sort_tab_and_this_one_use_buttons_of_one_height() {
        use crate::ui::MainWindow;
        use i_slint_backend_testing::ElementHandle;

        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().unwrap();
        window.set_sort_have(true);

        let height = |label: &str| {
            ElementHandle::find_by_accessible_label(&window, label)
                .next()
                .unwrap_or_else(|| panic!("no {label:?} button"))
                .size()
                .height
        };

        window.set_tab(5);
        let sources = height("Add source");
        window.set_tab(4);
        let (previous, file) = (height("Previous"), height("Delete"));

        assert!(sources > 0.0);
        assert_eq!(previous, sources, "Sort's stepping buttons match Sources'");
        assert_eq!(file, sources, "and so do the ones that act on a file");
    }

    /// Adding a source can mean waiting on a browser, which is somebody else's pace. Only the
    /// Add button waits on it: shutting the tab meant a sign-in that stalled took Scan, Remove
    /// and everything else down with it for as long as it stalled.
    #[test]
    fn adding_a_source_holds_only_its_own_button() {
        use crate::ui::MainWindow;
        use i_slint_backend_testing::ElementHandle;

        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().unwrap();
        window.set_tab(5);

        let button = |label: &str| ElementHandle::find_by_accessible_label(&window, label).next();
        let enabled =
            |label: &str| button(label).map(|found| found.accessible_enabled().unwrap_or(false));

        assert_eq!(enabled("Add source"), Some(true));
        assert_eq!(enabled("Scan now"), Some(false), "nothing is selected yet");

        window.set_source_adding(true);
        assert!(button("Add source").is_none(), "it says what it is doing");
        assert_eq!(enabled("Adding…"), Some(false));

        // The whole point: the rest of the tab is not gated on it, and neither is anything
        // on any other page — adding never touches `busy`.
        assert!(!window.get_busy(), "the tab was never shut");
        assert_eq!(
            enabled("Scan now"),
            Some(false),
            "still only waiting on a selection"
        );

        window.set_source_adding(false);
        assert_eq!(enabled("Add source"), Some(true), "and it comes back");
    }

    /// The Add source menu. It was a `PopupWindow` first, which renders in a layer of its
    /// own that a test cannot look into — so a broken one could not have been caught here.
    /// It is part of the ordinary tree now, and this is what says so.
    #[test]
    fn the_add_menu_offers_every_implementation_and_closes_behind_itself() {
        use crate::ui::MainWindow;
        use i_slint_backend_testing::ElementHandle;

        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().unwrap();
        window.set_tab(5);
        window.set_source_kinds(ModelRc::from(Rc::new(VecModel::from(vec![
            slint::SharedString::from("folder"),
            slint::SharedString::from("drive"),
        ]))));

        let listed = |kind: &str| {
            ElementHandle::find_by_accessible_label(&window, kind)
                .next()
                .is_some()
        };
        assert!(!listed("folder"), "the menu is shut to begin with");

        let press = || {
            ElementHandle::find_by_accessible_label(&window, "Add source")
                .next()
                .expect("no Add source button")
                .invoke_accessible_default_action();
        };

        press();
        // Every implementation this build has, and nothing in the view names one.
        assert!(
            listed("folder") && listed("drive"),
            "the menu opens on a click"
        );

        press();
        assert!(!listed("folder"), "and the same button shuts it again");
    }

    /// The dialog is the only way in, and it is gated on an implementation being named —
    /// which is what picking one from the Add source menu does.
    #[test]
    fn the_add_dialog_opens_only_once_an_implementation_is_picked() {
        use crate::ui::MainWindow;
        use i_slint_backend_testing::ElementHandle;

        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().unwrap();
        window.set_tab(5);

        let open = || {
            ElementHandle::find_by_accessible_label(&window, "Cancel")
                .next()
                .is_some()
        };
        assert!(!open(), "no dialog until one is picked");

        window.set_adding_source("folder".into());
        assert!(open(), "picking one opens it");
        assert!(
            ElementHandle::find_by_accessible_label(&window, "Add")
                .next()
                .is_some_and(|add| !add.accessible_enabled().unwrap_or(true)),
            "and it will not add anything until it is named"
        );

        // Dismissing is what closes it, and nothing else is left behind.
        window.set_adding_source("".into());
        assert!(!open());
    }

    /// What the dialog offers for one implementation: its own config, and the settings it
    /// shares — both straight off the declaration.
    #[test]
    fn the_dialog_offers_the_config_and_the_shared_settings_together() {
        let (_tmp, paths) = crate::groups::tests::home("jonathan");

        // The one source this build has declares a path and shares nothing, which is what
        // a source with nothing to share looks like rather than a gap.
        assert_eq!(fields("folder").len(), 1);
        assert_eq!(fields("folder")[0].key, "path");
        assert!(settings_fields(&paths, "folder").is_empty());
        assert!(settings_fields(&paths, "nothing-like-this").is_empty());
    }

    /// A shared setting belongs to the implementation, not to the source being added, so it
    /// is asked once and then never again — including the case where that leaves the dialog
    /// with nothing extra to ask at all.
    #[test]
    fn the_dialog_stops_asking_for_a_shared_setting_once_it_has_one() {
        let (_tmp, paths) = crate::groups::tests::home("jonathan");

        let asked = |paths: &Paths| -> Vec<String> {
            settings_fields(paths, "drive")
                .iter()
                .map(|field| field.key.to_string())
                .collect()
        };
        assert_eq!(asked(&paths), ["client_id", "client_secret"]);

        ops::import::set_setting(&paths, "drive", "client_id", "an-id").unwrap();
        assert_eq!(
            asked(&paths),
            ["client_secret"],
            "the answered one drops out"
        );

        ops::import::set_setting(&paths, "drive", "client_secret", "shh").unwrap();
        assert!(
            asked(&paths).is_empty(),
            "a second Drive is asked only which folder it is"
        );

        // Which Drive is still per source, and is still asked every time.
        let own = fields("drive");
        let own: Vec<&str> = own.iter().map(|f| f.key.as_str()).collect();
        assert_eq!(own, ["folder"]);
    }

    /// The token belongs to one source rather than to the implementation — that is what lets
    /// two of them be two Google accounts — and it is asked for in neither place.
    #[test]
    fn the_token_is_never_a_field_anyone_is_offered() {
        let (_tmp, paths) = crate::groups::tests::home("jonathan");

        for offered in [settings_fields(&paths, "drive"), fields("drive")] {
            assert!(
                !offered.iter().any(|field| field.key == "refresh_token"),
                "a box nobody can fill in"
            );
        }

        // And it is not a shared setting at all, so it has no Settings row either.
        assert!(
            !shared_settings(&paths)
                .iter()
                .any(|item| item.key == "refresh_token")
        );
    }

    /// Changing one is what the Settings tab is for, and a value that cannot be read back
    /// cannot be checked against the one that was meant to be pasted.
    #[test]
    fn the_settings_tab_shows_what_is_stored_secret_or_not() {
        let (_tmp, paths) = crate::groups::tests::home("jonathan");
        ops::import::set_setting(&paths, "drive", "client_secret", "shh-1234").unwrap();

        let row = shared_settings(&paths)
            .into_iter()
            .find(|item| item.key == "client_secret")
            .expect("the secret has a row of its own");
        assert_eq!(row.value, "shh-1234");
    }

    /// A scan of a whole Drive can skip hundreds of files. The bar says how many; the log
    /// says which, because one line cannot hold them and a growing bar moves the page.
    #[test]
    fn what_a_scan_passed_over_is_counted_rather_than_listed() {
        assert_eq!(also_skipped(&[]), "");
        assert_eq!(also_skipped(&["skipping Notes".to_owned()]), ", 1 skipped");

        let many: Vec<String> = (0..200).map(|at| format!("skipping {at}")).collect();
        let said = also_skipped(&many);
        assert_eq!(said, ", 200 skipped");
        assert!(!said.contains('\n'), "it stays one line: {said:?}");
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
        window.set_tab(5); // Sources
        // The form is the Add dialog's, and naming an implementation is what opens it.
        window.set_adding_source("phone".into());

        let rendered: Vec<FieldItem> = DECLARED
            .iter()
            .map(|field| FieldItem {
                key: field.key.into(),
                label: field.label.into(),
                kind: kind_of(field.kind),
                required: field.required,
                value: Default::default(),
                shown: Default::default(),
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
        // One path, which may be a file or a folder — not a repeatable selection.
        assert_eq!(declared[0].kind, KIND_PATH);
        assert!(declared[0].required);
        assert!(fields("nothing-like-this").is_empty());
    }
}

#[cfg(test)]
mod tabs {
    use crate::ui::MainWindow;
    use i_slint_backend_testing::ElementHandle;

    /// Which page each nav entry opens, by something only that page has.
    ///
    /// Renumbering the nav is the one change here that breaks quietly — the wrong page
    /// simply appears, and nothing else notices. Peers and About are left out: neither has
    /// a button that is always there to name them by.
    #[test]
    fn each_nav_entry_opens_the_page_it_names() {
        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().unwrap();
        // The Sort tab draws its buttons only when it has a file to show.
        window.set_sort_have(true);

        for (tab, page, only_here) in [
            (0, "Status", "Copy"),
            (1, "Groups", "Create"),
            (3, "Files", "Verify"),
            (4, "Sort", "Previous"),
            (5, "Sources", "Add source"),
            (6, "Settings", "Save"),
        ] {
            window.set_tab(tab);
            assert!(
                ElementHandle::find_by_accessible_label(&window, only_here)
                    .next()
                    .is_some(),
                "tab {tab} should be {page}, but nothing on it says {only_here:?}"
            );
        }

        // And the two halves really did come apart: the Sort tab no longer carries the
        // Sources section that used to sit under it.
        window.set_tab(4);
        assert!(
            ElementHandle::find_by_accessible_label(&window, "Add source")
                .next()
                .is_none(),
            "adding a source belongs to the Sources tab now"
        );
    }
}
