//! Configuring a source, and what one has been told.

use std::path::Path;

use ac_files::dirname::sanitize;
use ac_import::config::{Field, FieldKind, Fields};
use ac_import::ledger::{Ledger, SourceRow, Tally};
use ac_import::registry::{self, Registered};
use ac_import::source::{Source, SourceType};
use ac_net::config::Paths;
use anyhow::{Context, Result, anyhow, bail};

use super::ledger;
use crate::ops::now;

/// Suffixes tried before giving up on finding a free directory.
const MAX_DIRS: u32 = 1000;

/// The one source every build has, and the field it takes. Named here because the registry
/// keeps its implementations to itself; a test holds this to the declaration.
const FOLDER: &str = "folder";
const FOLDER_PATH: &str = "path";

/// What this build can import from, and what each one has to be told.
pub fn available() -> &'static [Registered] {
    registry::known()
}

pub fn implementation(source: &str) -> Result<&'static Registered> {
    registry::find(source).ok_or_else(|| {
        let names: Vec<&str> = available().iter().map(|entry| entry.name).collect();
        anyhow!(
            "no source called {source:?}; this build has {}",
            names.join(", ")
        )
    })
}

/// One configured source, with everything the Sources section shows about it.
pub struct Configured {
    /// What it was told is here too, minus anything its implementation declared `Secret`:
    /// see [`without_secrets`].
    pub row: SourceRow,
    pub kind: Option<SourceType>,
    pub owed: u64,
    pub tally: Tally,
    /// A one-shot that has been scanned and owes nothing more. It ran, and there is nothing
    /// further it will do — so a list of sources worth watching leaves it out. The row is
    /// still here, and [`tidy`] is what eventually takes it away.
    pub finished: bool,
}

pub fn sources(paths: &Paths) -> Result<Vec<Configured>> {
    let ledger = ledger(paths)?;
    let tallies = ledger
        .tallies()
        .context("counting what each source brought in")?;

    let mut out = Vec::new();
    for row in ledger.sources().context("reading the configured sources")? {
        let tally = tallies
            .iter()
            .find(|(dir, _)| *dir == row.dir)
            .map(|(_, tally)| *tally)
            .unwrap_or_default();
        let entry = registry::find(&row.source);
        let kind = entry.map(|entry| entry.kind);
        let owed = ledger.owed(&row.dir)?;
        out.push(Configured {
            finished: done(kind, &row, owed),
            kind,
            owed,
            tally,
            row: without_secrets(row, entry.map(|entry| entry.config)),
        });
    }
    Ok(out)
}

/// Whether a source has run its course.
///
/// Only a one-shot ever does: everything else is polled again on a cadence, so there is
/// always something more it will do. A scan has to have finished at least once — a row
/// created a moment ago owes nothing yet, and is not finished but unstarted — and one that
/// failed stays, because the error is the whole reason to look at it.
fn done(kind: Option<SourceType>, row: &SourceRow, owed: u64) -> bool {
    kind == Some(SourceType::OneShot) && row.last_error.is_none() && row.scanned_at > 0 && owed == 0
}

/// Forget a one-shot source there is nothing left to say about.
///
/// A one-shot import is a single act: it is scanned once, it brings in what it found, and
/// after that it is only a name — one already copied onto every row it produced, which is
/// why those rows were built to outlive it. So once its files have all been sorted or
/// thrown away, the row goes, the same moment its directory frees itself.
///
/// Held until then rather than dropped as soon as the fetching stops, so that re-importing
/// the same folder while its files are still waiting finds the source it already has
/// instead of reading every file again.
pub fn tidy(paths: &Paths) -> Result<u64> {
    let mut ledger = ledger(paths)?;
    let tallies = ledger.tallies()?;

    let mut gone = 0;
    for row in ledger.sources()? {
        let kind = registry::find(&row.source).map(|entry| entry.kind);
        if !done(kind, &row, ledger.owed(&row.dir)?) {
            continue;
        }
        // Still something to sort, so the source stays: it is what a re-import matches on.
        let waiting = tallies
            .iter()
            .find(|(dir, _)| *dir == row.dir)
            .is_some_and(|(_, tally)| tally.waiting > 0);
        if waiting {
            continue;
        }

        if ledger.remove_source(&row.dir)? {
            tracing::debug!(source = %row.name, "forgot a one-shot import that is done with");
            gone += 1;
        }
    }
    Ok(gone)
}

/// A source row with its credentials taken out
fn without_secrets(mut row: SourceRow, declared: Option<&[Field]>) -> SourceRow {
    let Some(declared) = declared else {
        row.config = Fields::new();
        return row;
    };

    let mut kept = Fields::new();
    for (key, value) in row.config.iter() {
        let secret = declared
            .iter()
            .any(|field| field.key == key && field.kind == FieldKind::Secret);
        if !secret {
            kept.push(key, value);
        }
    }
    row.config = kept;
    row
}

/// Create a source
pub fn add_source(paths: &Paths, source: &str, name: &str, config: Fields) -> Result<SourceRow> {
    let entry = implementation(source)?;
    let name = name.trim();
    if name.is_empty() {
        bail!("a source needs a name: it is what its files are filed under");
    }

    let ledger = ledger(paths)?;
    if let Some(existing) = ledger.source_named(name)? {
        bail!(
            "there is already a source called {name:?}, importing from {}",
            existing.source
        );
    }

    config.check(entry.name, entry.config)?;
    let settings = ledger.settings(entry.name)?;
    check_settings(entry.name, entry.settings, &settings)?;
    entry
        .open(&config, &settings)
        .with_context(|| format!("checking how {name} is configured"))?;

    let row = SourceRow {
        dir: allocate_dir(&ledger, name)?,
        name: name.to_owned(),
        source: entry.name.to_owned(),
        config,
        added_at: now(),
        scanned_at: 0,
        last_error: None,
        reachable: true,
    };
    ledger
        .add_source(&row)
        .with_context(|| format!("adding {name}"))?;
    Ok(row)
}

/// One configured source, by the name it was given or by the directory that name became.
///
/// Named first, because the name is what somebody typed when they added the source and the
/// only thing `source list` prints — asking for what is on screen has to work. The directory
/// still answers too: it is what `source add` says to scan it with, and what the files sit
/// under, so it is a fair thing to have written down.
///
/// Both are unique, so neither lookup can be ambiguous on its own. One string can be a name
/// here and a directory there — two sources called "Pictures" and "pictures" take the
/// directories `pictures` and `pictures-2` — and the name wins, because the name is the half
/// somebody read off the list.
fn source_matching(ledger: &Ledger, needle: &str) -> Result<Option<SourceRow>> {
    match ledger.source_named(needle)? {
        Some(row) => Ok(Some(row)),
        None => Ok(ledger.source(needle)?),
    }
}

/// The same, for the callers that have nothing to do without one.
pub(super) fn find_source(ledger: &Ledger, needle: &str) -> Result<SourceRow> {
    source_matching(ledger, needle)?
        .ok_or_else(|| anyhow!("no source called {needle:?}; `ac import source list` shows them"))
}

/// Delete a source and its queue
pub fn remove_source(paths: &Paths, needle: &str) -> Result<bool> {
    let mut ledger = ledger(paths)?;
    let Some(row) = source_matching(&ledger, needle)? else {
        return Ok(false);
    };
    ledger
        .remove_source(&row.dir)
        .with_context(|| format!("removing {}", row.name))
}

/// One implementation's shared setting, and whether it is filled in.
pub struct Setting {
    pub field: Field,
    /// `None` for a `Secret`, whether or not it is set: it is replaced rather than displayed.
    pub value: Option<String>,
    pub set: bool,
}

pub fn settings(paths: &Paths, source: &str) -> Result<Vec<Setting>> {
    let entry = implementation(source)?;
    let stored = ledger(paths)?.settings(entry.name)?;

    Ok(entry
        .settings
        .iter()
        .map(|field| {
            let value = stored.get(field.key);
            Setting {
                field: *field,
                set: value.is_some_and(|value| !value.is_empty()),
                value: match field.kind {
                    FieldKind::Secret => None,
                    _ => value.map(str::to_owned),
                },
            }
        })
        .collect())
}

pub fn set_setting(paths: &Paths, source: &str, key: &str, value: &str) -> Result<()> {
    let entry = implementation(source)?;
    if !entry.settings.iter().any(|field| field.key == key) {
        let keys: Vec<&str> = entry.settings.iter().map(|field| field.key).collect();
        bail!(
            "{source} has nothing called {key:?}{}",
            match keys.is_empty() {
                true => "; it shares no settings at all".to_owned(),
                false => format!("; it has {}", keys.join(", ")),
            }
        );
    }

    ledger(paths)?
        .set_setting(entry.name, key, value)
        .with_context(|| format!("setting {source} {key}"))
}

/// A one-shot import: the source its files are filed under, and whether it is new.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Picked {
    pub row: SourceRow,
    /// False when these same folders were already a source, which is scanned again instead.
    pub added: bool,
}

/// Import from folders someone picked, without their having to know what the `folder`
/// implementation calls its fields.
pub fn from_folder(paths: &Paths, name: Option<&str>, picked: &Path) -> Result<Picked> {
    if !picked.exists() {
        bail!("{} is not there", picked.display());
    }
    // What was typed is rarely absolute, and the implementation takes nothing else.
    let full = std::path::absolute(picked)
        .with_context(|| format!("working out where {} is", picked.display()))?;

    let mut config = Fields::new();
    config.push(FOLDER_PATH, &full.display().to_string());

    if let Some(row) = configured_for(&ledger(paths)?, &config)? {
        return Ok(Picked { row, added: false });
    }

    let named = match name {
        Some(name) => name.to_owned(),
        None => folder_name(picked)?,
    };
    Ok(Picked {
        row: add_source(paths, FOLDER, &named, config)?,
        added: true,
    })
}

/// The folder source already importing from this path, if there is one.
fn configured_for(ledger: &Ledger, config: &Fields) -> Result<Option<SourceRow>> {
    let want = config.get(FOLDER_PATH);

    Ok(ledger
        .sources()?
        .into_iter()
        .find(|row| row.source == FOLDER && row.config.get(FOLDER_PATH) == want))
}

/// What a picked folder is called, as a name for the source.
fn folder_name(picked: &Path) -> Result<String> {
    picked
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| {
            anyhow!(
                "{} has no name to import under; give one with --name",
                picked.display()
            )
        })
}

/// Open one configured source: its own config, and its implementation's shared settings.
pub fn open_source(ledger: &Ledger, row: &SourceRow) -> Result<Box<dyn Source>> {
    let settings = ledger.settings(&row.source)?;
    registry::open(&row.source, &row.config, &settings)
        .with_context(|| format!("opening {}", row.name))
}

fn check_settings(implementation: &'static str, declared: &[Field], have: &Fields) -> Result<()> {
    have.check(implementation, declared).map_err(|e| {
        anyhow!("{e}\nset it first: ac import settings set {implementation} <key> <value>")
    })
}

/// The directory a source's files land in, allocated once from its name and then frozen, so
/// renaming it later never moves a file.
fn allocate_dir(ledger: &Ledger, name: &str) -> Result<String> {
    let base = slug(name)
        .ok_or_else(|| anyhow!("{name:?} has no characters a directory can be named after"))?;

    let mut candidate = base.clone();
    for suffix in 2..MAX_DIRS {
        if !ledger.dir_taken(&candidate)? {
            return Ok(candidate);
        }
        candidate = format!("{base}-{suffix}");
    }
    bail!("could not find an unused directory for {name:?}")
}

fn slug(name: &str) -> Option<String> {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if c.is_alphanumeric() {
            out.extend(c.to_lowercase());
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
    }
    sanitize(out.trim_end_matches('-'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::import::fetch::drain;
    use crate::ops::import::fixtures::*;
    use crate::ops::import::scan::scan;
    use ac_import::ledger::State;
    use ac_import::source::SourceType;

    #[test]
    fn the_build_offers_the_folder_source_and_says_what_it_wants() {
        let folder = implementation("folder").unwrap();
        assert_eq!(folder.kind, SourceType::OneShot);
        assert_eq!(folder.config.len(), 1);
        assert_eq!(folder.config[0].key, "path");
        assert!(folder.settings.is_empty());

        let err = implementation("drive").unwrap_err().to_string();
        assert!(err.contains("folder"), "it should say what there is: {err}");
    }

    #[test]
    fn a_second_source_of_the_same_name_gets_a_directory_of_its_own() {
        let home = home();
        let paths = paths(&home);
        let ledger = ledger(&paths).unwrap();

        let first = add_source(&paths, "folder", "Pictures", picked(home.path())).unwrap();
        assert_eq!(first.dir, "pictures");

        // The name itself is taken while the source exists.
        let err = add_source(&paths, "folder", "Pictures", picked(home.path())).unwrap_err();
        assert!(err.to_string().contains("already a source"), "{err}");

        ledger
            .keep(&ac_import::ledger::Imported {
                hash: "aa".to_owned(),
                state: State::Unsorted,
                name: "a.jpg".to_owned(),
                size: 1,
                at: now(),
                group_id: None,
                source_dir: first.dir.clone(),
                source_name: first.name.clone(),
                source_ref: "a.jpg".to_owned(),
                folder: String::new(),
            })
            .unwrap();
        remove_source(&paths, &first.dir).unwrap();

        let second = add_source(&paths, "folder", "Pictures", picked(home.path())).unwrap();
        assert_eq!(second.dir, "pictures-2");
    }

    #[test]
    fn a_directory_is_a_name_that_can_also_be_typed_as_an_argument() {
        assert_eq!(slug("Pictures 2024").as_deref(), Some("pictures-2024"));
        assert_eq!(slug("  Noël / 2024  ").as_deref(), Some("noël-2024"));
        assert_eq!(slug("a___b").as_deref(), Some("a-b"));
        // The structural guarantee `.unsorted` rests on: nothing reaches a leading dot.
        assert_eq!(slug("..").as_deref(), None);
        assert_eq!(slug(".staging").as_deref(), Some("staging"));
        assert_eq!(slug("///").as_deref(), None);
    }

    #[test]
    fn a_config_the_implementation_would_refuse_never_becomes_a_source() {
        let home = home();
        let paths = paths(&home);

        for (name, config) in [
            ("Nothing", Fields::new()),
            ("Relative", picked(Path::new("pictures/2024"))),
        ] {
            assert!(add_source(&paths, "folder", name, config).is_err());
        }

        let mut undeclared = picked(home.path());
        undeclared.push("recursive", "true");
        let err = add_source(&paths, "folder", "Typo", undeclared).unwrap_err();
        assert!(err.to_string().contains("recursive"), "{err}");

        assert!(sources(&paths).unwrap().is_empty(), "nothing was written");
    }

    #[test]
    fn a_setting_nothing_declared_is_refused_rather_than_stored() {
        let home = home();
        let paths = paths(&home);

        let err = set_setting(&paths, "folder", "client_id", "abc").unwrap_err();
        assert!(err.to_string().contains("shares no settings"), "{err}");
        assert!(settings(&paths, "folder").unwrap().is_empty());
    }

    #[test]
    fn a_source_cannot_be_added_before_its_implementation_is_configured() {
        const NEEDED: &[Field] = &[Field::secret("client_id", "Client id")];

        let err = check_settings("drive", NEEDED, &Fields::new()).unwrap_err();
        assert!(err.to_string().contains("Client id"), "{err}");
        assert!(
            err.to_string().contains("ac import settings set drive"),
            "{err}"
        );

        let mut set = Fields::new();
        set.push("client_id", "abc");
        check_settings("drive", NEEDED, &set).unwrap();
    }

    #[test]
    fn removing_a_source_stops_what_is_owed_and_keeps_what_arrived() {
        let home = home();
        let paths = paths(&home);
        let album = home.path().join("album");
        tree(&album, &["a.jpg", "b.jpg"]);

        let row = add_source(&paths, "folder", "Pictures", picked(&album)).unwrap();
        scan(&paths, &row.dir).unwrap();
        assert_eq!(ledger(&paths).unwrap().owed(&row.dir).unwrap(), 2);

        assert!(remove_source(&paths, &row.dir).unwrap());
        assert_eq!(ledger(&paths).unwrap().owed(&row.dir).unwrap(), 0);
        assert!(sources(&paths).unwrap().is_empty());
        assert!(!remove_source(&paths, &row.dir).unwrap());
    }

    /// `source list` prints the name and nothing else, so the name has to be what the
    /// commands take. It was the directory — a lowercased, hyphenated version of the name —
    /// and copying what the list showed failed for every name that was not already shaped
    /// like one, with the error pointing back at that same list.
    #[test]
    fn a_source_answers_to_the_name_the_list_shows() {
        let home = home();
        let paths = paths(&home);
        let album = home.path().join("album");
        tree(&album, &["a.jpg"]);

        let row = add_source(&paths, "folder", "Family Photos", picked(&album)).unwrap();
        assert_eq!(row.dir, "family-photos", "which is nothing anybody typed");

        assert!(scan(&paths, "Family Photos").is_ok());
        assert!(remove_source(&paths, "Family Photos").unwrap());
    }

    /// The directory still answers: `source add` says to scan with it, and it is what the
    /// files are under, so somebody may well have written it down.
    #[test]
    fn a_source_still_answers_to_its_directory() {
        let home = home();
        let paths = paths(&home);
        let album = home.path().join("album");
        tree(&album, &["a.jpg"]);

        let row = add_source(&paths, "folder", "Family Photos", picked(&album)).unwrap();
        assert!(scan(&paths, &row.dir).is_ok());
        assert!(remove_source(&paths, &row.dir).unwrap());
    }

    /// One string can be a name here and a directory there. The name wins, because the name
    /// is the half somebody read off the list.
    #[test]
    fn a_name_is_preferred_to_another_sources_directory() {
        let home = home();
        let paths = paths(&home);
        let album = home.path().join("album");
        tree(&album, &["a.jpg"]);

        // "Pictures" takes the directory `pictures`, so "pictures" cannot have it.
        let upper = add_source(&paths, "folder", "Pictures", picked(&album)).unwrap();
        let lower = add_source(&paths, "folder", "pictures", picked(&album)).unwrap();
        assert_eq!(upper.dir, "pictures");
        assert_eq!(lower.dir, "pictures-2");

        let ledger = ledger(&paths).unwrap();
        let found = find_source(&ledger, "pictures").unwrap();
        assert_eq!(
            found.name, "pictures",
            "the name, not the other one's folder"
        );
        assert_eq!(found.dir, "pictures-2");
    }

    #[test]
    fn the_same_folders_picked_again_are_the_same_import() {
        let home = home();
        let paths = paths(&home);
        let album = home.path().join("album");
        tree(&album, &["a.jpg", "b.jpg"]);

        // The three steps the CLI and the GUI both drive: find or create, scan, pump.
        let first = from_folder(&paths, None, &album).unwrap();
        assert!(first.added);
        assert_eq!(scan(&paths, &first.row.dir).unwrap().owed, 2);
        assert_eq!(drain(&paths, None).unwrap().kept, 2);

        // The same pick again: the same source, rescanned, owing nothing new.
        let again = from_folder(&paths, None, &album).unwrap();
        assert!(!again.added, "it was not added a second time");
        assert_eq!(again.row.dir, first.row.dir);
        assert_eq!(sources(&paths).unwrap().len(), 1);

        assert_eq!(scan(&paths, &again.row.dir).unwrap().owed, 0);
        assert_eq!(drain(&paths, None).unwrap().kept, 0, "nothing to bring in");
        assert_eq!(ledger(&paths).unwrap().waiting().unwrap(), 2);

        // And what is genuinely new there is picked up by that rescan.
        tree(&album, &["c.jpg"]);
        let third = from_folder(&paths, None, &album).unwrap();
        assert!(!third.added);
        assert_eq!(scan(&paths, &third.row.dir).unwrap().owed, 1);
        assert_eq!(drain(&paths, None).unwrap().kept, 1);
    }

    #[test]
    fn a_picked_folder_is_imported_under_its_own_name() {
        let home = home();
        let paths = paths(&home);
        let album = home.path().join("Pictures 2024");
        tree(&album, &["a.jpg"]);

        let picked = from_folder(&paths, None, &album).unwrap();
        assert!(picked.added);
        assert_eq!(picked.row.name, "Pictures 2024");
        assert_eq!(picked.row.source, "folder");
        assert_eq!(picked.row.dir, "pictures-2024");
        assert_eq!(
            picked.row.config.get("path").map(Path::new),
            Some(album.as_path()),
            "the implementation takes nothing but an absolute path"
        );

        // A name can still be given rather than taken from what was picked.
        let other = home.path().join("other");
        std::fs::create_dir_all(&other).unwrap();
        assert_eq!(
            from_folder(&paths, Some("Everything"), &other)
                .unwrap()
                .row
                .dir,
            "everything"
        );

        // A single file is as good a source as a folder, and is named after itself.
        let one = home.path().join("Pictures 2024/a.jpg");
        let file = from_folder(&paths, None, &one).unwrap();
        assert_eq!(file.row.name, "a.jpg");

        // What is not there is refused before anything is written down.
        let err = from_folder(&paths, None, &home.path().join("nope")).unwrap_err();
        assert!(err.to_string().contains("is not there"), "{err}");
        assert_eq!(sources(&paths).unwrap().len(), 3);
    }

    #[test]
    fn what_a_source_was_told_is_listed_without_its_credentials() {
        // What a Drive account or a phone declares: somewhere to look, and the credential
        // that reaches it. No source in this build has one, which is the whole reason this
        // is tested against a declaration rather than through the registry.
        let declared = [
            Field::paths("path", "Folders"),
            Field::secret("token", "Refresh token"),
        ];

        let mut config = Fields::new();
        config.push("path", "/one");
        config.push("token", "shhh");
        config.push("path", "/two");
        let row = SourceRow {
            dir: "phone".to_owned(),
            name: "Phone".to_owned(),
            source: "phone".to_owned(),
            config,
            added_at: now(),
            scanned_at: 0,
            last_error: None,
            reachable: true,
        };

        let shown = without_secrets(row.clone(), Some(&declared));
        assert_eq!(shown.config.get("token"), None, "the credential stays here");
        assert_eq!(
            shown.config.all("path").collect::<Vec<_>>(),
            ["/one", "/two"],
            "and a repeated answer keeps every one of its values"
        );

        // Nothing says which key of an implementation this build has never seen is the
        // credential, so none of it is handed out.
        assert!(without_secrets(row, None).config.is_empty());
    }

    #[test]
    fn a_source_lists_with_what_it_owes_and_what_it_brought_in() {
        let home = home();
        let paths = paths(&home);
        let album = home.path().join("album");
        tree(&album, &["a.jpg", "b.jpg", "c.jpg"]);

        let row = add_source(&paths, "folder", "Pictures", picked(&album)).unwrap();
        scan(&paths, &row.dir).unwrap();

        let listed = sources(&paths).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].row.name, "Pictures");
        assert_eq!(listed[0].kind, Some(SourceType::OneShot));
        assert_eq!(listed[0].owed, 3);
        assert_eq!(listed[0].tally, Tally::default());
    }

    /// The two halves of what happens to a one-shot: it stops being worth watching once it
    /// has fetched what it found, and stops existing once its files have been dealt with.
    #[test]
    fn a_one_shot_is_finished_when_fetched_and_forgotten_when_sorted() {
        let home = home();
        let (paths, dir) = imported(&home, &["a.jpg", "b.jpg"]);

        // Fetched, so there is nothing further it will do.
        let listed = sources(&paths).unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].finished, "it ran, and owes nothing more");

        // But its files are still waiting, so the row stays: it is what a re-import of the
        // same folder matches on rather than reading every file again.
        assert_eq!(tidy(&paths).unwrap(), 0, "nothing to forget yet");
        assert_eq!(sources(&paths).unwrap().len(), 1);

        // Deal with them, and there is nothing left of it worth a row.
        for file in crate::ops::import::backlog::unsorted(&paths, None, 10).unwrap() {
            crate::ops::import::backlog::drop(&paths, &file.row.hash).unwrap();
        }
        assert_eq!(tidy(&paths).unwrap(), 1);
        assert!(sources(&paths).unwrap().is_empty());

        // What it brought in is untouched: those rows carry the name themselves, which is
        // why they were built not to need the source.
        let ledger = ledger(&paths).unwrap();
        assert_eq!(
            ledger.tallies().unwrap().len(),
            1,
            "the history is still there"
        );
        assert!(ledger.source(&dir).unwrap().is_none());
    }

    #[test]
    fn a_source_still_working_or_broken_is_never_forgotten() {
        let home = home();
        let (paths, dir) = home_with_owed(&home);

        // Scanned and owing files: it has not run its course.
        assert!(!sources(&paths).unwrap()[0].finished);
        assert_eq!(tidy(&paths).unwrap(), 0);

        // A row created a moment ago owes nothing yet — unstarted, not finished. Forgetting
        // it here would delete a source out from under the scan that is about to run.
        let ledger = ledger(&paths).unwrap();
        ledger
            .add_source(&SourceRow {
                dir: "fresh".to_owned(),
                name: "Fresh".to_owned(),
                source: "folder".to_owned(),
                config: picked(home.path()),
                added_at: now(),
                scanned_at: 0,
                last_error: None,
                reachable: true,
            })
            .unwrap();
        assert_eq!(
            tidy(&paths).unwrap(),
            0,
            "a source that has never been scanned stays"
        );

        // And one that failed stays too: the error is the whole reason to look at it.
        ledger.scanned("fresh", now()).unwrap();
        ledger.failed("fresh", "the folder is not there").unwrap();
        assert_eq!(tidy(&paths).unwrap(), 0, "a broken source stays");
        assert!(
            !sources(&paths)
                .unwrap()
                .iter()
                .any(|s| s.row.dir == "fresh" && s.finished)
        );

        let _ = dir;
    }
}
