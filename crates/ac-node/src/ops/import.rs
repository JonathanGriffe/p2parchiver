use ac_files::Files;
use ac_files::dirname::sanitize;
use ac_import::config::{Field, FieldKind, Fields};
use ac_import::ledger::{Ledger, SourceRow, Tally};
use ac_import::registry::{self, Registered};
use ac_import::source::{Held, Source, SourceError, SourceType};
use ac_net::config::Paths;
use anyhow::{Context, Result, anyhow, bail};

use super::now;

/// Suffixes tried before giving up on finding a free directory. Far past anything real; it is
/// here so a bug cannot spin.
const MAX_DIRS: u32 = 1000;

pub fn ledger(paths: &Paths) -> Result<Ledger> {
    let db = paths.db_file();
    Ledger::open(&db).with_context(|| format!("opening the import ledger at {}", db.display()))
}

/// The `Held` port: whether a group already holds these bytes. The inbox has no business
/// asking `ac-files` that itself, so this is the node answering for it.
pub struct HeldHere<'a>(pub &'a Files);

impl Held for HeldHere<'_> {
    fn held(&self, hash: &str) -> Result<bool, SourceError> {
        self.0
            .held_anywhere(hash)
            .map_err(|e| SourceError::Failed(format!("reading the file index: {e}")))
    }
}

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
    pub row: SourceRow,
    /// `None` when the row names an implementation this build does not have. Reported rather
    /// than hidden: the files it brought in are still here.
    pub kind: Option<SourceType>,
    /// References it still owes. Goes up when a scan finds things, down as the pump works.
    pub owed: u64,
    pub tally: Tally,
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
        out.push(Configured {
            kind: registry::find(&row.source).map(|entry| entry.kind),
            owed: ledger.owed(&row.dir)?,
            tally,
            row,
        });
    }
    Ok(out)
}

/// Create a source. Everything that could make it fail on its first scan is checked here,
/// where it can still be explained, and nothing is written until it all passes.
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
    // Opened before the row is written, so a config the implementation refuses never becomes a
    // source that can only fail later.
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
fn find_source(ledger: &Ledger, needle: &str) -> Result<SourceRow> {
    source_matching(ledger, needle)?
        .ok_or_else(|| anyhow!("no source called {needle:?}; `ac import source list` shows them"))
}

/// Delete a source and its queue. Its files stay under `.unsorted`, still unsorted, still
/// listed and still sortable: they were never the source's property.
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

/// What a scan found, and what it changed. It moves no bytes, so this is the whole of it.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Scanned {
    pub name: String,
    /// Items the source offered, over every page.
    pub found: u64,
    /// References written down for the first time.
    pub owed: u64,
    /// Exhausted references the source still offers, put back on the queue.
    pub again: u64,
    /// Exhausted references it no longer offers: the file has gone from the source.
    pub retired: u64,
    pub skipped: Vec<String>,
    /// False when the source could not be reached. Not a failure, and not recorded as one.
    pub reachable: bool,
    /// A scan that reached the end. Only a complete one may retire rows or stamp `scanned_at`.
    pub complete: bool,
}

/// Scan one source now, ignoring both its cadence and its backoff.
pub fn scan(paths: &Paths, needle: &str) -> Result<Scanned> {
    let ledger = ledger(paths)?;
    let row = find_source(&ledger, needle)?;

    let source = open_source(&ledger, &row)?;
    scan_with(&ledger, &row, source.as_ref())
}

/// The scan itself, over an already-opened source, so the daemon and a test can drive it
/// without going back through the registry.
pub fn scan_with(ledger: &Ledger, row: &SourceRow, source: &dyn Source) -> Result<Scanned> {
    let mut out = Scanned {
        name: row.name.clone(),
        reachable: true,
        ..Scanned::default()
    };

    if !source.reachable() {
        // A phone that is simply elsewhere. Nothing is recorded, or the tab would show a
        // permanent failure for a source that is working perfectly.
        out.reachable = false;
        return Ok(out);
    }

    let mut cursor = None;
    loop {
        let page = match source.scan(cursor.as_ref()) {
            Ok(page) => page,
            Err(e) => {
                let why = e.to_string();
                ledger.scan_failed(&row.dir, &why)?;
                return Err(anyhow!(why)).with_context(|| format!("scanning {}", row.name));
            }
        };

        let refs: Vec<&str> = page
            .items
            .iter()
            .map(|item| item.reference.as_str())
            .collect();
        // One query for the whole page. On a source that has not changed, this is the only
        // thing a complete scan runs.
        let known = ledger.known_refs(&row.dir, &refs)?;

        let mut stale = Vec::new();
        for item in &page.items {
            out.found += 1;
            match known.iter().find(|(seen, _)| *seen == item.reference) {
                // Already known and still worth trying: nothing to do, which is the case a
                // complete scan is cheap because of.
                Some((_, fails)) if *fails < ac_import::ledger::MAX_FETCH_ATTEMPTS => {}
                Some(_) => stale.push(item.reference.as_str()),
                None => {
                    ledger.owe(&row.dir, item)?;
                    out.owed += 1;
                }
            }
        }
        out.again += ledger.offer_again(&row.dir, &stale)? as u64;
        out.skipped.extend(page.skipped);

        match page.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }

    // Only now: an interrupted scan has not seen the whole source, so it may no more delete a
    // row than it may stamp `scanned_at`. Both hang off having reached the end.
    out.complete = true;
    out.retired = ledger.retire_gone(&row.dir)? as u64;
    ledger.scanned(&row.dir, now())?;
    Ok(out)
}

/// Open one configured source: its own config, and its implementation's shared settings.
pub fn open_source(ledger: &Ledger, row: &SourceRow) -> Result<Box<dyn Source>> {
    let settings = ledger.settings(&row.source)?;
    registry::open(&row.source, &row.config, &settings)
        .with_context(|| format!("opening {}", row.name))
}

/// A missing setting is a different mistake from a missing config field — it is fixed once,
/// for every source of that implementation — so it says where to fix it.
fn check_settings(implementation: &'static str, declared: &[Field], have: &Fields) -> Result<()> {
    have.check(implementation, declared).map_err(|e| {
        anyhow!("{e}\nset it first: ac import settings set {implementation} <key> <value>")
    })
}

/// The directory a source's files land in, allocated once from its name and then frozen, so
/// renaming it later never moves a file.
///
/// A name stays taken while unsorted files still live under it, which is what makes removing a
/// source safe: re-adding one called "Pictures" gets `pictures-2` and the old files stay put.
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

/// A directory name from a source's name: lowercase, with one dash for every run of anything
/// else, so `Pictures 2024` becomes `pictures-2024` — a name that is also a command-line
/// argument, since it is what `ac import scan` takes.
///
/// `sanitize` still has the last word, which is what keeps a source directory out of
/// `.unsorted`'s own staging area and stops one being named `..`.
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
    use ac_import::ledger::State;
    use ac_import::source::{Cursor, Item, Page};
    use std::io::Write;
    use std::path::Path;

    fn home() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn paths(home: &tempfile::TempDir) -> Paths {
        Paths::rooted_at(home.path())
    }

    fn picked(path: &Path) -> Fields {
        let mut config = Fields::new();
        config.push("path", &path.display().to_string());
        config
    }

    /// A tree of empty files, so a scan has something to find.
    fn tree(root: &Path, files: &[&str]) {
        for file in files {
            let path = root.join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, file.as_bytes()).unwrap();
        }
    }

    /// A source that offers whatever it is handed. Stands in for the Remote and Intermittent
    /// implementations that are not in this build.
    struct Fake {
        kind: SourceType,
        items: Vec<Item>,
        reachable: bool,
    }

    impl Source for Fake {
        fn source_type(&self) -> SourceType {
            self.kind
        }
        fn reachable(&self) -> bool {
            self.reachable
        }
        fn scan(&self, from: Option<&Cursor>) -> Result<Page, SourceError> {
            assert!(from.is_none(), "this fake offers one page");
            Ok(Page {
                items: self.items.clone(),
                next: None,
                skipped: Vec::new(),
            })
        }
        fn fetch(&self, _item: &Item, _into: &mut dyn Write) -> Result<(), SourceError> {
            unreachable!("step 4 moves no bytes")
        }
    }

    fn fake(kind: SourceType, refs: &[&str]) -> Fake {
        Fake {
            kind,
            reachable: true,
            items: refs
                .iter()
                .map(|reference| Item {
                    reference: (*reference).to_owned(),
                    folder: String::new(),
                    name: (*reference).to_owned(),
                    size: Some(1),
                    checksum: None,
                })
                .collect(),
        }
    }

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
    fn a_scan_writes_down_what_it_owes_and_moves_no_bytes() {
        let home = home();
        let paths = paths(&home);
        let album = home.path().join("album");
        tree(&album, &["a.jpg", "DCIM/b.jpg", "DCIM/c.jpg"]);

        let row = add_source(&paths, "folder", "Pictures 2024", picked(&album)).unwrap();
        assert_eq!(row.dir, "pictures-2024");

        let scanned = scan(&paths, &row.dir).unwrap();
        assert_eq!(scanned.found, 3);
        assert_eq!(scanned.owed, 3);
        assert!(scanned.complete);

        let ledger = ledger(&paths).unwrap();
        assert_eq!(ledger.owed(&row.dir).unwrap(), 3);
        assert_eq!(ledger.waiting().unwrap(), 0, "a scan imports nothing");
        assert_eq!(ledger.unsorted_bytes().unwrap(), 0);
        assert!(ledger.source(&row.dir).unwrap().unwrap().scanned_at > 0);
    }

    #[test]
    fn scanning_a_source_that_has_not_changed_owes_nothing_new() {
        let home = home();
        let paths = paths(&home);
        let album = home.path().join("album");
        tree(&album, &["a.jpg", "b.jpg"]);

        let row = add_source(&paths, "folder", "Pictures", picked(&album)).unwrap();
        scan(&paths, &row.dir).unwrap();

        let again = scan(&paths, &row.dir).unwrap();
        assert_eq!(again.found, 2);
        assert_eq!(again.owed, 0, "everything is already written down");
        assert_eq!(ledger(&paths).unwrap().owed(&row.dir).unwrap(), 2);
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

        // Once it is removed the name is free again — but the directory is not, while its
        // unsorted files are still there.
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
        // `folder` shares nothing, so the rule is checked against the declaration it would be
        // checked against — the one a Drive implementation will bring with it.
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
    fn an_unreachable_source_is_skipped_without_being_called_a_failure() {
        let home = home();
        let paths = paths(&home);
        let ledger = ledger(&paths).unwrap();

        let row = add_source(&paths, "folder", "Phone", picked(home.path())).unwrap();
        let mut phone = fake(SourceType::Intermittent, &["a.jpg"]);
        phone.reachable = false;

        let scanned = scan_with(&ledger, &row, &phone).unwrap();
        assert!(!scanned.reachable);
        assert!(!scanned.complete);
        assert_eq!(scanned.found, 0);

        let back = ledger.source(&row.dir).unwrap().unwrap();
        assert_eq!(back.last_error, None, "elsewhere is not broken");
        assert_eq!(back.scanned_at, 0, "and it is still overdue");
    }

    #[test]
    fn a_scan_puts_back_what_it_still_offers_and_retires_what_it_does_not() {
        let home = home();
        let paths = paths(&home);
        let mut ledger = ledger(&paths).unwrap();
        let row = add_source(&paths, "folder", "Drive", picked(home.path())).unwrap();

        let both = fake(SourceType::Remote, &["kept.jpg", "gone.jpg"]);
        assert_eq!(scan_with(&ledger, &row, &both).unwrap().owed, 2);

        // Both run out of attempts, as an unreadable file would.
        let mut at = now();
        for _ in 0..ac_import::ledger::MAX_FETCH_ATTEMPTS {
            ledger.claim(at, 8).unwrap();
            at += ac_import::ledger::FETCH_RETRY_DELAY + 1;
        }
        assert!(ledger.claim(at, 8).unwrap().is_empty());

        // The next scan offers only one of them.
        let one = fake(SourceType::Remote, &["kept.jpg"]);
        let scanned = scan_with(&ledger, &row, &one).unwrap();
        assert_eq!(scanned.again, 1, "still offered, so back on the queue");
        assert_eq!(
            scanned.retired, 1,
            "no longer offered, so the file has gone"
        );
        assert_eq!(ledger.owed(&row.dir).unwrap(), 1);
        assert_eq!(ledger.claim(at, 8).unwrap().len(), 1);
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
}
