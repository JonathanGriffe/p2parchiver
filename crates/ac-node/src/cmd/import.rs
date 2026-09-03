use std::path::Path;

use ac_import::config::{Field, FieldKind, Fields};
use ac_net::config::{Config, Paths};
use ac_peers::sync::{Limits, Space};
use anyhow::{Result, bail};

use crate::ops::format::{ago, human_size};
use crate::ops::{self};

/// The one command that needs no node: what this build can import from is a fact about the
/// binary, not about anything on disk.
pub fn available(source: Option<&str>) -> Result<()> {
    let Some(source) = source else {
        for entry in ops::import::available() {
            println!("{:<10}  {}", entry.name, entry.kind);
        }
        return Ok(());
    };

    let entry = ops::import::implementation(source)?;
    println!("{}  {}", entry.name, entry.kind);
    print_fields(
        "per source, given with --set when you add one",
        entry.config,
    );
    let asked: Vec<Field> = entry.asked_settings().copied().collect();
    print_fields(
        "shared by every one of them, set with `ac import settings set`",
        &asked,
    );
    if entry.signs_in() {
        println!();
        println!("Adding one signs in to it, in a browser. Each is its own account.");
    }
    Ok(())
}

fn print_fields(what: &str, fields: &[Field]) {
    if fields.is_empty() {
        return;
    }
    println!();
    println!("{what}:");
    let widest = fields.iter().map(|f| f.key.len()).max().unwrap_or(0);
    for field in fields {
        let optional = if field.required { "" } else { "  (optional)" };
        println!(
            "  {:<widest$}  {}{optional}",
            field.key,
            describe(field.kind)
        );
    }
}

fn describe(kind: FieldKind) -> &'static str {
    match kind {
        FieldKind::Text => "text",
        FieldKind::Path => "a path",
        FieldKind::Paths => "a path, repeatable",
        FieldKind::Secret => "a secret",
        FieldKind::Toggle => "true or false",
    }
}

pub fn source_add(paths: &Paths, source: &str, name: &str, set: &[String]) -> Result<()> {
    let row = ops::import::add_source(paths, source, name, pairs(set)?)?;

    println!("added {} ({})", row.name, row.source);
    println!(
        "its files will land in {}/{}",
        ops::import::UNSORTED,
        row.dir
    );
    println!();
    println!("scan it now with: ac import scan {}", row.dir);
    Ok(())
}

/// Add a folder, scan it, and bring it in: the whole of an import, with no daemon running.
pub fn from(paths: &Paths, picked: &Path, name: Option<&str>) -> Result<()> {
    let ops::import::Picked { row, added } = ops::import::from_folder(paths, name, picked)?;
    match added {
        true => println!("added {} ({})", row.name, row.source),
        false => println!("{} was imported before, looking for what is new", row.name),
    }

    let scanned = ops::import::scan(paths, &row.dir)?;
    for note in &scanned.skipped {
        eprintln!("{note}");
    }
    println!("{}: {} to bring in", scanned.name, scanned.owed);
    if scanned.owed == 0 {
        return Ok(());
    }

    println!();
    report(&work(paths, None)?, Some(&row.dir));
    Ok(())
}

/// Work through what every source is owed.
pub fn fetch(paths: &Paths, limit: Option<usize>) -> Result<()> {
    let fetched = work(paths, limit)?;
    if fetched.tried == 0 {
        println!("nothing is owed. `ac import scan <source>` looks for more");
        return Ok(());
    }
    report(&fetched, None);
    Ok(())
}

/// Whether there is room to bring anything in, and what to say if there is not.
///
/// The same `Limits` the daemon holds imports to and the sync side refuses transfers on, so
/// "full" means one thing on this node however the bytes were going to arrive. Measured once
/// rather than per file: this is a foreground command somebody is watching, and stopping at
/// the top with a reason beats stopping partway with none.
fn no_room(paths: &Paths) -> Option<String> {
    let storage = ops::file::storage(paths).ok()?;
    let limits = Limits {
        storage_max: Config::load(&paths.config_file())
            .unwrap_or_default()
            .storage_max,
        ..Limits::default()
    };
    let space = Space {
        free: storage.free?,
        held: storage.held,
    };
    limits
        .room(space)
        .map(|why| format!("there is no room to import: {why:?}"))
}

fn work(paths: &Paths, limit: Option<usize>) -> Result<ops::import::Fetched> {
    use ops::import::Outcome;

    if let Some(why) = no_room(paths) {
        bail!("{why}");
    }

    let mut pump = ops::import::pump(paths, limit)?;
    let mut fetched = ops::import::Fetched::default();
    while let Some(brought) = pump.next()? {
        match &brought.outcome {
            Outcome::Kept { size } => println!("{}  {}", brought.name, human_size(*size)),
            Outcome::Failed(why) => eprintln!("{}: {why}", brought.name),
            Outcome::Known | Outcome::Held | Outcome::Gone => {}
        }
        fetched.count(&brought);
    }
    pump.finish()?;
    Ok(fetched)
}

/// The summary under the per-file lines [`work`] has already printed.
fn report(fetched: &ops::import::Fetched, dir: Option<&str>) {
    println!(
        "{} imported ({}), {} already had, {} in a group already",
        fetched.kept,
        human_size(fetched.bytes),
        fetched.known,
        fetched.held,
    );
    if fetched.gone > 0 {
        println!("{} had left the source", fetched.gone);
    }
    if !fetched.failed.is_empty() {
        println!(
            "{} did not come in, and will be tried again",
            fetched.failed.len()
        );
    }
    if fetched.kept > 0 {
        let unsorted = ops::import::UNSORTED;
        println!();
        match dir {
            Some(dir) => println!("they are waiting in {unsorted}/{dir}"),
            None => println!("they are waiting in {unsorted}"),
        }
    }
}

/// How many files one page of the listing shows.
const PAGE: usize = 50;

/// What is waiting to be sorted, oldest first.
pub fn list(paths: &Paths, all: bool) -> Result<()> {
    let backlog = ops::import::backlog(paths, None)?;
    if backlog.total == 0 {
        println!("nothing is waiting. `ac import from <path>` brings files in");
        return Ok(());
    }

    let inbox = ops::import::Inbox::open(paths)?;
    let mut after: Option<(i64, String)> = None;
    let mut shown = 0u64;
    loop {
        let page = inbox.page(after.as_ref().map(|(at, h)| (*at, h.as_str())), PAGE)?;
        let Some(last) = page.last() else { break };
        after = Some((last.row.at, last.row.hash.clone()));

        for file in &page {
            let where_from = match file.row.folder.as_str() {
                "" => file.row.source_name.clone(),
                folder => format!("{}/{folder}", file.row.source_name),
            };
            println!(
                "{}  {:>9}  {where_from}{}",
                &file.row.hash[..12],
                human_size(file.row.size),
                match file.held {
                    true => "  (a group already has these bytes)",
                    false => "",
                }
            );
            println!("{:14}{}", "", file.row.name);
        }
        shown += page.len() as u64;

        if !all || page.len() < PAGE {
            break;
        }
    }

    println!();
    match shown < backlog.total {
        true => println!(
            "{shown} of {} waiting. `ac import list --all` shows the rest",
            backlog.total
        ),
        false => println!("{} waiting", backlog.total),
    }
    println!("sort one with: ac import sort <hash> <group>");
    Ok(())
}

/// File one into a group, or everything that came from the same source folder.
pub fn sort(
    paths: &Paths,
    hash: &str,
    group: &str,
    folder: bool,
    into: Option<&str>,
) -> Result<()> {
    let row = ops::import::find(paths, hash)?;
    let into = into.unwrap_or_default();
    let filed = match folder {
        false => ops::import::sort(paths, &row.hash, group, into)?,
        true => ops::import::sort_folder(paths, &row.source_dir, &row.folder, group, into)?,
    };
    report_filed(&filed, "filed", Some(group))
}

pub fn drop(paths: &Paths, hash: &str, folder: bool) -> Result<()> {
    let row = ops::import::find(paths, hash)?;
    let (filed, gone) = match folder {
        false => (ops::import::drop(paths, &row.hash)?, vec![row.hash.clone()]),
        true => {
            let hashes = ops::import::in_folder(paths, &row.source_dir, &row.folder)?;
            (
                ops::import::drop_folder(paths, &row.source_dir, &row.folder)?,
                hashes,
            )
        }
    };
    // Nothing here can take it back, so there is nothing to keep the bytes for.
    for hash in &gone {
        ops::import::forget(paths, hash)?;
    }
    report_filed(&filed, "deleted", None)
}

fn report_filed(filed: &ops::import::Filed, did: &str, group: Option<&str>) -> Result<()> {
    for note in &filed.failed {
        eprintln!("{note}");
    }

    match group {
        Some(group) => println!("{} {did} into {group}", filed.done),
        None => println!("{} {did}", filed.done),
    }
    if filed.missing > 0 {
        println!(
            "{} had already gone from disk, and are settled from what is held now",
            filed.missing
        );
    }
    if filed.done == 0 && filed.missing == 0 {
        bail!("nothing was {did}");
    }
    Ok(())
}

pub fn source_list(paths: &Paths) -> Result<()> {
    let configured = ops::import::sources(paths)?;
    if configured.is_empty() {
        println!("no sources yet. add one with:");
        println!("  ac import source add --source folder --name <n> --set path=<path>");
        return Ok(());
    }

    let widest = configured
        .iter()
        .map(|c| c.row.name.len())
        .max()
        .unwrap_or(0);
    for entry in &configured {
        let kind = match entry.kind {
            Some(kind) => kind.to_string(),
            None => format!("{} (not in this build)", entry.row.source),
        };
        let scanned = match entry.row.scanned_at {
            0 => "never scanned".to_owned(),
            at => format!("scanned {}", ago(at)),
        };
        println!("{:<widest$}  {:<13}  {scanned}", entry.row.name, kind,);
        println!(
            "{:<widest$}  {} waiting · {} sorted · {} deleted · {} owed",
            "", entry.tally.waiting, entry.tally.sorted, entry.tally.dropped, entry.owed,
        );
        if let Some(why) = &entry.row.last_error {
            eprintln!("{:<widest$}  last error: {why}", "");
        }
    }
    Ok(())
}

pub fn source_remove(paths: &Paths, source: &str) -> Result<()> {
    if !ops::import::remove_source(paths, source)? {
        bail!("no source called {source:?}; `ac import source list` shows them");
    }
    println!("removed {source}");
    println!("anything it already imported is still there, and still needs sorting");
    Ok(())
}

pub fn settings_show(paths: &Paths, source: &str) -> Result<()> {
    let settings = ops::import::settings(paths, source)?;
    if settings.is_empty() {
        println!("{source} shares no settings");
        return Ok(());
    }

    let widest = settings
        .iter()
        .map(|s| s.field.key.len())
        .max()
        .unwrap_or(0);
    for setting in &settings {
        // Masked here, whatever the window does with it: a terminal is scrolled back
        // through, piped into a file and pasted into bug reports.
        let secret = setting.field.kind == FieldKind::Secret;
        let shown = match (&setting.value, secret) {
            (Some(value), false) => value.clone(),
            (Some(_), true) => "(set)".to_owned(),
            (None, _) => "(not set)".to_owned(),
        };
        println!("{:<widest$}  {shown}", setting.field.key);
    }
    Ok(())
}

pub fn auth(paths: &Paths, source: &str) -> Result<()> {
    let row = ops::import::authorize(paths, source)?;
    println!("signed in again as {}", row.name);
    Ok(())
}

pub fn settings_set(paths: &Paths, source: &str, key: &str, value: &str) -> Result<()> {
    ops::import::set_setting(paths, source, key, value)?;
    println!("set {source} {key}");
    Ok(())
}

pub fn scan(paths: &Paths, source: &str) -> Result<()> {
    let scanned = ops::import::scan(paths, source)?;

    for note in &scanned.skipped {
        eprintln!("{note}");
    }
    if !scanned.reachable {
        println!("{} cannot be reached right now", scanned.name);
        return Ok(());
    }

    println!(
        "{}: {} offered, {} new, {} retried, {} gone",
        scanned.name, scanned.found, scanned.owed, scanned.again, scanned.retired
    );
    if scanned.ignored > 0 {
        println!(
            "{} were not pictures or video, and were left alone",
            scanned.ignored
        );
    }
    if scanned.owed > 0 {
        println!();
        println!("nothing has been downloaded yet: `ac import fetch` brings them in now,");
        println!("and `ac run` works through them in the background");
    }
    Ok(())
}

/// `--set key=value`, repeated. One flag serves every source there will ever be, so nothing
/// here knows what any of them are called.
fn pairs(set: &[String]) -> Result<Fields> {
    let mut fields = Fields::new();
    for raw in set {
        let Some((key, value)) = raw.split_once('=') else {
            bail!("--set wants key=value, not {raw:?}");
        };
        fields.push(key.trim(), value.trim());
    }
    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The daemon holds imports to `Limits` and the sync side refuses transfers on the same
    /// ones; a fetch typed at a terminal answers to them too. What is asserted here is the
    /// half a mistake would break silently: an empty node must not refuse. Whether a spent
    /// budget says no is `Limits::room`'s own question, and `ac-peers` tests it.
    #[test]
    fn a_fetch_on_an_empty_node_is_not_refused_for_want_of_room() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::rooted_at(home.path());
        ops::identity(&paths).unwrap();

        assert_eq!(no_room(&paths), None, "nothing is held, so nothing is full");

        // A ceiling well above nothing does not change that.
        let mut config = Config::load(&paths.config_file()).unwrap_or_default();
        config.storage_max = Some(64 * 1024 * 1024 * 1024);
        config.save(&paths.config_file()).unwrap();
        assert_eq!(no_room(&paths), None, "and the ceiling is nowhere near");
    }

    #[test]
    fn a_set_flag_is_split_once_so_a_value_may_hold_an_equals_sign() {
        let set = ["path=/home/a/pictures".to_owned(), "token=ab=cd".to_owned()];
        let fields = pairs(&set).unwrap();

        assert_eq!(fields.get("path"), Some("/home/a/pictures"));
        assert_eq!(fields.get("token"), Some("ab=cd"));
    }

    #[test]
    fn a_repeated_flag_answers_a_field_that_takes_several() {
        let set = ["path=/one".to_owned(), "path=/two".to_owned()];
        assert_eq!(pairs(&set).unwrap().all("path").count(), 2);
    }

    #[test]
    fn a_flag_that_is_not_a_pair_says_so() {
        assert!(pairs(&["path".to_owned()]).is_err());
    }
}
