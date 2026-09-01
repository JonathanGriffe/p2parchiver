use ac_import::config::{Field, FieldKind, Fields};
use ac_net::config::Paths;
use anyhow::{Result, bail};

use crate::ops::format::ago;
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
    print_fields(
        "shared by every one of them, set with `ac import settings set`",
        entry.settings,
    );
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
    println!("its files will land in .unsorted/{}", row.dir);
    println!();
    println!("scan it now with: ac import scan {}", row.dir);
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
            eprintln!("{:<widest$}  last scan failed: {why}", "");
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
        let shown = match (&setting.value, setting.set) {
            (Some(value), _) => value.clone(),
            // A secret is replaced rather than displayed, so a screenshot cannot leak it.
            (None, true) => "(set)".to_owned(),
            (None, false) => "(not set)".to_owned(),
        };
        println!("{:<widest$}  {shown}", setting.field.key);
    }
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
    if scanned.owed > 0 {
        println!();
        println!("nothing has been downloaded yet: `ac run` works through what is owed");
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
