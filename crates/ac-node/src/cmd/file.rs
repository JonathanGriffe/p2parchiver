use std::path::PathBuf;

use ac_files::store::Recorded;
use ac_net::config::Paths;
use anyhow::{Result, bail};

use crate::ops::format::{ago, human_size};
use crate::ops::{self};

pub fn add(
    paths: &Paths,
    needle: &str,
    sources: &[PathBuf],
    to: Option<&str>,
    rename: Option<&str>,
    recursive: bool,
    force: bool,
) -> Result<()> {
    let mut s = ops::file::session(paths, needle)?;
    ops::file::writable(&s.row)?;

    let planned = ops::file::plan(sources, to, rename, recursive)?;
    for note in &planned.skipped {
        eprintln!("{note}");
    }

    if planned.items.is_empty() {
        println!("nothing to add");
        return Ok(());
    }

    let single = planned.items.len() == 1;
    let (mut added, mut unchanged, mut failed) = (0usize, 0usize, 0usize);
    for (src, dest) in &planned.items {
        match ops::file::add_one(&mut s, src, dest, force) {
            Ok(Recorded::Unchanged) => {
                unchanged += 1;
                if single {
                    println!("{dest} is already there, unchanged");
                }
            }
            Ok(_) => {
                added += 1;
                println!("added {dest}");
            }
            Err(e) => {
                failed += 1;
                eprintln!("skipped {}: {e:#}", src.display());
            }
        }
    }

    if planned.items.len() > 1 || failed > 0 {
        println!();
        println!("{added} added, {unchanged} unchanged, {failed} skipped");
    }
    if failed > 0 {
        bail!(
            "{failed} of {} file(s) could not be added",
            planned.items.len()
        );
    }
    Ok(())
}

pub fn list(paths: &Paths, needle: &str, prefix: Option<&str>, removed: bool) -> Result<()> {
    let listing = ops::file::list(paths, needle, prefix, removed)?;

    println!("{}", listing.dir.display());
    println!();

    if listing.rows.is_empty() {
        match prefix {
            Some(p) => println!("nothing under {p:?}"),
            None => println!(
                "no files. add some with: ac file add {} <path>...",
                listing.group.id.short()
            ),
        }
        return Ok(());
    }

    let widest = listing
        .rows
        .iter()
        .map(|r| r.path.as_str().len())
        .max()
        .unwrap_or(0);
    for row in &listing.rows {
        let held = match (row.is_removed(), row.have) {
            (true, _) => "removed",
            (false, true) => "local",
            (false, false) => "remote",
        };
        println!(
            "{:<widest$}  {:>9}  {}  {held}",
            row.path.as_str(),
            human_size(row.size),
            &row.hash[..8.min(row.hash.len())],
        );
    }

    if listing.rows.iter().any(|r| !r.have && !r.is_removed()) {
        println!();
        println!("`remote` means this node knows the file exists but does not hold it.");
    }
    Ok(())
}

pub fn show(paths: &Paths, needle: &str, path: &str) -> Result<()> {
    let detail = ops::file::show(paths, needle, path)?;
    let row = &detail.row;

    println!("path      {}", row.path);
    println!("size      {} ({} bytes)", human_size(row.size), row.size);
    println!("hash      {}", row.hash);
    println!(
        "added     {} by {}",
        ago(row.added_at),
        if detail.added_by_me {
            "this node".to_owned()
        } else {
            row.added_by.to_string()
        }
    );
    if let Some(at) = row.removed_at {
        println!("removed   {}", ago(at));
    }
    println!("location  {}", detail.location.display());

    println!(
        "held      {}",
        if row.have {
            "yes, on this node"
        } else {
            "no, the catalogue knows it, the bytes are elsewhere"
        }
    );

    if !row.is_removed() && !row.have {
        println!();
    } else if !row.is_removed() && !detail.bytes_present {
        println!();
        println!("The bytes are missing. `ac file verify {needle}` checks the whole group.");
    }
    Ok(())
}

pub fn remove(paths: &Paths, needle: &str, path: &str) -> Result<()> {
    let path = ops::file::remove(paths, needle, path)?;

    println!("removed {path}");
    println!();
    println!("This node stops offering it. Nothing reaches back, a member who already has");
    println!("a copy keeps it, and no removal can undo that.");
    Ok(())
}

pub fn verify(paths: &Paths, needle: &str) -> Result<()> {
    let report = ops::file::verify(paths, needle)?;

    for (path, why) in &report.unreadable {
        eprintln!("could not read {path}: {why}");
    }

    println!("{} file(s) checked", report.checked);
    for path in &report.missing {
        println!("  missing    {path}");
    }
    for path in &report.changed {
        println!("  changed    {path}");
    }
    for path in &report.untracked {
        println!("  untracked  {path}");
    }

    if report.everything_matches() {
        println!("everything matches");
    } else if !report.untracked.is_empty() {
        println!();
        println!("Untracked files are bytes this node holds but does not index, usually an");
        println!("add that was interrupted after the copy. They are not shared with anyone.");
    }
    Ok(())
}
