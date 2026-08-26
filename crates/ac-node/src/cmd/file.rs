//! `ac file` — put content into a group, and see what is there.
//!
//! Like `ac group`, every command here writes `state.sqlite` and returns; nothing talks to the
//! network, so all of it works offline. Unlike `ac group`, it also writes the filesystem, and
//! the ordering between the two is the thing to keep hold of: **bytes land, then the row
//! commits**. The index is a cache of the disk, so a row that promised bytes which were never
//! written would be a lie the rest of the node believes. The reverse — bytes with no row — is
//! recoverable, and is what `ac file verify` reports.
//!
//! Adding is not admin-only. The group chain has one writer because membership needs one, but
//! content does not: anybody in a group may contribute to it.

use std::path::{Path, PathBuf};

use ac_files::store::Recorded;
use ac_files::{Content, FileRow, Files, RelPath};
use ac_groups::id::GroupId;
use ac_groups::store::{GroupRow, State};
use ac_net::config::Paths;
use anyhow::{Context, Result, anyhow, bail};

use super::{now, open, open_files, resolve};

/// Everything the file commands need, opened together.
struct Session {
    files: Files,
    content: Content,
    id: GroupId,
    row: GroupRow,
    /// The group's directory name, allocated on first use.
    dir: String,
}

fn session(paths: &Paths, needle: &str) -> Result<Session> {
    let (identity, groups) = open(paths)?;
    let (id, row) = resolve(&groups, needle)?;
    let (mut files, content) = open_files(paths, &identity)?;

    let dir = files
        .dir_for(id, &row.name)
        .with_context(|| format!("choosing a directory for {}", row.name))?;

    Ok(Session {
        files,
        content,
        id,
        row,
        dir,
    })
}

/// Refuse the groups where adding content would be meaningless.
///
/// Not a membership check: this is about whether the group is still a going concern on *this*
/// node. One we have left is one we have stopped taking part in.
fn writable(row: &GroupRow) -> Result<()> {
    if row.state == State::Left {
        bail!(
            "you have left {}; rejoin with `ac group accept {}` before adding to it",
            row.name,
            row.id.short()
        );
    }
    Ok(())
}

pub fn add(
    paths: &Paths,
    needle: &str,
    sources: &[PathBuf],
    to: Option<&str>,
    rename: Option<&str>,
    recursive: bool,
    force: bool,
) -> Result<()> {
    let mut s = session(paths, needle)?;
    writable(&s.row)?;

    if rename.is_some() && sources.len() != 1 {
        bail!(
            "--as names one destination, but {} sources were given; use --to <dir> instead",
            sources.len()
        );
    }

    // Expand directories first, so a failure to read one is reported before anything is
    // copied rather than half way through.
    let mut planned: Vec<(PathBuf, RelPath)> = Vec::new();
    for src in sources {
        let meta = std::fs::metadata(src).with_context(|| format!("reading {}", src.display()))?;

        if meta.is_dir() {
            if !recursive {
                bail!(
                    "{} is a directory; pass --recursive to add what is in it",
                    src.display()
                );
            }
            expand_dir(src, to.unwrap_or(""), &mut planned)?;
        } else {
            let dest = match rename {
                Some(exact) => RelPath::parse(exact),
                None => RelPath::under(to.unwrap_or(""), &file_name_of(src)?),
            }
            .with_context(|| format!("working out where {} should go", src.display()))?;
            planned.push((src.clone(), dest));
        }
    }

    if planned.is_empty() {
        println!("nothing to add");
        return Ok(());
    }

    let single = planned.len() == 1;
    let (mut added, mut unchanged, mut failed) = (0usize, 0usize, 0usize);
    for (src, dest) in &planned {
        match add_one(&mut s, src, dest, force) {
            Ok(Recorded::Unchanged) => {
                unchanged += 1;
                // Said out loud only when there is nothing else to report. In a bulk add the
                // summary covers it, but one file that silently did nothing reads as a
                // command that failed quietly.
                if single {
                    println!("{dest} is already there, unchanged");
                }
            }
            Ok(_) => {
                added += 1;
                println!("added {dest}");
            }
            Err(e) => {
                // One bad file must not abandon the rest of a bulk import: what succeeded is
                // already durable, and stopping would leave the user to work out where.
                failed += 1;
                eprintln!("skipped {}: {e:#}", src.display());
            }
        }
    }

    if planned.len() > 1 || failed > 0 {
        println!();
        println!("{added} added, {unchanged} unchanged, {failed} skipped");
    }
    if failed > 0 {
        bail!("{failed} of {} file(s) could not be added", planned.len());
    }
    Ok(())
}

/// Copy one file in, then record it. Never the other way round.
fn add_one(s: &mut Session, src: &Path, dest: &RelPath, force: bool) -> Result<Recorded> {
    let staged = s
        .content
        .stage(&s.dir, dest, src)
        .with_context(|| format!("copying {}", src.display()))?;

    // A group keeps one copy of any content, and a fresh add is always the later one, so it
    // would always lose. Saying so now beats accepting the file and having the next sync
    // remove it — and it names where the content already is.
    if let Some(held) = s.files.path_of_hash(s.id, &staged.hash)?
        && held != *dest
    {
        s.content.discard(staged).ok();
        bail!(
            "these bytes are already in {}, at {held}\n\
             Nothing was added: a group keeps one copy of any file.",
            s.row.name
        );
    }

    // Decided before committing: overwriting the bytes and *then* refusing to record would
    // destroy content to report a conflict.
    if let Some(existing) = s.files.get(s.id, dest)?
        && !existing.is_removed()
    {
        if existing.hash == staged.hash {
            s.content.discard(staged).ok();
            return Ok(Recorded::Unchanged);
        }
        if !force {
            s.content.discard(staged).ok();
            bail!("{dest} already holds different content; pass --force to replace it");
        }
    }

    let row = FileRow {
        path: dest.clone(),
        size: staged.size,
        hash: staged.hash.clone(),
        modified: staged.modified,
        added_at: now(),
        added_by: s.files.me(),
        removed_at: None,
        // We are about to put the bytes there ourselves.
        have: true,
        // The store assigns the log position; whatever is here is ignored.
        seen_seq: 0,
    };

    s.content
        .commit(staged)
        .with_context(|| format!("putting {dest} in place"))?;
    Ok(s.files.record(s.id, &row, force)?)
}

/// Every regular file under `dir`, destined for `<to>/<dir-name>/<relative path>`.
fn expand_dir(dir: &Path, to: &str, out: &mut Vec<(PathBuf, RelPath)>) -> Result<()> {
    let base = dir
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("{} has no usable name", dir.display()))?;

    let prefix = if to.trim_matches('/').is_empty() {
        base.to_owned()
    } else {
        format!("{}/{base}", to.trim_matches('/'))
    };
    collect(dir, dir, &prefix, out)
}

fn collect(base: &Path, dir: &Path, prefix: &str, out: &mut Vec<(PathBuf, RelPath)>) -> Result<()> {
    let entries = std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        // Not `metadata`: following a symlink here would walk out of the tree the user named,
        // and a link to a parent directory would loop forever.
        let meta = std::fs::symlink_metadata(&path)?;

        if meta.is_symlink() {
            eprintln!("skipping symlink {}", path.display());
            continue;
        }
        if meta.is_dir() {
            collect(base, &path, prefix, out)?;
        } else if meta.is_file() {
            let rel = path
                .strip_prefix(base)
                .ok()
                .and_then(|p| p.to_str())
                .ok_or_else(|| anyhow!("{} has an unusable name", path.display()))?;
            let dest = RelPath::under(prefix, rel)
                .with_context(|| format!("working out where {} should go", path.display()))?;
            out.push((path, dest));
        } else {
            eprintln!("skipping {} (not a regular file)", path.display());
        }
    }
    Ok(())
}

fn file_name_of(src: &Path) -> Result<String> {
    src.file_name()
        .and_then(|n| n.to_str())
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("{} has no usable file name", src.display()))
}

pub fn list(paths: &Paths, needle: &str, prefix: Option<&str>, removed: bool) -> Result<()> {
    let s = session(paths, needle)?;
    let rows = s
        .files
        .list(s.id, prefix, removed)
        .context("listing files")?;

    println!("{}", s.content.group_dir(&s.dir).display());
    println!();

    if rows.is_empty() {
        match prefix {
            Some(p) => println!("nothing under {p:?}"),
            None => println!(
                "no files. add some with: ac file add {} <path>...",
                s.row.id.short()
            ),
        }
        return Ok(());
    }

    let widest = rows
        .iter()
        .map(|r| r.path.as_str().len())
        .max()
        .unwrap_or(0);
    for row in &rows {
        // What this node actually holds. Once a group is shared this is most of what a
        // listing is for: the catalogue belongs to everyone, the bytes do not.
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

    if rows.iter().any(|r| !r.have && !r.is_removed()) {
        println!();
        println!("`remote` means this node knows the file exists but does not hold it.");
    }
    Ok(())
}

pub fn show(paths: &Paths, needle: &str, path: &str) -> Result<()> {
    let s = session(paths, needle)?;
    let path = RelPath::parse(path).map_err(|e| anyhow!("{e}"))?;

    let row = s
        .files
        .get(s.id, &path)
        .context("reading the file")?
        .ok_or_else(|| {
            anyhow!(
                "{path} is not in {}; `ac file list {needle}` shows what is",
                s.row.name
            )
        })?;

    let me = s.files.me();
    println!("path      {}", row.path);
    println!("size      {} ({} bytes)", human_size(row.size), row.size);
    println!("hash      {}", row.hash);
    println!(
        "added     {} by {}",
        ago(row.added_at),
        if row.added_by == me {
            "this node".to_owned()
        } else {
            row.added_by.to_string()
        }
    );
    if let Some(at) = row.removed_at {
        println!("removed   {}", ago(at));
    }
    println!(
        "location  {}",
        s.content.locate(&s.dir, &row.path).display()
    );

    println!(
        "held      {}",
        if row.have {
            "yes, on this node"
        } else {
            "no — the catalogue knows it, the bytes are elsewhere"
        }
    );

    if !row.is_removed() && !row.have {
        println!();
    } else if !row.is_removed() && !s.content.exists(&s.dir, &row.path) {
        println!();
        println!("The bytes are missing. `ac file verify {needle}` checks the whole group.");
    }
    Ok(())
}

pub fn remove(paths: &Paths, needle: &str, path: &str) -> Result<()> {
    let mut s = session(paths, needle)?;
    let path = RelPath::parse(path).map_err(|e| anyhow!("{e}"))?;

    if !s.files.remove(s.id, &path, now()).context("removing")? {
        bail!("{path} is not in {}", s.row.name);
    }
    s.content
        .remove(&s.dir, &path)
        .with_context(|| format!("deleting {path}"))?;

    println!("removed {path}");
    println!();
    println!("This node stops offering it. Nothing reaches back — a member who already has");
    println!("a copy keeps it, and no removal can undo that.");
    Ok(())
}

pub fn verify(paths: &Paths, needle: &str) -> Result<()> {
    let s = session(paths, needle)?;
    let rows = s.files.list(s.id, None, false).context("listing files")?;

    let mut missing = Vec::new();
    let mut changed = Vec::new();
    for row in &rows {
        if !s.content.exists(&s.dir, &row.path) {
            missing.push(row.path.clone());
            continue;
        }
        match s.content.hash_at(&s.dir, &row.path) {
            Ok(hash) if hash != row.hash => changed.push(row.path.clone()),
            Ok(_) => {}
            Err(e) => {
                eprintln!("could not read {}: {e}", row.path);
                missing.push(row.path.clone());
            }
        }
    }

    // Anything on disk the index does not claim. A removed file's bytes are deleted, so bytes
    // at a removed path count here too — which is right, since nothing is tracking them.
    let indexed: std::collections::BTreeSet<_> = rows.iter().map(|r| r.path.clone()).collect();
    let untracked: Vec<_> = s
        .content
        .walk(&s.dir)
        .with_context(|| format!("reading {}", s.content.group_dir(&s.dir).display()))?
        .into_iter()
        .filter(|p| !indexed.contains(p))
        .collect();

    println!("{} file(s) checked", rows.len());
    for path in &missing {
        println!("  missing    {path}");
    }
    for path in &changed {
        println!("  changed    {path}");
    }
    for path in &untracked {
        println!("  untracked  {path}");
    }

    if missing.is_empty() && changed.is_empty() && untracked.is_empty() {
        println!("everything matches");
    } else if !untracked.is_empty() {
        println!();
        println!("Untracked files are bytes this node holds but does not index — usually an");
        println!("add that was interrupted after the copy. They are not shared with anyone.");
    }
    Ok(())
}

/// How long ago a timestamp was, in the largest useful unit.
///
/// Relative rather than a date, matching `ac-server invite list`, and because rendering a
/// calendar date correctly needs a timezone database this workspace has no reason to carry.
fn ago(at: i64) -> String {
    let seconds = now() - at;
    match seconds {
        s if s < 0 => "in the future".to_owned(),
        s if s < 60 => "just now".to_owned(),
        s if s < 3_600 => format!("{}m ago", s / 60),
        s if s < 86_400 => format!("{}h ago", s / 3_600),
        s => format!("{}d ago", s / 86_400),
    }
}

/// Sizes at a glance. Binary units, because that is what a filesystem reports.
fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_read_in_the_largest_useful_unit() {
        let t = now();
        assert_eq!(ago(t), "just now");
        assert_eq!(ago(t - 300), "5m ago");
        assert_eq!(ago(t - 7_200), "2h ago");
        assert_eq!(ago(t - 172_800), "2d ago");
        // A clock that went backwards, or a row written by a peer ahead of us. Saying
        // something odd beats a negative duration formatted as if it were normal.
        assert_eq!(ago(t + 600), "in the future");
    }

    #[test]
    fn sizes_read_the_way_a_person_would_say_them() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1024), "1.0 KiB");
        assert_eq!(human_size(1536), "1.5 KiB");
        assert_eq!(human_size(4 * 1024 * 1024), "4.0 MiB");
    }

    #[test]
    fn a_directory_expands_under_its_own_name() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("holiday");
        std::fs::create_dir_all(src.join("2024")).unwrap();
        std::fs::write(src.join("a.jpg"), b"a").unwrap();
        std::fs::write(src.join("2024/b.jpg"), b"b").unwrap();

        let mut out = Vec::new();
        expand_dir(&src, "raw", &mut out).unwrap();
        out.sort_by(|a, b| a.1.cmp(&b.1));

        let dests: Vec<_> = out.iter().map(|(_, d)| d.as_str()).collect();
        assert_eq!(dests, vec!["raw/holiday/2024/b.jpg", "raw/holiday/a.jpg"]);
    }

    #[test]
    fn expanding_without_a_destination_keeps_the_directory_name() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("docs");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("n.md"), b"n").unwrap();

        let mut out = Vec::new();
        expand_dir(&src, "", &mut out).unwrap();

        assert_eq!(out[0].1.as_str(), "docs/n.md");
    }

    #[test]
    fn a_symlink_in_the_source_tree_is_not_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("secret.txt");
        std::fs::write(&outside, b"not yours").unwrap();

        let src = tmp.path().join("docs");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("real.md"), b"r").unwrap();
        std::os::unix::fs::symlink(&outside, src.join("link.txt")).unwrap();

        let mut out = Vec::new();
        expand_dir(&src, "", &mut out).unwrap();

        assert_eq!(out.len(), 1, "only the real file");
        assert_eq!(out[0].1.as_str(), "docs/real.md");
    }
}
