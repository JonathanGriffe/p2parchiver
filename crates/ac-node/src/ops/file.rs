use std::path::{Path, PathBuf};

use ac_files::store::Recorded;
use ac_files::{Content, FileRow, Files, RelPath};
use ac_groups::id::GroupId;
use ac_groups::store::{GroupRow, State};
use ac_net::config::{Config, Paths};
use anyhow::{Context, Result, anyhow, bail};

use super::{now, open, open_files, resolve};

/// Everything the file operations need, opened together. Public because adding is a loop the
/// caller drives: the CLI prints a line per file, the UI advances a progress bar.
pub struct Session {
    pub files: Files,
    pub content: Content,
    pub id: GroupId,
    pub row: GroupRow,
    pub dir: String,
}

pub fn session(paths: &Paths, needle: &str) -> Result<Session> {
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
pub fn writable(row: &GroupRow) -> Result<()> {
    if row.state == State::Left {
        bail!(
            "you have left {}; rejoin with `ac group accept {}` before adding to it",
            row.name,
            row.id.short()
        );
    }
    Ok(())
}

/// What an add would do, worked out before anything is copied.
#[derive(Default)]
pub struct Planned {
    pub items: Vec<(PathBuf, RelPath)>,
    /// Entries passed over while walking, and why. Reported, never silently dropped.
    pub skipped: Vec<String>,
}

pub fn plan(
    sources: &[PathBuf],
    to: Option<&str>,
    rename: Option<&str>,
    recursive: bool,
) -> Result<Planned> {
    if rename.is_some() && sources.len() != 1 {
        bail!(
            "--as names one destination, but {} sources were given; use --to <dir> instead",
            sources.len()
        );
    }

    let mut planned = Planned::default();

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
            planned.items.push((src.clone(), dest));
        }
    }
    Ok(planned)
}

/// Copy one file in, then record it. Never the other way round.
pub fn add_one(s: &mut Session, src: &Path, dest: &RelPath, force: bool) -> Result<Recorded> {
    let staged = s
        .content
        .stage(&s.dir, dest, src)
        .with_context(|| format!("copying {}", src.display()))?;

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
        have: true,
        seen_seq: 0,
    };

    s.content
        .commit(staged)
        .with_context(|| format!("putting {dest} in place"))?;
    Ok(s.files.record(s.id, &row, force)?)
}

/// Every regular file under `dir`, destined for `<to>/<dir-name>/<relative path>`.
fn expand_dir(dir: &Path, to: &str, out: &mut Planned) -> Result<()> {
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

fn collect(base: &Path, dir: &Path, prefix: &str, out: &mut Planned) -> Result<()> {
    let entries = std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let meta = std::fs::symlink_metadata(&path)?;

        if meta.is_symlink() {
            out.skipped
                .push(format!("skipping symlink {}", path.display()));
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
            out.items.push((path, dest));
        } else {
            out.skipped
                .push(format!("skipping {} (not a regular file)", path.display()));
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

/// What this node is holding, and what it has room for.
pub struct Storage {
    pub root: PathBuf,
    pub held: u64,
    /// Absent when the volume could not be measured.
    pub free: Option<u64>,
    /// The ceiling from config, if one is set.
    pub max: Option<u64>,
    /// `held`, split by group id and largest first. Groups holding nothing are absent.
    pub by_group: Vec<(String, u64)>,
}

pub fn storage(paths: &Paths) -> Result<Storage> {
    let (identity, _) = open(paths)?;
    let (files, _) = open_files(paths, &identity)?;
    let config = Config::load(&paths.config_file())
        .with_context(|| format!("reading the config at {}", paths.config_file().display()))?;

    let root = config.storage_root(paths);
    // A storage root that does not exist yet still sits on a volume worth measuring.
    let probe = if root.exists() {
        Some(root.clone())
    } else {
        root.parent().map(Path::to_path_buf)
    };

    Ok(Storage {
        held: files
            .held_bytes()
            .context("measuring what this node holds")?,
        by_group: files
            .held_bytes_by_group()
            .context("measuring what each group holds")?,
        free: probe.and_then(|p| fs4::available_space(&p).ok()),
        max: config.storage_max,
        root,
    })
}

pub struct Listing {
    pub group: GroupRow,
    /// Where the bytes live on this node.
    pub dir: PathBuf,
    pub rows: Vec<FileRow>,
}

pub fn list(paths: &Paths, needle: &str, prefix: Option<&str>, removed: bool) -> Result<Listing> {
    let s = session(paths, needle)?;
    let rows = s
        .files
        .list(s.id, prefix, removed)
        .context("listing files")?;

    Ok(Listing {
        dir: s.content.group_dir(&s.dir),
        group: s.row,
        rows,
    })
}

pub struct FileDetail {
    pub row: FileRow,
    pub group: GroupRow,
    pub added_by_me: bool,
    pub location: PathBuf,
    /// Whether the bytes are actually on disk, which `have` only claims.
    pub bytes_present: bool,
}

pub fn show(paths: &Paths, needle: &str, path: &str) -> Result<FileDetail> {
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

    Ok(FileDetail {
        added_by_me: row.added_by == s.files.me(),
        location: s.content.locate(&s.dir, &row.path),
        bytes_present: s.content.exists(&s.dir, &row.path),
        row,
        group: s.row,
    })
}

pub fn remove(paths: &Paths, needle: &str, path: &str) -> Result<RelPath> {
    let mut s = session(paths, needle)?;
    let path = RelPath::parse(path).map_err(|e| anyhow!("{e}"))?;

    if !s.files.remove(s.id, &path, now()).context("removing")? {
        bail!("{path} is not in {}", s.row.name);
    }
    s.content
        .remove(&s.dir, &path)
        .with_context(|| format!("deleting {path}"))?;
    Ok(path)
}

pub struct VerifyReport {
    pub checked: usize,
    pub missing: Vec<RelPath>,
    pub changed: Vec<RelPath>,
    /// Bytes this node holds but does not index.
    pub untracked: Vec<RelPath>,
    /// Counted as missing too, but the reason is worth repeating.
    pub unreadable: Vec<(RelPath, String)>,
}

impl VerifyReport {
    pub fn everything_matches(&self) -> bool {
        self.missing.is_empty() && self.changed.is_empty() && self.untracked.is_empty()
    }
}

pub fn verify(paths: &Paths, needle: &str) -> Result<VerifyReport> {
    let s = session(paths, needle)?;
    let rows = s.files.list(s.id, None, false).context("listing files")?;

    let mut report = VerifyReport {
        checked: rows.len(),
        missing: Vec::new(),
        changed: Vec::new(),
        untracked: Vec::new(),
        unreadable: Vec::new(),
    };

    for row in &rows {
        if !s.content.exists(&s.dir, &row.path) {
            report.missing.push(row.path.clone());
            continue;
        }
        match s.content.hash_at(&s.dir, &row.path) {
            Ok(hash) if hash != row.hash => report.changed.push(row.path.clone()),
            Ok(_) => {}
            Err(e) => {
                report.unreadable.push((row.path.clone(), e.to_string()));
                report.missing.push(row.path.clone());
            }
        }
    }

    let indexed: std::collections::BTreeSet<_> = rows.iter().map(|r| r.path.clone()).collect();
    report.untracked = s
        .content
        .walk(&s.dir)
        .with_context(|| format!("reading {}", s.content.group_dir(&s.dir).display()))?
        .into_iter()
        .filter(|p| !indexed.contains(p))
        .collect();

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_directory_expands_under_its_own_name() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("holiday");
        std::fs::create_dir_all(src.join("2024")).unwrap();
        std::fs::write(src.join("a.jpg"), b"a").unwrap();
        std::fs::write(src.join("2024/b.jpg"), b"b").unwrap();

        let mut out = Planned::default();
        expand_dir(&src, "raw", &mut out).unwrap();
        out.items.sort_by(|a, b| a.1.cmp(&b.1));

        let dests: Vec<_> = out.items.iter().map(|(_, d)| d.as_str()).collect();
        assert_eq!(dests, vec!["raw/holiday/2024/b.jpg", "raw/holiday/a.jpg"]);
    }

    #[test]
    fn expanding_without_a_destination_keeps_the_directory_name() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("docs");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("n.md"), b"n").unwrap();

        let mut out = Planned::default();
        expand_dir(&src, "", &mut out).unwrap();

        assert_eq!(out.items[0].1.as_str(), "docs/n.md");
    }

    // Creating a symlink on Windows needs a privilege this test cannot assume.
    #[cfg(unix)]
    #[test]
    fn a_symlink_in_the_source_tree_is_not_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("secret.txt");
        std::fs::write(&outside, b"not yours").unwrap();

        let src = tmp.path().join("docs");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("real.md"), b"r").unwrap();
        std::os::unix::fs::symlink(&outside, src.join("link.txt")).unwrap();

        let mut out = Planned::default();
        expand_dir(&src, "", &mut out).unwrap();

        assert_eq!(out.items.len(), 1, "only the real file");
        assert_eq!(out.items[0].1.as_str(), "docs/real.md");
        assert_eq!(
            out.skipped.len(),
            1,
            "and the caller is told it was passed over"
        );
    }
}
