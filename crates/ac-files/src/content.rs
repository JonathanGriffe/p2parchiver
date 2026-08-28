use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::path::RelPath;

/// Where staging files are written,
const STAGING_DIRNAME: &str = ".staging";

/// Read buffer. Large enough that a multi-gigabyte video is not read a page at a time, small
/// enough to stay off the stack and out of the way.
const CHUNK: usize = 64 * 1024;

/// A file copied into staging, hashed, and waiting to be renamed into place.
#[derive(Debug)]
pub struct Staged {
    staged: PathBuf,
    dest: PathBuf,
    pub size: u64,
    pub hash: String,
    pub modified: i64,
}

/// A transfer in progress: bytes going into staging, hashed as they arrive.
#[derive(Debug)]
pub struct Sink {
    file: File,
    staged: PathBuf,
    dest: PathBuf,
    hasher: Sha256,
    size: u64,
}

impl Sink {
    pub fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.hasher.update(bytes);
        self.file.write_all(bytes)?;
        self.size += bytes.len() as u64;
        Ok(())
    }

    /// Stop, keeping what has arrived so a later attempt can continue from it.
    pub fn park(mut self) -> io::Result<u64> {
        self.file.flush()?;
        self.file.sync_all()?;
        Ok(self.size)
    }

    /// Finish, giving back something [`Content::commit`] can put in place.
    pub fn finish(mut self) -> io::Result<Staged> {
        self.file.flush()?;
        self.file.sync_all()?;

        Ok(Staged {
            staged: self.staged,
            dest: self.dest,
            size: self.size,
            hash: hex::encode(self.hasher.finalize()),
            modified: crate::content::now(),
        })
    }

    pub fn size(&self) -> u64 {
        self.size
    }
}

/// Unix seconds, for the mtime a downloaded file gets.
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

/// The storage root, and everything done beneath it.
#[derive(Debug, Clone)]
pub struct Content {
    root: PathBuf,
}

impl Content {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The directory holding one group's files. `dir` comes from `Files::dir_for`.
    pub fn group_dir(&self, dir: &str) -> PathBuf {
        self.root.join(dir)
    }

    /// Where one file lives on disk.
    pub fn locate(&self, dir: &str, path: &RelPath) -> PathBuf {
        path.join_under(&self.group_dir(dir))
    }

    /// Copy `src` into staging, hashing it in the same pass.
    pub fn stage(&self, dir: &str, path: &RelPath, src: &Path) -> io::Result<Staged> {
        let group_dir = self.group_dir(dir);
        let staging = group_dir.join(STAGING_DIRNAME);
        fs::create_dir_all(&staging)?;

        let meta = fs::metadata(src)?;
        if !meta.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a regular file", src.display()),
            ));
        }

        // Named for the destination so a leftover staging file says what it was going to be.
        let staged = staging.join(format!("{}.part", sanitize_stem(path)));
        let mut reader = File::open(src)?;
        let mut writer = File::create(&staged)?;

        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; CHUNK];
        let mut size = 0u64;
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            writer.write_all(&buf[..n])?;
            size += n as u64;
        }
        writer.flush()?;
        writer.sync_all()?;

        Ok(Staged {
            staged,
            dest: self.locate(dir, path),
            size,
            hash: hex::encode(hasher.finalize()),
            modified: mtime_of(&meta),
        })
    }

    /// Move a staged file into place, durably.
    pub fn commit(&self, staged: Staged) -> io::Result<()> {
        if let Some(parent) = staged.dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(&staged.staged, &staged.dest)?;

        // Without this the rename can be lost even though the data was flushed, leaving the
        // staging file and no destination.
        if let Some(parent) = staged.dest.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    }

    /// Where a partly-downloaded file waits between attempts.
    fn staging_of(&self, dir: &str, path: &RelPath) -> PathBuf {
        self.group_dir(dir)
            .join(STAGING_DIRNAME)
            .join(Self::staging_name(path))
    }

    /// What a partial for `path` is called.
    pub fn staging_name(path: &RelPath) -> String {
        format!("{}.part", sanitize_stem(path))
    }

    /// Delete partials in `dir` that no live transfer could still want.
    pub fn sweep_staging<'a>(
        &self,
        dir: &str,
        keep: impl IntoIterator<Item = &'a RelPath>,
        idle_for: std::time::Duration,
    ) -> io::Result<usize> {
        let keep: std::collections::HashSet<String> =
            keep.into_iter().map(Self::staging_name).collect();

        let staging = self.group_dir(dir).join(STAGING_DIRNAME);
        let entries = match fs::read_dir(&staging) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e),
        };

        let mut swept = 0;
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if keep.contains(name) {
                continue;
            }

            let meta = entry.metadata()?;
            if !meta.is_file() || !idle_since(&meta, idle_for) {
                continue;
            }

            match fs::remove_file(entry.path()) {
                Ok(()) => swept += 1,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(swept)
    }

    /// How much of this file a previous attempt already wrote.
    pub fn staged_len(&self, dir: &str, path: &RelPath) -> u64 {
        fs::metadata(self.staging_of(dir, path)).map_or(0, |m| m.len())
    }

    /// Open the staging file to continue a transfer at `from`.
    pub fn resume(&self, dir: &str, path: &RelPath, from: u64) -> io::Result<Sink> {
        let staged = self.staging_of(dir, path);
        if let Some(parent) = staged.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut hasher = Sha256::new();
        let mut size = 0u64;

        if from > 0 && fs::metadata(&staged).is_ok_and(|m| m.len() == from) {
            let mut existing = File::open(&staged)?;
            let mut buf = vec![0u8; CHUNK];
            loop {
                let n = existing.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                size += n as u64;
            }
        } else {
            // Nothing usable to continue from.
            let _ = fs::remove_file(&staged);
        }

        let file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(size == 0)
            .append(size > 0)
            .open(&staged)?;

        Ok(Sink {
            file,
            staged,
            dest: self.locate(dir, path),
            hasher,
            size,
        })
    }

    /// Open a file for reading from `offset`, for serving it to a peer.
    pub fn open_at(&self, dir: &str, path: &RelPath, offset: u64) -> io::Result<File> {
        let mut file = File::open(self.locate(dir, path))?;
        if offset > 0 {
            use std::io::Seek;
            file.seek(io::SeekFrom::Start(offset))?;
        }
        Ok(file)
    }

    /// Move a file to another path inside the same group.
    pub fn rename(&self, dir: &str, from: &RelPath, to: &RelPath) -> io::Result<()> {
        let source = self.locate(dir, from);
        let dest = self.locate(dir, to);

        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(&source, &dest)?;
        if let Some(parent) = dest.parent() {
            File::open(parent)?.sync_all()?;
        }

        // The source's directories may now be empty. Same sweep as `remove`, and it stops at
        // the group directory for the same reason.
        self.prune_above(dir, &source);
        Ok(())
    }

    /// Throw away a staged file without putting it in place.
    pub fn discard(&self, staged: Staged) -> io::Result<()> {
        match fs::remove_file(&staged.staged) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Delete a file's bytes, and any now-empty directories above it.
    pub fn remove(&self, dir: &str, path: &RelPath) -> io::Result<()> {
        let target = self.locate(dir, path);
        match fs::remove_file(&target) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        }

        self.prune_above(dir, &target);
        Ok(())
    }

    /// Drop directories left empty above `target`, stopping at the group's own directory.
    fn prune_above(&self, dir: &str, target: &Path) {
        let group_dir = self.group_dir(dir);
        let mut parent = target.parent().map(Path::to_path_buf);
        while let Some(p) = parent {
            if p == group_dir || fs::remove_dir(&p).is_err() {
                break;
            }
            parent = p.parent().map(Path::to_path_buf);
        }
    }

    /// The hash of a file already in place, for `verify`.
    pub fn hash_at(&self, dir: &str, path: &RelPath) -> io::Result<String> {
        let mut file = File::open(self.locate(dir, path))?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; CHUNK];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(hex::encode(hasher.finalize()))
    }

    pub fn exists(&self, dir: &str, path: &RelPath) -> bool {
        self.locate(dir, path).is_file()
    }

    /// Every file actually present in a group's directory, as group-relative paths.
    pub fn walk(&self, dir: &str) -> io::Result<Vec<RelPath>> {
        let group_dir = self.group_dir(dir);
        let mut found = Vec::new();
        if !group_dir.is_dir() {
            return Ok(found);
        }
        walk_into(&group_dir, &group_dir, &mut found)?;
        found.sort();
        Ok(found)
    }
}

fn walk_into(base: &Path, dir: &Path, out: &mut Vec<RelPath>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        // `symlink_metadata` does not follow, which is the point.
        let meta = fs::symlink_metadata(&path)?;

        if meta.is_symlink() {
            continue;
        }
        if meta.is_dir() {
            if path.file_name().is_some_and(|n| n == STAGING_DIRNAME) {
                continue;
            }
            walk_into(base, &path, out)?;
        } else if meta.is_file()
            && let Ok(rel) = path.strip_prefix(base)
            && let Some(text) = rel.to_str()
            && let Ok(rel) = RelPath::parse(text)
        {
            out.push(rel);
        }
    }
    Ok(())
}

/// A staging filename derived from the destination, kept short and free of separators.
fn sanitize_stem(path: &RelPath) -> String {
    let mut readable = String::new();
    for c in path.file_name().chars() {
        let c = if c.is_alphanumeric() { c } else { '_' };
        if readable.len() + c.len_utf8() > 64 {
            break;
        }
        readable.push(c);
    }

    let mut hasher = Sha256::new();
    hasher.update(path.as_str().as_bytes());
    let digest = hex::encode(hasher.finalize());

    format!("{readable}-{}", &digest[..16])
}

/// Whether this file has gone untouched for at least `idle_for`.
fn idle_since(meta: &fs::Metadata, idle_for: std::time::Duration) -> bool {
    meta.modified()
        .ok()
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|idle| idle >= idle_for)
}

fn mtime_of(meta: &fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn content() -> (Content, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (Content::new(dir.path().join("files")), dir)
    }

    fn source(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, bytes).unwrap();
        path
    }

    fn rel(p: &str) -> RelPath {
        RelPath::parse(p).unwrap()
    }

    #[test]
    fn staging_then_committing_puts_the_file_in_place() {
        let (content, tmp) = content();
        let src = source(tmp.path(), "in.txt", b"hello");
        let path = rel("docs/notes.txt");

        let staged = content.stage("g", &path, &src).unwrap();
        assert_eq!(staged.size, 5);
        assert_eq!(
            staged.hash,
            // sha256("hello")
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );

        assert!(!content.exists("g", &path), "not there until committed");
        content.commit(staged).unwrap();

        assert!(content.exists("g", &path));
        assert_eq!(
            fs::read_to_string(content.locate("g", &path)).unwrap(),
            "hello"
        );
    }

    #[test]
    fn an_uncommitted_stage_leaves_the_destination_untouched() {
        // The interrupted-add case: a truncated file must never look like a real one.
        let (content, tmp) = content();
        let src = source(tmp.path(), "in.txt", b"hello");
        let path = rel("a.txt");

        let staged = content.stage("g", &path, &src).unwrap();
        drop(staged);

        assert!(!content.exists("g", &path));
        assert!(
            content.walk("g").unwrap().is_empty(),
            "and the leftover is not mistaken for content"
        );
    }

    #[test]
    fn the_hash_is_of_the_content_not_the_name() {
        let (content, tmp) = content();
        let a = source(tmp.path(), "a.txt", b"same");
        let b = source(tmp.path(), "b.txt", b"same");

        let sa = content.stage("g", &rel("a.txt"), &a).unwrap();
        let sb = content.stage("g", &rel("b.txt"), &b).unwrap();
        assert_eq!(sa.hash, sb.hash);
    }

    #[test]
    fn a_committed_file_hashes_the_same_on_the_way_back() {
        let (content, tmp) = content();
        let src = source(tmp.path(), "in.bin", &vec![7u8; CHUNK * 2 + 13]);
        let path = rel("big.bin");

        let staged = content.stage("g", &path, &src).unwrap();
        let expected = staged.hash.clone();
        content.commit(staged).unwrap();

        assert_eq!(content.hash_at("g", &path).unwrap(), expected);
    }

    #[test]
    fn a_directory_source_is_refused() {
        let (content, tmp) = content();
        let dir = tmp.path().join("adir");
        fs::create_dir(&dir).unwrap();

        assert!(content.stage("g", &rel("x"), &dir).is_err());
    }

    #[test]
    fn removing_takes_empty_parents_but_stops_at_the_group() {
        let (content, tmp) = content();
        let src = source(tmp.path(), "in.txt", b"x");
        let path = rel("photos/2024/a.txt");

        let staged = content.stage("g", &path, &src).unwrap();
        content.commit(staged).unwrap();
        content.remove("g", &path).unwrap();

        assert!(!content.exists("g", &path));
        assert!(!content.group_dir("g").join("photos").exists());
        assert!(content.group_dir("g").is_dir(), "the group dir survives");
    }

    #[test]
    fn removing_something_absent_is_not_an_error() {
        let (content, _tmp) = content();
        content.remove("g", &rel("nothing.txt")).unwrap();
    }

    #[test]
    fn walking_finds_committed_files_and_ignores_staging() {
        let (content, tmp) = content();
        for (name, path) in [("a", "a.txt"), ("b", "photos/b.txt")] {
            let src = source(tmp.path(), name, b"x");
            let staged = content.stage("g", &rel(path), &src).unwrap();
            content.commit(staged).unwrap();
        }
        // A staging file left by an interrupted add.
        let src = source(tmp.path(), "c", b"x");
        let _abandoned = content.stage("g", &rel("c.txt"), &src).unwrap();

        let found = content.walk("g").unwrap();
        assert_eq!(
            found.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
            vec!["a.txt", "photos/b.txt"]
        );
    }

    // Creating a symlink on Windows needs a privilege this test cannot assume.
    #[cfg(unix)]
    #[test]
    fn walking_does_not_follow_a_symlink_out_of_the_root() {
        let (content, tmp) = content();
        let outside = source(tmp.path(), "secret.txt", b"not yours");
        fs::create_dir_all(content.group_dir("g")).unwrap();
        std::os::unix::fs::symlink(&outside, content.group_dir("g").join("link.txt")).unwrap();

        assert!(
            content.walk("g").unwrap().is_empty(),
            "a symlink is not content"
        );
    }

    #[test]
    fn a_parked_transfer_resumes_where_it_stopped() {
        let (content, _tmp) = content();
        let path = rel("big.bin");
        let whole: Vec<u8> = (0..CHUNK * 3 + 77).map(|i| (i % 251) as u8).collect();
        let (first, second) = whole.split_at(CHUNK + 13);

        let mut sink = content.resume("g", &path, 0).unwrap();
        sink.write(first).unwrap();
        let parked = sink.park().unwrap();

        assert_eq!(parked, first.len() as u64);
        assert_eq!(
            content.staged_len("g", &path),
            parked,
            "the next attempt learns where to start from the partial itself"
        );
        assert!(!content.exists("g", &path), "nothing is in place yet");

        // A second attempt, as a fresh task would make it.
        let mut sink = content.resume("g", &path, parked).unwrap();
        sink.write(second).unwrap();
        let staged = sink.finish().unwrap();
        content.commit(staged).unwrap();

        assert_eq!(std::fs::read(content.locate("g", &path)).unwrap(), whole);
        assert_eq!(
            content.hash_at("g", &path).unwrap(),
            sha256_of(&whole),
            "the hash spans both halves, so the state really was rebuilt"
        );
    }

    #[test]
    fn a_resume_from_the_wrong_offset_starts_over() {
        // The peer is answering a different question than we asked. Continuing would splice
        // two unrelated byte ranges into one file that hashes to nothing.
        let (content, _tmp) = content();
        let path = rel("big.bin");

        let mut sink = content.resume("g", &path, 0).unwrap();
        sink.write(b"one hundred bytes of something").unwrap();
        sink.park().unwrap();

        let mut sink = content.resume("g", &path, 999_999).unwrap();
        assert_eq!(sink.size(), 0, "the partial was discarded, not appended to");

        sink.write(b"fresh").unwrap();
        let staged = sink.finish().unwrap();
        assert_eq!(staged.size, 5);
        assert_eq!(staged.hash, sha256_of(b"fresh"));
    }

    #[test]
    fn a_transfer_that_never_started_resumes_from_zero() {
        let (content, _tmp) = content();
        let path = rel("new.bin");

        assert_eq!(content.staged_len("g", &path), 0);
        let sink = content.resume("g", &path, 0).unwrap();
        assert_eq!(sink.size(), 0);
    }

    #[test]
    fn a_sweep_keeps_what_is_still_wanted_and_drops_the_rest() {
        let (content, _tmp) = content();
        let wanted = rel("videos/wanted.mp4");
        let orphan = rel("videos/tombstoned.mp4");

        for path in [&wanted, &orphan] {
            let mut sink = content.resume("g", path, 0).unwrap();
            sink.write(b"partial").unwrap();
            sink.park().unwrap();
        }

        // Only `wanted` is still a live row we lack bytes for.
        let swept = content
            .sweep_staging("g", [&wanted], Duration::ZERO)
            .unwrap();

        assert_eq!(swept, 1);
        assert_eq!(content.staged_len("g", &wanted), 7, "still resumable");
        assert_eq!(content.staged_len("g", &orphan), 0, "the orphan is gone");
    }

    #[test]
    fn a_sweep_leaves_a_partial_that_was_just_written_to() {
        // The race the idle window exists for: a row can be tombstoned by a peer's merge while
        // its bytes are still arriving, and unlinking under an open `Sink` breaks the rename.
        let (content, _tmp) = content();
        let path = rel("live.mp4");

        let mut sink = content.resume("g", &path, 0).unwrap();
        sink.write(b"arriving").unwrap();

        let swept = content
            .sweep_staging("g", [], Duration::from_secs(3600))
            .unwrap();

        assert_eq!(swept, 0);
        sink.park().unwrap();
        assert_eq!(content.staged_len("g", &path), 8);
    }

    #[test]
    fn sweeping_a_group_that_never_staged_anything_is_not_an_error() {
        let (content, _tmp) = content();
        assert_eq!(content.sweep_staging("g", [], Duration::ZERO).unwrap(), 0);
    }

    #[test]
    fn a_sweep_does_not_touch_committed_files() {
        let (content, tmp) = content();
        let src = source(tmp.path(), "in.txt", b"hello");
        let path = rel("docs/notes.txt");

        let staged = content.stage("g", &path, &src).unwrap();
        content.commit(staged).unwrap();

        assert_eq!(content.sweep_staging("g", [], Duration::ZERO).unwrap(), 0);
        assert!(content.exists("g", &path));
    }

    #[test]
    fn two_files_sharing_a_basename_do_not_share_a_staging_file() {
        let (content, _tmp) = content();
        let a = rel("2024/clip.mp4");
        let b = rel("2023/clip.mp4");

        let mut sink = content.resume("g", &a, 0).unwrap();
        sink.write(&[1u8; 4096]).unwrap();
        let parked = sink.park().unwrap();

        assert_eq!(content.staged_len("g", &a), parked);
        assert_eq!(
            content.staged_len("g", &b),
            0,
            "the other path must see nothing staged"
        );
    }

    #[test]
    fn a_staging_name_fits_what_a_filesystem_will_take() {
        // The longest component a `RelPath` allows, in the widest characters there are: 64 of
        // those is 256 bytes of stem on its own, before the suffix and the extension.
        let (content, _tmp) = content();
        let path = rel(&format!("deep/{}.mp4", "🎬".repeat(62)));

        let staged = content.staging_of("g", &path);
        let name = staged.file_name().unwrap().to_str().unwrap();
        assert!(name.len() <= 255, "{} bytes: {name:?}", name.len());
    }

    #[test]
    fn serving_from_an_offset_sends_only_the_remainder() {
        let (content, tmp) = content();
        let path = rel("big.bin");
        let src = source(tmp.path(), "in.bin", b"0123456789");

        let staged = content.stage("g", &path, &src).unwrap();
        content.commit(staged).unwrap();

        let mut rest = Vec::new();
        std::io::Read::read_to_end(&mut content.open_at("g", &path, 4).unwrap(), &mut rest)
            .unwrap();
        assert_eq!(rest, b"456789");
    }

    /// The hash `Content` would compute, for comparing against.
    fn sha256_of(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex::encode(hasher.finalize())
    }

    #[test]
    fn walking_a_group_that_has_nothing_yet_is_empty() {
        let (content, _tmp) = content();
        assert!(content.walk("never-used").unwrap().is_empty());
    }
}
