use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::source::{Cursor, Item, Page, Result, Source, SourceError, SourceType};

pub const NAME: &str = "folder";
pub const TYPE: SourceType = SourceType::OneShot;

/// Items per page
const PAGE: usize = 500;

/// Read buffer, the size `ac-files` copies with.
const CHUNK: usize = 64 * 1024;

pub fn open(config: &str) -> Result<Box<dyn Source>> {
    Ok(Box::new(Folder::parse(config)?))
}

struct Folder {
    roots: Vec<Root>,
    /// How many items a page holds
    page: usize,
}

/// One picked path, and the folder its contents take within the source.
struct Root {
    path: PathBuf,
    prefix: String,
}

impl Folder {
    fn parse(config: &str) -> Result<Self> {
        let picked: Vec<&str> = config
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect();

        if picked.is_empty() {
            return Err(refused("no paths were given"));
        }

        let single = picked.len() == 1;
        let mut roots = Vec::with_capacity(picked.len());
        for line in picked {
            let path = PathBuf::from(line);
            if !path.is_absolute() {
                return Err(refused(format!("{line} is not an absolute path")));
            }
            let prefix = if single {
                String::new()
            } else {
                name_of(&path)?.to_owned()
            };
            roots.push(Root { path, prefix });
        }

        Ok(Self { roots, page: PAGE })
    }

    /// Everything one picked path offers. `false` when the page filled.
    fn visit_root(&self, root: &Root, after: Option<&str>, page: &mut Page) -> bool {
        let meta = match fs::symlink_metadata(&root.path) {
            Ok(meta) => meta,
            Err(e) => {
                if after.is_none() {
                    page.skipped
                        .push(format!("skipping {}: {e}", root.path.display()));
                }
                return true;
            }
        };

        if meta.is_symlink() {
            if after.is_none() {
                page.skipped
                    .push(format!("skipping symlink {}", root.path.display()));
            }
            return true;
        }
        if meta.is_dir() {
            return self.visit(&root.path, &root.prefix, after, page);
        }
        if !meta.is_file() {
            if after.is_none() {
                page.skipped.push(format!(
                    "skipping {} (not a regular file)",
                    root.path.display()
                ));
            }
            return true;
        }

        let Ok(name) = name_of(&root.path) else {
            if after.is_none() {
                page.skipped.push(format!(
                    "skipping {} (its name is not usable)",
                    root.path.display()
                ));
            }
            return true;
        };
        if after.is_some_and(|cursor| name <= cursor) {
            return true;
        }
        page.items.push(Item {
            reference: name.to_owned(),
            folder: String::new(),
            name: name.to_owned(),
            size: Some(meta.len()),
        });
        page.items.len() < self.page
    }

    /// Everything under `dir`, in reference order, starting after `after`. `false` when the
    /// page filled and the walk has to stop where it is.
    fn visit(&self, dir: &Path, folder: &str, after: Option<&str>, page: &mut Page) -> bool {
        let read = match fs::read_dir(dir) {
            Ok(read) => read,
            Err(e) => {
                if after.is_none() {
                    page.skipped
                        .push(format!("skipping {}: {e}", dir.display()));
                }
                return true;
            }
        };

        let mut entries = Vec::new();
        for entry in read {
            let path = match entry {
                Ok(entry) => entry.path(),
                Err(e) => {
                    page.skipped
                        .push(format!("skipping an entry of {}: {e}", dir.display()));
                    continue;
                }
            };
            // Lossy so that a name we cannot import still has a reference to be ordered by,
            // and so its skip is reported once rather than on every page.
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            let reference = join(folder, &name);

            let kind = if path.file_name().and_then(|name| name.to_str()).is_some() {
                classify(&path)
            } else {
                Kind::Skip(format!(
                    "skipping {} (its name is not valid UTF-8)",
                    path.display()
                ))
            };

            entries.push(Entry {
                // A directory sorts where its contents do, so `a.txt` and `a/x` come out in
                // the order the cursor will compare them in. Without the slash they do not:
                // `a/x` is greater than `a.txt`, and resuming would step over the file.
                key: match kind {
                    Kind::Dir => format!("{reference}/"),
                    _ => reference.clone(),
                },
                reference,
                name,
                path,
                kind,
            });
        }
        entries.sort_by(|a, b| a.key.cmp(&b.key));

        for entry in entries {
            match entry.kind {
                Kind::Dir => {
                    // Against the key, never the reference: `a` compares below `a.txt` while
                    // everything in it — `a/x` — sorts above it, so a directory is judged by
                    // where its contents are, which is what the trailing slash says.
                    let past = |cursor: &str| {
                        entry.key.as_str() <= cursor && !cursor.starts_with(&entry.key)
                    };
                    if after.is_some_and(past) {
                        continue;
                    }
                    if !self.visit(&entry.path, &entry.reference, after, page) {
                        return false;
                    }
                }
                Kind::File(size) => {
                    if after.is_some_and(|cursor| entry.reference.as_str() <= cursor) {
                        continue;
                    }
                    page.items.push(Item {
                        reference: entry.reference,
                        folder: folder.to_owned(),
                        name: entry.name,
                        size: Some(size),
                    });
                    if page.items.len() >= self.page {
                        return false;
                    }
                }
                // Only ever said once: an entry the last page already walked past is not
                // mentioned again.
                Kind::Skip(why) => {
                    if after.is_some_and(|cursor| entry.reference.as_str() <= cursor) {
                        continue;
                    }
                    page.skipped.push(why);
                }
            }
        }
        true
    }

    /// The file a reference names, or `Gone` if it has left.
    fn locate(&self, reference: &str) -> Result<PathBuf> {
        let gone = || SourceError::Gone {
            reference: reference.to_owned(),
        };
        if reference.is_empty()
            || reference
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(gone());
        }

        for root in &self.roots {
            // A picked file answers to its own name.
            if root.path.file_name().and_then(|name| name.to_str()) == Some(reference)
                && is_file(&root.path)
            {
                return Ok(root.path.clone());
            }

            let rest = if root.prefix.is_empty() {
                Some(reference)
            } else {
                reference.strip_prefix(&format!("{}/", root.prefix))
            };
            if let Some(rest) = rest {
                let mut candidate = root.path.clone();
                for part in rest.split('/') {
                    candidate.push(part);
                }
                if is_file(&candidate) {
                    return Ok(candidate);
                }
            }
        }
        Err(gone())
    }
}

impl Source for Folder {
    fn source_type(&self) -> SourceType {
        TYPE
    }

    fn scan(&self, from: Option<&Cursor>) -> Result<Page> {
        // The cursor names the pick it stopped in as well as where in it, so the picks need no
        // order between them: each is resumed on its own terms.
        let (start, within) = match from {
            None => (0, None),
            Some(cursor) => {
                let unreadable =
                    || SourceError::Failed(format!("{NAME} cannot resume from {cursor:?}"));
                let (index, reference) = cursor.split_once(':').ok_or_else(unreadable)?;
                let index: usize = index.parse().map_err(|_| unreadable())?;
                (index, Some(reference.to_owned()))
            }
        };

        let mut page = Page::default();
        for (index, root) in self.roots.iter().enumerate().skip(start) {
            let after = if index == start {
                within.as_deref()
            } else {
                None
            };
            if !self.visit_root(root, after, &mut page) {
                let last = page.items.last().map_or("", |item| item.reference.as_str());
                page.next = Some(format!("{index}:{last}"));
                return Ok(page);
            }
        }
        Ok(page)
    }

    fn fetch(&self, item: &Item, into: &mut dyn Write) -> Result<()> {
        let path = self.locate(&item.reference)?;
        let mut file =
            fs::File::open(&path).map_err(|e| SourceError::io(path.display().to_string(), e))?;

        let mut buf = vec![0u8; CHUNK];
        loop {
            let read = file
                .read(&mut buf)
                .map_err(|e| SourceError::io(path.display().to_string(), e))?;
            if read == 0 {
                return Ok(());
            }
            into.write_all(&buf[..read])
                .map_err(|e| SourceError::io(format!("the copy of {}", item.name), e))?;
        }
    }
}

enum Kind {
    Dir,
    File(u64),
    Skip(String),
}

struct Entry {
    key: String,
    reference: String,
    name: String,
    path: PathBuf,
    kind: Kind,
}

/// What an entry is, and why it is being passed over if it is.
fn classify(path: &Path) -> Kind {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) => return Kind::Skip(format!("skipping {}: {e}", path.display())),
    };
    // Before `is_dir`: a symlink to a directory is a way out of the picked tree.
    if meta.is_symlink() {
        Kind::Skip(format!("skipping symlink {}", path.display()))
    } else if meta.is_dir() {
        Kind::Dir
    } else if meta.is_file() {
        Kind::File(meta.len())
    } else {
        Kind::Skip(format!("skipping {} (not a regular file)", path.display()))
    }
}

fn is_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file())
}

fn join(folder: &str, name: &str) -> String {
    if folder.is_empty() {
        name.to_owned()
    } else {
        format!("{folder}/{name}")
    }
}

fn name_of(path: &Path) -> Result<&str> {
    path.file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| refused(format!("{} has no usable name", path.display())))
}

fn refused(reason: impl Into<String>) -> SourceError {
    SourceError::Config {
        implementation: NAME,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a tree from `<relative path>` entries, each written with its own path as content.
    fn tree(root: &Path, files: &[&str]) {
        for file in files {
            let path = root.join(file);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&path, file.as_bytes()).unwrap();
        }
    }

    fn config(paths: &[&Path]) -> String {
        paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Every page of a full scan, drained the way `ops::import` will drain it.
    fn drain(source: &Folder) -> (Vec<Item>, Vec<String>) {
        let mut items = Vec::new();
        let mut skipped = Vec::new();
        let mut cursor = None;
        loop {
            let page = source.scan(cursor.as_ref()).unwrap();
            items.extend(page.items);
            skipped.extend(page.skipped);
            match page.next {
                Some(next) => cursor = Some(next),
                None => return (items, skipped),
            }
            assert!(items.len() < 10_000, "a scan that will not end");
        }
    }

    #[test]
    fn a_picked_directory_gives_up_its_tree_without_its_own_name() {
        let dir = tempfile::tempdir().unwrap();
        let album = dir.path().join("2024");
        tree(&album, &["DCIM/2024-07/a.heic", "DCIM/b.jpg", "top.png"]);

        let source = Folder::parse(&config(&[&album])).unwrap();
        let (items, skipped) = drain(&source);

        assert!(skipped.is_empty(), "{skipped:?}");
        let mut refs: Vec<&str> = items.iter().map(|i| i.reference.as_str()).collect();
        refs.sort();
        // The source's own directory already says "2024"; the folder within it does not.
        assert_eq!(refs, ["DCIM/2024-07/a.heic", "DCIM/b.jpg", "top.png"]);

        let deep = items.iter().find(|i| i.name == "a.heic").unwrap();
        assert_eq!(deep.folder, "DCIM/2024-07");
        assert_eq!(deep.size, Some("DCIM/2024-07/a.heic".len() as u64));
    }

    #[test]
    fn a_reference_is_always_the_folder_and_the_name() {
        let dir = tempfile::tempdir().unwrap();
        tree(dir.path(), &["a/b/c.txt", "d.txt"]);

        let source = Folder::parse(&config(&[dir.path()])).unwrap();
        for item in drain(&source).0 {
            assert_eq!(item.reference, join(&item.folder, &item.name));
        }
    }

    #[test]
    fn picked_files_sit_at_the_top_of_the_source() {
        let dir = tempfile::tempdir().unwrap();
        tree(dir.path(), &["one.jpg", "sub/two.jpg"]);

        let source = Folder::parse(&config(&[
            &dir.path().join("one.jpg"),
            &dir.path().join("sub/two.jpg"),
        ]))
        .unwrap();
        let (items, _) = drain(&source);

        let mut names: Vec<&str> = items.iter().map(|i| i.name.as_str()).collect();
        names.sort();
        assert_eq!(names, ["one.jpg", "two.jpg"]);
        assert!(items.iter().all(|i| i.folder.is_empty()), "{items:?}");
        assert!(
            items.iter().all(|i| i.reference == i.name),
            "a picked file answers to its own name: {items:?}"
        );
    }

    #[test]
    fn several_picked_directories_keep_their_trees_apart() {
        let dir = tempfile::tempdir().unwrap();
        tree(dir.path(), &["one/x.jpg", "two/x.jpg"]);

        let source =
            Folder::parse(&config(&[&dir.path().join("one"), &dir.path().join("two")])).unwrap();
        let (items, _) = drain(&source);

        let mut refs: Vec<&str> = items.iter().map(|i| i.reference.as_str()).collect();
        refs.sort();
        // Two files of the same name, and two references: without the pick's own name in
        // front they would be one reference and one of them would never be imported.
        assert_eq!(refs, ["one/x.jpg", "two/x.jpg"]);
    }

    #[cfg(unix)]
    #[test]
    fn what_cannot_be_imported_is_reported_once_and_walked_past() {
        let dir = tempfile::tempdir().unwrap();
        tree(dir.path(), &["a.txt", "sub/b.txt"]);
        std::os::unix::fs::symlink(dir.path().join("a.txt"), dir.path().join("link.txt")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("sub"), dir.path().join("sublink")).unwrap();

        let mut source = Folder::parse(&config(&[dir.path()])).unwrap();
        source.page = 1;
        let (items, skipped) = drain(&source);

        assert_eq!(items.len(), 2, "{items:?}");
        assert_eq!(
            skipped.len(),
            2,
            "each skip is said once, not once a page: {skipped:?}"
        );
        assert!(
            skipped.iter().all(|why| why.contains("symlink")),
            "{skipped:?}"
        );
    }

    #[test]
    fn paging_offers_every_file_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        // Names chosen so a directory and a file disagree about their order unless the walk
        // sorts a directory where its contents actually sort: `a.txt` before `a/x`.
        tree(
            dir.path(),
            &[
                "a/x.txt",
                "a/y.txt",
                "a.txt",
                "a-b/z.txt",
                "b/c/deep.txt",
                "b/c.txt",
                "z.txt",
            ],
        );

        let all = {
            let source = Folder::parse(&config(&[dir.path()])).unwrap();
            drain(&source).0
        };
        assert_eq!(all.len(), 7);

        for page in 1..=8 {
            let mut source = Folder::parse(&config(&[dir.path()])).unwrap();
            source.page = page;
            let (items, _) = drain(&source);
            assert_eq!(items, all, "a page of {page} lost or repeated something");
        }
    }

    #[test]
    fn paging_across_several_picks_offers_every_file_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        tree(
            dir.path(),
            &["one/a.txt", "one/b.txt", "two/c.txt", "loose.txt"],
        );

        let picks = config(&[
            &dir.path().join("two"),
            &dir.path().join("loose.txt"),
            &dir.path().join("one"),
        ]);

        let all = {
            let source = Folder::parse(&picks).unwrap();
            drain(&source).0
        };
        assert_eq!(all.len(), 4);

        for page in 1..=5 {
            let mut source = Folder::parse(&picks).unwrap();
            source.page = page;
            assert_eq!(drain(&source).0, all, "a page of {page} lost something");
        }
    }

    #[test]
    fn an_empty_scan_is_not_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        let source = Folder::parse(&config(&[dir.path()])).unwrap();
        let page = source.scan(None).unwrap();

        assert!(page.items.is_empty());
        assert_eq!(page.next, None, "an empty source is a finished scan");
    }

    #[test]
    fn a_config_that_names_nothing_reachable_is_refused_at_open() {
        for config in ["", "   \n\n"] {
            assert!(matches!(
                Folder::parse(config),
                Err(SourceError::Config { .. })
            ));
        }
        // A daemon reads this row from some other working directory, so a relative path is
        // refused where it can still be explained rather than silently importing nothing.
        assert!(matches!(
            Folder::parse("pictures/2024"),
            Err(SourceError::Config { .. })
        ));
    }

    #[test]
    fn the_bytes_a_reference_names_are_the_ones_that_come_back() {
        let dir = tempfile::tempdir().unwrap();
        tree(dir.path(), &["sub/a.txt"]);

        let source = Folder::parse(&config(&[dir.path()])).unwrap();
        let item = drain(&source).0.pop().unwrap();

        let mut got = Vec::new();
        source.fetch(&item, &mut got).unwrap();
        assert_eq!(got, b"sub/a.txt");
    }

    #[test]
    fn fetching_something_that_has_left_says_it_is_gone() {
        let dir = tempfile::tempdir().unwrap();
        tree(dir.path(), &["a.txt"]);
        let source = Folder::parse(&config(&[dir.path()])).unwrap();
        let item = drain(&source).0.pop().unwrap();
        fs::remove_file(dir.path().join("a.txt")).unwrap();

        let err = source.fetch(&item, &mut Vec::new()).unwrap_err();
        assert!(matches!(err, SourceError::Gone { .. }), "{err}");
    }

    #[test]
    fn a_reference_cannot_climb_out_of_what_was_picked() {
        let dir = tempfile::tempdir().unwrap();
        tree(dir.path(), &["inside/a.txt", "outside.txt"]);
        let source = Folder::parse(&config(&[&dir.path().join("inside")])).unwrap();

        for reference in ["../outside.txt", "..", "./a.txt", "a.txt/../../outside.txt"] {
            let item = Item {
                reference: reference.to_owned(),
                folder: String::new(),
                name: "x".to_owned(),
                size: None,
            };
            let err = source.fetch(&item, &mut Vec::new()).unwrap_err();
            assert!(
                matches!(err, SourceError::Gone { .. }),
                "{reference}: {err}"
            );
        }
    }

    #[test]
    fn a_folder_is_never_polled() {
        let dir = tempfile::tempdir().unwrap();
        let source = open(&config(&[dir.path()])).unwrap();
        assert_eq!(source.source_type(), SourceType::OneShot);
        assert!(!source.source_type().polled());
    }
}
