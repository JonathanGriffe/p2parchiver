use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::config::{Field, Fields};
use crate::registry::{Registered, RegisteredSource};
use crate::source::{Cursor, Item, Page, Result, Source, SourceError, SourceType};

const PAGE: usize = 500;

/// Read buffer, the size `ac-files` copies with.
const CHUNK: usize = 64 * 1024;

/// This source's row in the registry
pub(super) const ENTRY: Registered = Registered::of::<Folder>();

impl RegisteredSource for Folder {
    const NAME: &'static str = "folder";
    const TYPE: SourceType = SourceType::OneShot;

    /// Nothing to share: what one folder import is told has no bearing on the next.
    const SETTINGS: &'static [Field] = &[];

    /// One path, which may be a file or a folder. One rather than a selection: two picks
    /// that share a basename would offer one reference for two files.
    const CONFIG: &'static [Field] = &[Field::path("path", "File or folder")];

    fn open(config: &Fields, _settings: &Fields) -> Result<Box<dyn Source>> {
        Ok(Box::new(Folder::parse(config)?))
    }
}

struct Folder {
    /// The one thing picked: a folder to walk, or a single file.
    root: PathBuf,
    page: usize,
}

impl Folder {
    fn parse(config: &Fields) -> Result<Self> {
        config.check(Self::NAME, Self::CONFIG)?;
        let picked: Vec<&str> = config.all("path").filter(|path| !path.is_empty()).collect();

        let [path] = picked[..] else {
            return match picked.is_empty() {
                true => Err(refused("no path was given")),
                false => Err(refused("one file or folder, not several")),
            };
        };

        let root = PathBuf::from(path);
        if !root.is_absolute() {
            return Err(refused(format!("{path} is not an absolute path")));
        }
        Ok(Self { root, page: PAGE })
    }

    /// Everything the picked path offers. `false` when the page filled.
    fn visit_root(&self, after: Option<&str>, page: &mut Page) -> bool {
        let root = &self.root;
        let meta = match fs::symlink_metadata(root) {
            Ok(meta) => meta,
            Err(e) => {
                if after.is_none() {
                    page.skipped
                        .push(format!("skipping {}: {e}", root.display()));
                }
                return true;
            }
        };

        if meta.is_symlink() {
            if after.is_none() {
                page.skipped
                    .push(format!("skipping symlink {}", root.display()));
            }
            return true;
        }
        if meta.is_dir() {
            // The picked folder is not itself a folder within the source: its contents land
            // at the top, so `<source>/DCIM/a.jpg` and not `<source>/album/DCIM/a.jpg`.
            return self.visit(root, "", after, page);
        }
        if !meta.is_file() {
            if after.is_none() {
                page.skipped
                    .push(format!("skipping {} (not a regular file)", root.display()));
            }
            return true;
        }

        let Ok(name) = name_of(root) else {
            if after.is_none() {
                page.skipped.push(format!(
                    "skipping {} (its name is not usable)",
                    root.display()
                ));
            }
            return true;
        };
        // A picked file answers to its own name and has no folder within the source.
        let reference = name;
        if after.is_some_and(|cursor| reference <= cursor) {
            return true;
        }
        page.items.push(Item {
            reference: reference.to_owned(),
            folder: String::new(),
            name: name.to_owned(),
            size: Some(meta.len()),
            checksum: None,
        });
        page.items.len() < self.page
    }

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
                        checksum: None,
                    });
                    if page.items.len() >= self.page {
                        return false;
                    }
                }
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

        // A picked file answers to its own name; a picked folder to a path inside it.
        if self.root.file_name().and_then(|name| name.to_str()) == Some(reference)
            && is_file(&self.root)
        {
            return Ok(self.root.clone());
        }

        let mut candidate = self.root.clone();
        for part in reference.split('/') {
            candidate.push(part);
        }
        match is_file(&candidate) {
            true => Ok(candidate),
            false => Err(gone()),
        }
    }
}

impl Source for Folder {
    fn source_type(&self) -> SourceType {
        Self::TYPE
    }

    fn scan(&self, from: Option<&Cursor>) -> Result<Page> {
        let mut page = Page::default();
        if !self.visit_root(from.map(String::as_str), &mut page) {
            let last = page.items.last().map_or("", |item| item.reference.as_str());
            page.next = Some(last.to_owned());
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

fn classify(path: &Path) -> Kind {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) => return Kind::Skip(format!("skipping {}: {e}", path.display())),
    };
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
    SourceError::config(Folder::NAME, reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each file is written with its own path as its content.
    fn tree(root: &Path, files: &[&str]) {
        for file in files {
            let path = root.join(file);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&path, file.as_bytes()).unwrap();
        }
    }

    fn config(paths: &[&Path]) -> Fields {
        let mut fields = Fields::new();
        for path in paths {
            fields.push("path", &path.display().to_string());
        }
        fields
    }

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
    fn a_single_picked_file_is_the_whole_of_the_source() {
        let dir = tempfile::tempdir().unwrap();
        tree(dir.path(), &["holiday/beach.jpg", "holiday/other.jpg"]);
        let picked = dir.path().join("holiday/beach.jpg");

        let source = Folder::parse(&config(&[&picked])).unwrap();
        let (items, skipped) = drain(&source);

        assert!(skipped.is_empty(), "{skipped:?}");
        assert_eq!(items.len(), 1, "the file, and nothing beside it");
        assert_eq!(items[0].name, "beach.jpg");
        assert_eq!(items[0].reference, "beach.jpg");
        assert_eq!(items[0].folder, "", "a picked file sits at the top");
        assert_eq!(source.locate("beach.jpg").unwrap(), picked);
    }

    #[test]
    fn a_picked_folder_gives_up_its_tree_from_the_top() {
        let dir = tempfile::tempdir().unwrap();
        let album = dir.path().join("2024");
        tree(&album, &["DCIM/a.jpg", "top.png"]);

        let source = Folder::parse(&config(&[&album])).unwrap();
        let (items, _) = drain(&source);

        let mut refs: Vec<&str> = items.iter().map(|i| i.reference.as_str()).collect();
        refs.sort();
        // The picked folder's own name is not part of the reference: its contents are the
        // source, and the source already has a directory of its own.
        assert_eq!(refs, ["DCIM/a.jpg", "top.png"]);
        assert_eq!(
            source.locate("DCIM/a.jpg").unwrap(),
            album.join("DCIM/a.jpg")
        );
    }

    #[test]
    fn one_path_is_the_whole_of_what_it_takes() {
        let dir = tempfile::tempdir().unwrap();
        tree(dir.path(), &["a/x.jpg", "b/x.jpg"]);

        // Two would have needed a name invented for each to tell their files apart, which
        // is exactly the machinery taking one entry does without.
        let both = config(&[&dir.path().join("a"), &dir.path().join("b")]);
        match Folder::parse(&both) {
            Ok(_) => panic!("two paths should be refused"),
            Err(e) => assert!(e.to_string().contains("not several"), "{e}"),
        }

        assert!(Folder::parse(&config(&[])).is_err(), "nor none at all");
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
    fn an_empty_scan_is_not_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        let source = Folder::parse(&config(&[dir.path()])).unwrap();
        let page = source.scan(None).unwrap();

        assert!(page.items.is_empty());
        assert_eq!(page.next, None, "an empty source is a finished scan");
    }

    #[test]
    fn a_config_that_names_nothing_reachable_is_refused_at_open() {
        for empty in [Fields::new(), config(&[Path::new("")])] {
            assert!(matches!(
                Folder::parse(&empty),
                Err(SourceError::Config { .. })
            ));
        }
        assert!(matches!(
            Folder::parse(&config(&[Path::new("pictures/2024")])),
            Err(SourceError::Config { .. })
        ));
    }

    #[test]
    fn a_config_answering_a_field_the_folder_never_declared_is_refused() {
        let mut fields = config(&[Path::new("/home/a/pictures")]);
        fields.push("recursive", "true");

        let Err(err) = Folder::parse(&fields) else {
            panic!("a field the folder never declared cannot be answered");
        };
        assert!(err.to_string().contains("recursive"), "{err}");
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
                checksum: None,
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
        let source = Folder::open(&config(&[dir.path()]), &Fields::new()).unwrap();
        assert_eq!(source.source_type(), SourceType::OneShot);
        assert!(!source.source_type().polled());
    }
}
