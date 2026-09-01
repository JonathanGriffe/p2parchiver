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

    const CONFIG: &'static [Field] = &[Field::paths("path", "Folders or files")];

    fn open(config: &Fields, _settings: &Fields) -> Result<Box<dyn Source>> {
        Ok(Box::new(Folder::parse(config)?))
    }
}

struct Folder {
    roots: Vec<Root>,
    page: usize,
}

/// One picked path, and the folder its contents take within the source.
struct Root {
    path: PathBuf,
    prefix: String,
}

impl Root {
    fn as_file(&self) -> Option<&str> {
        match self.prefix.is_empty() {
            true => self.path.file_name().and_then(|name| name.to_str()),
            false => Some(&self.prefix),
        }
    }
}

impl Folder {
    fn parse(config: &Fields) -> Result<Self> {
        config.check(Self::NAME, Self::CONFIG)?;
        let picked: Vec<&str> = config.all("path").filter(|path| !path.is_empty()).collect();

        if picked.is_empty() {
            return Err(refused("no paths were given"));
        }

        let mut paths: Vec<PathBuf> = Vec::with_capacity(picked.len());
        for line in picked {
            let path = PathBuf::from(line);
            if !path.is_absolute() {
                return Err(refused(format!("{line} is not an absolute path")));
            }
            if !paths.contains(&path) {
                paths.push(path);
            }
        }

        let single = paths.len() == 1;
        let mut roots: Vec<Root> = Vec::with_capacity(paths.len());
        for path in paths {
            let prefix = match single {
                true => String::new(),
                false => free_prefix(name_of(&path)?, &roots),
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
        let reference = root.as_file().unwrap_or(name);
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

        for root in &self.roots {
            if root.as_file() == Some(reference) && is_file(&root.path) {
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
        Self::TYPE
    }

    fn scan(&self, from: Option<&Cursor>) -> Result<Page> {
        let (start, within) = match from {
            None => (0, None),
            Some(cursor) => {
                let unreadable = || {
                    SourceError::Failed(format!("{} cannot resume from {cursor:?}", Folder::NAME))
                };
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

fn free_prefix(name: &str, taken: &[Root]) -> String {
    let mut candidate = name.to_owned();
    let mut suffix = 2;
    while taken.iter().any(|root| root.prefix == candidate) {
        candidate = format!("{name}-{suffix}");
        suffix += 1;
    }
    candidate
}

fn refused(reason: impl Into<String>) -> SourceError {
    SourceError::config(Folder::NAME, reason)
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
        assert_eq!(refs, ["one/x.jpg", "two/x.jpg"]);
    }

    #[test]
    fn picks_that_share_a_name_are_still_told_apart() {
        let dir = tempfile::tempdir().unwrap();
        tree(
            dir.path(),
            &["a/DCIM/IMG_1.jpg", "b/DCIM/IMG_1.jpg", "c/DCIM-2/x.jpg"],
        );

        let picked = [
            dir.path().join("a/DCIM"),
            dir.path().join("b/DCIM"),
            dir.path().join("c/DCIM-2"),
            dir.path().join("a/DCIM"),
        ];
        let source =
            Folder::parse(&config(&picked.iter().map(Path::new).collect::<Vec<_>>())).unwrap();
        let (items, _) = drain(&source);

        let mut refs: Vec<&str> = items.iter().map(|i| i.reference.as_str()).collect();
        refs.sort();
        assert_eq!(
            refs,
            ["DCIM-2-2/x.jpg", "DCIM-2/IMG_1.jpg", "DCIM/IMG_1.jpg"]
        );

        let mut found: Vec<PathBuf> = items
            .iter()
            .map(|item| source.locate(&item.reference).unwrap())
            .collect();
        found.sort();
        assert_eq!(
            found,
            [
                dir.path().join("a/DCIM/IMG_1.jpg"),
                dir.path().join("b/DCIM/IMG_1.jpg"),
                dir.path().join("c/DCIM-2/x.jpg"),
            ]
        );
    }

    #[test]
    fn picked_files_that_share_a_name_are_still_told_apart() {
        let dir = tempfile::tempdir().unwrap();
        tree(dir.path(), &["a/beach.jpg", "b/beach.jpg"]);

        let source = Folder::parse(&config(&[
            &dir.path().join("a/beach.jpg"),
            &dir.path().join("b/beach.jpg"),
        ]))
        .unwrap();
        let (items, _) = drain(&source);

        let mut refs: Vec<&str> = items.iter().map(|i| i.reference.as_str()).collect();
        refs.sort();
        assert_eq!(refs, ["beach.jpg", "beach.jpg-2"]);

        assert!(items.iter().all(|item| item.name == "beach.jpg"));
        assert!(items.iter().all(|item| item.folder.is_empty()));
        for item in &items {
            assert!(source.locate(&item.reference).is_ok());
        }
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
