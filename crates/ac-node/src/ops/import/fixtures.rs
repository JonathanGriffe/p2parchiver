//! What the import tests share: a home, a configured source, and a source that answers
//! from memory rather than from anywhere real.

use std::io::Write;
use std::path::Path;

use ac_files::{Content, Files};
use ac_import::config::Fields;
use ac_import::source::{Checksum, Cursor, Digest, Item, Page, Source, SourceError, SourceType};
use ac_net::config::Paths;

use crate::ops::import::fetch::drain;
use crate::ops::import::scan::scan;
use crate::ops::import::sources::add_source;
use crate::ops::now;

pub(crate) struct Fake {
    pub(crate) kind: SourceType,
    pub(crate) items: Vec<Item>,
    pub(crate) bytes: Vec<(String, Vec<u8>)>,
    pub(crate) reachable: bool,
    walks_out: bool,
    asked: std::sync::atomic::AtomicBool,
}

impl Source for Fake {
    fn source_type(&self) -> SourceType {
        self.kind
    }
    fn reachable(&self) -> bool {
        match self.walks_out {
            true => !self.asked.load(std::sync::atomic::Ordering::SeqCst),
            false => self.reachable,
        }
    }
    fn scan(&self, from: Option<&Cursor>) -> Result<Page, SourceError> {
        if self.walks_out {
            self.asked.store(true, std::sync::atomic::Ordering::SeqCst);
            return Err(SourceError::Failed(
                "could not reach this phone: connection reset".to_owned(),
            ));
        }
        assert!(from.is_none(), "this fake offers one page");
        Ok(Page {
            items: self.items.clone(),
            next: None,
            skipped: Vec::new(),
        })
    }
    fn fetch(&self, item: &Item, into: &mut dyn Write) -> Result<(), SourceError> {
        match self.bytes.iter().find(|(at, _)| *at == item.reference) {
            Some((_, bytes)) => into
                .write_all(bytes)
                .map_err(|e| SourceError::io(item.name.clone(), e)),
            None => Err(SourceError::Gone {
                reference: item.reference.clone(),
            }),
        }
    }
}

impl Fake {
    /// Stop offering a reference's bytes, as a file deleted between a scan and a fetch.
    pub(crate) fn lost(mut self, reference: &str) -> Self {
        self.bytes.retain(|(at, _)| at != reference);
        self
    }

    /// Offer one reference as being a size other than what it serves.
    pub(crate) fn claims_size(mut self, reference: &str, size: u64) -> Self {
        for item in &mut self.items {
            if item.reference == reference {
                item.size = Some(size);
            }
        }
        self
    }

    /// Promise something about one reference's bytes.
    /// Here when asked, and gone by the time its pages are read.
    pub(crate) fn walks_out(mut self) -> Self {
        self.walks_out = true;
        self
    }

    pub(crate) fn promises(mut self, reference: &str, algo: Digest, value: &str) -> Self {
        for item in &mut self.items {
            if item.reference == reference {
                item.checksum = Some(Checksum {
                    algo,
                    value: value.to_owned(),
                });
            }
        }
        self
    }
}

/// Each reference is offered under its own name, holding its own name as its bytes.
pub(crate) fn fake(kind: SourceType, refs: &[&str]) -> Fake {
    Fake {
        kind,
        reachable: true,
        walks_out: false,
        asked: std::sync::atomic::AtomicBool::new(false),
        items: refs
            .iter()
            .map(|reference| Item {
                reference: (*reference).to_owned(),
                folder: String::new(),
                name: (*reference).to_owned(),
                size: Some(reference.len() as u64),
                checksum: None,
            })
            .collect(),
        bytes: refs
            .iter()
            .map(|reference| ((*reference).to_owned(), reference.as_bytes().to_vec()))
            .collect(),
    }
}

pub(crate) fn home() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

pub(crate) fn paths(home: &tempfile::TempDir) -> Paths {
    Paths::rooted_at(home.path())
}

pub(crate) fn picked(path: &Path) -> Fields {
    let mut config = Fields::new();
    config.push("path", &path.display().to_string());
    config
}

pub(crate) fn tree(root: &Path, files: &[&str]) {
    for file in files {
        let path = root.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, file.as_bytes()).unwrap();
    }
}

/// The file index and the storage root, opened as the pump opens them.
pub(crate) fn store(paths: &Paths) -> (Files, Content) {
    let identity = crate::ops::identity(paths).unwrap();
    crate::ops::open_files(paths, &identity).unwrap()
}

/// A group to file into, made straight in the store: `ops::group::create` wants an
/// enrolment, and what is being tested here is the filing, not the joining.
pub(crate) fn group(paths: &Paths, name: &str) -> ac_groups::id::GroupId {
    let identity = crate::ops::identity(paths).unwrap();
    let mut groups = ac_groups::store::Groups::open(&paths.db_file(), identity.peer_id()).unwrap();
    groups
        .create(identity.keypair(), name, "tester", now())
        .unwrap()
}

/// An album imported and sitting in `.unsorted`, and a group to file it into.
pub(crate) fn imported(home: &tempfile::TempDir, files: &[&str]) -> (Paths, String) {
    let paths = paths(home);
    let album = home.path().join("album");
    tree(&album, files);

    let row = add_source(&paths, "folder", "Pictures", picked(&album)).unwrap();
    scan(&paths, &row.dir).unwrap();
    assert_eq!(drain(&paths, None).unwrap().kept as usize, files.len());
    (paths, row.dir)
}

/// A source scanned but not yet fetched: it still owes what the scan found.
pub(crate) fn home_with_owed(home: &tempfile::TempDir) -> (Paths, String) {
    let paths = paths(home);
    let album = home.path().join("owed");
    tree(&album, &["a.jpg"]);

    let row = add_source(&paths, "folder", "Owed", picked(&album)).unwrap();
    scan(&paths, &row.dir).unwrap();
    (paths, row.dir)
}

/// Reachable throughout, and refuses anyway.
pub(crate) struct Stubborn;

impl Source for Stubborn {
    fn source_type(&self) -> SourceType {
        SourceType::Remote
    }
    fn scan(&self, _from: Option<&Cursor>) -> Result<Page, SourceError> {
        Err(SourceError::Failed("the drive said no".to_owned()))
    }
    fn fetch(&self, _item: &Item, _into: &mut dyn Write) -> Result<(), SourceError> {
        unreachable!("this one never gets that far")
    }
}
