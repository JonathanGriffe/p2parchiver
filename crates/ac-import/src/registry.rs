use std::sync::Mutex;

use crate::config::{Field, Fields};
use crate::source::{Result, Source, SourceError, SourceType};

type Opener = fn(&Fields, &Fields) -> Result<Box<dyn Source>>;

pub type Authorize = fn(&Fields) -> Result<Fields>;

/// The info a service needs to run
#[derive(Debug, Clone, Copy)]
pub struct NodeInfo<'a> {
    pub db: &'a std::path::Path,
    pub state: &'a std::path::Path,
    pub id: &'a str,
}

pub type Serve = fn(NodeInfo<'_>) -> Result<()>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Qr {
    pub size: usize,
    pub dark: Vec<bool>,
}

impl Qr {
    pub fn at(&self, row: usize, column: usize) -> bool {
        self.dark.get(row * self.size + column).copied() == Some(true)
    }
}

/// What a sign-in currently wants a person to look at, if one is waiting.
static SHOWING: Mutex<Option<Qr>> = Mutex::new(None);

pub fn showing() -> Option<Qr> {
    SHOWING.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// How to give up on the sign-in that is waiting, left here by the sign-in itself.
static STOP: Mutex<Option<fn()>> = Mutex::new(None);

/// Give up on whatever sign-in is waiting, if it left a way to.
///
/// A sign-in blocks a thread until somebody acts, and somebody may instead close the window
/// it was asking through. Without this, the button that started it would stay disabled until
/// the wait gave up on its own — minutes later, for no reason a person could see.
///
/// Nothing waiting, or a sign-in that cannot be interrupted, is a no-op: this is called from
/// a window closing, which is not a place to be refusing things.
pub fn stop() {
    let hook = *STOP.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(stop) = hook {
        stop();
    }
}

/// Say how to be given up on, around a wait. `None` takes it back.
pub fn stoppable(with: Option<fn()>) {
    *STOP.lock().unwrap_or_else(|e| e.into_inner()) = with;
}

/// Put something up, or take it down. Called by an `Authorize` around its wait.
pub fn show(qr: Option<Qr>) {
    *SHOWING.lock().unwrap_or_else(|e| e.into_inner()) = qr;
}

include!(concat!(env!("OUT_DIR"), "/registry.rs"));

/// What a source has to say about itself to be one of these.
pub trait RegisteredSource {
    const NAME: &'static str;
    const TYPE: SourceType;
    const SETTINGS: &'static [Field];
    const CONFIG: &'static [Field];

    /// How to sign in, for a source that is an account somewhere rather than a place on this
    /// machine. Defaulted, because most are not.
    const AUTH: Option<Authorize> = None;

    /// What to say while a sign-in is waiting on somebody. Empty for a source that never
    /// waits on anybody.
    const WAITING: &'static str = "";

    /// Something to run for as long as the node does, for a source that has to be listened
    /// for rather than asked. Most have nothing.
    const SERVICE: Option<Serve> = None;

    fn open(config: &Fields, settings: &Fields) -> Result<Box<dyn Source>>;
}

#[derive(Debug)]
pub struct Registered {
    pub name: &'static str,
    pub kind: SourceType,
    pub settings: &'static [Field],
    pub config: &'static [Field],
    open: Opener,
    auth: Option<Authorize>,
    waiting: &'static str,
    service: Option<Serve>,
}

impl Registered {
    /// One source's entry, read off its implementation.
    ///
    /// `const` so the whole table is built before the program runs, and generic so adding a
    /// field here is a change to this function and the trait — not to the text `build.rs`
    /// writes out.
    pub const fn of<S: RegisteredSource>() -> Self {
        Self {
            name: S::NAME,
            kind: S::TYPE,
            settings: S::SETTINGS,
            config: S::CONFIG,
            open: S::open,
            auth: S::AUTH,
            waiting: S::WAITING,
            service: S::SERVICE,
        }
    }

    pub fn open(&self, config: &Fields, settings: &Fields) -> Result<Box<dyn Source>> {
        (self.open)(config, settings)
    }

    /// Whether this source can be signed in to, which is what makes offering it worth doing.
    pub fn signs_in(&self) -> bool {
        self.auth.is_some()
    }

    /// What to say while this source's sign-in is waiting on somebody.
    pub fn waiting(&self) -> &'static str {
        self.waiting
    }

    /// Whether this source has something to run for as long as the node does.
    pub fn serves(&self) -> bool {
        self.service.is_some()
    }

    pub fn start(&self, node: NodeInfo<'_>) -> Result<()> {
        match self.service {
            Some(serve) => serve(node),
            None => Ok(()),
        }
    }

    /// Whether one configured source already has been.
    pub fn signed_in(&self, config: &Fields) -> bool {
        self.config
            .iter()
            .filter(|field| !field.asked)
            .all(|field| config.get(field.key).is_some_and(|held| !held.is_empty()))
    }

    /// What a person is actually asked for. The rest is either issued by a sign-in or, for
    /// settings, typed once and shared.
    pub fn asked_settings(&self) -> impl Iterator<Item = &'static Field> {
        self.settings.iter().filter(|field| field.asked)
    }

    pub fn asked_config(&self) -> impl Iterator<Item = &'static Field> {
        self.config.iter().filter(|field| field.asked)
    }

    /// Sign in, if this source has a way to. The settings that come back are to be stored
    /// beside the ones given.
    pub fn authorize(&self, settings: &Fields) -> Result<Fields> {
        match self.auth {
            Some(auth) => auth(settings),
            None => Err(SourceError::config(
                "this source",
                "it has no sign-in of its own; every setting it needs is typed",
            )),
        }
    }
}

/// Every source this build knows how to import from
pub fn known() -> &'static [Registered] {
    KNOWN
}

pub fn find(source: &str) -> Option<&'static Registered> {
    known().iter().find(|entry| entry.name == source)
}

/// Open one configured source from its stored row.
pub fn open(source: &str, config: &Fields, settings: &Fields) -> Result<Box<dyn Source>> {
    match find(source) {
        Some(entry) => entry.open(config, settings),
        None => Err(SourceError::Unknown {
            name: source.to_owned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_build_knows_how_to_import_from_a_folder() {
        assert!(find("folder").is_some(), "the folder source is missing");
    }

    #[test]
    fn a_source_with_nothing_to_run_starts_anyway_and_does_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let node = NodeInfo {
            db: &dir.path().join("ac.db"),
            state: dir.path(),
            id: "12D3KooWTestPeerId",
        };

        for entry in known() {
            if entry.serves() {
                continue;
            }
            entry.start(node).unwrap_or_else(|e| {
                panic!(
                    "{} has no service and still failed to start: {e}",
                    entry.name
                )
            });
        }

        let folder = find("folder").unwrap();
        assert!(
            !folder.serves(),
            "a folder needs nothing running to be found"
        );
    }

    #[test]
    fn every_name_the_registry_lists_can_be_opened() {
        for entry in known() {
            let opened = open(entry.name, &Fields::new(), &Fields::new());
            if let Err(SourceError::Unknown { name }) = opened {
                panic!("{name} is listed but cannot be opened");
            }
        }
    }

    #[test]
    fn an_unknown_source_says_so_rather_than_dropping_the_row() {
        let Err(err) = open("nextcloud", &Fields::new(), &Fields::new()) else {
            panic!("a source this build does not have cannot open");
        };
        assert!(matches!(err, SourceError::Unknown { .. }), "{err}");
        assert!(err.to_string().contains("nextcloud"), "{err}");
    }

    #[test]
    fn no_two_sources_answer_to_the_same_name() {
        let mut names: Vec<&str> = known().iter().map(|entry| entry.name).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "two sources share a name: {names:?}");
    }

    #[test]
    fn every_declared_field_can_be_told_apart_from_its_neighbours() {
        for entry in known() {
            for fields in [entry.settings, entry.config] {
                let mut keys: Vec<&str> = fields.iter().map(|field| field.key).collect();
                keys.sort_unstable();
                let count = keys.len();
                keys.dedup();
                assert_eq!(keys.len(), count, "{} repeats a key: {keys:?}", entry.name);
            }
        }
    }
}
