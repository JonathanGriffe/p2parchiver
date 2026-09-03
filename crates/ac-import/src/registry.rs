use crate::config::{Field, Fields};
use crate::source::{Result, Source, SourceError, SourceType};

type Opener = fn(&Fields, &Fields) -> Result<Box<dyn Source>>;

/// Sign a person in, and hand back the settings that says they are.
///
/// Some sources cannot be configured by typing alone: what they need is a token only their
/// operator can issue, and only to someone who has just said yes in a browser. Such a source
/// declares one of these, and whatever drives it — a command, a button — asks for it rather
/// than asking the person to produce the token by hand. It is given the settings so far and
/// returns the ones to keep beside them.
pub type Authorize = fn(&Fields) -> Result<Fields>;

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

    fn open(config: &Fields, settings: &Fields) -> Result<Box<dyn Source>>;
}

#[derive(Debug)]
pub struct Registered {
    pub name: &'static str,
    pub kind: SourceType,
    pub settings: &'static [Field],
    pub config: &'static [Field],
    open: Opener,
    /// Set when the source has a sign-in of its own; nothing for one that has not.
    auth: Option<Authorize>,
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
        }
    }

    pub fn open(&self, config: &Fields, settings: &Fields) -> Result<Box<dyn Source>> {
        (self.open)(config, settings)
    }

    /// Whether this source can be signed in to, which is what makes offering it worth doing.
    pub fn signs_in(&self) -> bool {
        self.auth.is_some()
    }

    /// Whether one configured source already has been.
    ///
    /// Asked of that source's own config, because whose account it is belongs to the source
    /// and not to the implementation — two of them are two accounts. Answered by the fields
    /// the sign-in fills in: they are exactly the ones nobody is asked for, so holding them
    /// is the same thing as having signed in. That keeps the question answerable without
    /// every source growing a second hook to answer it.
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
