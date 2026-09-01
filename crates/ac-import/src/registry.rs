use crate::config::{Field, Fields};
use crate::source::{Result, Source, SourceError, SourceType};

type Opener = fn(&Fields, &Fields) -> Result<Box<dyn Source>>;

include!(concat!(env!("OUT_DIR"), "/registry.rs"));

/// What a source has to say about itself to be one of these.
pub trait RegisteredSource {
    const NAME: &'static str;
    const TYPE: SourceType;
    const SETTINGS: &'static [Field];
    const CONFIG: &'static [Field];

    fn open(config: &Fields, settings: &Fields) -> Result<Box<dyn Source>>;
}

#[derive(Debug)]
pub struct Registered {
    pub name: &'static str,
    pub kind: SourceType,
    pub settings: &'static [Field],
    pub config: &'static [Field],
    open: Opener,
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
        }
    }

    pub fn open(&self, config: &Fields, settings: &Fields) -> Result<Box<dyn Source>> {
        (self.open)(config, settings)
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
        // The key is how an answer finds its field, so a duplicate would make one of them
        // unreachable — and the two lists are stored separately, so they may share keys.
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
