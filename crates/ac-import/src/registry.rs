use crate::source::{Result, Source, SourceError, SourceType};

type Opener = fn(&str) -> Result<Box<dyn Source>>;

include!(concat!(env!("OUT_DIR"), "/registry.rs"));

pub fn known() -> &'static [(&'static str, SourceType)] {
    KNOWN
}

/// Open one configured source from its stored row
pub fn open(source: &str, config: &str) -> Result<Box<dyn Source>> {
    match opener(source) {
        Some(open) => open(config),
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
        assert!(
            known().iter().any(|(name, _)| *name == "folder"),
            "the folder source is missing from {:?}",
            known()
        );
    }

    #[test]
    fn every_name_the_registry_lists_can_be_opened() {
        // Not that every config is valid — each implementation judges its own — only that the
        // name resolves. A listed name that cannot be opened is a table out of step with the
        // folder it was generated from.
        for (name, _) in known() {
            if let Err(SourceError::Unknown { name }) = open(name, "") {
                panic!("{name} is listed but cannot be opened");
            }
        }
    }

    #[test]
    fn an_unknown_source_says_so_rather_than_dropping_the_row() {
        let Err(err) = open("nextcloud", "") else {
            panic!("a source this build does not have cannot open");
        };
        assert!(matches!(err, SourceError::Unknown { .. }), "{err}");
        assert!(err.to_string().contains("nextcloud"), "{err}");
    }

    #[test]
    fn no_two_sources_answer_to_the_same_name() {
        // A stored row names one implementation. Two files claiming the same `NAME` would make
        // that ambiguous, and the second would simply never be reached.
        let mut names: Vec<&str> = known().iter().map(|(name, _)| *name).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "two sources share a name: {names:?}");
    }
}
