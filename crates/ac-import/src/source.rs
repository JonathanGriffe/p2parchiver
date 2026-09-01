use std::fmt;
use std::io::{self, Write};

pub type Result<T> = std::result::Result<T, SourceError>;

/// How a source is driven
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceType {
    OneShot,
    Remote,
    Intermittent,
}

impl SourceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OneShot => "one-shot",
            Self::Remote => "remote",
            Self::Intermittent => "intermittent",
        }
    }

    pub fn polled(&self) -> bool {
        !matches!(self, Self::OneShot)
    }
}

impl fmt::Display for SourceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One thing a source is offering, before any bytes have moved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub reference: String,
    pub folder: String,
    pub name: String,
    pub size: Option<u64>,
    /// What the source says these bytes will come to, if it says anything at all.
    pub checksum: Option<Checksum>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checksum {
    pub algo: Digest,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Digest {
    Md5,
    Sha1,
    Sha256,
}

impl Checksum {
    /// Case-insensitively: hex is published in either case.
    pub fn matches(&self, computed: &str) -> bool {
        self.value.eq_ignore_ascii_case(computed)
    }
}

impl Digest {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }
}

pub type Cursor = String;

/// One page of a scan.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Page {
    pub items: Vec<Item>,
    pub next: Option<Cursor>,
    pub skipped: Vec<String>,
}

/// What the host knows that the inbox cannot: whether a group already holds these bytes.
pub trait Held {
    fn held(&self, hash: &str) -> Result<bool>;
}

pub trait Source {
    fn source_type(&self) -> SourceType;

    /// Only ever asked of an Intermittent source.
    fn reachable(&self) -> bool {
        true
    }

    fn scan(&self, from: Option<&Cursor>) -> Result<Page>;

    /// Only ever called for items the ledger has not already settled.
    fn fetch(&self, item: &Item, into: &mut dyn Write) -> Result<()>;
}

#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("this build cannot import from {name:?}")]
    Unknown { name: String },
    #[error("{implementation} cannot be configured with that: {reason}")]
    Config {
        implementation: &'static str,
        reason: String,
    },
    #[error("{reference} is no longer there")]
    Gone { reference: String },
    #[error("could not read {what}")]
    Io {
        what: String,
        #[source]
        source: io::Error,
    },
    #[error("{0}")]
    Failed(String),
}

impl SourceError {
    pub fn config(implementation: &'static str, reason: impl Into<String>) -> Self {
        Self::Config {
            implementation,
            reason: reason.into(),
        }
    }

    pub fn io(what: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            what: what.into(),
            source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_one_shot_source_is_left_out_of_the_schedule() {
        assert!(!SourceType::OneShot.polled());
        assert!(SourceType::Remote.polled());
        assert!(SourceType::Intermittent.polled());
    }

    #[test]
    fn a_published_digest_is_compared_in_either_case() {
        let checksum = Checksum {
            algo: Digest::Md5,
            value: "D41D8CD98F00B204E9800998ECF8427E".to_owned(),
        };
        assert!(checksum.matches("d41d8cd98f00b204e9800998ecf8427e"));
        assert!(!checksum.matches("d41d8cd98f00b204e9800998ecf8427f"));
    }

    #[test]
    fn each_type_has_a_name_of_its_own() {
        let names = [
            SourceType::OneShot,
            SourceType::Remote,
            SourceType::Intermittent,
        ]
        .map(|t| t.as_str());
        assert_eq!(
            names.len(),
            names.iter().collect::<std::collections::HashSet<_>>().len()
        );
    }
}
