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

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "md5" => Some(Self::Md5),
            "sha1" => Some(Self::Sha1),
            "sha256" => Some(Self::Sha256),
            _ => None,
        }
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

pub struct Verify<'a> {
    into: &'a mut dyn Write,
    hasher: Hasher,
}

enum Hasher {
    Md5(md5::Md5),
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
}

impl<'a> Verify<'a> {
    pub fn new(algo: Digest, into: &'a mut dyn Write) -> Self {
        use sha2::Digest as _;

        Self {
            into,
            hasher: match algo {
                Digest::Md5 => Hasher::Md5(md5::Md5::new()),
                Digest::Sha1 => Hasher::Sha1(sha1::Sha1::new()),
                Digest::Sha256 => Hasher::Sha256(sha2::Sha256::new()),
            },
        }
    }

    /// What arrived, in the algorithm it was promised in.
    pub fn digest(self) -> String {
        use sha2::Digest as _;

        match self.hasher {
            Hasher::Md5(hasher) => hex::encode(hasher.finalize()),
            Hasher::Sha1(hasher) => hex::encode(hasher.finalize()),
            Hasher::Sha256(hasher) => hex::encode(hasher.finalize()),
        }
    }
}

impl Write for Verify<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        use sha2::Digest as _;

        // Only what was taken is hashed, or a short write would leave the digest describing
        // bytes that never landed.
        let wrote = self.into.write(buf)?;
        match &mut self.hasher {
            Hasher::Md5(hasher) => hasher.update(&buf[..wrote]),
            Hasher::Sha1(hasher) => hasher.update(&buf[..wrote]),
            Hasher::Sha256(hasher) => hasher.update(&buf[..wrote]),
        }
        Ok(wrote)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.into.flush()
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

/// The pictures and video an import is for.
///
/// A camera roll, a phone and a Drive folder all carry things that are not photographs —
/// documents, spreadsheets, the odd installer — and fetching them costs the bandwidth and the
/// disk that the photographs wanted. So a scan offers everything and only these are taken.
///
/// Named by extension rather than by sniffing the bytes, because the decision has to be made
/// from a listing: the whole point is to decide before anything is downloaded.
const PICTURES: &[&str] = &[
    "jpg", "jpeg", "jpe", "jfif", "png", "gif", "bmp", "tif", "tiff", "webp", "avif", "heic",
    "heif", "jxl", "svg", "ico",
];

/// Raw, which is a picture that the camera has not developed yet.
const NEGATIVES: &[&str] = &[
    "cr2", "cr3", "nef", "nrw", "arw", "srf", "sr2", "dng", "raf", "orf", "rw2", "pef", "srw",
    "x3f", "3fr", "erf", "kdc", "mrw", "raw",
];

const FOOTAGE: &[&str] = &[
    "mp4", "m4v", "mov", "avi", "mkv", "webm", "3gp", "3g2", "mpg", "mpeg", "m2ts", "mts", "ts",
    "wmv", "flv", "ogv", "mxf", "insv",
];

/// Whether this is the kind of thing an archive of photographs is for.
///
/// Nothing without an extension passes: a name that says nothing about itself is not worth
/// the download on the chance that it is a photograph.
pub fn is_media(name: &str) -> bool {
    let Some((_, ext)) = name.rsplit_once('.') else {
        return false;
    };
    let ext = ext.to_ascii_lowercase();
    let ext = ext.as_str();

    PICTURES.contains(&ext) || NEGATIVES.contains(&ext) || FOOTAGE.contains(&ext)
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

    /// What an archive of photographs is for, and what it is not. The cost of the second list
    /// is a download and the disk it lands on, so the rule is "media or nothing" rather than
    /// "everything but these".
    #[test]
    fn pictures_and_video_are_taken_and_everything_else_is_left_where_it_is() {
        for wanted in [
            "a.jpg",
            "a.JPEG",
            "a.png",
            "a.gif",
            "a.webp",
            "a.avif",
            "a.heic",
            "a.tif",
            "IMG_0001.CR3",
            "IMG_0001.dng",
            "a.arw",
            "a.raf",
            "clip.mp4",
            "clip.MOV",
            "clip.mkv",
            "clip.webm",
            "clip.3gp",
            "clip.m2ts",
        ] {
            assert!(is_media(wanted), "{wanted} should have been taken");
        }

        for unwanted in [
            "notes.pdf",
            "deck.pptx",
            "sheet.xlsx",
            "letter.docx",
            "notes.txt",
            "archive.zip",
            "song.mp3",
            "setup.exe",
            "script.sh",
            "database.db",
            "thumbs.db",
            ".DS_Store",
        ] {
            assert!(!is_media(unwanted), "{unwanted} should have been left");
        }

        // A name that says nothing about itself is not worth a download on the chance.
        assert!(!is_media("README"));
        assert!(!is_media(""));

        // The extension is the last one, so a document does not get in by wearing two.
        assert!(!is_media("holiday.jpg.pdf"));
        assert!(is_media("holiday.pdf.jpg"));
    }

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
    fn what_was_promised_is_checked_in_whichever_algorithm_it_was_promised_in() {
        // "hello", in the three algorithms a source might already have a digest in.
        for (algo, expected) in [
            (Digest::Md5, "5d41402abc4b2a76b9719d911017c592"),
            (Digest::Sha1, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"),
            (
                Digest::Sha256,
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            ),
        ] {
            let mut arrived = Vec::new();
            let mut verify = Verify::new(algo, &mut arrived);
            verify.write_all(b"hel").unwrap();
            verify.write_all(b"lo").unwrap();

            assert_eq!(verify.digest(), expected, "{algo}");
            assert_eq!(arrived, b"hello", "the bytes go through untouched");

            let promised = Checksum {
                algo,
                value: expected.to_owned(),
            };
            assert!(promised.matches(expected));
        }
    }

    #[test]
    fn an_algorithm_survives_the_round_trip_through_the_ledger() {
        for algo in [Digest::Md5, Digest::Sha1, Digest::Sha256] {
            assert_eq!(Digest::parse(algo.as_str()), Some(algo));
        }
        assert_eq!(Digest::parse("crc32"), None);
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
