use std::fmt;
use std::path::{Component, Path, PathBuf};

/// Longest single component, in bytes. 255 is the limit on ext4, APFS and NTFS alike.
const MAX_COMPONENT: usize = 255;

/// Longest whole path, in bytes. Well under `PATH_MAX` (4096 on Linux) so that joining a
/// storage root and a group directory on top still leaves room.
const MAX_PATH: usize = 1024;

/// A group-relative path: non-empty, forward-slash separated, and provably inside its group.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelPath(String);

impl RelPath {
    /// Validate a path typed by a user or read from the database.
    pub fn parse(raw: &str) -> Result<Self, PathError> {
        if raw.is_empty() {
            return Err(PathError::Empty);
        }
        if raw.len() > MAX_PATH {
            return Err(PathError::TooLong { bytes: raw.len() });
        }
        // Checked before splitting: a backslash is a separator on Windows, and treating it as
        // an ordinary character would make `..\..\x` a single innocent-looking component.
        if raw.contains('\\') {
            return Err(PathError::Backslash);
        }
        if raw.starts_with('/') {
            return Err(PathError::Absolute);
        }

        for component in raw.split('/') {
            match component {
                "" => return Err(PathError::EmptyComponent),
                "." | ".." => {
                    return Err(PathError::Traversal {
                        component: component.to_owned(),
                    });
                }
                _ => {}
            }
            if component.len() > MAX_COMPONENT {
                return Err(PathError::ComponentTooLong {
                    component: component.to_owned(),
                });
            }
            if let Some(bad) = component.chars().find(|c| c.is_control()) {
                return Err(PathError::Control { found: bad });
            }
        }

        Ok(Self(raw.to_owned()))
    }

    /// Read a relative filesystem path as a group path.
    ///
    /// The separator is the platform's going in and always `/` coming out. A group path
    /// travels to other machines, and `photos\b.jpg` names nothing on the far end of one.
    pub fn from_fs(rel: &Path) -> Result<Self, PathError> {
        let mut parts = Vec::new();
        for component in rel.components() {
            match component {
                Component::Normal(name) => {
                    parts.push(name.to_str().ok_or_else(|| PathError::NotUtf8 {
                        component: name.to_string_lossy().into_owned(),
                    })?)
                }
                Component::ParentDir => {
                    return Err(PathError::Traversal {
                        component: "..".to_owned(),
                    });
                }
                Component::CurDir => {
                    return Err(PathError::Traversal {
                        component: ".".to_owned(),
                    });
                }
                Component::RootDir | Component::Prefix(_) => return Err(PathError::Absolute),
            }
        }
        Self::parse(&parts.join("/"))
    }

    /// Join this path beneath `dir`.
    pub fn join_under(&self, dir: &Path) -> PathBuf {
        let mut out = dir.to_path_buf();
        for component in self.0.split('/') {
            out.push(component);
        }
        out
    }

    pub fn file_name(&self) -> &str {
        self.0.rsplit('/').next().unwrap_or(&self.0)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The name this path takes when it loses a fight for its own name.
    pub fn conflict_name(&self, hash: &str) -> Self {
        let (dir, name) = match self.0.rfind('/') {
            Some(at) => (&self.0[..=at], &self.0[at + 1..]),
            None => ("", self.0.as_str()),
        };

        let first = name.chars().next().map_or(0, char::len_utf8);
        let split = name[first..].rfind('.').map(|at| at + first);
        let (stem, ext) = match split {
            Some(at) => (&name[..at], &name[at..]),
            None => (name, ""),
        };

        let mark = format!(".conflict-{}", &hash[..8.min(hash.len())]);

        let room = MAX_COMPONENT.saturating_sub(mark.len() + ext.len());
        let mut cut = room.min(stem.len());
        while cut > 0 && !stem.is_char_boundary(cut) {
            cut -= 1;
        }
        let stem = &stem[..cut];

        Self::parse(&format!("{dir}{stem}{mark}{ext}")).unwrap_or_else(|_| self.clone())
    }

    /// Build a path from a directory prefix and a name, validating the result.
    pub fn under(dir: &str, name: &str) -> Result<Self, PathError> {
        let dir = dir.trim_matches('/');
        if dir.is_empty() {
            Self::parse(name)
        } else {
            Self::parse(&format!("{dir}/{name}"))
        }
    }
}

impl fmt::Display for RelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    #[error("a path inside a group cannot be empty")]
    Empty,
    #[error("{component:?} would climb out of the group")]
    Traversal { component: String },
    #[error("a path inside a group must be relative, not absolute")]
    Absolute,
    #[error("a path cannot contain an empty component, as in `a//b`")]
    EmptyComponent,
    #[error("a path cannot contain a backslash")]
    Backslash,
    #[error("{component:?} is not valid UTF-8")]
    NotUtf8 { component: String },
    #[error("a path cannot contain the control character {found:?}")]
    Control { found: char },
    #[error("a path of {bytes} bytes is too long (limit {MAX_PATH})")]
    TooLong { bytes: usize },
    #[error("{component:?} is longer than {MAX_COMPONENT} bytes")]
    ComponentTooLong { component: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ordinary_path_survives_unchanged() {
        let p = RelPath::parse("photos/2024/beach.jpg").unwrap();
        assert_eq!(p.as_str(), "photos/2024/beach.jpg");
        assert_eq!(p.file_name(), "beach.jpg");
    }

    #[test]
    fn a_bare_filename_is_a_path() {
        assert_eq!(RelPath::parse("notes.md").unwrap().file_name(), "notes.md");
    }

    #[test]
    fn everything_that_could_escape_is_refused() {
        // The table is the point: each of these has reached a storage root somewhere.
        for raw in [
            "..",
            "../x",
            "a/../b",
            "a/..",
            ".",
            "./a",
            "a/./b",
            "/etc/passwd",
            "/",
            "a//b",
            "a\\..\\b",
            "..\\x",
        ] {
            assert!(RelPath::parse(raw).is_err(), "{raw:?} should be refused");
        }
    }

    /// The separator a walk hands back is the platform's: on Windows this path arrives as
    /// `photos\2024\beach.jpg`, and stored that way it would name nothing on any other node.
    #[test]
    fn a_path_off_the_filesystem_comes_back_slash_separated() {
        let walked = Path::new("photos").join("2024").join("beach.jpg");

        assert_eq!(
            RelPath::from_fs(&walked).unwrap().as_str(),
            "photos/2024/beach.jpg"
        );
    }

    #[test]
    fn a_filesystem_path_that_could_escape_is_refused() {
        assert_eq!(
            RelPath::from_fs(Path::new("a").join("..").as_path()),
            Err(PathError::Traversal {
                component: "..".to_owned()
            })
        );
        assert_eq!(
            RelPath::from_fs(Path::new("/etc/passwd")),
            Err(PathError::Absolute)
        );
        assert_eq!(RelPath::from_fs(Path::new("")), Err(PathError::Empty));
    }

    #[test]
    fn a_dot_inside_a_name_is_fine() {
        // Only a whole component of `.` or `..` traverses; `..hidden` and `a..b` do not.
        for raw in ["..hidden", "a..b", ".hidden", "file.tar.gz"] {
            assert!(RelPath::parse(raw).is_ok(), "{raw:?} should be allowed");
        }
    }

    #[test]
    fn empty_and_control_characters_are_refused() {
        assert_eq!(RelPath::parse(""), Err(PathError::Empty));
        assert!(matches!(
            RelPath::parse("a\0b"),
            Err(PathError::Control { .. })
        ));
        assert!(matches!(
            RelPath::parse("a\nb"),
            Err(PathError::Control { .. })
        ));
    }

    #[test]
    fn length_limits_apply_per_component_and_overall() {
        let long = "x".repeat(MAX_COMPONENT + 1);
        assert!(matches!(
            RelPath::parse(&long),
            Err(PathError::ComponentTooLong { .. })
        ));

        // Each component legal, the whole thing not.
        let deep = vec!["x".repeat(100); 20].join("/");
        assert!(matches!(
            RelPath::parse(&deep),
            Err(PathError::TooLong { .. })
        ));
    }

    #[test]
    fn joining_stays_under_the_directory() {
        let root = Path::new("/store/group");
        let joined = RelPath::parse("photos/beach.jpg").unwrap().join_under(root);

        assert_eq!(joined, PathBuf::from("/store/group/photos/beach.jpg"));
        assert!(joined.starts_with(root));
    }

    #[test]
    fn a_conflict_name_keeps_the_extension_and_the_directory() {
        let p = RelPath::parse("photos/2024/beach.jpg").unwrap();
        assert_eq!(
            p.conflict_name("a41f9c3d5e").as_str(),
            "photos/2024/beach.conflict-a41f9c3d.jpg"
        );
    }

    #[test]
    fn a_conflict_name_handles_awkward_filenames() {
        // No extension at all.
        assert_eq!(
            RelPath::parse("notes")
                .unwrap()
                .conflict_name("aabbccdd")
                .as_str(),
            "notes.conflict-aabbccdd"
        );
        // Several extensions: only the last is a suffix.
        assert_eq!(
            RelPath::parse("archive.tar.gz")
                .unwrap()
                .conflict_name("aabbccdd")
                .as_str(),
            "archive.tar.conflict-aabbccdd.gz"
        );
        // A leading dot is a name, not an extension.
        assert_eq!(
            RelPath::parse(".bashrc")
                .unwrap()
                .conflict_name("aabbccdd")
                .as_str(),
            ".bashrc.conflict-aabbccdd"
        );
    }

    #[test]
    fn a_conflict_name_is_derived_only_from_the_content() {
        // Every peer must reach the same name without coordinating, and doing it twice for
        // the same content must not produce a third name.
        let p = RelPath::parse("a.jpg").unwrap();
        assert_eq!(p.conflict_name("deadbeef"), p.conflict_name("deadbeef"));
        assert_ne!(p.conflict_name("deadbeef"), p.conflict_name("feedface"));
    }

    #[test]
    fn a_long_name_still_yields_a_valid_path() {
        let long = format!("{}.jpg", "x".repeat(MAX_COMPONENT - 4));
        let renamed = RelPath::parse(&long).unwrap().conflict_name("aabbccdd");

        assert!(RelPath::parse(renamed.as_str()).is_ok());
        assert!(renamed.file_name().len() <= MAX_COMPONENT);
        assert!(
            renamed.as_str().ends_with(".conflict-aabbccdd.jpg"),
            "the marker and extension survive; the stem is what gives way: {renamed}"
        );
    }

    #[test]
    fn a_multibyte_stem_is_not_cut_mid_character() {
        let long = format!("{}.jpg", "é".repeat(120));
        let renamed = RelPath::parse(&long).unwrap().conflict_name("aabbccdd");

        assert!(RelPath::parse(renamed.as_str()).is_ok());
        assert!(renamed.file_name().len() <= MAX_COMPONENT);
        assert!(renamed.as_str().ends_with(".conflict-aabbccdd.jpg"));
    }

    #[test]
    fn under_combines_a_directory_and_a_name() {
        assert_eq!(RelPath::under("", "a.jpg").unwrap().as_str(), "a.jpg");
        assert_eq!(
            RelPath::under("raw", "a.jpg").unwrap().as_str(),
            "raw/a.jpg"
        );
        assert_eq!(
            RelPath::under("/raw/", "a.jpg").unwrap().as_str(),
            "raw/a.jpg",
            "surrounding slashes are a typing habit, not a meaning"
        );
        assert!(
            RelPath::under("..", "a.jpg").is_err(),
            "the combination is validated, not just the name"
        );
    }
}
