//! A path inside a group, validated once and carried as a type.
//!
//! Every path a user types, and in the next milestone every path a peer sends, becomes one of
//! these before anything joins it to a directory. The alternative — checking at each call site
//! — is one forgotten check away from writing outside the storage root, and the check is not
//! the sort of thing a reviewer notices missing.
//!
//! The rules are deliberately strict rather than clever. Nothing here tries to *repair* a bad
//! path: a caller that meant `a/../b` can say `b`, and silently rewriting it would mean the
//! path stored differs from the path asked for.

use std::fmt;
use std::path::{Path, PathBuf};

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
            // A NUL truncates the path at the syscall boundary, so a name containing one is
            // not the name it appears to be. The other control characters are refused for a
            // weaker reason — they make a path unquotable in a terminal — but neither belongs
            // in an archive.
            if let Some(bad) = component.chars().find(|c| c.is_control()) {
                return Err(PathError::Control { found: bad });
            }
        }

        Ok(Self(raw.to_owned()))
    }

    /// Join this path beneath `dir`.
    ///
    /// Safe by construction: every component was proved to be an ordinary name, so the result
    /// cannot climb out of `dir`. It may still traverse a **symlink** placed inside the
    /// storage root by something other than this crate, which is why `content` resolves the
    /// final location before writing rather than trusting this alone.
    pub fn join_under(&self, dir: &Path) -> PathBuf {
        let mut out = dir.to_path_buf();
        for component in self.0.split('/') {
            out.push(component);
        }
        out
    }

    /// The last component — the file's own name.
    pub fn file_name(&self) -> &str {
        self.0.rsplit('/').next().unwrap_or(&self.0)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Build a path from a directory prefix and a name, validating the result.
    ///
    /// `dir` may be empty, meaning the group's root. Used by `ac file add --to`, where the
    /// two halves come from different places and only their combination is meaningful.
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
