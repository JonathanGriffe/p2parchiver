//! Turning a group's name into a directory name.
//!
//! A group name is display text. `ac_groups::chain::check_name` caps its length and requires
//! it non-empty, and that is the whole rule — no character is excluded, and the name reaches
//! this node inside a log signed by *someone else's* admin. So it cannot be used as a path
//! component as it stands: `../../.ssh` is a legal group name.
//!
//! Sanitising is lossy on purpose. Two different names can produce one directory name, and
//! that is fine, because nothing here decides the final directory — [`crate::store::Files`]
//! does, by trying this and adding a suffix until it is unused, then writing the answer down.
//! This function only has to produce something safe and recognisable.

/// Longest directory name to produce, in bytes, leaving room for a `-<hex>` suffix.
const MAX_DIRNAME: usize = 128;

/// A safe directory name for `name`, or `None` if nothing usable survives.
///
/// `None` means the caller should fall back to the group's id, which is always safe. That is
/// better than inventing a placeholder here: the store already has an unambiguous name for
/// the group, and this module has no business choosing one.
pub fn sanitize(name: &str) -> Option<String> {
    let mut out = String::with_capacity(name.len());

    for c in name.chars() {
        // Separators and control characters become `_`. Everything else survives, including
        // spaces and non-ASCII: this is an archive people browse, and mangling `Noël` into
        // `No_l` would be a worse outcome than the shell quoting it needs.
        if c == '/' || c == '\\' || c.is_control() {
            out.push('_');
        } else {
            out.push(c);
        }
    }

    let trimmed = trim_edges(&out);
    if trimmed.is_empty() {
        return None;
    }

    let mut result = trimmed.to_owned();
    if result.len() > MAX_DIRNAME {
        // Truncate on a character boundary, then re-trim: cutting mid-name can expose a
        // trailing dot or space that was harmless in the middle.
        let mut cut = MAX_DIRNAME;
        while cut > 0 && !result.is_char_boundary(cut) {
            cut -= 1;
        }
        result.truncate(cut);
        result = trim_edges(&result).to_owned();
        if result.is_empty() {
            return None;
        }
    }

    Some(result)
}

/// Strip whitespace and dots from both ends, repeatedly.
///
/// Repeatedly because one pass is not a fixed point: `". . ."` loses its outer dots, then its
/// spaces, and leaves a single `.` — which is not a spare directory name but the *current*
/// one. Alternating characters are exactly the case a single pass gets wrong.
fn trim_edges(raw: &str) -> &str {
    let mut s = raw;
    loop {
        let next = s.trim().trim_matches('.');
        if next == s {
            return s;
        }
        s = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ordinary_name_is_left_alone() {
        assert_eq!(sanitize("holiday").as_deref(), Some("holiday"));
        assert_eq!(sanitize("Family Photos").as_deref(), Some("Family Photos"));
        assert_eq!(sanitize("Noël 2024").as_deref(), Some("Noël 2024"));
    }

    #[test]
    fn a_traversal_attempt_cannot_survive() {
        // The case this module exists for: a remote admin's chosen name.
        for name in ["../../.ssh", "..", ".", "./.", "../"] {
            match sanitize(name) {
                None => {}
                Some(dir) => {
                    assert!(!dir.contains('/'), "{name:?} kept a separator: {dir:?}");
                    assert_ne!(dir, "..", "{name:?} survived as a traversal");
                    assert_ne!(dir, ".");
                    assert!(!dir.starts_with('.'), "{name:?} stayed hidden: {dir:?}");
                }
            }
        }
    }

    #[test]
    fn separators_and_control_characters_become_underscores() {
        assert_eq!(sanitize("a/b").as_deref(), Some("a_b"));
        assert_eq!(sanitize("a\\b").as_deref(), Some("a_b"));
        assert_eq!(sanitize("a\0b").as_deref(), Some("a_b"));
        assert_eq!(sanitize("a\nb").as_deref(), Some("a_b"));
    }

    #[test]
    fn nothing_usable_gives_nothing() {
        // Only names that leave *no* character behind. A name of control characters is not
        // one of these: it becomes underscores, which is safe and is a directory a person can
        // still type. `None` is reserved for having nothing at all to work with.
        for name in ["", "   ", "...", ". . .", " . . "] {
            assert_eq!(sanitize(name), None, "{name:?} should yield no name");
        }
        assert_eq!(sanitize("\0").as_deref(), Some("_"));
    }

    #[test]
    fn a_long_name_is_cut_on_a_character_boundary() {
        // A group name is capped at 64 bytes today, but this must not depend on that.
        let name = "é".repeat(200);
        let dir = sanitize(&name).unwrap();

        assert!(dir.len() <= MAX_DIRNAME);
        assert!(dir.chars().all(|c| c == 'é'), "cut mid-character: {dir:?}");
    }

    #[test]
    fn the_result_never_starts_or_ends_with_a_dot_or_space() {
        for name in [" spaced ", ".hidden", "trailing.", " .both. "] {
            let dir = sanitize(name).unwrap();
            assert!(!dir.starts_with('.') && !dir.ends_with('.'), "{dir:?}");
            assert_eq!(dir.trim(), dir, "{dir:?}");
        }
    }
}
