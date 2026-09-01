use crate::source::{Result, SourceError};

/// One thing a source needs to be told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field {
    /// What it is called in the stored answers.
    pub key: &'static str,
    /// What a form calls it.
    pub label: &'static str,
    pub kind: FieldKind,
    pub required: bool,
}

/// Enough to lay out a form, and to keep a secret out of a log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    Text,
    Path,
    /// One or more paths, so the key repeats.
    Paths,
    /// Never read back: shown as set or unset, replaced rather than displayed.
    Secret,
    Toggle,
}

impl Field {
    pub const fn text(key: &'static str, label: &'static str) -> Self {
        Self::of(key, label, FieldKind::Text)
    }

    pub const fn path(key: &'static str, label: &'static str) -> Self {
        Self::of(key, label, FieldKind::Path)
    }

    pub const fn paths(key: &'static str, label: &'static str) -> Self {
        Self::of(key, label, FieldKind::Paths)
    }

    pub const fn secret(key: &'static str, label: &'static str) -> Self {
        Self::of(key, label, FieldKind::Secret)
    }

    pub const fn toggle(key: &'static str, label: &'static str) -> Self {
        Self::of(key, label, FieldKind::Toggle)
    }

    pub const fn optional(self) -> Self {
        Self {
            key: self.key,
            label: self.label,
            kind: self.kind,
            required: false,
        }
    }

    const fn of(key: &'static str, label: &'static str, kind: FieldKind) -> Self {
        Self {
            key,
            label,
            kind,
            required: true,
        }
    }
}

/// The answers to a source's declared fields, as stored.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Fields(Vec<(String, String)>);

impl Fields {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, key: &str, value: &str) -> &mut Self {
        self.0.push((key.to_owned(), value.to_owned()));
        self
    }

    /// The first answer for `key`.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.all(key).next()
    }

    /// Every answer for `key`, in the order they were given.
    pub fn all<'a>(&'a self, key: &str) -> impl Iterator<Item = &'a str> {
        self.0
            .iter()
            .filter(move |(k, _)| k == key)
            .map(|(_, value)| value.as_str())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// One `key = value` line per answer, readable in the database and typeable by hand.
    pub fn encode(&self) -> String {
        self.0
            .iter()
            .map(|(key, value)| format!("{key} = {}\n", escape(value)))
            .collect()
    }

    pub fn parse(raw: &str) -> Result<Self> {
        let mut fields = Self::new();
        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(SourceError::Failed(format!(
                    "{line:?} is not a `key = value` line"
                )));
            };
            fields.push(key.trim(), &unescape(value.trim()));
        }
        Ok(fields)
    }

    pub fn check(&self, implementation: &'static str, declared: &[Field]) -> Result<()> {
        for (key, _) in &self.0 {
            if !declared.iter().any(|field| field.key == key) {
                return Err(SourceError::config(
                    implementation,
                    format!("it has nothing called {key:?}"),
                ));
            }
        }
        for field in declared {
            if field.required && self.get(field.key).is_none_or(str::is_empty) {
                return Err(SourceError::config(
                    implementation,
                    format!("{} is required", field.label),
                ));
            }
        }
        Ok(())
    }
}

fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\n', "\\n")
}

fn unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('\\') => out.push('\\'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const DECLARED: &[Field] = &[
        Field::paths("path", "Folders"),
        Field::secret("token", "Token").optional(),
    ];

    #[test]
    fn answers_survive_being_written_down_and_read_back() {
        let mut fields = Fields::new();
        fields
            .push("path", "/home/a/one")
            .push("path", "/home/a/two")
            .push("token", "s3cret");

        let back = Fields::parse(&fields.encode()).unwrap();
        assert_eq!(back, fields);
        assert_eq!(back.get("path"), Some("/home/a/one"));
        assert_eq!(back.all("path").count(), 2, "a repeated key keeps both");
    }

    #[test]
    fn a_value_with_a_newline_or_a_backslash_comes_back_whole() {
        // Nothing types one, but a pasted key might carry one, and losing the rest of the
        // config to it would be silent.
        let mut fields = Fields::new();
        fields.push("token", "line\nnext\\slash = not a key");

        let back = Fields::parse(&fields.encode()).unwrap();
        assert_eq!(back, fields);
        assert_eq!(back.encode().lines().count(), 1);
    }

    #[test]
    fn a_config_can_be_typed_by_hand() {
        let fields = Fields::parse("  path = /home/a/pictures  \n\n").unwrap();
        assert_eq!(fields.get("path"), Some("/home/a/pictures"));
    }

    #[test]
    fn a_line_that_answers_nothing_is_refused() {
        assert!(Fields::parse("just some words").is_err());
    }

    #[test]
    fn a_missing_required_answer_is_refused_by_name() {
        let err = Fields::new().check("folder", DECLARED).unwrap_err();
        assert!(err.to_string().contains("Folders"), "{err}");
    }

    #[test]
    fn an_optional_answer_can_be_left_out() {
        let mut fields = Fields::new();
        fields.push("path", "/home/a");
        fields.check("folder", DECLARED).unwrap();
    }

    #[test]
    fn a_key_nothing_declared_is_refused_rather_than_ignored() {
        let mut fields = Fields::new();
        fields.push("path", "/home/a").push("recursive", "true");

        let err = fields.check("folder", DECLARED).unwrap_err();
        assert!(err.to_string().contains("recursive"), "{err}");
    }
}
