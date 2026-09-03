//! Importing: configuring a source, asking it what it has, and bringing the bytes in.
//!
//! One module per step, because that is the order they happen in and none of them calls
//! another — they meet at the ledger. What stays here is what all of them need: the ledger
//! itself, where unsorted bytes wait, and the one question the host can answer that the
//! importer cannot.

use ac_files::{Files, PathError, RelPath};
use ac_import::ledger::Ledger;
use ac_import::source::{Held, Result as SourceResult};
use ac_net::config::Paths;
use anyhow::{Context, Result};

pub mod backlog;
pub mod fetch;
pub mod scan;
pub mod sources;

#[cfg(test)]
pub(crate) mod fixtures;

pub use backlog::{
    Backlog, Filed, Inbox, Waiting, backlog, drop, drop_folder, find, forget, in_folder, sort,
    sort_folder, sweep_dropped, undo,
};
pub use fetch::{Brought, Fetched, Outcome, Pace, Pump, drain, pump};
pub use scan::{Scanned, pollable, scan, scan_with};
pub use sources::{
    Configured, Picked, Setting, add_source, available, from_folder, implementation, open_source,
    remove_source, set_setting, settings, sources, tidy,
};

/// Where imported files wait to be sorted. The leading dot is what keeps it out of the way of
/// a group: `sanitize` strips one, so no group directory can ever be called this.
pub const UNSORTED: &str = ".unsorted";

/// Where a file from `source_dir`'s `folder` sits under [`UNSORTED`].
pub(super) fn unsorted_path(
    source_dir: &str,
    folder: &str,
    name: &str,
) -> Result<RelPath, PathError> {
    let raw = match folder.trim_matches('/') {
        "" => format!("{source_dir}/{name}"),
        folder => format!("{source_dir}/{folder}/{name}"),
    };
    RelPath::parse(&raw).or_else(|_| RelPath::under(source_dir, name))
}

pub fn ledger(paths: &Paths) -> Result<Ledger> {
    let db = paths.db_file();
    Ledger::open(&db).with_context(|| format!("opening the import ledger at {}", db.display()))
}

/// What the host knows that the inbox cannot: whether a group already holds these bytes.
pub struct HeldHere<'a>(pub &'a Files);

impl Held for HeldHere<'_> {
    fn held(&self, hash: &str) -> SourceResult<bool> {
        Ok(self.0.held_anywhere(hash).unwrap_or(false))
    }
}
