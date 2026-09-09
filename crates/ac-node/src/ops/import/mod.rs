//! Importing: configuring a source, asking it what it has, and bringing the bytes in.
//!
//! One module per step, because that is the order they happen in and none of them calls
//! another — they meet at the ledger. What stays here is what all of them need: the ledger
//! itself, where unsorted bytes wait, and the one question the host can answer that the
//! importer cannot.

use std::path::Path;

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
    Backlog, Filed, Inbox, Waiting, adopt_unsorted, backlog, backlog_with, drop, drop_folder, find,
    forget, in_folder, sort, sort_folder, sweep_dropped, undo,
};
pub use fetch::{Brought, Fetched, Outcome, Pace, Pump, drain, pump};
pub use scan::{Scanned, pollable, scan, scan_with};
pub use sources::{
    Configured, Picked, Setting, add_source, authorize, available, from_folder, implementation,
    open_source, remove_source, set_setting, settings, settings_with, showing, sources,
    sources_with, stop_signing_in, tidy,
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

/// Bytes held by files imported and not yet sorted. Content this node is holding, so it
/// counts against the same budget peer transfers answer to, and it is part of what the
/// storage bar calls held.
pub fn unsorted_bytes(ledger: &Ledger) -> Result<u64> {
    ledger
        .unsorted_bytes()
        .context("measuring what is waiting to be sorted")
}

/// What the host knows that the inbox cannot: whether a group already holds these bytes.
pub struct HeldHere<'a>(pub &'a Files);

impl Held for HeldHere<'_> {
    fn held(&self, hash: &str) -> SourceResult<bool> {
        Ok(self.0.held_anywhere(hash).unwrap_or(false))
    }
}

pub(super) fn ledger_at(db: &Path) -> Result<Ledger> {
    Ledger::open(db).with_context(|| format!("opening the import ledger at {}", db.display()))
}

/// Start whatever each source needs running for as long as this node is.
///
/// A source that has to be *found* cannot answer "are you there?" by opening a socket every
/// time it is asked, so it declares something to run once and answers from what that learns.
/// Here rather than at the first scan because a phone that came home while nothing was
/// listening would be invisible until something else woke the question.
///
/// **A service that will not start is not a failed node.** It is logged and stepped over: the
/// source it belongs to will simply never be reachable, and every other source still works.
/// A listener that cannot bind must not be the reason a folder import stops happening.
pub fn start_services(paths: &Paths) {
    // Who this node is, for a source that has to be findable again after its address moves.
    // Not fatal if it cannot be read: a service that needs it will say so, and the ones that
    // do not are unaffected.
    let db = paths.db_file();
    let id = match node_id(paths) {
        Ok(id) => id,
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "could not read this node's id");
            String::new()
        }
    };

    let node = ac_import::registry::NodeInfo {
        db: &db,
        state: &paths.root,
        id: &id,
    };

    for entry in available().iter().filter(|entry| entry.serves()) {
        match entry.start(node) {
            Ok(()) => tracing::debug!(source = entry.name, "started its service"),
            Err(error) => tracing::warn!(
                source = entry.name,
                error = %error,
                "could not start this source's service; it will not be reachable"
            ),
        }
    }
}

/// This node's peer id, as a person would read it off the Status tab.
///
/// What a source puts in front of somebody so their other device can find this one again.
pub fn node_id(paths: &Paths) -> Result<String> {
    Ok(super::identity(paths)?.peer_id().to_string())
}
