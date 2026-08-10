//! The subcommands, and the few things all of them need.
//!
//! Every command here opens `state.sqlite`, does its work, prints, and exits. None of them
//! talk to a running daemon: the database *is* the channel between the two, which is why the
//! stores insist on `BEGIN IMMEDIATE` and a busy timeout.
//!
//! The openers live here rather than in one command's module because two now need them —
//! `group` and `file` — and `ac-server` already puts its shared opener in the same place.

use ac_files::{Content, Files};
use ac_groups::id::GroupId;
use ac_groups::store::{GroupRow, Groups, Resolved};
use ac_net::attest;
use ac_net::config::{Config, Paths};
use ac_net::identity::Identity;
use anyhow::{Context, Result, anyhow};

pub mod file;
pub mod group;
pub mod id;
pub mod join;
pub mod peer;
pub mod probe;
pub mod run;

/// Unix seconds, for the `at` field of anything we sign or stamp. Advisory and never
/// validated — see `ac_groups::chain`.
pub fn now() -> i64 {
    attest::now()
}

/// This node's identity and its group store.
pub fn open(paths: &Paths) -> Result<(Identity, Groups)> {
    let key_path = paths.identity_file();
    let (identity, _) = Identity::load_or_generate(&key_path)
        .with_context(|| format!("loading identity from {}", key_path.display()))?;

    let db = paths.db_file();
    let groups = Groups::open(&db, identity.peer_id())
        .with_context(|| format!("opening the group store at {}", db.display()))?;

    Ok((identity, groups))
}

/// The file index, and the storage root it describes.
///
/// The root comes from the config, so it is read here rather than passed in: a command that
/// forgot to consult it would quietly use a different directory from the rest of the node.
pub fn open_files(paths: &Paths, identity: &Identity) -> Result<(Files, Content)> {
    let db = paths.db_file();
    let files = Files::open(&db, identity.peer_id())
        .with_context(|| format!("opening the file index at {}", db.display()))?;

    let config = Config::load(&paths.config_file())
        .with_context(|| format!("reading the config at {}", paths.config_file().display()))?;

    Ok((files, Content::new(config.storage_root(paths))))
}

/// Turn what the user typed into one group, or explain why it was not one.
///
/// Returns the row as well as the id: resolving already proved the group is there, and
/// handing back only an id would leave every caller re-reading it and re-handling a `None`
/// that cannot happen.
pub fn resolve(groups: &Groups, needle: &str) -> Result<(GroupId, GroupRow)> {
    match groups.resolve(needle).context("looking up the group")? {
        Resolved::One(id) => {
            let row = groups
                .get(id)
                .context("reading the group")?
                .ok_or_else(|| anyhow!("group {needle:?} vanished while being read"))?;
            Ok((id, row))
        }
        Resolved::None => Err(anyhow!(
            "no group matches {needle:?}; `ac group list` shows what this node holds"
        )),
        Resolved::Ambiguous(ids) => {
            let names: Vec<String> = ids.iter().map(|id| id.short()).collect();
            Err(anyhow!(
                "{needle:?} matches {} groups ({}); use a longer id",
                ids.len(),
                names.join(", ")
            ))
        }
    }
}
