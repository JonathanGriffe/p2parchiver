use ac_files::{Content, Files};
use ac_groups::id::GroupId;
use ac_groups::store::{GroupRow, Groups, Resolved};
use ac_net::attest;
use ac_net::config::{Config, Paths};
use ac_net::identity::Identity;
use anyhow::{Context, Result, anyhow};

pub mod file;
pub mod format;
pub mod group;
pub mod peer;

pub use crate::directory::{Known, Source};

pub fn now() -> i64 {
    attest::now()
}

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
pub fn open_files(paths: &Paths, identity: &Identity) -> Result<(Files, Content)> {
    let db = paths.db_file();
    let files = Files::open(&db, identity.peer_id())
        .with_context(|| format!("opening the file index at {}", db.display()))?;

    let config = Config::load(&paths.config_file())
        .with_context(|| format!("reading the config at {}", paths.config_file().display()))?;

    Ok((files, Content::new(config.storage_root(paths))))
}

/// Turn what the user typed into one group, or explain why it was not one.
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
