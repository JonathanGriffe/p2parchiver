pub mod client;
pub mod init;
pub mod invite;
pub mod run;

use anyhow::{Context, Result};

use ac_net::config::Paths;

use crate::store::Store;

/// Open the server database, shared by every subcommand.
pub fn open_store(paths: &Paths) -> Result<Store> {
    let path = paths.db_file();
    Store::open(&path).with_context(|| format!("opening the server database at {}", path.display()))
}
