use anyhow::{Context, Result};
use libp2p::Multiaddr;

use ac_net::config::Paths;

use crate::daemon;
use crate::ops;
use crate::ops::lock::NodeLock;

pub fn run(paths: &Paths, dial: &[Multiaddr]) -> Result<()> {
    // Before anything is opened: a second daemon on this home would share the identity and
    // the database with the first. Held until this function returns.
    let _lock = NodeLock::take(paths)?;

    let (identity, config) = ops::startup(paths)?;

    let runtime = tokio::runtime::Runtime::new().context("starting the tokio runtime")?;
    runtime.block_on(daemon::run(&identity, &config, paths, dial))
}
