//! `ac run` — start the node.

use anyhow::{Context, Result};
use libp2p::Multiaddr;

use ac_net::config::{Config, Paths};
use ac_net::identity::Identity;

use crate::daemon;

pub fn run(paths: &Paths, dial: &[Multiaddr]) -> Result<()> {
    let key_path = paths.identity_file();
    let (identity, _) = Identity::load_or_generate(&key_path)
        .with_context(|| format!("loading identity from {}", key_path.display()))?;

    let config_path = paths.config_file();
    let config = Config::load(&config_path)
        .with_context(|| format!("loading config from {}", config_path.display()))?;

    let runtime = tokio::runtime::Runtime::new().context("starting the tokio runtime")?;
    runtime.block_on(daemon::run(&identity, &config, paths, dial))
}
