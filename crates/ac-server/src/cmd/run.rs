use anyhow::{Context, Result};

use ac_net::config::{Config, Paths};
use ac_net::identity::Identity;

use crate::daemon;
use crate::store::Enrolled;

pub fn run(paths: &Paths) -> Result<()> {
    let key_path = paths.identity_file();
    let identity =
        Identity::load(&key_path).context("loading the server identity; run `ac-server init`")?;

    let config_path = paths.config_file();
    let config = Config::load(&config_path)
        .with_context(|| format!("loading config from {}", config_path.display()))?;

    let store = super::open_store(paths)?;
    let service_gate = Enrolled(super::open_store(paths)?);
    let enroll_gate = super::open_store(paths)?;

    let runtime = tokio::runtime::Runtime::new().context("starting the tokio runtime")?;
    runtime.block_on(daemon::run(
        &identity,
        &config,
        store,
        service_gate,
        enroll_gate,
    ))
}
