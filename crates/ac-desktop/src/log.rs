use std::path::PathBuf;

use ac_net::config::Paths;
use anyhow::{Context, Result};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{Builder, Rotation};
use tracing_subscriber::EnvFilter;

pub const LOG_DIRNAME: &str = "logs";

pub fn dir(paths: &Paths) -> PathBuf {
    paths.root.join(LOG_DIRNAME)
}

pub fn init(paths: &Paths, to_stderr: bool) -> Result<WorkerGuard> {
    let dir = dir(paths);
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let appender = Builder::new()
        .rotation(Rotation::DAILY)
        .filename_prefix("ac-desktop")
        .filename_suffix("log")
        .max_log_files(7)
        .build(&dir)
        .with_context(|| format!("opening a log in {}", dir.display()))?;

    let (writer, guard) = tracing_appender::non_blocking(appender);
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(ac_node::DEFAULT_LOG));

    if to_stderr {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .with_target(false)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(writer)
            .with_ansi(false)
            .with_target(false)
            .init();
    }
    Ok(guard)
}
