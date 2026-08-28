#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod log;
mod node;
mod view;

mod ui {
    #![allow(clippy::all, clippy::unwrap_used, clippy::expect_used)]
    slint::include_modules!();
}

use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use ac_net::config::{Config, Paths};
use ac_node::ops;
use ac_node::ops::lock::NodeLock;
use anyhow::{Context, Result};
use clap::Parser;
use slint::{ComponentHandle, ModelRc, VecModel};

use crate::ui::{GroupRow, MainWindow, PeerRow};

/// Matches `ac`, so both halves of the app find the same home.
const APP: &str = "archiverclient";
const HOME_ENV: &str = "AC_HOME";

/// The snapshot is republished every 5s, so polling faster only costs a SQLite read.
const POLL: Duration = Duration::from_secs(2);

#[derive(Parser)]
#[command(name = "ac-desktop", version, about = "archiverclient, with a window")]
struct Cli {
    /// Use this directory for config and data instead of the per-OS defaults.
    #[arg(long, env = "AC_HOME")]
    home: Option<PathBuf>,
    #[arg(long)]
    headless: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let paths = match &cli.home {
        Some(root) => Paths::rooted_at(root),
        None => Paths::discover(APP, HOME_ENV)?,
    };

    let _logging = log::init(&paths, cli.headless)?;

    let _lock = NodeLock::take(&paths)?;

    // No window, so nothing needs the main thread and the daemon can have it.
    if cli.headless {
        tracing::info!("running headless");
        return node::run_here(paths);
    }

    let mut node = node::Node::start(paths.clone())?;

    let window = MainWindow::new().context("creating the window")?;
    describe_node(&window, &paths)?;

    let groups = Rc::new(VecModel::<GroupRow>::from(Vec::new()));
    let peers = Rc::new(VecModel::<PeerRow>::from(Vec::new()));
    window.set_groups(ModelRc::from(groups.clone()));
    window.set_peers(ModelRc::from(peers.clone()));

    let refresh = {
        let window = window.as_weak();
        let paths = paths.clone();
        move || {
            let Some(window) = window.upgrade() else {
                return;
            };
            match ops::peer::status(&paths) {
                Ok(report) => {
                    let storage = ops::file::storage(&paths).ok();
                    let snapshot = view::present(&report, storage.as_ref());
                    apply(&window, snapshot, &groups, &peers);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "could not read the node's status");
                    window.set_node_state(format!("could not read status: {e}").into());
                    window.set_running(false);
                }
            }
        }
    };

    refresh();
    let timer = slint::Timer::default();
    timer.start(slint::TimerMode::Repeated, POLL, refresh);

    window.run().context("running the window")?;

    node.stop()
}

fn apply(
    window: &MainWindow,
    snapshot: view::Snapshot,
    groups: &Rc<VecModel<GroupRow>>,
    peers: &Rc<VecModel<PeerRow>>,
) {
    window.set_running(snapshot.running);
    window.set_node_state(snapshot.node_state.into());
    window.set_storage(snapshot.storage.into());
    groups.set_vec(snapshot.groups);
    peers.set_vec(snapshot.peers);
}

/// The facts that do not change while the app is open.
fn describe_node(window: &MainWindow, paths: &Paths) -> Result<()> {
    let identity = ops::identity(paths)?;
    let config = Config::load(&paths.config_file()).unwrap_or_default();

    window.set_version(env!("CARGO_PKG_VERSION").into());
    window.set_peer_id(identity.peer_id().to_string().into());
    window.set_home(paths.root.display().to_string().into());
    window.set_storage_root(config.storage_root(paths).display().to_string().into());
    window.set_log_dir(log::dir(paths).display().to_string().into());
    Ok(())
}
