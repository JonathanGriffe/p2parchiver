#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod autostart;
mod groups;
mod log;
mod node;
mod selection;
mod tray;
mod view;
mod work;

mod ui {
    #![allow(clippy::all, clippy::unwrap_used, clippy::expect_used)]
    slint::include_modules!();
}

use std::path::PathBuf;

use ac_net::config::{Config, Paths};
use ac_node::ops;
use ac_node::ops::lock::NodeLock;
use anyhow::{Context, Result};
use clap::Parser;
use slint::ComponentHandle;

use crate::ui::MainWindow;

/// Matches `ac`, so both halves of the app find the same home.
const APP: &str = "archiverclient";
const HOME_ENV: &str = "AC_HOME";

#[derive(Parser)]
#[command(name = "ac-desktop", version, about = "archiverclient, with a window")]
struct Cli {
    /// Use this directory for config and data instead of the per-OS defaults.
    #[arg(long, env = "AC_HOME")]
    home: Option<PathBuf>,
    #[arg(long)]
    headless: bool,

    /// Start in the tray with no window. What the autostart entry uses, so logging in does
    /// not put a window in front of you.
    #[arg(long)]
    background: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let paths = match &cli.home {
        Some(root) => Paths::rooted_at(root),
        None => Paths::discover(APP, HOME_ENV)?,
    };

    let _logging = log::init(&paths, cli.headless)?;

    let _lock = NodeLock::take(&paths)?;

    // Cheaper than explaining why autostart quietly stopped working after a rebuild.
    if let Err(e) = autostart::repair() {
        tracing::warn!(error = %e, "could not check the autostart entry");
    }

    // No window, so nothing needs the main thread and the daemon can have it.
    if cli.headless {
        tracing::info!("running headless");
        return node::run_here(paths);
    }

    let mut node = node::Node::start(paths.clone())?;

    let window = MainWindow::new().context("creating the window")?;
    describe_node(&window, &paths)?;

    let _tray = tray::spawn(window.as_weak());

    let live = _tray.as_ref().map(tray::Tray::live);
    window.window().on_close_requested(move || {
        if live.as_ref().is_none_or(|live| !live.get()) {
            // Nothing to reopen from, so closing the window is how you quit.
            if let Err(e) = slint::quit_event_loop() {
                tracing::warn!(error = %e, "could not stop the event loop");
            }
        }
        slint::CloseRequestResponse::HideWindow
    });

    let selection = selection::Selection::new();
    let nudge = work::poll(window.as_weak(), paths.clone(), selection.clone());
    groups::wire(&window, &paths, &selection, &nudge);

    if !cli.background || _tray.is_none() {
        window.show().context("showing the window")?;
    }

    slint::run_event_loop_until_quit().context("running the window")?;

    node.stop()
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
