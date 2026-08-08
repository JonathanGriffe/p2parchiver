//! `ac` — the client CLI.
//!
//! Thin by design: parse a command, load the node's paths and identity, and hand off to
//! `ac-net`. Protocol logic belongs in `ac-net`, not here.

// The workspace warns on unwrap/expect because a panic in the event loop takes the whole
// daemon down. In tests a panic *is* the failure report, so let them through.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod cmd;
mod contacts;
mod daemon;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use libp2p::{Multiaddr, PeerId};

use ac_net::config::Paths;

/// Application name used for the per-OS config and data directories.
const APP: &str = "archiverclient";

/// Set this to a directory to override both, which is how several nodes run on one host.
const HOME_ENV: &str = "AC_HOME";

#[derive(Parser)]
#[command(name = "ac", version, about = "archiverclient node")]
struct Cli {
    /// Use this directory for config and data instead of the per-OS defaults.
    #[arg(long, global = true, env = "AC_HOME")]
    home: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show this node's peer id, generating an identity on first run.
    Id,

    /// Enrol with a server by redeeming an invite code.
    Join {
        /// The server's address, ending in /p2p/<peer-id>.
        server: Multiaddr,
        /// The invite code, as issued by `ac-server invite new`.
        code: String,
    },

    /// Run the node.
    Run {
        /// Dial this address on startup. Repeatable.
        #[arg(long, value_name = "MULTIADDR")]
        dial: Vec<Multiaddr>,
    },

    /// Check reachability, the relay reservation, and how a peer is reached.
    ///
    /// Starts a node of its own — it does not inspect a running `ac run`.
    Probe {
        /// Also dial this peer and report whether the connection ended up direct.
        #[arg(long)]
        peer: Option<PeerId>,
    },

    /// Manage the contact list: peers this node looks for.
    ///
    /// Contacts do not control who may connect. Anyone may connect; what they can
    /// obtain is decided per group.
    #[command(subcommand)]
    Peer(PeerCommand),
}

#[derive(Subcommand)]
enum PeerCommand {
    /// Add a peer to look for, or relabel one already present.
    Add {
        peer: PeerId,
        /// The name you will refer to this peer by.
        #[arg(long)]
        label: String,
    },
    /// Stop looking for a peer.
    Remove { peer: PeerId },
    /// Show every contact.
    List,
}

fn main() -> Result<()> {
    init_tracing();

    let cli = Cli::parse();
    let paths = match &cli.home {
        Some(root) => Paths::rooted_at(root),
        None => Paths::discover(APP, HOME_ENV)?,
    };

    match cli.command {
        Command::Id => cmd::id::run(&paths),
        Command::Join { server, code } => cmd::join::run(&paths, &server, &code),
        Command::Run { dial } => cmd::run::run(&paths, &dial),
        Command::Probe { peer } => cmd::probe::run(&paths, peer),
        Command::Peer(PeerCommand::Add { peer, label }) => cmd::peer::add(&paths, &peer, &label),
        Command::Peer(PeerCommand::Remove { peer }) => cmd::peer::remove(&paths, &peer),
        Command::Peer(PeerCommand::List) => cmd::peer::list(&paths),
    }
}

/// Logs go to stderr so that stdout stays parseable for commands that print an id or an
/// address. `RUST_LOG` controls the level; the default keeps libp2p's internals quiet.
fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("ac=info,ac_net=info,libp2p=warn"));

    fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
}
