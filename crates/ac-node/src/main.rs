//! `ac` — the client CLI.
//!
//! Thin by design: parse a command, load the node's paths and identity, and hand off to
//! `ac-net`. Protocol logic belongs in `ac-net`, not here.

// The workspace warns on unwrap/expect because a panic in the event loop takes the whole
// daemon down. In tests a panic *is* the failure report, so let them through.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod blob;
mod cmd;
mod contacts;
mod daemon;
mod directory;
mod file_link;
mod group_link;
mod peer_link;
mod status;

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
        /// The server's address, ending in `/p2p/<peer-id>`.
        server: Multiaddr,
        /// The invite code, as issued by `ac-server invite new`.
        code: String,
        /// The name other peers will know you by. Must be free on this server.
        ///
        /// 3-32 characters: letters, digits, '-' and '_', starting with a letter or
        /// digit. It goes into the signed attestation this node shows other peers, so
        /// changing it later means enrolling again with a fresh invite.
        #[arg(long)]
        username: String,
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

    /// Manage groups: who this node shares with.
    ///
    /// A group is a signed log, not a local list. Only the node that created a group can
    /// change its membership — and only you can decide whether you take part in it.
    #[command(subcommand)]
    Group(GroupCommand),

    /// Manage the files a group holds on this node.
    ///
    /// Content lives under the storage root, one directory per group. Nothing here talks to
    /// the network: a file is added locally and shared later.
    #[command(subcommand)]
    File(FileCommand),
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
    /// Show what the running node is waiting on, per group and per peer.
    ///
    /// Reads a snapshot the daemon publishes; it does not connect to anything.
    Status,
}

#[derive(Subcommand)]
enum GroupCommand {
    /// Create a group. This node becomes its sole, permanent admin.
    Create {
        #[arg(long)]
        name: String,
    },
    /// Show every group this node holds.
    List,
    /// Show one group's members, and optionally its whole log.
    Show {
        /// A group id, a unique prefix of one, or an exact name.
        group: String,
        /// Also print every entry in the log.
        #[arg(long)]
        log: bool,
    },
    /// Invite a peer. Admin only.
    Add {
        group: String,
        peer: PeerId,
        /// What to call them. Defaults to their contact label if they have one.
        #[arg(long)]
        username: Option<String>,
    },
    /// Remove a member. Admin only.
    Remove { group: String, peer: PeerId },
    /// Take part in a group you have been invited to, or rejoin one you left.
    Accept { group: String },
    /// Stop taking part, and tell the others. Aliased as `decline` for an invitation.
    #[command(alias = "decline")]
    Leave { group: String },
    /// Drop a group from this node only, telling nobody.
    Forget { group: String },
}

#[derive(Subcommand)]
enum FileCommand {
    /// Copy files into a group. Directories need --recursive.
    Add {
        /// A group id, a unique prefix of one, or an exact name.
        group: String,
        /// One or more files, or directories with --recursive.
        #[arg(required = true)]
        source: Vec<PathBuf>,
        /// Directory inside the group to put them in. Defaults to its root.
        #[arg(long)]
        to: Option<String>,
        /// Exact path inside the group for a single source. Not with --to.
        #[arg(long, conflicts_with = "to")]
        r#as: Option<String>,
        /// Add what is inside a directory, keeping its shape.
        #[arg(long)]
        recursive: bool,
        /// Replace a path that already holds different content.
        #[arg(long)]
        force: bool,
    },
    /// Show the files in a group.
    List {
        group: String,
        /// Only paths starting with this.
        prefix: Option<String>,
        /// Include files that have been removed.
        #[arg(long)]
        removed: bool,
    },
    /// Show one file's details.
    Show { group: String, path: String },
    /// Ask for a file's bytes from whoever in the group holds them.
    Get { group: String, path: String },
    /// Remove a file: delete its bytes, and stop offering it.
    Remove { group: String, path: String },
    /// Check the index against what is actually on disk.
    Verify { group: String },
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
        Command::Join {
            server,
            code,
            username,
        } => cmd::join::run(&paths, &server, &code, &username),
        Command::Run { dial } => cmd::run::run(&paths, &dial),
        Command::Probe { peer } => cmd::probe::run(&paths, peer),
        Command::Peer(PeerCommand::Add { peer, label }) => cmd::peer::add(&paths, &peer, &label),
        Command::Peer(PeerCommand::Remove { peer }) => cmd::peer::remove(&paths, &peer),
        Command::Peer(PeerCommand::List) => cmd::peer::list(&paths),
        Command::Peer(PeerCommand::Status) => cmd::peer::status(&paths),
        Command::Group(GroupCommand::Create { name }) => cmd::group::create(&paths, &name),
        Command::Group(GroupCommand::List) => cmd::group::list(&paths),
        Command::Group(GroupCommand::Show { group, log }) => cmd::group::show(&paths, &group, log),
        Command::Group(GroupCommand::Add {
            group,
            peer,
            username,
        }) => cmd::group::add(&paths, &group, &peer, username.as_deref()),
        Command::Group(GroupCommand::Remove { group, peer }) => {
            cmd::group::remove(&paths, &group, &peer)
        }
        Command::Group(GroupCommand::Accept { group }) => cmd::group::accept(&paths, &group),
        Command::Group(GroupCommand::Leave { group }) => cmd::group::leave(&paths, &group),
        Command::Group(GroupCommand::Forget { group }) => cmd::group::forget(&paths, &group),
        Command::File(FileCommand::Add {
            group,
            source,
            to,
            r#as,
            recursive,
            force,
        }) => cmd::file::add(
            &paths,
            &group,
            &source,
            to.as_deref(),
            r#as.as_deref(),
            recursive,
            force,
        ),
        Command::File(FileCommand::List {
            group,
            prefix,
            removed,
        }) => cmd::file::list(&paths, &group, prefix.as_deref(), removed),
        Command::File(FileCommand::Show { group, path }) => cmd::file::show(&paths, &group, &path),
        Command::File(FileCommand::Get { group, path }) => cmd::file::get(&paths, &group, &path),
        Command::File(FileCommand::Remove { group, path }) => {
            cmd::file::remove(&paths, &group, &path)
        }
        Command::File(FileCommand::Verify { group }) => cmd::file::verify(&paths, &group),
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
