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

/// Application name used for the per-OS data directory, which is a node's whole home.
const APP: &str = "archiverclient";

/// Set this to a directory to override it, which is how several nodes run on one host.
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
    Id,

    Join {
        server: Multiaddr,
        code: String,
        #[arg(long)]
        username: String,
    },

    Run {
        #[arg(long, value_name = "MULTIADDR")]
        dial: Vec<Multiaddr>,
    },

    Probe {
        #[arg(long)]
        peer: Option<PeerId>,
    },

    #[command(subcommand)]
    Peer(PeerCommand),

    #[command(subcommand)]
    Group(GroupCommand),

    #[command(subcommand)]
    File(FileCommand),
}

#[derive(Subcommand)]
enum PeerCommand {
    Add {
        peer: PeerId,
        #[arg(long)]
        label: String,
    },
    Remove {
        peer: PeerId,
    },
    List,
    Status,
}

#[derive(Subcommand)]
enum GroupCommand {
    Create {
        #[arg(long)]
        name: String,
    },
    List,
    Show {
        group: String,
        #[arg(long)]
        log: bool,
    },
    Add {
        group: String,
        peer: PeerId,
        #[arg(long)]
        username: Option<String>,
    },
    Remove {
        group: String,
        peer: PeerId,
    },
    Accept {
        group: String,
    },
    #[command(alias = "decline")]
    Leave {
        group: String,
    },
    Forget {
        group: String,
    },
}

#[derive(Subcommand)]
enum FileCommand {
    Add {
        group: String,
        #[arg(required = true)]
        source: Vec<PathBuf>,
        #[arg(long)]
        to: Option<String>,
        #[arg(long, conflicts_with = "to")]
        r#as: Option<String>,
        #[arg(long)]
        recursive: bool,
        #[arg(long)]
        force: bool,
    },
    List {
        group: String,
        prefix: Option<String>,
        #[arg(long)]
        removed: bool,
    },
    Show {
        group: String,
        path: String,
    },
    Get {
        group: String,
        path: String,
    },
    Remove {
        group: String,
        path: String,
    },
    Verify {
        group: String,
    },
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
