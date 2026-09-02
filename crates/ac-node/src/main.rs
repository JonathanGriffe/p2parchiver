use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use libp2p::{Multiaddr, PeerId};

use ac_net::config::Paths;
use ac_node::{DEFAULT_LOG, cmd};

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

    /// Enrol with a server, using the token its operator gave you.
    Join {
        /// The invite token, as `ac-server invite new` printed it.
        token: String,
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

    #[command(subcommand)]
    Import(ImportCommand),
}

#[derive(Subcommand)]
enum ImportCommand {
    /// What this build can import from, and what each source needs to be told.
    Available { source: Option<String> },

    #[command(subcommand)]
    Source(ImportSourceCommand),

    /// One implementation's settings, shared by every source built from it.
    #[command(subcommand)]
    Settings(SettingsCommand),

    /// Scan one source now, whatever its cadence says.
    Scan { source: String },

    /// Import folders in one go: add them, scan them, and bring them in.
    From {
        #[arg(required = true, value_name = "PATH")]
        paths: Vec<PathBuf>,
        /// What to file them under. Defaults to the name of the folder itself.
        #[arg(long)]
        name: Option<String>,
    },

    /// Bring in what the sources are owed, without waiting for the daemon.
    Fetch {
        /// Stop after this many files.
        #[arg(long)]
        limit: Option<usize>,
    },

    /// What is waiting to be sorted.
    List {
        /// Every page of it, rather than the first.
        #[arg(long)]
        all: bool,
    },

    /// File one into a group.
    Sort {
        hash: String,
        group: String,
        /// Everything that came from the same source folder.
        #[arg(long)]
        folder: bool,
    },

    /// Throw one away, permanently.
    Drop {
        hash: String,
        #[arg(long)]
        folder: bool,
    },
}

#[derive(Subcommand)]
enum ImportSourceCommand {
    Add {
        #[arg(long)]
        source: String,
        #[arg(long)]
        name: String,
        /// Answer one of the source's fields. Repeatable: `--set path=~/Pictures`.
        #[arg(long = "set", value_name = "KEY=VALUE")]
        set: Vec<String>,
    },
    List,
    Remove {
        source: String,
    },
}

#[derive(Subcommand)]
enum SettingsCommand {
    Show {
        source: String,
    },
    Set {
        source: String,
        key: String,
        value: String,
    },
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
        Command::Join { token, username } => cmd::join::run(&paths, &token, &username),
        Command::Run { dial } => cmd::run::run(&paths, &dial),
        Command::Probe { peer } => cmd::probe::run(&paths, peer),
        Command::Peer(PeerCommand::Add { peer, label }) => cmd::peer::add(&paths, &peer, &label),
        Command::Peer(PeerCommand::Remove { peer }) => cmd::peer::remove(&paths, &peer),
        Command::Peer(PeerCommand::List) => cmd::peer::list(&paths),
        Command::Peer(PeerCommand::Status) => cmd::peer::status(&paths),
        Command::Group(GroupCommand::Create { name }) => cmd::group::create(&paths, &name),
        Command::Group(GroupCommand::List) => cmd::group::list(&paths),
        Command::Group(GroupCommand::Show { group, log }) => cmd::group::show(&paths, &group, log),
        Command::Group(GroupCommand::Add { group, peer }) => cmd::group::add(&paths, &group, &peer),
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
        Command::File(FileCommand::Remove { group, path }) => {
            cmd::file::remove(&paths, &group, &path)
        }
        Command::File(FileCommand::Verify { group }) => cmd::file::verify(&paths, &group),
        Command::Import(ImportCommand::Available { source }) => {
            cmd::import::available(source.as_deref())
        }
        Command::Import(ImportCommand::Source(ImportSourceCommand::Add { source, name, set })) => {
            cmd::import::source_add(&paths, &source, &name, &set)
        }
        Command::Import(ImportCommand::Source(ImportSourceCommand::List)) => {
            cmd::import::source_list(&paths)
        }
        Command::Import(ImportCommand::Source(ImportSourceCommand::Remove { source })) => {
            cmd::import::source_remove(&paths, &source)
        }
        Command::Import(ImportCommand::Settings(SettingsCommand::Show { source })) => {
            cmd::import::settings_show(&paths, &source)
        }
        Command::Import(ImportCommand::Settings(SettingsCommand::Set { source, key, value })) => {
            cmd::import::settings_set(&paths, &source, &key, &value)
        }
        Command::Import(ImportCommand::Scan { source }) => cmd::import::scan(&paths, &source),
        Command::Import(ImportCommand::From {
            paths: picked,
            name,
        }) => cmd::import::from(&paths, &picked, name.as_deref()),
        Command::Import(ImportCommand::Fetch { limit }) => cmd::import::fetch(&paths, limit),
        Command::Import(ImportCommand::List { all }) => cmd::import::list(&paths, all),
        Command::Import(ImportCommand::Sort {
            hash,
            group,
            folder,
        }) => cmd::import::sort(&paths, &hash, &group, folder),
        Command::Import(ImportCommand::Drop { hash, folder }) => {
            cmd::import::drop(&paths, &hash, folder)
        }
    }
}

/// Logs go to stderr so that stdout stays parseable for commands that print an id or an
/// address. `RUST_LOG` controls the level; the default keeps libp2p's internals quiet.
fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(DEFAULT_LOG));

    fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
}
