#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod cmd;
mod daemon;
mod invite;
mod store;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use libp2p::{Multiaddr, PeerId};

use ac_net::config::Paths;

/// The service listener's port: relay, rendezvous, AutoNAT, enrolled peers only.
pub const SERVICE_PORT: u16 = 4001;

/// The enrolment listener's port: `/ac/enroll/3.0.0` only, open to anyone.
pub const ENROLL_PORT: u16 = 4002;

/// Kept distinct from the client's directory so both can run on one host.
const APP: &str = "archiverclient-server";
const HOME_ENV: &str = "AC_SERVER_HOME";

#[derive(Parser)]
#[command(
    name = "ac-server",
    version,
    about = "archiverclient rendezvous and relay server"
)]
struct Cli {
    /// Use this directory for config and data instead of the per-OS defaults.
    #[arg(long, global = true, env = "AC_SERVER_HOME")]
    home: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create this server's identity and database.
    Init,

    /// Run the server.
    Run,

    /// Mint and inspect invite tokens.
    #[command(subcommand)]
    Invite(InviteCommand),

    /// Inspect and revoke enrolled clients.
    #[command(subcommand)]
    Client(ClientCommand),
}

#[derive(Subcommand)]
enum InviteCommand {
    /// Mint a single-use invite token. Shown once and not recoverable.
    New {
        /// What this invite is for, e.g. the device it will be used on.
        #[arg(long)]
        label: String,
        /// Hours until the invite expires.
        #[arg(long, default_value_t = 24)]
        ttl_hours: i64,
        /// The enrolment address to put in the token, if `external` in config.toml does not
        /// already say where this server is reached.
        #[arg(long)]
        address: Option<Multiaddr>,
    },
    /// Show every invite and whether it has been used.
    List,
}

#[derive(Subcommand)]
enum ClientCommand {
    /// Show every enrolled client.
    List,
    /// Withdraw a client's access to this server.
    Revoke { peer: PeerId },
    /// Restore a client that was revoked.
    ///
    /// Needed because a revoked client cannot reach enrolment either, so issuing them a
    /// fresh invite does not bring them back.
    Unrevoke { peer: PeerId },
}

fn main() -> Result<()> {
    init_tracing();

    let cli = Cli::parse();
    let paths = match &cli.home {
        Some(root) => Paths::rooted_at(root),
        None => Paths::discover(APP, HOME_ENV)?,
    };

    match cli.command {
        Command::Init => cmd::init::run(&paths),
        Command::Run => cmd::run::run(&paths),
        Command::Invite(InviteCommand::New {
            label,
            ttl_hours,
            address,
        }) => cmd::invite::new(&paths, &label, ttl_hours, address.as_ref()),
        Command::Invite(InviteCommand::List) => cmd::invite::list(&paths),
        Command::Client(ClientCommand::List) => cmd::client::list(&paths),
        Command::Client(ClientCommand::Revoke { peer }) => cmd::client::revoke(&paths, &peer),
        Command::Client(ClientCommand::Unrevoke { peer }) => cmd::client::unrevoke(&paths, &peer),
    }
}

/// Logs go to stderr so stdout stays parseable for commands that print a peer id or an
/// invite token.
fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("ac_server=info,ac_net=info,libp2p=warn"));

    fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
}
