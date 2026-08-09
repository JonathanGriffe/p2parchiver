//! `ac-server` — the rendezvous and relay server.
//!
//! Thin by design, like `ac`: parse a command, own one small database, and hand the
//! swarm to `ac-net`. It never touches media, and it is never authoritative for group
//! membership — its only say is who may consume its own bandwidth.

// The workspace warns on unwrap/expect because a panic in the event loop takes the whole
// daemon down. In tests a panic *is* the failure report, so let them through.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod cmd;
mod daemon;
mod invite;
mod store;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use libp2p::PeerId;

use ac_net::config::Paths;

/// The service listener's port: relay, rendezvous, AutoNAT, enrolled peers only.
///
/// **Fixed, and that is load-bearing.** A client is told this address once, when it
/// enrols, and stores it permanently — there is no address refresh and no re-enrolment
/// without a fresh invite. An ephemeral port would orphan every enrolled client the first
/// time this server restarted. It is also the port an operator has to route, and a
/// firewall rule cannot name a port the OS picks at random.
pub const SERVICE_PORT: u16 = 4001;

/// The enrolment listener's port: `/ac/enroll/2.0.0` only, open to anyone.
///
/// Fixed for the step-earlier version of the same reason: this is the address that goes
/// into an invite the admin hands out.
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

    /// Mint and inspect invite codes.
    #[command(subcommand)]
    Invite(InviteCommand),

    /// Inspect and revoke enrolled clients.
    #[command(subcommand)]
    Client(ClientCommand),
}

#[derive(Subcommand)]
enum InviteCommand {
    /// Mint a single-use invite code. Shown once and not recoverable.
    New {
        /// What this invite is for, e.g. the device it will be used on.
        #[arg(long)]
        label: String,
        /// Hours until the code expires.
        #[arg(long, default_value_t = 24)]
        ttl_hours: i64,
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
        Command::Invite(InviteCommand::New { label, ttl_hours }) => {
            cmd::invite::new(&paths, &label, ttl_hours)
        }
        Command::Invite(InviteCommand::List) => cmd::invite::list(&paths),
        Command::Client(ClientCommand::List) => cmd::client::list(&paths),
        Command::Client(ClientCommand::Revoke { peer }) => cmd::client::revoke(&paths, &peer),
        Command::Client(ClientCommand::Unrevoke { peer }) => cmd::client::unrevoke(&paths, &peer),
    }
}

/// Logs go to stderr so stdout stays parseable for commands that print a peer id or an
/// invite code.
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
