//! `ac-server init` — create this server's identity, database and starter config.

use std::fs;

use anyhow::{Context, Result};

use ac_net::config::Paths;
use ac_net::identity::{Identity, Origin};

use crate::{ENROLL_PORT, SERVICE_PORT};

/// A starter `config.toml`, written on first init.
///
/// Hand-formatted rather than serialised, because `toml::to_string_pretty` cannot emit
/// comments and both port choices need explaining to whoever opens this file next.
fn starter_config() -> String {
    format!(
        r#"# archiverclient server configuration.

# The service listener: relay, rendezvous, AutoNAT. Only enrolled clients may connect.
#
# The port is FIXED on purpose. Clients learn this address once, at enrolment, and store
# it permanently — an ephemeral port would orphan every one of them on the next restart.
# This is the port to route or open in a firewall.
listen = [
    "/ip4/0.0.0.0/udp/{SERVICE_PORT}/quic-v1",
    "/ip4/0.0.0.0/tcp/{SERVICE_PORT}",
    "/ip6/::/udp/{SERVICE_PORT}/quic-v1",
    "/ip6/::/tcp/{SERVICE_PORT}",
]

# The enrolment listener: `/ac/enroll/2.0.0` and nothing else, open to anyone.
#
# Separate because one listener cannot both admit strangers (so they can enrol) and
# require enrolment (so the services are protected). This address goes into an invite.
listen_enroll = [
    "/ip4/0.0.0.0/udp/{ENROLL_PORT}/quic-v1",
    "/ip6/::/udp/{ENROLL_PORT}/quic-v1",
]

# What this server tells clients to reach it at. Left empty, it announces whatever it
# bound — right only when that is genuinely how the world reaches it.
#
# Set this behind a cloud NAT or load balancer, where the public address differs from the
# bound one. Prefer a DNS name over a literal IP: clients store what they are given, so a
# hostname survives this machine changing address and an IP does not.
#
# external = ["/dns4/ac.example.net/udp/{SERVICE_PORT}/quic-v1"]
"#
    )
}

pub fn run(paths: &Paths) -> Result<()> {
    let key_path = paths.identity_file();
    let (identity, origin) = Identity::load_or_generate(&key_path)
        .with_context(|| format!("creating identity at {}", key_path.display()))?;

    // Creating the store runs the schema, so `init` leaves a server ready to run.
    super::open_store(paths)?;

    let config_path = paths.config_file();
    // Never overwrite: an operator's edits to ports or `external` outlive a re-init.
    let wrote_config = !config_path.exists();
    if wrote_config {
        if let Some(dir) = config_path.parent() {
            fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        fs::write(&config_path, starter_config())
            .with_context(|| format!("writing {}", config_path.display()))?;
    }

    match origin {
        Origin::Generated => println!("created a new server identity"),
        Origin::Loaded => println!("server already initialised"),
    }
    println!("peer   {}", identity.peer_id());
    println!("data   {}", paths.data_dir.display());
    println!(
        "config {}{}",
        config_path.display(),
        if wrote_config {
            ""
        } else {
            "  (kept existing)"
        }
    );
    println!();
    println!("Ports to route: {SERVICE_PORT} (services), {ENROLL_PORT} (enrolment).");
    println!();
    // The peer id is half of what a client needs to trust this server; `ac join` prints
    // the one it pinned so the two can be compared out of band, as with an SSH host key.
    println!("Clients pin this peer id on first contact. Compare it against what");
    println!("`ac join` reports to be sure they reached the right server.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_starter_config_parses_and_uses_the_declared_ports() {
        let config: ac_net::config::Config =
            toml::from_str(&starter_config()).expect("starter config must be valid TOML");

        let has_port = |addrs: &[libp2p::Multiaddr], port: u16| {
            addrs
                .iter()
                .any(|a| a.to_string().contains(&port.to_string()))
        };

        assert!(has_port(&config.listen, SERVICE_PORT));
        assert!(has_port(&config.listen_enroll, ENROLL_PORT));
    }

    #[test]
    fn no_listen_address_is_ephemeral() {
        // Port 0 here would orphan every enrolled client on the next restart.
        let config: ac_net::config::Config = toml::from_str(&starter_config()).unwrap();

        for addr in config.listen.iter().chain(&config.listen_enroll) {
            assert!(
                !addr.to_string().contains("/0/") && !addr.to_string().ends_with("/0"),
                "{addr} uses an ephemeral port"
            );
        }
    }
}
