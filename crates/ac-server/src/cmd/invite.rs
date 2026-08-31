use anyhow::{Context, Result};
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;

use ac_net::config::{Config, Paths};
use ac_net::identity::Identity;
use ac_net::invite::Invite;

use crate::invite::InviteCode;
use crate::store::now;

pub fn new(paths: &Paths, label: &str, ttl_hours: i64, address: Option<&Multiaddr>) -> Result<()> {
    let identity = Identity::load(&paths.identity_file())
        .context("loading the server identity; run `ac-server init` first")?;

    let config = Config::load(&paths.config_file()).unwrap_or_default();
    let server = address
        .cloned()
        .or_else(|| enrol_address(&config))
        .map(|addr| addr.with(Protocol::P2p(identity.peer_id())))
        .context(
            "this server has no public enrolment address to put in a token. Set `external` \
             in config.toml, or pass --address <multiaddr>",
        )?;

    let store = super::open_store(paths)?;
    let code = InviteCode::generate().context("reading system randomness")?;
    let token = Invite::new(server, *code.as_bytes())
        .and_then(|invite| invite.encode())
        .context("building the invite token")?;

    let expires_at = now() + ttl_hours * 3600;
    store
        .create_invite(&code, label, expires_at)
        .with_context(|| format!("recording an invite for {label}"))?;

    println!("token   {token}");
    println!("label   {label}");
    println!("expires in {ttl_hours}h");
    println!("server  {}", identity.peer_id());
    println!();
    println!("Send the token. It carries this server's address and peer id along with the");
    println!("secret, so whoever holds it enrols against this server and no other.");
    println!();
    println!("It is shown once and is not recoverable. It is a bearer secret: whoever holds");
    println!("it can enrol. Send it over a channel you trust.");

    Ok(())
}

/// Where the world reaches this server's enrolment listener.
fn enrol_address(config: &Config) -> Option<Multiaddr> {
    let host = config
        .external
        .iter()
        .find_map(|addr| addr.iter().next().filter(is_host))?;
    let transport: Vec<Protocol<'_>> = config
        .listen_enroll
        .iter()
        .find(|addr| addr.iter().any(|p| matches!(p, Protocol::QuicV1)))?
        .iter()
        .skip(1)
        .collect();

    let mut out = Multiaddr::empty();
    out.push(host);
    for part in transport {
        out.push(part);
    }
    Some(out)
}

fn is_host(part: &Protocol<'_>) -> bool {
    matches!(
        part,
        Protocol::Ip4(_)
            | Protocol::Ip6(_)
            | Protocol::Dns(_)
            | Protocol::Dns4(_)
            | Protocol::Dns6(_)
    )
}

pub fn list(paths: &Paths) -> Result<()> {
    let invites = super::open_store(paths)?
        .list_invites()
        .context("listing invites")?;

    if invites.is_empty() {
        println!("no invites. create one with: ac-server invite new --label <name>");
        return Ok(());
    }

    let now = now();
    let widest = invites.iter().map(|i| i.label.len()).max().unwrap_or(0);

    for invite in invites {
        let status = match (&invite.redeemed_by, invite.expires_at > now) {
            (Some(peer), _) => format!("redeemed by {peer}"),
            (None, true) => format!(
                "pending, expires in {}",
                human_duration(invite.expires_at - now)
            ),
            (None, false) => "expired".to_owned(),
        };
        println!(
            "{:<widest$}  {}…  {status}",
            invite.label,
            &invite.code_hash[..8]
        );
    }
    Ok(())
}

fn human_duration(seconds: i64) -> String {
    match seconds {
        s if s >= 86_400 => format!("{}d", s / 86_400),
        s if s >= 3_600 => format!("{}h", s / 3_600),
        s if s >= 60 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(external: &[&str], listen_enroll: &[&str]) -> Config {
        Config {
            external: external.iter().map(|a| a.parse().unwrap()).collect(),
            listen_enroll: listen_enroll.iter().map(|a| a.parse().unwrap()).collect(),
            ..Config::default()
        }
    }

    #[test]
    fn the_enrolment_address_is_the_public_host_on_the_enrolment_port() {
        let config = config(
            &["/dns4/ac.example.net/udp/4001/quic-v1"],
            &["/ip4/0.0.0.0/udp/4002/quic-v1"],
        );

        assert_eq!(
            enrol_address(&config).unwrap().to_string(),
            "/dns4/ac.example.net/udp/4002/quic-v1",
            "the public name, and the port that answers enrolments"
        );
    }

    #[test]
    fn a_server_that_has_not_said_where_it_is_reached_offers_no_address() {
        assert_eq!(
            enrol_address(&config(&[], &["/ip4/0.0.0.0/udp/4002/quic-v1"])),
            None
        );
        assert_eq!(
            enrol_address(&config(&["/dns4/ac.example.net/udp/4001/quic-v1"], &[])),
            None
        );
    }

    #[test]
    fn durations_read_in_the_largest_useful_unit() {
        assert_eq!(human_duration(30), "30s");
        assert_eq!(human_duration(90), "1m");
        assert_eq!(human_duration(7_200), "2h");
        assert_eq!(human_duration(172_800), "2d");
    }
}
