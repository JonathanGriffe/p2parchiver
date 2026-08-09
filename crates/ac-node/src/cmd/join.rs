//! `ac join` — redeem an invite code with a server.
//!
//! One short-lived swarm: dial, ask, record the answer, exit. It does not become the
//! daemon, so a failed enrolment leaves nothing behind to clean up.

use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use libp2p::futures::StreamExt;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId, request_response};

use ac_net::attest::{self, Attestation, normalise_username};
use ac_net::authz::AcceptAnyPeer;
use ac_net::config::{Config, Paths};
use ac_net::identity::Identity;
use ac_net::proto::{EnrollRequest, EnrollResponse};
use ac_net::swarm::{AcBehaviourEvent, Role, build};

/// Long enough for a slow link and a relay hop, short enough that a wrong address fails
/// while the user is still watching.
const TIMEOUT: Duration = Duration::from_secs(30);

pub fn run(paths: &Paths, server: &Multiaddr, code: &str, username: &str) -> Result<()> {
    let server_peer = peer_id_of(server).ok_or_else(|| {
        anyhow!(
            "the server address must end with /p2p/<peer-id> so the right server can be \
             identified; `ac-server init` prints it"
        )
    })?;

    // Checked here as well as on the server so a typo costs nothing — no dial, no round
    // trip, and the invite stays unspent. The server's check is the one that counts.
    let username = normalise_username(username)
        .map_err(|e| anyhow!("{e}"))
        .context("that username cannot be used")?;

    let key_path = paths.identity_file();
    let (identity, _) = Identity::load_or_generate(&key_path)
        .with_context(|| format!("loading identity from {}", key_path.display()))?;

    let config_path = paths.config_file();
    let mut config = Config::load(&config_path)
        .with_context(|| format!("loading config from {}", config_path.display()))?;

    let runtime = tokio::runtime::Runtime::new().context("starting the tokio runtime")?;
    let (username, service, attestation) = runtime.block_on(enroll(
        &identity,
        &config,
        server,
        server_peer,
        code,
        &username,
    ))?;

    // Verified before it is stored, so a server that hands out something unusable is
    // caught here rather than on the first peer connection days later. Everything checked
    // is known locally: our own peer id, and the server's from the address just dialled.
    attestation
        .verify(&identity.peer_id(), &server_peer, attest::now())
        .map_err(|e| anyhow!("{e}"))
        .context("the server issued an attestation this node cannot use")?;

    // The address given on the command line reaches the *enrolment* listener, which
    // speaks nothing else. Everything from here on — relay, rendezvous, AutoNAT — lives
    // on the service listener, whose address the server just told us. Store that one; the
    // enrolment address is never needed again.
    let service_addr = pick_service_addr(&service, server).ok_or_else(|| {
        anyhow!("the server did not say where to reach its services; it may be misconfigured")
    })?;

    // Only recorded once the server has accepted, so a failed attempt leaves the node's
    // configuration untouched.
    config.server = Some(service_addr.clone());
    config
        .save(&config_path)
        .with_context(|| format!("saving config to {}", config_path.display()))?;

    let attestation_path = paths.attestation_file();
    attest::save(&attestation_path, &attestation)
        .with_context(|| format!("saving the attestation to {}", attestation_path.display()))?;

    let expires_at = attestation.expires_at().unwrap_or_default();
    println!("enrolled as {username}");
    println!("peer     {}", identity.peer_id());
    println!("server   {server_peer}");
    println!("services {service_addr}");
    println!(
        "attested for {}h, renewed automatically while `ac run` is up",
        (expires_at - attest::now()).max(0) / 3600
    );
    println!();
    println!("Compare that server peer id against what `ac-server init` printed. It is");
    println!("pinned now: a different server at the same address will fail to connect.");

    Ok(())
}

async fn enroll(
    identity: &Identity,
    config: &Config,
    server: &Multiaddr,
    server_peer: PeerId,
    code: &str,
    username: &str,
) -> Result<(String, Vec<Multiaddr>, Attestation)> {
    let mut swarm = build(
        identity,
        config,
        Role::Client,
        AcceptAnyPeer,
        libp2p::swarm::dummy::Behaviour,
    )
    .context("building the swarm")?;

    swarm
        .dial(server.clone())
        .with_context(|| format!("dialling {server}"))?;

    let exchange = async {
        let mut asked = false;
        loop {
            match swarm.select_next_some().await {
                SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == server_peer => {
                    // Reaching here already proves the server holds the key for the peer
                    // id in the address; the handshake would have failed otherwise.
                    if !asked && let Some(enroll) = swarm.behaviour_mut().enroll.as_mut() {
                        asked = true;
                        enroll.send_request(
                            &server_peer,
                            EnrollRequest {
                                code: code.to_owned(),
                                username: username.to_owned(),
                            },
                        );
                    }
                }

                SwarmEvent::Behaviour(AcBehaviourEvent::Enroll(
                    request_response::Event::Message {
                        message: request_response::Message::Response { response, .. },
                        ..
                    },
                )) => {
                    return match response {
                        EnrollResponse::Enrolled {
                            username,
                            service,
                            attestation,
                        } => Ok((username, service, attestation)),
                        EnrollResponse::Refused(reason) => Err(anyhow!("{}", reason.explain())),
                    };
                }

                SwarmEvent::Behaviour(AcBehaviourEvent::Enroll(
                    request_response::Event::OutboundFailure { error, .. },
                )) => {
                    bail!("the server did not answer the enrolment request: {error}");
                }

                SwarmEvent::OutgoingConnectionError { peer_id, error, .. }
                    if peer_id == Some(server_peer) =>
                {
                    bail!("could not reach the server: {error}");
                }

                other => tracing::debug!(?other, "swarm event"),
            }
        }
    };

    tokio::time::timeout(TIMEOUT, exchange)
        .await
        .map_err(|_| anyhow!("the server did not respond within {}s", TIMEOUT.as_secs()))?
}

/// Choose which of the server's service addresses to keep.
///
/// The server offers one per bound interface and transport, most unreachable from here.
/// Two preferences, in order:
///
/// 1. **Same host as enrolment.** If the enrolment listener answered at that address, the
///    service listener on the same machine almost certainly will too.
/// 2. **QUIC over TCP.** QUIC carries its own TLS and multiplexing, so it connects in
///    fewer round trips, and its single UDP flow is what makes hole punching viable in
///    stage 9. Picking TCP here would work and quietly forgo both.
///
/// This is the one address the client keeps, so getting it wrong is not a slow path — it
/// is the only path.
fn pick_service_addr(service: &[Multiaddr], enrolled_via: &Multiaddr) -> Option<Multiaddr> {
    let host = enrolled_via.iter().find(|p| {
        matches!(
            p,
            Protocol::Ip4(_) | Protocol::Ip6(_) | Protocol::Dns4(_) | Protocol::Dns6(_)
        )
    });

    let same_host = |addr: &&Multiaddr| host.is_some() && addr.iter().next() == host;
    let is_quic = |addr: &&Multiaddr| addr.iter().any(|p| matches!(p, Protocol::QuicV1));

    let candidates = || service.iter();
    candidates()
        .find(|a| same_host(a) && is_quic(a))
        .or_else(|| candidates().find(same_host))
        .or_else(|| candidates().find(is_quic))
        .or_else(|| service.first())
        .cloned()
}

/// The `/p2p/<peer-id>` component of an address, if it has one.
fn peer_id_of(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|p| match p {
        Protocol::P2p(peer) => Some(peer),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: &str = "12D3KooWDmPLKCjUV7snQBQVod5bNQnDmZ5X4MYNnPx8NM95zxke";

    fn addrs(list: &[&str]) -> Vec<Multiaddr> {
        list.iter().map(|a| a.parse().unwrap()).collect()
    }

    #[test]
    fn quic_is_preferred_over_tcp_on_the_same_host() {
        // TCP would work, and would quietly forgo the transport stage 9 depends on.
        let service = addrs(&["/ip4/127.0.0.1/tcp/4001", "/ip4/127.0.0.1/udp/4001/quic-v1"]);
        let via: Multiaddr = "/ip4/127.0.0.1/udp/4002/quic-v1".parse().unwrap();

        assert_eq!(
            pick_service_addr(&service, &via).unwrap().to_string(),
            "/ip4/127.0.0.1/udp/4001/quic-v1"
        );
    }

    #[test]
    fn the_host_that_enrolment_worked_on_wins_over_transport() {
        // A QUIC address on an interface we cannot reach is worse than TCP on one we can.
        let service = addrs(&["/ip4/10.9.9.9/udp/4001/quic-v1", "/ip4/127.0.0.1/tcp/4001"]);
        let via: Multiaddr = "/ip4/127.0.0.1/udp/4002/quic-v1".parse().unwrap();

        assert_eq!(
            pick_service_addr(&service, &via).unwrap().to_string(),
            "/ip4/127.0.0.1/tcp/4001"
        );
    }

    #[test]
    fn a_dns_server_address_still_yields_something() {
        let service = addrs(&["/dns4/ac.example.net/udp/4001/quic-v1"]);
        let via: Multiaddr = "/ip4/203.0.113.7/udp/4002/quic-v1".parse().unwrap();

        assert_eq!(
            pick_service_addr(&service, &via).unwrap().to_string(),
            "/dns4/ac.example.net/udp/4001/quic-v1"
        );
    }

    #[test]
    fn no_service_addresses_yields_none() {
        let via: Multiaddr = "/ip4/127.0.0.1/udp/4002/quic-v1".parse().unwrap();
        assert!(pick_service_addr(&[], &via).is_none());
    }

    #[test]
    fn extracts_the_peer_id_from_an_address() {
        let addr: Multiaddr = format!("/ip4/203.0.113.7/udp/4001/quic-v1/p2p/{PEER}")
            .parse()
            .unwrap();
        assert_eq!(peer_id_of(&addr).unwrap().to_string(), PEER);
    }

    #[test]
    fn an_address_without_a_peer_id_yields_none() {
        // Refusing this is the point: without a peer id there is nothing pinned, and a
        // different server at that address would be accepted silently.
        let addr: Multiaddr = "/ip4/203.0.113.7/udp/4001/quic-v1".parse().unwrap();
        assert!(peer_id_of(&addr).is_none());
    }

    #[test]
    fn a_dns_address_works_too() {
        let addr: Multiaddr = format!("/dns4/ac.example.net/udp/4001/quic-v1/p2p/{PEER}")
            .parse()
            .unwrap();
        assert_eq!(peer_id_of(&addr).unwrap().to_string(), PEER);
    }
}
