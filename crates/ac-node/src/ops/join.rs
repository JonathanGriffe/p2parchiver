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
use ac_net::invite::Invite;
use ac_net::proto::{AttestRequest, AttestResponse, EnrollRequest, EnrollResponse};
use ac_net::swarm::{AcBehaviourEvent, Role, build};

const TIMEOUT: Duration = Duration::from_secs(30);

/// What enrolling settled, once it has been written down.
#[derive(Debug)]
pub struct Enrolled {
    pub username: String,
    pub peer: PeerId,
    pub server: PeerId,
    pub service: Multiaddr,
    /// Hours this node is attested for. Renewed automatically while the node is running.
    pub attested_for: i64,
}

/// Enrol `identity` using the one token an operator hands out.
///
/// The token is the whole point: the address and the server's peer id travel with the code,
/// so pinning the right server costs whoever is joining nothing but a paste.
pub fn from_token(
    paths: &Paths,
    identity: &Identity,
    token: &str,
    username: &str,
) -> Result<Enrolled> {
    let invite = Invite::decode(token).map_err(|e| anyhow!("{e}"))?;
    run(paths, identity, &invite.server, &invite.code, username)
}

/// Enrol `identity` with an invite code. Writes nothing unless it succeeds.
pub fn run(
    paths: &Paths,
    identity: &Identity,
    server: &Multiaddr,
    code: &[u8],
    username: &str,
) -> Result<Enrolled> {
    let server_peer = server_peer_of(server)?;

    let username = normalise_username(username)
        .map_err(|e| anyhow!("{e}"))
        .context("that username cannot be used")?;

    let config = load_config(paths)?;
    let runtime = tokio::runtime::Runtime::new().context("starting the tokio runtime")?;
    let (_, service, attestation) = runtime.block_on(enroll(
        identity,
        &config,
        server,
        server_peer,
        code,
        &username,
    ))?;

    let service_addr = pick_service_addr(&service, server).ok_or_else(|| {
        anyhow!("the server did not say where to reach its services; it may be misconfigured")
    })?;
    keep(
        paths,
        identity,
        config,
        server_peer,
        service_addr,
        &attestation,
    )
}

/// Enrol `identity` again with the server it enrolled with before, such as one restored from
/// a backup, by asking that server's service address for an attestation. Writes nothing
/// unless it succeeds.
pub fn from_server(paths: &Paths, identity: &Identity, server: &Multiaddr) -> Result<Enrolled> {
    let server_peer = server_peer_of(server)?;
    let config = load_config(paths)?;

    let runtime = tokio::runtime::Runtime::new().context("starting the tokio runtime")?;
    let attestation = runtime.block_on(attest_with(identity, &config, server, server_peer))?;
    keep(
        paths,
        identity,
        config,
        server_peer,
        server.clone(),
        &attestation,
    )
}

fn server_peer_of(server: &Multiaddr) -> Result<PeerId> {
    peer_id_of(server).ok_or_else(|| {
        anyhow!(
            "the server address must end with /p2p/<peer-id> so the right server can be \
             identified; `ac-server init` prints it"
        )
    })
}

fn load_config(paths: &Paths) -> Result<Config> {
    let config_path = paths.config_file();
    Config::load(&config_path)
        .with_context(|| format!("loading config from {}", config_path.display()))
}

/// Check the attestation, then write the key, the attestation, and last the server, which is
/// what marks the home as enrolled. A failure at any step leaves it looking unenrolled.
fn keep(
    paths: &Paths,
    identity: &Identity,
    mut config: Config,
    server_peer: PeerId,
    service: Multiaddr,
    attestation: &Attestation,
) -> Result<Enrolled> {
    let statement = attestation
        .verify(&identity.peer_id(), &server_peer, attest::now())
        .map_err(|e| anyhow!("{e}"))
        .context("the server issued an attestation this node cannot use")?;

    let key_path = paths.identity_file();
    identity
        .save(&key_path)
        .with_context(|| format!("saving the identity to {}", key_path.display()))?;

    let attestation_path = paths.attestation_file();
    attest::save(&attestation_path, attestation)
        .with_context(|| format!("saving the attestation to {}", attestation_path.display()))?;

    let config_path = paths.config_file();
    config.server = Some(service.clone());
    config
        .save(&config_path)
        .with_context(|| format!("saving config to {}", config_path.display()))?;

    Ok(Enrolled {
        username: statement.username,
        peer: identity.peer_id(),
        server: server_peer,
        service,
        attested_for: (statement.expires_at - attest::now()).max(0) / 3600,
    })
}

/// Ask the server's service address for an attestation, as the daemon does to renew one.
async fn attest_with(
    identity: &Identity,
    config: &Config,
    server: &Multiaddr,
    server_peer: PeerId,
) -> Result<Attestation> {
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
                    if !asked && let Some(attest) = swarm.behaviour_mut().attest.as_mut() {
                        asked = true;
                        attest.send_request(&server_peer, AttestRequest);
                    }
                }

                SwarmEvent::Behaviour(AcBehaviourEvent::Attest(
                    request_response::Event::Message {
                        message: request_response::Message::Response { response, .. },
                        ..
                    },
                )) => {
                    return match response {
                        AttestResponse::Issued(attestation) => Ok(attestation),
                        AttestResponse::Refused(reason) => Err(anyhow!("{}", reason.explain())),
                    };
                }

                SwarmEvent::Behaviour(AcBehaviourEvent::Attest(
                    request_response::Event::OutboundFailure { error, .. },
                )) => {
                    bail!("the server did not answer the attestation request: {error}");
                }

                SwarmEvent::OutgoingConnectionError { peer_id, error, .. }
                    if peer_id == Some(server_peer) =>
                {
                    bail!("could not reach the server: {error}");
                }

                SwarmEvent::ConnectionClosed { peer_id, .. } if peer_id == server_peer => {
                    bail!("the server closed the connection; it may not know this identity");
                }

                other => tracing::debug!(?other, "swarm event"),
            }
        }
    };

    tokio::time::timeout(TIMEOUT, exchange)
        .await
        .map_err(|_| anyhow!("the server did not respond within {}s", TIMEOUT.as_secs()))?
}

async fn enroll(
    identity: &Identity,
    config: &Config,
    server: &Multiaddr,
    server_peer: PeerId,
    code: &[u8],
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
                    if !asked && let Some(enroll) = swarm.behaviour_mut().enroll.as_mut() {
                        asked = true;
                        enroll.send_request(
                            &server_peer,
                            EnrollRequest {
                                code: code.to_vec(),
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
    use ac_net::proto::AttestRefusal;
    use libp2p::identity::Keypair;

    const PEER: &str = "12D3KooWDmPLKCjUV7snQBQVod5bNQnDmZ5X4MYNnPx8NM95zxke";

    fn loopback() -> Config {
        Config {
            listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
            mdns: false,
            ..Config::default()
        }
    }

    /// A fresh home whose config keeps the swarm on loopback.
    fn home() -> (tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::rooted_at(dir.path());
        loopback().save(&paths.config_file()).unwrap();
        (dir, paths)
    }

    fn fresh_identity() -> Identity {
        Identity::from_protobuf(&Keypair::generate_ed25519().to_protobuf_encoding().unwrap())
            .unwrap()
    }

    fn enrolled(paths: &Paths) -> bool {
        Config::load(&paths.config_file()).unwrap().server.is_some()
    }

    /// How a stand-in server answers.
    #[derive(Clone, Copy)]
    enum Answer {
        Issue,
        Refuse,
    }

    /// A stand-in server on its own thread, answering enrolment and attestation requests.
    /// Returns its address, ending in `/p2p/<its peer id>`.
    fn stand_in(role: Role, answer: Answer) -> Multiaddr {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async move {
                let identity = fresh_identity();
                let mut swarm = build(
                    &identity,
                    &loopback(),
                    role,
                    AcceptAnyPeer,
                    libp2p::swarm::dummy::Behaviour,
                )
                .unwrap();
                let me = identity.peer_id();
                let issue = |peer: &PeerId, username: &str| {
                    Attestation::issue(
                        identity.keypair(),
                        peer,
                        username,
                        attest::now(),
                        attest::LIFETIME,
                    )
                    .unwrap()
                };
                let mut sent_address = false;
                loop {
                    match swarm.select_next_some().await {
                        SwarmEvent::NewListenAddr { address, .. } if !sent_address => {
                            sent_address = true;
                            let _ = tx.send(address.with(Protocol::P2p(me)));
                        }
                        SwarmEvent::Behaviour(AcBehaviourEvent::Enroll(
                            request_response::Event::Message {
                                peer,
                                message:
                                    request_response::Message::Request {
                                        request, channel, ..
                                    },
                                ..
                            },
                        )) => {
                            let response = match answer {
                                Answer::Issue => EnrollResponse::Enrolled {
                                    username: request.username.clone(),
                                    service: vec![
                                        format!("/ip4/127.0.0.1/tcp/1/p2p/{me}").parse().unwrap(),
                                    ],
                                    attestation: issue(&peer, &request.username),
                                },
                                Answer::Refuse => {
                                    EnrollResponse::Refused(ac_net::proto::Refusal::UnknownCode)
                                }
                            };
                            let enroll = swarm.behaviour_mut().enroll.as_mut().unwrap();
                            let _ = enroll.send_response(channel, response);
                        }
                        SwarmEvent::Behaviour(AcBehaviourEvent::Attest(
                            request_response::Event::Message {
                                peer,
                                message: request_response::Message::Request { channel, .. },
                                ..
                            },
                        )) => {
                            let response = match answer {
                                Answer::Issue => AttestResponse::Issued(issue(&peer, "alice")),
                                Answer::Refuse => {
                                    AttestResponse::Refused(AttestRefusal::NoUsername)
                                }
                            };
                            let attest = swarm.behaviour_mut().attest.as_mut().unwrap();
                            let _ = attest.send_response(channel, response);
                        }
                        _ => {}
                    }
                }
            });
        });
        rx.recv_timeout(Duration::from_secs(10)).unwrap()
    }

    #[test]
    fn enrolling_with_a_given_identity_writes_it_and_the_server() {
        let (_dir, paths) = home();
        ops_identity_is_generated(&paths);
        let identity = fresh_identity();
        let server = stand_in(Role::Enrollment, Answer::Issue);

        let done = run(&paths, &identity, &server, b"code", "bob").unwrap();
        assert_eq!(done.username, "bob");
        assert_eq!(done.peer, identity.peer_id());
        assert_eq!(
            Identity::load(&paths.identity_file()).unwrap().peer_id(),
            identity.peer_id(),
            "the given key replaced the one the home had"
        );
        assert!(attest::load(&paths.attestation_file()).unwrap().is_some());
        assert!(enrolled(&paths));
    }

    /// The home's own key, as `load_or_generate` leaves it before any enrolment.
    fn ops_identity_is_generated(paths: &Paths) {
        Identity::load_or_generate(&paths.identity_file()).unwrap();
    }

    #[test]
    fn a_refused_enrolment_writes_nothing() {
        let (_dir, paths) = home();
        let identity = fresh_identity();
        let server = stand_in(Role::Enrollment, Answer::Refuse);

        assert!(run(&paths, &identity, &server, b"code", "bob").is_err());
        assert!(
            !paths.identity_file().exists(),
            "the given key was not kept"
        );
        assert!(attest::load(&paths.attestation_file()).unwrap().is_none());
        assert!(!enrolled(&paths), "no config.server");
    }

    #[test]
    fn an_unreachable_server_writes_nothing() {
        let (_dir, paths) = home();
        let identity = fresh_identity();
        let nobody: Multiaddr = format!("/ip4/127.0.0.1/tcp/1/p2p/{PEER}").parse().unwrap();

        assert!(from_server(&paths, &identity, &nobody).is_err());
        assert!(run(&paths, &identity, &nobody, b"code", "bob").is_err());
        assert!(!paths.identity_file().exists());
        assert!(!enrolled(&paths));
    }

    #[test]
    fn continuing_with_a_known_server_takes_a_fresh_attestation() {
        let (_dir, paths) = home();
        let identity = fresh_identity();
        let server = stand_in(Role::Server, Answer::Issue);

        let done = from_server(&paths, &identity, &server).unwrap();
        assert_eq!(done.username, "alice", "the name the server holds");
        assert_eq!(done.service, server);
        assert_eq!(
            Identity::load(&paths.identity_file()).unwrap().peer_id(),
            identity.peer_id()
        );
        assert_eq!(
            Config::load(&paths.config_file()).unwrap().server,
            Some(server)
        );
    }

    #[test]
    fn a_server_that_does_not_know_the_identity_leaves_the_home_unenrolled() {
        let (_dir, paths) = home();
        let identity = fresh_identity();
        let server = stand_in(Role::Server, Answer::Refuse);

        let err = from_server(&paths, &identity, &server).unwrap_err();
        assert!(format!("{err:#}").contains("no username"), "{err:#}");
        assert!(!paths.identity_file().exists());
        assert!(!enrolled(&paths));
    }

    #[test]
    fn a_server_without_a_peer_id_is_refused_before_dialling() {
        let (_dir, paths) = home();
        let bare: Multiaddr = "/ip4/127.0.0.1/tcp/1".parse().unwrap();
        assert!(from_server(&paths, &fresh_identity(), &bare).is_err());
    }

    fn addrs(list: &[&str]) -> Vec<Multiaddr> {
        list.iter().map(|a| a.parse().unwrap()).collect()
    }

    #[test]
    fn quic_is_preferred_over_tcp_on_the_same_host() {
        let service = addrs(&["/ip4/127.0.0.1/tcp/4001", "/ip4/127.0.0.1/udp/4001/quic-v1"]);
        let via: Multiaddr = "/ip4/127.0.0.1/udp/4002/quic-v1".parse().unwrap();

        assert_eq!(
            pick_service_addr(&service, &via).unwrap().to_string(),
            "/ip4/127.0.0.1/udp/4001/quic-v1"
        );
    }

    #[test]
    fn the_host_that_enrolment_worked_on_wins_over_transport() {
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
