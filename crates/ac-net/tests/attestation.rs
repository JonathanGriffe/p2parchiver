//! The mutual attestation exchange, over a real connection between two swarms.
//!
//! The unit tests in `ac_net::attest` prove the verification *logic*; this proves the
//! protocol is actually mounted, negotiable between two clients, and that an attestation
//! survives the wire intact — a signature checked over bytes that were re-encoded in
//! transit would pass every unit test and fail in production.
//!
//! What it deliberately does not test is the daemon's *reaction* to a verdict (closing the
//! connection), which lives in `ac-node` and needs the whole event loop. Here the verdict
//! itself is the assertion.

// An integration test is its own crate, so the library's test-only allow does not reach
// here. In a test a panic is the failure report.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use libp2p::futures::StreamExt;
use libp2p::identity::Keypair;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId, request_response};

use ac_net::attest::{self, Attestation};
use ac_net::authz::AcceptAnyPeer;
use ac_net::config::Config;
use ac_net::identity::Identity;
use ac_net::proto::{PeerAttestRequest, PeerAttestResponse};
use ac_net::swarm::{AcBehaviour, AcBehaviourEvent, Role, build};

const TIMEOUT: Duration = Duration::from_secs(20);

/// This test exercises admission, so it mounts no application layer.
type NoApp = libp2p::swarm::dummy::Behaviour;
const NO_APP: NoApp = libp2p::swarm::dummy::Behaviour;

type ClientSwarm = libp2p::Swarm<AcBehaviour<AcceptAnyPeer, NoApp>>;

/// What one side made of the other's attestation: their username, or why it was refused.
type Verdict = Result<String, String>;

fn identity() -> Identity {
    let dir = tempfile::tempdir().expect("tempdir");
    Identity::load_or_generate(&dir.path().join("identity.key"))
        .expect("identity")
        .0
}

/// Loopback only: binding every interface drags in Docker bridges and link-local IPv6.
fn loopback_config() -> Config {
    Config {
        listen: vec![
            "/ip4/127.0.0.1/udp/0/quic-v1"
                .parse()
                .expect("valid multiaddr"),
        ],
        listen_enroll: Vec::new(),
        external: Vec::new(),
        mdns: false,
        server: None,
        storage_root: None,
        storage_max: None,
    }
}

async fn first_listen_addr(swarm: &mut ClientSwarm) -> Multiaddr {
    loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
            return address;
        }
    }
}

/// One node's half of the exchange: send ours on connect, verify theirs on arrival.
///
/// Mirrors what `ac-node`'s daemon does, minus the closing — symmetric, so neither side is
/// the interrogator and both reach their own verdict.
fn step(
    swarm: &mut ClientSwarm,
    event: SwarmEvent<AcBehaviourEvent<AcceptAnyPeer, NoApp>>,
    mine: &Attestation,
    server: PeerId,
    sent: &mut bool,
    verdict: &mut Option<Verdict>,
) {
    match event {
        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            if !*sent {
                *sent = true;
                swarm
                    .behaviour_mut()
                    .peer_attest
                    .as_mut()
                    .expect("a client must speak peer-attest")
                    .send_request(
                        &peer_id,
                        PeerAttestRequest {
                            attestation: mine.clone(),
                        },
                    );
            }
        }

        SwarmEvent::Behaviour(AcBehaviourEvent::PeerAttest(request_response::Event::Message {
            peer,
            message:
                request_response::Message::Request {
                    request, channel, ..
                },
            ..
        })) => {
            // `peer` is the identity libp2p authenticated on this connection, which is
            // exactly what makes the attestation non-transferable.
            let result = request
                .attestation
                .verify(&peer, &server, attest::now())
                .map(|statement| statement.username)
                .map_err(|e| e.to_string());

            let response = match &result {
                Ok(_) => PeerAttestResponse::Accepted,
                Err(why) => PeerAttestResponse::Rejected(why.clone()),
            };
            let _ = swarm
                .behaviour_mut()
                .peer_attest
                .as_mut()
                .expect("a client must speak peer-attest")
                .send_response(channel, response);

            *verdict = Some(result);
        }

        _ => {}
    }
}

/// Connect two clients, exchange attestations, and report what each made of the other's.
async fn exchange(
    (id_a, att_a): (&Identity, &Attestation),
    (id_b, att_b): (&Identity, &Attestation),
    server: PeerId,
) -> (Verdict, Verdict) {
    let mut a = build(
        id_a,
        &loopback_config(),
        Role::Client,
        AcceptAnyPeer,
        NO_APP,
    )
    .expect("swarm a");
    let mut b = build(
        id_b,
        &loopback_config(),
        Role::Client,
        AcceptAnyPeer,
        NO_APP,
    )
    .expect("swarm b");

    let addr_a = tokio::time::timeout(TIMEOUT, first_listen_addr(&mut a))
        .await
        .expect("a should bind a listen address");

    b.dial(addr_a.with(Protocol::P2p(id_a.peer_id())))
        .expect("dial should be accepted");

    let (mut sent_a, mut sent_b) = (false, false);
    let (mut verdict_a, mut verdict_b) = (None, None);

    let settled = async {
        while verdict_a.is_none() || verdict_b.is_none() {
            tokio::select! {
                event = a.select_next_some() => {
                    step(&mut a, event, att_a, server, &mut sent_a, &mut verdict_a);
                }
                event = b.select_next_some() => {
                    step(&mut b, event, att_b, server, &mut sent_b, &mut verdict_b);
                }
            }
        }
    };

    tokio::time::timeout(TIMEOUT, settled)
        .await
        .expect("both sides should reach a verdict");

    (
        verdict_a.expect("a reached a verdict"),
        verdict_b.expect("b reached a verdict"),
    )
}

fn issue(server_key: &Keypair, subject: &PeerId, username: &str) -> Attestation {
    Attestation::issue(
        server_key,
        subject,
        username,
        attest::now(),
        attest::LIFETIME,
    )
    .expect("issuing an attestation")
}

#[tokio::test]
async fn two_enrolled_peers_vouch_for_each_other() {
    // The happy path, and the one that proves the protocol is negotiable at all: two
    // clients that have never met, each holding nothing but a statement signed by the
    // server they both enrolled with, admit each other with no shared state.
    let server_key = Keypair::generate_ed25519();
    let server = server_key.public().to_peer_id();

    let (id_a, id_b) = (identity(), identity());
    let att_a = issue(&server_key, &id_a.peer_id(), "alice");
    let att_b = issue(&server_key, &id_b.peer_id(), "bob");

    let (verdict_a, verdict_b) = exchange((&id_a, &att_a), (&id_b, &att_b), server).await;

    assert_eq!(verdict_a.unwrap(), "bob", "a should learn b's username");
    assert_eq!(verdict_b.unwrap(), "alice", "b should learn a's username");
}

#[tokio::test]
async fn an_attestation_from_another_server_is_refused() {
    // Nothing stops a stranger running their own `ac-server` and issuing themselves a
    // perfectly valid statement. It has to be worthless here, or enrolment means nothing.
    let server_key = Keypair::generate_ed25519();
    let server = server_key.public().to_peer_id();
    let rogue_key = Keypair::generate_ed25519();

    let (id_a, id_b) = (identity(), identity());
    let att_a = issue(&server_key, &id_a.peer_id(), "alice");
    let att_b = issue(&rogue_key, &id_b.peer_id(), "mallory");

    let (verdict_a, verdict_b) = exchange((&id_a, &att_a), (&id_b, &att_b), server).await;

    assert!(
        verdict_a.is_err(),
        "a must refuse an attestation signed by a server it did not enrol with"
    );
    assert_eq!(
        verdict_b.unwrap(),
        "alice",
        "the honest side's attestation is still good; only the rogue one fails"
    );
}

#[tokio::test]
async fn a_stolen_attestation_does_not_travel() {
    // b presents a genuine, unexpired, correctly-signed attestation — issued to somebody
    // else. This is the check that makes an attestation useless to copy: presenting one
    // means also holding the key it names, and then you are simply its subject.
    let server_key = Keypair::generate_ed25519();
    let server = server_key.public().to_peer_id();

    let (id_a, id_b) = (identity(), identity());
    let victim = identity();

    let att_a = issue(&server_key, &id_a.peer_id(), "alice");
    let stolen = issue(&server_key, &victim.peer_id(), "carol");

    let (verdict_a, _) = exchange((&id_a, &att_a), (&id_b, &stolen), server).await;

    assert!(
        verdict_a.is_err(),
        "an attestation naming a different peer must not be accepted from b"
    );
}

#[tokio::test]
async fn an_expired_attestation_is_refused() {
    let server_key = Keypair::generate_ed25519();
    let server = server_key.public().to_peer_id();

    let (id_a, id_b) = (identity(), identity());
    let att_a = issue(&server_key, &id_a.peer_id(), "alice");

    // Issued far enough in the past that its whole lifetime has elapsed.
    let stale = Attestation::issue(
        &server_key,
        &id_b.peer_id(),
        "bob",
        attest::now() - attest::LIFETIME.as_secs() as i64 - 60,
        attest::LIFETIME,
    )
    .expect("issuing an attestation");

    let (verdict_a, _) = exchange((&id_a, &att_a), (&id_b, &stale), server).await;

    assert!(
        verdict_a.is_err(),
        "an expired attestation must not be accepted, or revocation would never bite"
    );
}
