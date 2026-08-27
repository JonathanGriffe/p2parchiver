#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use libp2p::futures::StreamExt;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, StreamProtocol, multiaddr::Protocol};

use ac_net::authz::AcceptAnyPeer;
use ac_net::config::Config;
use ac_net::identity::Identity;
use ac_net::swarm::{AcBehaviour, AcBehaviourEvent, Role, build};

const TIMEOUT: Duration = Duration::from_secs(20);

/// A protocol name `ac-net` has never heard of, which is the point.
const TEST_PROTOCOL: &str = "/ac/test/1.0.0";

/// Stands in for whatever a real application layer would mount. `u32` payloads keep the test
/// about the plumbing rather than about a codec.
type TestApp = request_response::cbor::Behaviour<u32, u32>;

type TestSwarm = libp2p::Swarm<AcBehaviour<AcceptAnyPeer, TestApp>>;

fn test_app() -> TestApp {
    request_response::cbor::Behaviour::new(
        [(StreamProtocol::new(TEST_PROTOCOL), ProtocolSupport::Full)],
        request_response::Config::default(),
    )
}

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
        bandwidth_max: None,
    }
}

async fn first_listen_addr(swarm: &mut TestSwarm) -> Multiaddr {
    loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
            return address;
        }
    }
}

#[tokio::test]
async fn an_application_protocol_mounted_by_the_binary_carries_a_round_trip() {
    let (id_a, id_b) = (identity(), identity());
    let peer_a = id_a.peer_id();

    let mut a = build(
        &id_a,
        &loopback_config(),
        Role::Client,
        AcceptAnyPeer,
        test_app(),
    )
    .expect("swarm a");
    let mut b = build(
        &id_b,
        &loopback_config(),
        Role::Client,
        AcceptAnyPeer,
        test_app(),
    )
    .expect("swarm b");

    let addr_a = tokio::time::timeout(TIMEOUT, first_listen_addr(&mut a))
        .await
        .expect("a should bind a listen address");

    b.dial(addr_a.with(Protocol::P2p(peer_a)))
        .expect("dial should be accepted");

    // b asks once the connection exists; a answers by doubling; b checks what came back.
    let mut asked = false;
    let mut answer = None;

    let exchange = async {
        while answer.is_none() {
            tokio::select! {
                event = a.select_next_some() => {
                    if let SwarmEvent::Behaviour(AcBehaviourEvent::App(
                        request_response::Event::Message {
                            message: request_response::Message::Request { request, channel, .. },
                            ..
                        },
                    )) = event
                    {
                        a.behaviour_mut()
                            .app
                            .send_response(channel, request * 2)
                            .expect("b should still be connected");
                    }
                }
                event = b.select_next_some() => match event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } if !asked => {
                        asked = true;
                        b.behaviour_mut().app.send_request(&peer_id, 21);
                    }
                    SwarmEvent::Behaviour(AcBehaviourEvent::App(
                        request_response::Event::Message {
                            message: request_response::Message::Response { response, .. },
                            ..
                        },
                    )) => answer = Some(response),
                    _ => {}
                }
            }
        }
    };

    tokio::time::timeout(TIMEOUT, exchange)
        .await
        .expect("the application exchange should complete");

    assert_eq!(
        answer,
        Some(42),
        "a protocol defined outside ac-net must negotiate and round-trip over the slot"
    );
}

#[tokio::test]
async fn the_slot_does_not_disturb_the_protocols_around_it() {
    let (id_a, id_b) = (identity(), identity());
    let (peer_a, peer_b) = (id_a.peer_id(), id_b.peer_id());

    let mut a = build(
        &id_a,
        &loopback_config(),
        Role::Client,
        AcceptAnyPeer,
        test_app(),
    )
    .expect("swarm a");
    let mut b = build(
        &id_b,
        &loopback_config(),
        Role::Client,
        AcceptAnyPeer,
        test_app(),
    )
    .expect("swarm b");

    let addr_a = tokio::time::timeout(TIMEOUT, first_listen_addr(&mut a))
        .await
        .expect("a should bind a listen address");
    b.dial(addr_a.with(Protocol::P2p(peer_a)))
        .expect("dial should be accepted");

    let (mut a_saw, mut b_saw) = (false, false);

    let identified = async {
        while !a_saw || !b_saw {
            tokio::select! {
                event = a.select_next_some() => {
                    if let SwarmEvent::Behaviour(AcBehaviourEvent::Identify(
                        libp2p::identify::Event::Received { peer_id, info, .. },
                    )) = event
                    {
                        assert_eq!(peer_id, peer_b);
                        // The slot's protocol is advertised alongside the built-in ones,
                        // which is how a peer discovers the application layer is present.
                        assert!(
                            info.protocols.iter().any(|p| p.as_ref() == TEST_PROTOCOL),
                            "identify should advertise the mounted app protocol, got {:?}",
                            info.protocols,
                        );
                        a_saw = true;
                    }
                }
                event = b.select_next_some() => {
                    if let SwarmEvent::Behaviour(AcBehaviourEvent::Identify(
                        libp2p::identify::Event::Received { peer_id, .. },
                    )) = event
                    {
                        assert_eq!(peer_id, peer_a);
                        b_saw = true;
                    }
                }
            }
        }
    };

    tokio::time::timeout(TIMEOUT, identified)
        .await
        .expect("identify should still complete with an app behaviour mounted");
}
