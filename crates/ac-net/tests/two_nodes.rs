//! Two swarms, one dial, in one process.
//!
//! This is the automated form of the stage 2 check. It matters beyond "a connection
//! happened": every later stage is built on `identify` reporting the address a peer sees
//! us at. AutoNAT verifies those candidates and DCUtR punches toward the confirmed one,
//! so if this exchange silently stopped working, the failure would surface much later as
//! hole punching that never succeeds.

// An integration test is its own crate, so the library's test-only allow does not reach
// here. In a test a panic is the failure report.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use libp2p::futures::StreamExt;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId, identify};

use ac_net::authz::AcceptAnyPeer;
use ac_net::config::Config;
use ac_net::identity::Identity;
use ac_net::swarm::{AcBehaviour, AcBehaviourEvent, Role, build};

/// Generous enough to survive a loaded CI machine, short enough that a genuine hang
/// fails the test rather than blocking forever.
const TIMEOUT: Duration = Duration::from_secs(20);

/// These tests exercise connectivity, so they mount no application layer.
type NoApp = libp2p::swarm::dummy::Behaviour;
const NO_APP: NoApp = libp2p::swarm::dummy::Behaviour;

fn identity() -> Identity {
    let dir = tempfile::tempdir().expect("tempdir");
    Identity::load_or_generate(&dir.path().join("identity.key"))
        .expect("identity")
        .0
}

/// Loopback only: binding every interface drags in Docker bridges and link-local IPv6,
/// which makes the test slow and its output hard to read.
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
    }
}

/// Drive the swarm until it reports a listen address.
async fn first_listen_addr(
    swarm: &mut libp2p::Swarm<AcBehaviour<AcceptAnyPeer, NoApp>>,
) -> Multiaddr {
    loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
            return address;
        }
    }
}

/// The address a received identify event reports for *ourselves*.
///
/// identify's `observed_addr` travels in the direction "here is how I see you", so on a
/// `Received` event the address describes the local node, not the remote one. Getting
/// this backwards is easy and silent, which is most of why this test exists.
fn self_addr_reported_by(
    event: &SwarmEvent<AcBehaviourEvent<AcceptAnyPeer, NoApp>>,
) -> Option<(PeerId, Multiaddr)> {
    match event {
        SwarmEvent::Behaviour(AcBehaviourEvent::Identify(identify::Event::Received {
            peer_id,
            info,
            ..
        })) => Some((*peer_id, info.observed_addr.clone())),
        _ => None,
    }
}

#[tokio::test]
async fn two_nodes_connect_and_report_observed_addresses() {
    let (id_a, id_b) = (identity(), identity());
    let (peer_a, peer_b) = (id_a.peer_id(), id_b.peer_id());

    let mut a = build(
        &id_a,
        &loopback_config(),
        Role::Client,
        AcceptAnyPeer,
        NO_APP,
    )
    .expect("swarm a");
    let mut b = build(
        &id_b,
        &loopback_config(),
        Role::Client,
        AcceptAnyPeer,
        NO_APP,
    )
    .expect("swarm b");

    let addr_a = tokio::time::timeout(TIMEOUT, first_listen_addr(&mut a))
        .await
        .expect("a should bind a listen address");

    // Dialling with `/p2p/<peer>` appended makes the swarm verify that whoever answers
    // really holds that key, so a successful dial is also an authentication.
    b.dial(addr_a.clone().with(Protocol::P2p(peer_a)))
        .expect("dial should be accepted");

    // Each node learns its own address from the other, so poll them together until both
    // have produced an identify event.
    let (mut a_self_addr, mut b_self_addr) = (None, None);

    let exchange = async {
        while a_self_addr.is_none() || b_self_addr.is_none() {
            tokio::select! {
                event = a.select_next_some() => {
                    if let Some((peer, addr)) = self_addr_reported_by(&event) {
                        assert_eq!(peer, peer_b, "a identified the wrong peer");
                        a_self_addr = Some(addr);
                    }
                }
                event = b.select_next_some() => {
                    if let Some((peer, addr)) = self_addr_reported_by(&event) {
                        assert_eq!(peer, peer_a, "b identified the wrong peer");
                        b_self_addr = Some(addr);
                    }
                }
            }
        }
    };

    tokio::time::timeout(TIMEOUT, exchange)
        .await
        .expect("both nodes should exchange identify");

    let a_self_addr = a_self_addr.expect("a learned its own address");
    let b_self_addr = b_self_addr.expect("b learned its own address");

    // b dialled a's listen address, so that is exactly how b sees a.
    assert_eq!(
        a_self_addr, addr_a,
        "a should be observed at the address b dialled"
    );

    // b is seen at its ephemeral source port, which is not its listen address and cannot
    // be predicted. All that can be asserted is that it is a real loopback QUIC address —
    // which is precisely the kind of address a NATed node has to learn about itself.
    assert!(
        b_self_addr.iter().any(|p| matches!(p, Protocol::QuicV1)),
        "expected a QUIC address, got {b_self_addr}"
    );
    assert!(
        b_self_addr
            .iter()
            .any(|p| matches!(p, Protocol::Ip4(ip) if ip.is_loopback())),
        "expected a loopback address, got {b_self_addr}"
    );
    assert_ne!(
        b_self_addr, addr_a,
        "b should learn its own address, not a's"
    );
}

#[tokio::test]
async fn dialling_the_wrong_peer_id_is_refused() {
    // The security handshake proves the remote holds the private key for the peer id in
    // the address. This is the property the trust list relies on in stage 3: an
    // authorised peer id cannot be worn by someone else.
    let (id_a, id_b, impostor) = (identity(), identity(), identity());

    let mut a = build(
        &id_a,
        &loopback_config(),
        Role::Client,
        AcceptAnyPeer,
        NO_APP,
    )
    .expect("swarm a");
    let mut b = build(
        &id_b,
        &loopback_config(),
        Role::Client,
        AcceptAnyPeer,
        NO_APP,
    )
    .expect("swarm b");

    let addr_a = tokio::time::timeout(TIMEOUT, first_listen_addr(&mut a))
        .await
        .expect("a should bind a listen address");

    b.dial(addr_a.with(Protocol::P2p(impostor.peer_id())))
        .expect("dial should be accepted before the handshake runs");

    let outcome = async {
        loop {
            tokio::select! {
                _ = a.select_next_some() => {}
                event = b.select_next_some() => {
                    match event {
                        SwarmEvent::OutgoingConnectionError { .. } => return,
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            panic!("connected to {peer_id} while claiming to dial an impostor")
                        }
                        _ => {}
                    }
                }
            }
        }
    };

    tokio::time::timeout(TIMEOUT, outcome)
        .await
        .expect("the dial should fail rather than hang");
}
