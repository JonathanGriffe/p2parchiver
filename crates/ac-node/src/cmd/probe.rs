use std::collections::HashSet;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use libp2p::futures::StreamExt;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId, autonat, relay, upnp};

use ac_net::authz::AcceptAnyPeer;
use ac_net::config::{Config, Paths};
use ac_net::connectivity::{Connectivity, State};
use ac_net::identity::Identity;
use ac_net::swarm::{AcBehaviourEvent, Role, build};

const RUN_FOR: Duration = Duration::from_secs(20);

#[derive(Default)]
struct Findings {
    upnp: Option<Multiaddr>,
    upnp_failed: Option<String>,
    external: Vec<Multiaddr>,
    reachable: Vec<Multiaddr>,
    unreachable: usize,
    reservation: Option<PeerId>,
    circuit: Option<Multiaddr>,
    dial_error: Option<String>,
}

pub fn run(paths: &Paths, peer: Option<PeerId>) -> Result<()> {
    let key_path = paths.identity_file();
    let (identity, _) = Identity::load_or_generate(&key_path)
        .with_context(|| format!("loading identity from {}", key_path.display()))?;

    let config_path = paths.config_file();
    let config = Config::load(&config_path)
        .with_context(|| format!("loading config from {}", config_path.display()))?;

    let server = config
        .server
        .clone()
        .ok_or_else(|| anyhow!("this node has not enrolled with a server; run `ac join` first"))?;

    let runtime = tokio::runtime::Runtime::new().context("starting the tokio runtime")?;
    runtime.block_on(probe(&identity, &config, &server, peer))
}

async fn probe(
    identity: &Identity,
    config: &Config,
    server: &Multiaddr,
    target: Option<PeerId>,
) -> Result<()> {
    let mut swarm = build(
        identity,
        config,
        Role::Client,
        AcceptAnyPeer,
        libp2p::swarm::dummy::Behaviour,
    )
    .context("building the swarm")?;

    let server_peer = server
        .iter()
        .find_map(|p| match p {
            Protocol::P2p(peer) => Some(peer),
            _ => None,
        })
        .ok_or_else(|| anyhow!("the stored server address has no peer id"))?;

    swarm
        .dial(server.clone())
        .with_context(|| format!("dialling the server at {server}"))?;

    let mut findings = Findings::default();
    let mut connectivity = Connectivity::default();
    let mut reserved = false;
    let mut dialled = false;
    let deadline = Instant::now() + RUN_FOR;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }

        let Ok(event) = tokio::time::timeout(remaining, swarm.select_next_some()).await else {
            break;
        };

        match &event {
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                let relayed = endpoint
                    .get_remote_address()
                    .iter()
                    .any(|p| p == Protocol::P2pCircuit);
                connectivity.connected(*peer_id, relayed);

                if *peer_id == server_peer && !reserved {
                    reserved = true;
                    let circuit = server.clone().with(Protocol::P2pCircuit);
                    let _ = swarm.listen_on(circuit);
                }

                if *peer_id == server_peer
                    && let Some(peer) = target
                    && !dialled
                {
                    dialled = true;
                    let via = server
                        .clone()
                        .with(Protocol::P2pCircuit)
                        .with(Protocol::P2p(peer));
                    let _ = swarm.dial(via);
                }
            }

            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                connectivity.disconnected(*peer_id, swarm.is_connected(peer_id));
            }

            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } if *peer_id == target => {
                findings.dial_error = Some(error.to_string());
            }

            SwarmEvent::ExternalAddrConfirmed { address } => {
                findings.external.push(address.clone());
            }

            SwarmEvent::NewListenAddr { address, .. }
                if address.iter().any(|p| p == Protocol::P2pCircuit) =>
            {
                findings.circuit = Some(address.clone());
            }

            SwarmEvent::Behaviour(AcBehaviourEvent::Upnp(upnp::Event::NewExternalAddr(a))) => {
                findings.upnp = Some(a.clone());
            }
            SwarmEvent::Behaviour(AcBehaviourEvent::Upnp(other)) => {
                findings.upnp_failed = Some(format!("{other:?}"));
            }

            SwarmEvent::Behaviour(AcBehaviourEvent::AutonatClient(
                autonat::v2::client::Event {
                    tested_addr,
                    result,
                    ..
                },
            )) => match result {
                Ok(()) => findings.reachable.push(tested_addr.clone()),
                Err(_) => findings.unreachable += 1,
            },

            SwarmEvent::Behaviour(AcBehaviourEvent::RelayClient(
                relay::client::Event::ReservationReqAccepted { relay_peer_id, .. },
            )) => {
                findings.reservation = Some(*relay_peer_id);
            }

            SwarmEvent::Behaviour(AcBehaviourEvent::Dcutr(e)) => {
                connectivity.hole_punch(e.remote_peer_id, e.result.is_ok());
            }

            _ => {}
        }
    }

    report(identity, server_peer, target, &findings, &connectivity);
    Ok(())
}

fn report(
    identity: &Identity,
    server_peer: PeerId,
    target: Option<PeerId>,
    findings: &Findings,
    connectivity: &Connectivity,
) {
    println!("peer      {}", identity.peer_id());
    println!("server    {server_peer}");

    match (&findings.upnp, &findings.upnp_failed) {
        (Some(addr), _) => println!("upnp      mapped {addr}"),
        (None, Some(why)) => println!("upnp      no port mapping ({why})"),
        (None, None) => println!("upnp      no gateway responded"),
    }

    if !findings.reachable.is_empty() {
        println!(
            "reach     Public, {} address(es) confirmed",
            findings.reachable.len()
        );
        for addr in &findings.reachable {
            println!("            {addr}");
        }
    } else if findings.unreachable > 0 {
        println!(
            "reach     Private, {} probe(s) failed, so a relay is required",
            findings.unreachable
        );
    } else {
        println!("reach     Unknown, no AutoNAT server answered in time");
    }

    match (&findings.reservation, &findings.circuit) {
        (Some(relay), Some(circuit)) => {
            println!("relay     reserved via {relay}");
            println!("circuit   {circuit}");
        }
        (Some(relay), None) => println!("relay     reserved via {relay}, but no circuit address"),
        (None, _) => println!("relay     no reservation"),
    }

    let Some(peer) = target else {
        let others: HashSet<_> = connectivity
            .connected_peers()
            .map(|(p, _)| *p)
            .filter(|p| *p != server_peer)
            .collect();
        if !others.is_empty() {
            println!("peers     {} connected", others.len());
        }
        return;
    };

    match connectivity.get(&peer) {
        None => match &findings.dial_error {
            Some(why) => println!("path      {peer}: never connected, {why}"),
            None => println!("path      {peer}: never connected (no dial was attempted)"),
        },
        Some(state) => {
            let effective = state.effective_state();
            let how = match effective {
                State::Direct => "DIRECT",
                State::Relayed if state.attempts > 0 => "relayed (hole punch failed)",
                State::Relayed => "relayed (no hole punch result; treating as failed)",
                State::UpgradePending => "relayed (hole punch still pending)",
                State::Disconnected => "disconnected",
            };
            print!("path      {peer}: {how}");
            match state.upgrade_took() {
                Some(took) => println!(" after {:.1}s", took.as_secs_f32()),
                None => println!(),
            }
            println!("attempts  {}", state.attempts);
            println!("why       {}", state.reason);

            if effective.is_relayed() {
                println!();
                println!("Traffic to this peer crosses the relay, which carries it in");
                println!("circuit-sized pieces rather than one stream. Transfers still work;");
                println!("they resume across circuits, and a direct connection is faster.");
            }
        }
    }
}
