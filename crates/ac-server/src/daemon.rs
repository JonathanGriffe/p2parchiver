//! The server's event loop.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result};
use libp2p::futures::StreamExt;
use libp2p::multiaddr::Protocol;
use libp2p::request_response;
use libp2p::swarm::{ConnectionId, Swarm, SwarmEvent};
use libp2p::{PeerId, identify, ping, relay, rendezvous};

use ac_net::attest::{self, Attestation, normalise_username};
use ac_net::config::Config;
use ac_net::identity::Identity;
use ac_net::proto::{
    AttestRefusal, AttestRequest, AttestResponse, EnrollRequest, EnrollResponse,
    MAX_PRESENCE_QUERY, PresenceRequest, PresenceResponse, Refusal,
};
use ac_net::swarm::{AcBehaviour, AcBehaviourEvent, Role, build};

use crate::invite::InviteCode;
use crate::store::{Enrolled, Redemption, Store, now};

/// The server mounts no application layer.
type NoApp = libp2p::swarm::dummy::Behaviour;

/// The value form of [`NoApp`]; a type alias cannot be used as a constructor.
const NO_APP: NoApp = libp2p::swarm::dummy::Behaviour;

/// The service listener's swarm: relay, rendezvous, AutoNAT, attestation renewal, presence.
type ServiceSwarm = Swarm<AcBehaviour<Enrolled, NoApp>>;

/// The enrolment listener's swarm: `/ac/enroll/2.0.0` and nothing else.
type EnrollSwarm = Swarm<AcBehaviour<Store, NoApp>>;

/// Run the server: two listeners, one policy each.
pub async fn run(
    identity: &Identity,
    config: &Config,
    store: Store,
    service_gate: Enrolled,
    enroll_gate: Store,
) -> Result<()> {
    let mut swarm = build(identity, config, Role::Server, service_gate, NO_APP)
        .context("building the service swarm")?;

    if config.listen_enroll.is_empty() {
        anyhow::bail!(
            "no `listen_enroll` addresses configured, so nobody could enrol. \
             Run `ac-server init` to write a starter config, or add the field by hand."
        );
    }
    for addr in &config.listen {
        if addr.to_string().contains("/0/") || addr.to_string().ends_with("/0") {
            tracing::warn!(
                %addr,
                "service listener is on an ephemeral port; clients that enrol now will \
                 be unable to reconnect after a restart. Set a fixed port in config.toml."
            );
        }
    }

    // The enrolment listener binds its own addresses and speaks nothing but enrolment.
    let enroll_config = Config {
        listen: config.listen_enroll.clone(),
        ..Config::default()
    };
    let mut enroll_swarm = build(
        identity,
        &enroll_config,
        Role::Enrollment,
        enroll_gate,
        NO_APP,
    )
    .context("building the enrolment swarm")?;

    println!("peer {}", identity.peer_id());
    tracing::info!(peer = %identity.peer_id(), "server starting");

    let announce_bound = config.external.is_empty();
    for addr in &config.external {
        swarm.add_external_address(addr.clone());
        tracing::info!(%addr, "announcing configured external address");
    }
    if announce_bound {
        tracing::info!(
            "no `external` addresses configured; announcing bound addresses instead. \
             Set `external` in config.toml if this server is behind a NAT or load balancer."
        );
    }

    let mut service_addrs: Vec<libp2p::Multiaddr> = Vec::new();

    let mut links = ServiceLinks::default();

    // Relay use, reported once per sweep rather than per circuit.
    let mut meter = RelayMeter::default();

    let mut tick = tokio::time::interval(HOUSEKEEPING_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = tick.tick() => {
                disconnect_revoked(&mut swarm, &store);
                meter.report();
            }

            event = swarm.select_next_some() => {
                match &event {
                    SwarmEvent::ConnectionEstablished {
                        peer_id, connection_id, endpoint, ..
                    } if endpoint.is_listener() => {
                        if let Some(stale) = links.supersede(*peer_id, *connection_id) {
                            tracing::info!(
                                peer = %peer_id,
                                "reconnected; dropping the previous connection so circuits \
                                 reach the live one"
                            );
                            swarm.close_connection(stale);
                        }
                    }
                    SwarmEvent::ConnectionClosed { peer_id, connection_id, .. } => {
                        links.closed(*peer_id, *connection_id);
                    }
                    _ => {}
                }

                match event {
                    SwarmEvent::Behaviour(AcBehaviourEvent::Relay(event)) => {
                        on_relay(&mut meter, event);
                    }
                    SwarmEvent::Behaviour(AcBehaviourEvent::Attest(event)) => {
                        on_attest(&mut swarm, identity, &store, event);
                    }
                    SwarmEvent::Behaviour(AcBehaviourEvent::Presence(event)) => {
                        on_presence(&mut swarm, event);
                    }
                    SwarmEvent::NewListenAddr { address, listener_id } => {
                        if is_announceable(&address) {
                            service_addrs.push(
                                address.clone().with(Protocol::P2p(identity.peer_id())),
                            );
                            if announce_bound {
                                swarm.add_external_address(address.clone());
                            }
                        }
                        on_event(SwarmEvent::NewListenAddr { address, listener_id });
                    }
                    other => on_event(other),
                }
            }

            event = enroll_swarm.select_next_some() => {
                match event {
                    SwarmEvent::Behaviour(AcBehaviourEvent::Enroll(event)) => {
                        on_enroll(&mut enroll_swarm, identity, &store, &service_addrs, event);
                    }
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!("enrol {address}");
                    }
                    other => tracing::debug!(?other, "enrolment listener event"),
                }
            }

            _ = tokio::signal::ctrl_c() => {
                tracing::info!("interrupted, shutting down");
                return Ok(());
            }
        }
    }
}

/// The one connection each client is currently reachable on.
#[derive(Default)]
struct ServiceLinks {
    current: HashMap<PeerId, ConnectionId>,
}

impl ServiceLinks {
    fn supersede(&mut self, peer: PeerId, id: ConnectionId) -> Option<ConnectionId> {
        match self.current.insert(peer, id) {
            Some(previous) if previous != id => Some(previous),
            _ => None,
        }
    }

    /// Forget a connection, unless it was already replaced by a newer one.
    fn closed(&mut self, peer: PeerId, id: ConnectionId) {
        if self.current.get(&peer) == Some(&id) {
            self.current.remove(&peer);
        }
    }
}

/// Whether a bound address is worth announcing to clients.
fn is_announceable(addr: &libp2p::Multiaddr) -> bool {
    !addr.iter().any(|p| match p {
        libp2p::multiaddr::Protocol::Ip6(ip) => {
            // fe80::/10
            ip.segments()[0] & 0xffc0 == 0xfe80
        }
        _ => false,
    })
}

/// Answer enroll
fn on_enroll(
    swarm: &mut EnrollSwarm,
    identity: &Identity,
    store: &Store,
    service_addrs: &[libp2p::Multiaddr],
    event: request_response::Event<EnrollRequest, EnrollResponse>,
) {
    let request_response::Event::Message {
        peer,
        message: request_response::Message::Request {
            request, channel, ..
        },
        ..
    } = event
    else {
        // Outbound events cannot occur: the server advertises inbound support only.
        tracing::trace!(?event, "enroll event");
        return;
    };

    tracing::debug!(
        count = service_addrs.len(),
        quic = service_addrs
            .iter()
            .filter(|a| a.to_string().contains("quic"))
            .count(),
        "service addresses offered to the enrolling client"
    );
    let response = decide(
        store,
        identity,
        &request.code,
        &request.username,
        &peer,
        service_addrs,
    );

    match &response {
        EnrollResponse::Enrolled { username, .. } => {
            tracing::info!(%peer, %username, "enrolled a client")
        }
        EnrollResponse::Refused(reason) => {
            tracing::warn!(%peer, ?reason, "refused an enrolment")
        }
    }

    let Some(enroll) = swarm.behaviour_mut().enroll.as_mut() else {
        tracing::error!(%peer, "enrolment request on a listener that does not speak it");
        return;
    };
    if enroll.send_response(channel, response).is_err() {
        tracing::warn!(%peer, "client disconnected before the enrolment reply was sent");
    }
}

const HOUSEKEEPING_TICK: Duration = Duration::from_secs(5);

/// Circuits opened per client since the last report.
#[derive(Default)]
struct RelayMeter {
    opened: HashMap<PeerId, u32>,
    closed: u32,
}

impl RelayMeter {
    fn opened(&mut self, src: PeerId) {
        *self.opened.entry(src).or_default() += 1;
    }

    fn closed(&mut self) {
        self.closed += 1;
    }

    /// Log what happened this window and start a fresh one.
    fn report(&mut self) {
        if self.opened.is_empty() && self.closed == 0 {
            return;
        }

        let total: u32 = self.opened.values().sum();
        let busiest = self
            .opened
            .iter()
            .max_by_key(|(_, n)| **n)
            .map(|(peer, n)| (*peer, *n));

        match busiest {
            Some((peer, n)) => tracing::info!(
                circuits_opened = total,
                circuits_closed = self.closed,
                clients = self.opened.len(),
                busiest_client = %peer,
                busiest_circuits = n,
                "relay use"
            ),
            None => tracing::info!(circuits_closed = self.closed, "relay use"),
        }

        self.opened.clear();
        self.closed = 0;
    }
}

/// Close connections held by clients revoked since they connected.
fn disconnect_revoked(swarm: &mut ServiceSwarm, store: &Store) {
    let revoked: Vec<PeerId> = swarm
        .connected_peers()
        .copied()
        .filter(|peer| store.is_revoked(peer))
        .collect();

    for peer in revoked {
        tracing::warn!(%peer, "revoked; closing the connection and any circuits on it");
        let _ = swarm.disconnect_peer_id(peer);
    }
}

/// What the relay saw, including who asked to reach whom.
fn on_relay(meter: &mut RelayMeter, event: relay::Event) {
    match event {
        relay::Event::ReservationReqAccepted {
            src_peer_id,
            renewed,
        } => {
            tracing::info!(peer = %src_peer_id, renewed, "relay reservation granted");
        }
        relay::Event::CircuitReqAccepted {
            src_peer_id,
            dst_peer_id,
        } => {
            meter.opened(src_peer_id);
            tracing::info!(src = %src_peer_id, dst = %dst_peer_id, "relay circuit opened");
        }
        relay::Event::CircuitReqDenied {
            src_peer_id,
            dst_peer_id,
            status,
        } => {
            tracing::info!(
                src = %src_peer_id,
                dst = %dst_peer_id,
                reason = ?status,
                "relay circuit refused"
            );
        }
        relay::Event::CircuitClosed {
            src_peer_id,
            dst_peer_id,
            error,
        } => {
            meter.closed();
            tracing::debug!(
                src = %src_peer_id,
                dst = %dst_peer_id,
                error = ?error,
                "relay circuit closed"
            );
        }
        other => tracing::debug!(?other, "relay event"),
    }
}

/// Issue a fresh attestation to a client that already has one.
fn on_attest(
    swarm: &mut ServiceSwarm,
    identity: &Identity,
    store: &Store,
    event: request_response::Event<AttestRequest, AttestResponse>,
) {
    let request_response::Event::Message {
        peer,
        message: request_response::Message::Request { channel, .. },
        ..
    } = event
    else {
        // Outbound events cannot occur: the service listener advertises inbound only.
        tracing::trace!(?event, "attest event");
        return;
    };

    let response = match store.username_of(&peer) {
        Ok(Some(username)) => {
            match Attestation::issue(
                identity.keypair(),
                &peer,
                &username,
                now(),
                attest::LIFETIME,
            ) {
                Ok(attestation) => {
                    tracing::info!(%peer, %username, "issued an attestation");
                    AttestResponse::Issued(attestation)
                }
                Err(e) => {
                    tracing::error!(%peer, error = %e, "could not sign an attestation");
                    AttestResponse::Refused(AttestRefusal::ServerError)
                }
            }
        }
        Ok(None) => {
            tracing::warn!(%peer, "no username on file; cannot attest");
            AttestResponse::Refused(AttestRefusal::NoUsername)
        }
        Err(e) => {
            tracing::error!(%peer, error = %e, "could not read the username");
            AttestResponse::Refused(AttestRefusal::ServerError)
        }
    };

    let Some(attest) = swarm.behaviour_mut().attest.as_mut() else {
        tracing::error!(%peer, "attestation request on a listener that does not speak it");
        return;
    };
    if attest.send_response(channel, response).is_err() {
        tracing::warn!(%peer, "client disconnected before the attestation was sent");
    }
}

/// Answer "which of these peers are connected to you?".
fn on_presence(
    swarm: &mut ServiceSwarm,
    event: request_response::Event<PresenceRequest, PresenceResponse>,
) {
    let request_response::Event::Message {
        peer,
        message:
            request_response::Message::Request {
                channel,
                request: PresenceRequest::Who(asked),
                ..
            },
        ..
    } = event
    else {
        tracing::trace!(?event, "presence event");
        return;
    };

    let asked_count = asked.len();
    let online: Vec<PeerId> = {
        let connected: std::collections::HashSet<PeerId> =
            swarm.connected_peers().copied().collect();
        asked
            .into_iter()
            .take(MAX_PRESENCE_QUERY)
            .filter(|p| connected.contains(p))
            .collect()
    };

    tracing::debug!(
        %peer,
        asked = asked_count,
        online = online.len(),
        "answered a presence query"
    );

    let Some(presence) = swarm.behaviour_mut().presence.as_mut() else {
        tracing::error!(%peer, "presence query on a listener that does not speak it");
        return;
    };
    if presence
        .send_response(channel, PresenceResponse::Online(online))
        .is_err()
    {
        tracing::warn!(%peer, "client disconnected before the presence answer was sent");
    }
}

/// Pure decision, so the outcomes can be tested without a swarm.
fn decide(
    store: &Store,
    identity: &Identity,
    raw_code: &str,
    raw_username: &str,
    peer: &PeerId,
    service_addrs: &[libp2p::Multiaddr],
) -> EnrollResponse {
    let Ok(code) = InviteCode::parse(raw_code) else {
        return EnrollResponse::Refused(Refusal::Malformed);
    };
    let Ok(username) = normalise_username(raw_username) else {
        return EnrollResponse::Refused(Refusal::InvalidUsername);
    };

    match store.redeem(&code, peer, &username, now()) {
        Ok(Redemption::Enrolled) => {
            match Attestation::issue(identity.keypair(), peer, &username, now(), attest::LIFETIME) {
                Ok(attestation) => EnrollResponse::Enrolled {
                    username,
                    service: service_addrs.to_vec(),
                    attestation,
                },
                Err(e) => {
                    tracing::error!(%peer, error = %e, "enrolled, but could not sign an attestation");
                    EnrollResponse::Refused(Refusal::ServerError)
                }
            }
        }
        Ok(Redemption::UnknownCode) => EnrollResponse::Refused(Refusal::UnknownCode),
        Ok(Redemption::AlreadyRedeemed) => EnrollResponse::Refused(Refusal::AlreadyRedeemed),
        Ok(Redemption::Expired) => EnrollResponse::Refused(Refusal::Expired),
        Ok(Redemption::UsernameTaken) => EnrollResponse::Refused(Refusal::UsernameTaken),
        Err(e) => {
            tracing::error!(%peer, error = %e, "enrolment failed on the database");
            EnrollResponse::Refused(Refusal::ServerError)
        }
    }
}

fn on_event(event: SwarmEvent<AcBehaviourEvent<Enrolled, NoApp>>) {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            println!("listening {address}");
        }

        SwarmEvent::ConnectionEstablished {
            peer_id, endpoint, ..
        } => {
            tracing::info!(
                peer = %peer_id,
                addr = %endpoint.get_remote_address(),
                "client connected"
            );
        }

        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
            tracing::info!(peer = %peer_id, cause = ?cause, "client disconnected");
        }

        SwarmEvent::IncomingConnectionError {
            send_back_addr,
            error,
            ..
        } => {
            // Where a revoked client shows up: the authorizer denies during
            // establishment, so it surfaces here rather than as a closed connection.
            tracing::info!(from = %send_back_addr, %error, "incoming connection refused");
        }

        SwarmEvent::Behaviour(AcBehaviourEvent::Identify(identify::Event::Received {
            peer_id,
            info,
            ..
        })) => {
            tracing::info!(
                peer = %peer_id,
                agent = %info.agent_version,
                observed_addr = %info.observed_addr,
                "identified client"
            );
        }

        SwarmEvent::Behaviour(AcBehaviourEvent::Ping(ping::Event {
            peer,
            result: Ok(rtt),
            ..
        })) => {
            tracing::debug!(peer = %peer, rtt_ms = rtt.as_millis(), "ping");
        }

        SwarmEvent::Behaviour(AcBehaviourEvent::Rendezvous(event)) => match event {
            rendezvous::server::Event::PeerRegistered { peer, registration } => {
                tracing::info!(
                    %peer,
                    namespace = %registration.namespace,
                    ttl = registration.ttl,
                    "registered"
                );
            }
            rendezvous::server::Event::DiscoverServed {
                enquirer,
                registrations,
            } => {
                tracing::info!(%enquirer, found = registrations.len(), "served a discovery");
            }
            rendezvous::server::Event::PeerNotRegistered {
                peer,
                namespace,
                error,
            } => {
                tracing::warn!(%peer, %namespace, ?error, "refused a registration");
            }
            other => tracing::debug!(?other, "rendezvous event"),
        },

        SwarmEvent::Behaviour(AcBehaviourEvent::Autonat(event)) => {
            tracing::info!(?event, "autonat dial-back");
        }

        other => tracing::trace!(?other, "swarm event"),
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn the_relay_meter_reports_then_starts_a_fresh_window() {
        let mut meter = RelayMeter::default();
        let noisy = peer();

        meter.opened(noisy);
        meter.opened(noisy);
        meter.opened(peer());
        meter.closed();

        assert_eq!(meter.opened.len(), 2, "two distinct clients");
        assert_eq!(meter.opened[&noisy], 2);

        meter.report();

        assert!(meter.opened.is_empty(), "the window starts over");
        assert_eq!(meter.closed, 0);
    }

    #[test]
    fn an_idle_meter_reports_nothing() {
        // An idle server logging a zero every five seconds buries the lines that matter.
        let mut meter = RelayMeter::default();
        meter.report();
        assert!(meter.opened.is_empty());
    }
    use super::*;

    #[test]
    fn link_local_addresses_are_not_announced() {
        // fe80::/10 never routes off its own segment, so a client handed one as part of
        // its circuit address can only waste a dial attempt on it.
        for addr in [
            "/ip6/fe80::1/udp/4001/quic-v1",
            "/ip6/fe80::82e7:defe:d7af:b98d/tcp/4001",
            "/ip6/febf::1/tcp/4001",
        ] {
            assert!(
                !is_announceable(&addr.parse().unwrap()),
                "{addr} should be filtered"
            );
        }
    }

    #[test]
    fn routable_addresses_are_announced() {
        for addr in [
            "/ip4/203.0.113.7/udp/4001/quic-v1",
            "/ip6/2a01:e0a:cb6:1f10::1/udp/4001/quic-v1",
            // Kept on purpose: useless to a remote peer, but every local test runs on it.
            "/ip4/127.0.0.1/udp/4001/quic-v1",
        ] {
            assert!(
                is_announceable(&addr.parse().unwrap()),
                "{addr} should be announced"
            );
        }
    }

    #[test]
    fn the_boundary_of_the_link_local_range_is_respected() {
        // fec0::/10 was site-local and is deprecated, but it is *not* link-local, so a
        // naive `fe` prefix check would wrongly drop it.
        assert!(is_announceable(&"/ip6/fec0::1/tcp/4001".parse().unwrap()));
        assert!(!is_announceable(&"/ip6/febf::1/tcp/4001".parse().unwrap()));
    }

    use std::time::Duration;

    use ac_net::authz::AcceptAnyPeer;
    use libp2p::Multiaddr;

    /// Long enough for a loaded CI machine, short enough that a hang fails rather than
    /// blocking forever.
    const GATE_TIMEOUT: Duration = Duration::from_secs(20);

    fn test_identity() -> Identity {
        let dir = tempfile::tempdir().expect("tempdir");
        Identity::load_or_generate(&dir.path().join("identity.key"))
            .expect("identity")
            .0
    }

    /// Loopback only: binding every interface drags in Docker bridges and link-local IPv6.
    fn loopback_config() -> Config {
        Config {
            listen: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().expect("multiaddr")],
            listen_enroll: Vec::new(),
            external: Vec::new(),
            mdns: false,
            server: None,
            storage_root: None,
            storage_max: None,
            bandwidth_max: None,
        }
    }

    async fn first_listen_addr<A: ac_net::authz::PeerAuthorizer>(
        swarm: &mut Swarm<AcBehaviour<A, NoApp>>,
    ) -> Multiaddr {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                return address;
            }
        }
    }

    async fn admits<S, C>(
        server: &mut Swarm<AcBehaviour<S, NoApp>>,
        client: &mut Swarm<AcBehaviour<C, NoApp>>,
        addr: Multiaddr,
        who: PeerId,
    ) -> bool
    where
        S: ac_net::authz::PeerAuthorizer,
        C: ac_net::authz::PeerAuthorizer,
    {
        client.dial(addr).expect("dial starts");

        let settled = async {
            loop {
                tokio::select! {
                    event = server.select_next_some() => match event {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == who => {
                            return true;
                        }
                        SwarmEvent::IncomingConnectionError { .. } => return false,
                        _ => {}
                    },
                    _ = client.select_next_some() => {}
                }
            }
        };

        // A timeout counts as refusal: "nothing ever arrived" is a shape a rejection can
        // legitimately take.
        tokio::time::timeout(GATE_TIMEOUT, settled)
            .await
            .unwrap_or(false)
    }

    #[tokio::test]
    async fn the_service_listener_admits_the_enrolled_and_refuses_everyone_else() {
        let member = test_identity();
        let stranger = test_identity();

        let (store, code) = store_with_invite();
        assert!(
            matches!(
                decide(
                    &store,
                    &test_identity(),
                    &code.to_string(),
                    "alice",
                    &member.peer_id(),
                    &[]
                ),
                EnrollResponse::Enrolled { .. }
            ),
            "the member must start out enrolled"
        );
        assert!(!store.is_enrolled(&stranger.peer_id()));

        let mut server = build(
            &test_identity(),
            &loopback_config(),
            Role::Server,
            Enrolled(store),
            NO_APP,
        )
        .expect("server swarm");
        let addr = first_listen_addr(&mut server).await;

        let member_peer = member.peer_id();
        let mut member_swarm = build(
            &member,
            &loopback_config(),
            Role::Client,
            AcceptAnyPeer,
            NO_APP,
        )
        .expect("member swarm");
        assert!(
            admits(&mut server, &mut member_swarm, addr.clone(), member_peer).await,
            "an enrolled peer must reach the service listener"
        );

        let stranger_peer = stranger.peer_id();
        let mut stranger_swarm = build(
            &stranger,
            &loopback_config(),
            Role::Client,
            AcceptAnyPeer,
            NO_APP,
        )
        .expect("stranger swarm");
        assert!(
            !admits(&mut server, &mut stranger_swarm, addr, stranger_peer).await,
            "an unenrolled peer must be refused before it can negotiate a single protocol \
            otherwise the relay is open to anyone who learns the port"
        );
    }

    /// A control for the test above.
    #[tokio::test]
    async fn the_policy_is_what_refuses_and_not_something_incidental() {
        let stranger = test_identity();
        let stranger_peer = stranger.peer_id();

        let mut open = build(
            &test_identity(),
            &loopback_config(),
            Role::Server,
            AcceptAnyPeer,
            NO_APP,
        )
        .expect("open server swarm");
        let addr = first_listen_addr(&mut open).await;

        let mut stranger_swarm = build(
            &stranger,
            &loopback_config(),
            Role::Client,
            AcceptAnyPeer,
            NO_APP,
        )
        .expect("stranger swarm");

        assert!(
            admits(&mut open, &mut stranger_swarm, addr, stranger_peer).await,
            "with an open policy the very peer refused above must be admitted, or the \
             refusal proves nothing about the policy"
        );
    }

    #[tokio::test]
    async fn peers_that_have_never_met_still_connect_to_each_other() {
        let dialer = test_identity();
        let dialer_peer = dialer.peer_id();

        let mut a = build(
            &dialer,
            &loopback_config(),
            Role::Client,
            AcceptAnyPeer,
            NO_APP,
        )
        .expect("swarm a");
        let mut b = build(
            &test_identity(),
            &loopback_config(),
            Role::Client,
            AcceptAnyPeer,
            NO_APP,
        )
        .expect("swarm b");

        let addr = first_listen_addr(&mut b).await;

        assert!(
            admits(&mut b, &mut a, addr, dialer_peer).await,
            "clients must not filter by identity: a peer with no prior knowledge of the \
             dialer has to accept it, or a returning member can never be handed proof of \
             its own membership"
        );
    }

    #[tokio::test]
    async fn presence_answers_about_the_connected_and_nobody_else() {
        let server_identity = test_identity();
        let alice = test_identity();
        let bob = test_identity();
        // Enrolled, and never connects. The case presence exists to detect.
        let absent = peer();

        let store = Store::in_memory().unwrap();
        for (who, name) in [
            (alice.peer_id(), "alice"),
            (bob.peer_id(), "bob"),
            (absent, "carol"),
        ] {
            let code = InviteCode::generate().unwrap();
            store.create_invite(&code, name, now() + HOUR).unwrap();
            assert!(
                matches!(
                    decide(&store, &server_identity, &code.to_string(), name, &who, &[]),
                    EnrollResponse::Enrolled { .. }
                ),
                "{name} must start out enrolled"
            );
        }

        let mut server = build(
            &server_identity,
            &loopback_config(),
            Role::Server,
            Enrolled(store),
            NO_APP,
        )
        .expect("server swarm");
        let addr = first_listen_addr(&mut server).await;

        let mut alice_swarm = build(
            &alice,
            &loopback_config(),
            Role::Client,
            AcceptAnyPeer,
            NO_APP,
        )
        .expect("alice swarm");
        let mut bob_swarm = build(
            &bob,
            &loopback_config(),
            Role::Client,
            AcceptAnyPeer,
            NO_APP,
        )
        .expect("bob swarm");

        alice_swarm.dial(addr.clone()).expect("alice dials");
        bob_swarm.dial(addr).expect("bob dials");

        let server_peer = server_identity.peer_id();
        let asked = vec![bob.peer_id(), absent];
        let mut connected = std::collections::HashSet::new();
        let mut sent = false;

        let answered = async {
            loop {
                tokio::select! {
                    event = server.select_next_some() => match event {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            connected.insert(peer_id);
                        }
                        SwarmEvent::Behaviour(AcBehaviourEvent::Presence(event)) => {
                            on_presence(&mut server, event);
                        }
                        _ => {}
                    },
                    event = alice_swarm.select_next_some() => {
                        if let SwarmEvent::Behaviour(AcBehaviourEvent::Presence(
                            request_response::Event::Message {
                                message: request_response::Message::Response { response, .. },
                                ..
                            },
                        )) = event
                        {
                            let PresenceResponse::Online(online) = response;
                            return online;
                        }
                    },
                    _ = bob_swarm.select_next_some() => {},
                }

                // Both have to be in before asking, or the answer would be racing the
                // connection rather than reporting it.
                if !sent && connected.len() == 2 {
                    sent = true;
                    alice_swarm
                        .behaviour_mut()
                        .presence
                        .as_mut()
                        .expect("a client speaks presence")
                        .send_request(&server_peer, PresenceRequest::Who(asked.clone()));
                }
            }
        };

        let online = tokio::time::timeout(GATE_TIMEOUT, answered)
            .await
            .expect("the server must answer a presence query");

        assert_eq!(
            online,
            vec![bob.peer_id()],
            "only the connected peer that was asked about"
        );
        assert!(
            !online.contains(&alice.peer_id()),
            "the answer is a filter over what was asked, never a listing of who is connected"
        );
    }

    const HOUR: i64 = 3600;

    fn peer() -> PeerId {
        libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id()
    }

    fn store_with_invite() -> (Store, InviteCode) {
        let store = Store::in_memory().unwrap();
        let code = InviteCode::generate().unwrap();
        store
            .create_invite(&code, "bobs-laptop", now() + HOUR)
            .unwrap();
        (store, code)
    }

    #[test]
    fn a_valid_code_returns_the_username_that_was_asked_for() {
        let (store, code) = store_with_invite();
        let identity = test_identity();
        let p = peer();

        let EnrollResponse::Enrolled {
            username,
            service,
            attestation,
        } = decide(&store, &identity, &code.to_string(), "Alice", &p, &[])
        else {
            panic!("expected an enrolment");
        };

        // Normalised, so the client learns the canonical form of its own name rather than
        // the one it happened to type.
        assert_eq!(username, "alice");
        assert!(service.is_empty());

        let statement = attestation
            .verify(&p, &identity.peer_id(), now())
            .expect("the attestation the server just issued must verify");
        assert_eq!(statement.username, "alice");
    }

    #[test]
    fn the_attestation_is_signed_by_this_server_and_no_other() {
        let (store, code) = store_with_invite();
        let identity = test_identity();
        let p = peer();

        let EnrollResponse::Enrolled { attestation, .. } =
            decide(&store, &identity, &code.to_string(), "alice", &p, &[])
        else {
            panic!("expected an enrolment");
        };

        assert!(
            attestation
                .verify(&p, &test_identity().peer_id(), now())
                .is_err(),
            "an attestation must not verify against an unrelated server's peer id"
        );
    }

    #[test]
    fn a_taken_username_is_refused() {
        let store = Store::in_memory().unwrap();
        let identity = test_identity();
        let first = InviteCode::generate().unwrap();
        let second = InviteCode::generate().unwrap();
        store.create_invite(&first, "a", now() + HOUR).unwrap();
        store.create_invite(&second, "b", now() + HOUR).unwrap();

        decide(&store, &identity, &first.to_string(), "alice", &peer(), &[]);

        assert_eq!(
            decide(
                &store,
                &identity,
                &second.to_string(),
                "alice",
                &peer(),
                &[]
            ),
            EnrollResponse::Refused(Refusal::UsernameTaken)
        );
    }

    #[test]
    fn a_username_that_breaks_the_rules_is_refused_before_the_code_is_spent() {
        let (store, code) = store_with_invite();
        let identity = test_identity();

        for bad in ["ab", "alice smith", "-alice", &"a".repeat(64)] {
            assert_eq!(
                decide(&store, &identity, &code.to_string(), bad, &peer(), &[]),
                EnrollResponse::Refused(Refusal::InvalidUsername),
                "{bad:?}"
            );
        }

        assert!(
            matches!(
                decide(&store, &identity, &code.to_string(), "alice", &peer(), &[]),
                EnrollResponse::Enrolled { .. }
            ),
            "a bad username must not consume the invite"
        );
    }

    #[test]
    fn a_replayed_code_is_distinguished_from_an_unknown_one() {
        // The two deserve different messages: one means "you already used this", the
        // other means "check what you typed".
        let (store, code) = store_with_invite();
        let identity = test_identity();
        decide(&store, &identity, &code.to_string(), "alice", &peer(), &[]);

        assert_eq!(
            decide(&store, &identity, &code.to_string(), "bob", &peer(), &[]),
            EnrollResponse::Refused(Refusal::AlreadyRedeemed)
        );
        assert_eq!(
            decide(
                &store,
                &identity,
                &InviteCode::generate().unwrap().to_string(),
                "carol",
                &peer(),
                &[],
            ),
            EnrollResponse::Refused(Refusal::UnknownCode)
        );
    }

    #[test]
    fn an_expired_code_is_refused() {
        let store = Store::in_memory().unwrap();
        let code = InviteCode::generate().unwrap();
        store.create_invite(&code, "stale", now() - 1).unwrap();

        assert_eq!(
            decide(
                &store,
                &test_identity(),
                &code.to_string(),
                "alice",
                &peer(),
                &[]
            ),
            EnrollResponse::Refused(Refusal::Expired)
        );
    }

    #[test]
    fn something_that_is_not_a_code_is_refused_as_malformed() {
        let store = Store::in_memory().unwrap();
        let identity = test_identity();
        for junk in ["", "hello", "AAAA-BBBB", "!!!!-!!!!-!!!!-!!!!"] {
            assert_eq!(
                decide(&store, &identity, junk, "alice", &peer(), &[]),
                EnrollResponse::Refused(Refusal::Malformed),
                "{junk:?}"
            );
        }
    }

    #[test]
    fn a_mistyped_but_recoverable_code_still_works() {
        // Crockford normalisation happens before the lookup, so lowercase and missing
        // dashes reach the database as the same code.
        let (store, code) = store_with_invite();
        let mangled = code.to_string().to_lowercase().replace('-', "");

        assert!(matches!(
            decide(&store, &test_identity(), &mangled, "alice", &peer(), &[]),
            EnrollResponse::Enrolled { .. }
        ));
    }

    #[test]
    fn enrolment_admits_the_peer_that_asked_and_no_other() {
        let (store, code) = store_with_invite();
        let asker = peer();
        let bystander = peer();

        decide(
            &store,
            &test_identity(),
            &code.to_string(),
            "alice",
            &asker,
            &[],
        );

        assert!(store.is_enrolled(&asker));
        assert!(!store.is_enrolled(&bystander));
    }

    #[test]
    fn a_renewed_attestation_verifies_just_like_the_first() {
        // Renewal reads the stored username rather than being told one, so this is also
        // the check that enrolment and renewal agree on the name.
        let (store, code) = store_with_invite();
        let identity = test_identity();
        let p = peer();
        decide(&store, &identity, &code.to_string(), "alice", &p, &[]);

        let username = store.username_of(&p).unwrap().expect("a username on file");
        let renewed =
            Attestation::issue(identity.keypair(), &p, &username, now(), attest::LIFETIME).unwrap();

        let statement = renewed.verify(&p, &identity.peer_id(), now()).unwrap();
        assert_eq!(statement.username, "alice");
    }

    #[test]
    fn a_first_connection_displaces_nothing() {
        let mut links = ServiceLinks::default();
        assert_eq!(
            links.supersede(peer(), ConnectionId::new_unchecked(1)),
            None
        );
    }

    #[test]
    fn reconnecting_displaces_the_previous_connection() {
        let mut links = ServiceLinks::default();
        let p = peer();
        let first = ConnectionId::new_unchecked(1);

        links.supersede(p, first);

        assert_eq!(
            links.supersede(p, ConnectionId::new_unchecked(2)),
            Some(first),
            "the stale connection must be handed back so it can be closed"
        );
    }

    #[test]
    fn one_peer_reconnecting_leaves_another_alone() {
        let mut links = ServiceLinks::default();
        let (a, b) = (peer(), peer());

        links.supersede(a, ConnectionId::new_unchecked(1));
        links.supersede(b, ConnectionId::new_unchecked(2));

        assert_eq!(
            links.supersede(a, ConnectionId::new_unchecked(3)),
            Some(ConnectionId::new_unchecked(1))
        );
        assert_eq!(
            links.supersede(b, ConnectionId::new_unchecked(4)),
            Some(ConnectionId::new_unchecked(2))
        );
    }

    /// Evicting makes the old connection close, and that close arrives *after* the
    /// replacement was recorded. If it removed the entry, the next reconnection would find
    /// nothing to displace and the stale-routing bug would come straight back.
    #[test]
    fn the_evicted_connection_closing_does_not_forget_its_replacement() {
        let mut links = ServiceLinks::default();
        let p = peer();
        let (first, second) = (
            ConnectionId::new_unchecked(1),
            ConnectionId::new_unchecked(2),
        );

        links.supersede(p, first);
        links.supersede(p, second);
        links.closed(p, first); // the eviction landing, out of order

        assert_eq!(
            links.supersede(p, ConnectionId::new_unchecked(3)),
            Some(second),
            "the live connection must still be tracked after the evicted one closes"
        );
    }

    #[test]
    fn a_clean_disconnect_is_forgotten() {
        let mut links = ServiceLinks::default();
        let p = peer();
        let only = ConnectionId::new_unchecked(1);

        links.supersede(p, only);
        links.closed(p, only);

        assert_eq!(
            links.supersede(p, ConnectionId::new_unchecked(2)),
            None,
            "a peer that left properly has nothing to displace when it returns"
        );
    }
}
