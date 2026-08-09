//! The server's event loop.
//!
//! Structurally the same as the client's: `ac-net` owns the protocols, this drives them.
//! The differences are the role (which behaviours are enabled) and the policy handed to
//! the authorizer — here, the enrollment database.

use std::collections::HashMap;

use anyhow::{Context, Result};
use libp2p::futures::StreamExt;
use libp2p::multiaddr::Protocol;
use libp2p::request_response;
use libp2p::swarm::{ConnectionId, Swarm, SwarmEvent};
use libp2p::{PeerId, identify, ping, relay, rendezvous};

use ac_net::config::Config;
use ac_net::identity::Identity;
use ac_net::proto::{EnrollRequest, EnrollResponse, Refusal};
use ac_net::swarm::{AcBehaviour, AcBehaviourEvent, Role, build};

use crate::invite::InviteCode;
use crate::store::{Enrolled, Redemption, Store, now};

/// Run the server: two listeners, one policy each.
///
/// | | admits | speaks |
/// | --- | --- | --- |
/// | enrolment | anyone | `/ac/enroll/1.0.0` |
/// | service | enrolled peers only | relay, rendezvous, AutoNAT |
///
/// One listener could not do this. Strangers must reach enrolment, and only members may
/// reach the services — contradictory policies for a single admission check, which is why
/// services previously had to be gated one protocol at a time and why rendezvous was
/// left answering anybody. Split, each listener holds a policy that is uniformly correct,
/// and anything added to the service listener later is behind the gate by construction.
///
/// Three database handles, deliberately: each swarm's authorizer owns one for the
/// process's lifetime, and `store` stays here for enrolment. WAL supports concurrent
/// handles, and this is the same arrangement the admin CLI already uses.
pub async fn run(
    identity: &Identity,
    config: &Config,
    store: Store,
    service_gate: Enrolled,
    enroll_gate: Store,
) -> Result<()> {
    let mut swarm = build(identity, config, Role::Server, service_gate)
        .context("building the service swarm")?;

    if config.listen_enroll.is_empty() {
        anyhow::bail!(
            "no `listen_enroll` addresses configured, so nobody could enrol. \
             Run `ac-server init` to write a starter config, or add the field by hand."
        );
    }
    // Any service address on an ephemeral port is a trap rather than a mistake: it works
    // now and orphans every enrolled client the next time this process restarts, because
    // a client stores the service address at enrolment and has no way to be told a new
    // one.
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
    let mut enroll_swarm = build(identity, &enroll_config, Role::Enrollment, enroll_gate)
        .context("building the enrolment swarm")?;

    println!("peer {}", identity.peer_id());
    tracing::info!(peer = %identity.peer_id(), "server starting");

    // Without these the relay has nothing to put in front of a client's peer id, so a
    // reservation is accepted and then fails with `NoAddressesInReservation`. libp2p never
    // promotes a listen address on its own — binding `0.0.0.0` says nothing about how the
    // world reaches you, which is the whole reason AutoNAT exists — and this server runs
    // the AutoNAT *server*, so nothing is confirming its own addresses either.
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

    // Addresses the service listener bound, handed to each client when it enrols so it
    // knows where to go next. Grows as listeners resolve, which is why enrolment answers
    // with whatever is known at the time rather than a fixed list.
    let mut service_addrs: Vec<libp2p::Multiaddr> = Vec::new();

    // Which connection each client is currently reachable on, so a reconnection can
    // displace the connection it replaced rather than waiting for a timeout to notice.
    let mut links = ServiceLinks::default();

    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                // Inspected before dispatch: closing a superseded connection needs the
                // swarm, which the reporting path deliberately does not get.
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
                    // Enrolment cannot arrive here — the service listener does not speak
                    // it — so the only events needing the swarm are relay grants.
                    SwarmEvent::Behaviour(AcBehaviourEvent::Relay(event)) => {
                        on_relay(event);
                    }
                    // Promote each bound address as it appears, when the operator has not
                    // said otherwise. Done here rather than at startup because listeners
                    // resolve asynchronously — `0.0.0.0` becomes one address per interface,
                    // and none of them exist yet when `build` returns.
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
                        on_enroll(&mut enroll_swarm, &store, &service_addrs, event);
                    }
                    SwarmEvent::NewListenAddr { address, .. } => {
                        // Printed, not logged: this is the address that goes into invites.
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
///
/// A node that dies without closing its connection — a crash, a laptop suspending, a
/// network dropping — leaves the server believing it is still there for as long as the
/// ping timeout takes to notice, around fifteen seconds. When the node comes back it gets
/// a *new* connection and a fresh relay reservation, and both are granted, so everything
/// looks healthy from every side. But circuits keep being delivered into the dead
/// connection, so the restarted node never sees them and dialers get "Relay failed to
/// connect to destination" — indistinguishable from the peer simply being offline.
///
/// A client needs exactly one service connection, so a second inbound one is near proof
/// the first is gone. Closing the older one immediately makes the relay route to the live
/// connection instead of waiting to discover the corpse.
///
/// Inbound only. AutoNAT's dial-back is the server connecting *out* to a client to test
/// its reachability, and that legitimately coexists with the client's own connection —
/// evicting on it would break the very probe it comes from. Circuits add no connections
/// of their own; they ride as streams on the connection a peer already has.
#[derive(Default)]
struct ServiceLinks {
    current: HashMap<PeerId, ConnectionId>,
}

impl ServiceLinks {
    /// Record a new inbound connection, returning the one it displaces.
    fn supersede(&mut self, peer: PeerId, id: ConnectionId) -> Option<ConnectionId> {
        match self.current.insert(peer, id) {
            Some(previous) if previous != id => Some(previous),
            _ => None,
        }
    }

    /// Forget a connection, unless it was already replaced by a newer one.
    ///
    /// The check matters: evicting a stale connection makes it close, and that close
    /// arrives *after* the replacement was recorded. Removing blindly would erase the
    /// live entry and let the next reconnection skip the eviction entirely.
    fn closed(&mut self, peer: PeerId, id: ConnectionId) {
        if self.current.get(&peer) == Some(&id) {
            self.current.remove(&peer);
        }
    }
}

/// Whether a bound address is worth announcing to clients.
///
/// Every announced address becomes a prefix on *every* reserving client's circuit
/// address, so junk here multiplies. Link-local addresses are never routable off their
/// own segment, so a remote peer that tries one only wastes a dial attempt — and stage 9
/// will spend those attempts hole punching, where they are not free.
///
/// Loopback is deliberately kept: it is equally useless to a remote peer, but it is what
/// every local test runs on, and a server announcing it is not leaking anything a client
/// could not already see.
fn is_announceable(addr: &libp2p::Multiaddr) -> bool {
    !addr.iter().any(|p| match p {
        libp2p::multiaddr::Protocol::Ip6(ip) => {
            // fe80::/10
            ip.segments()[0] & 0xffc0 == 0xfe80
        }
        _ => false,
    })
}

/// Answer `/ac/enroll/1.0.0`.
///
/// `peer` comes from the connection, not the message — libp2p proved it during the
/// handshake, so the enrolling client cannot claim to be anyone else.
fn on_enroll(
    swarm: &mut Swarm<AcBehaviour<Store>>,
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
    let response = decide(store, &request.code, &peer, service_addrs);

    match &response {
        EnrollResponse::Enrolled { label, .. } => {
            tracing::info!(%peer, %label, "enrolled a client")
        }
        EnrollResponse::Refused(reason) => {
            tracing::warn!(%peer, ?reason, "refused an enrolment")
        }
    }

    let Some(enroll) = swarm.behaviour_mut().enroll.as_mut() else {
        // Unreachable: only the enrolment listener receives these, and it always has the
        // behaviour. Handled rather than unwrapped because a panic here kills the daemon.
        tracing::error!(%peer, "enrolment request on a listener that does not speak it");
        return;
    };
    if enroll.send_response(channel, response).is_err() {
        tracing::warn!(%peer, "client disconnected before the enrolment reply was sent");
    }
}

/// Report relay activity.
///
/// There is no enrolment check here any more, and that is the point of splitting the
/// listeners. The relay lives on the service listener, which refuses an unenrolled peer
/// during connection establishment, so a reservation request can only ever come from a
/// client that is already enrolled. The previous reactive gate — grant, notice, disconnect
/// — existed solely because one listener had to admit strangers so they could enrol.
///
/// # What milestone 2 changes
///
/// Enrolment is checked when the connection is made and not again. Today a circuit dies
/// after 128 KiB or two minutes, so a stale authorization cannot outlive much. Raise that
/// cap to carry a gigabyte over an hour and a peer revoked mid-transfer keeps relaying for
/// the rest of it, because nothing re-asks. Periodically re-checking live circuits is the
/// requirement that arrives with media.
fn on_relay(event: relay::Event) {
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
            tracing::info!(src = %src_peer_id, dst = %dst_peer_id, "relay circuit opened");
        }
        other => tracing::debug!(?other, "relay event"),
    }
}

/// Pure decision, so the outcomes can be tested without a swarm.
fn decide(
    store: &Store,
    raw_code: &str,
    peer: &PeerId,
    service_addrs: &[libp2p::Multiaddr],
) -> EnrollResponse {
    let Ok(code) = InviteCode::parse(raw_code) else {
        return EnrollResponse::Refused(Refusal::Malformed);
    };

    match store.redeem(&code, peer, now()) {
        Ok(Redemption::Enrolled) => {
            let label = store
                .list_clients()
                .ok()
                .and_then(|clients| clients.into_iter().find(|c| &c.peer == peer))
                .map(|c| c.label)
                .unwrap_or_default();
            EnrollResponse::Enrolled {
                label,
                service: service_addrs.to_vec(),
            }
        }
        Ok(Redemption::UnknownCode) => EnrollResponse::Refused(Refusal::UnknownCode),
        Ok(Redemption::AlreadyRedeemed) => EnrollResponse::Refused(Refusal::AlreadyRedeemed),
        Ok(Redemption::Expired) => EnrollResponse::Refused(Refusal::Expired),
        Err(e) => {
            // Never report a database fault as "wrong code" — the admin needs to see it,
            // and the client should not be told to check something that is not the cause.
            tracing::error!(%peer, error = %e, "enrolment failed on the database");
            EnrollResponse::Refused(Refusal::UnknownCode)
        }
    }
}

fn on_event(event: SwarmEvent<AcBehaviourEvent<Enrolled>>) {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            // A server's addresses are meant to be shared — this is what goes into an
            // invite, so print rather than log.
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

        // Rendezvous and AutoNAT are left ungated. Both are cheap — a registration is a
        // row and a lookup is a read, and an AutoNAT dial-back is one short outbound
        // connection — so their own quotas are a better fit than an identity check, which
        // would cost a database read on every request to protect almost nothing.
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

    // ---------------------------------------------------------------- the gate
    //
    // The two tests below are the ones that prove the architecture, and they are
    // deliberately a matched pair. The first says the service listener admits only
    // enrolled peers. The second says that once admitted, peers do *not* apply the same
    // rule to each other.
    //
    // Weakening either one breaks the design in a way that is invisible until much later.
    // Losing the first turns the relay into an open one for anybody who learns the port.
    // Losing the second — by giving clients an identity filter that "matches the server's"
    // — deadlocks membership: a member returning after an absence has to be handed a
    // membership proof by peers it does not yet recognise, and a client that refuses
    // strangers can never receive one.

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
        }
    }

    async fn first_listen_addr<A: ac_net::authz::PeerAuthorizer>(
        swarm: &mut Swarm<AcBehaviour<A>>,
    ) -> Multiaddr {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                return address;
            }
        }
    }

    /// Dial `addr` from `client`, driving `server` so it can answer, and report whether
    /// the *server* admitted `who`.
    ///
    /// The verdict is read from the listening side on purpose. A denial happens in the
    /// behaviour, after the transport handshake has already succeeded, so the dialer sees
    /// `ConnectionEstablished` followed by a close — asking the dialer whether it got in
    /// reports "yes" for a peer that was in fact refused. The server is the only side that
    /// knows, and it says so as `IncomingConnectionError`.
    ///
    /// Both swarms must still be polled: a connection needs the listening side to make
    /// progress, so driving only the dialer would time out whatever the policy.
    async fn admits<S, C>(
        server: &mut Swarm<AcBehaviour<S>>,
        client: &mut Swarm<AcBehaviour<C>>,
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
                decide(&store, &code.to_string(), &member.peer_id(), &[]),
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
        )
        .expect("server swarm");
        let addr = first_listen_addr(&mut server).await;

        let member_peer = member.peer_id();
        let mut member_swarm =
            build(&member, &loopback_config(), Role::Client, AcceptAnyPeer).expect("member swarm");
        assert!(
            admits(&mut server, &mut member_swarm, addr.clone(), member_peer).await,
            "an enrolled peer must reach the service listener"
        );

        let stranger_peer = stranger.peer_id();
        let mut stranger_swarm = build(&stranger, &loopback_config(), Role::Client, AcceptAnyPeer)
            .expect("stranger swarm");
        assert!(
            !admits(&mut server, &mut stranger_swarm, addr, stranger_peer).await,
            "an unenrolled peer must be refused before it can negotiate a single protocol \
             — otherwise the relay is open to anyone who learns the port"
        );
    }

    /// A control for the test above.
    ///
    /// The same unenrolled peer, dialling the same kind of listener, gets in when the
    /// policy is open. Without this, a refusal caused by something incidental — a bind
    /// that failed, a dial that never started — would read exactly like the gate working,
    /// and the test would keep passing after the gate was gone.
    #[tokio::test]
    async fn the_policy_is_what_refuses_and_not_something_incidental() {
        let stranger = test_identity();
        let stranger_peer = stranger.peer_id();

        let mut open = build(
            &test_identity(),
            &loopback_config(),
            Role::Server,
            AcceptAnyPeer,
        )
        .expect("open server swarm");
        let addr = first_listen_addr(&mut open).await;

        let mut stranger_swarm = build(&stranger, &loopback_config(), Role::Client, AcceptAnyPeer)
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

        let mut a =
            build(&dialer, &loopback_config(), Role::Client, AcceptAnyPeer).expect("swarm a");
        let mut b = build(
            &test_identity(),
            &loopback_config(),
            Role::Client,
            AcceptAnyPeer,
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
    fn a_valid_code_returns_the_label_from_the_invite() {
        let (store, code) = store_with_invite();
        assert_eq!(
            decide(&store, &code.to_string(), &peer(), &[]),
            EnrollResponse::Enrolled {
                label: "bobs-laptop".to_owned(),
                service: Vec::new(),
            }
        );
    }

    #[test]
    fn a_replayed_code_is_distinguished_from_an_unknown_one() {
        // The two deserve different messages: one means "you already used this", the
        // other means "check what you typed".
        let (store, code) = store_with_invite();
        decide(&store, &code.to_string(), &peer(), &[]);

        assert_eq!(
            decide(&store, &code.to_string(), &peer(), &[]),
            EnrollResponse::Refused(Refusal::AlreadyRedeemed)
        );
        assert_eq!(
            decide(
                &store,
                &InviteCode::generate().unwrap().to_string(),
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
            decide(&store, &code.to_string(), &peer(), &[]),
            EnrollResponse::Refused(Refusal::Expired)
        );
    }

    #[test]
    fn something_that_is_not_a_code_is_refused_as_malformed() {
        let store = Store::in_memory().unwrap();
        for junk in ["", "hello", "AAAA-BBBB", "!!!!-!!!!-!!!!-!!!!"] {
            assert_eq!(
                decide(&store, junk, &peer(), &[]),
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
            decide(&store, &mangled, &peer(), &[]),
            EnrollResponse::Enrolled { .. }
        ));
    }

    #[test]
    fn enrolment_admits_the_peer_that_asked_and_no_other() {
        let (store, code) = store_with_invite();
        let asker = peer();
        let bystander = peer();

        decide(&store, &code.to_string(), &asker, &[]);

        assert!(store.is_enrolled(&asker));
        assert!(!store.is_enrolled(&bystander));
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
