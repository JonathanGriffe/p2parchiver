//! Construction of the libp2p swarm both binaries drive.
//!
//! One [`AcBehaviour`] serves both roles. Behaviours that only make sense on one side get
//! toggled off on the other rather than living in a second type, so the client and the
//! server always speak the same protocol set and there is one place to look when they
//! disagree about it.
//!
//! This module decides nothing about *who* may connect — that is the binaries' job, via
//! the `PeerAuthorizer` they supply.
//!
//! # What belongs here, and what does not
//!
//! Everything in [`AcBehaviour`] answers one of two questions: **can we talk** (identify,
//! ping, relay, rendezvous, AutoNAT, DCUtR, mDNS, UPnP) or **should we** (enrol, attest,
//! peer-attest, and the authorizer). What a node then *does* over a verified connection is
//! not this crate's business.
//!
//! That distinction is load-bearing rather than tidy-minded. Rust only lets a field be added
//! to a struct from the crate that defines it, so without an escape hatch every application
//! protocol would have to be declared here — dragging its wire types, and transitively its
//! whole model, into the networking crate, and making the server compile code it never runs.
//!
//! [`AcBehaviour::app`] is that escape hatch: a generic slot the binary fills in. `ac-net`
//! never names what goes in it. `ac-server` passes `dummy::Behaviour` and provably cannot
//! receive an application event; `ac-node` will pass the group protocol from `ac-groups`.
//!
//! **Do not "simplify" the parameter away** by declaring an application protocol here. It is
//! the boundary that keeps the group layer — and whatever follows it — out of the networking
//! crate. `tests/app_slot.rs` exercises it with a protocol defined outside `ac-net`.

use std::time::Duration;

use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::NetworkBehaviour;
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::{
    StreamProtocol, Swarm, SwarmBuilder, autonat, connection_limits, identify, noise, ping, relay,
    rendezvous, tcp, yamux,
};

use crate::authz::{self, PeerAuthorizer};
use crate::config::Config;
use crate::identity::Identity;
use crate::limits;
use crate::proto::{
    ATTEST_PROTOCOL, AttestRequest, AttestResponse, ENROLL_PROTOCOL, EnrollRequest, EnrollResponse,
    PEER_ATTEST_PROTOCOL, PeerAttestRequest, PeerAttestResponse,
};

/// How long a connection with no active streams is held open.
///
/// Generous on purpose: tearing down an idle connection throws away a hole punch that may
/// have taken seconds to land and cannot be assumed to succeed a second time. Not a user
/// setting until something shows it needs to be one.
const IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);

/// How often each connection is pinged.
///
/// Two things depend on this that its name does not suggest:
///
/// **It is the NAT keepalive.** A quiet connection carries no other traffic, and a UDP
/// mapping on consumer hardware can lapse after as little as 30 seconds idle — RFC 4787
/// asks for two minutes, which plenty of routers ignore. At 25 seconds a single *lost*
/// ping leaves a 50-second gap, long enough for such a router to drop the mapping and make
/// the peer unreachable until something redials.
///
/// **It bounds failure detection.** QUIC has no close signal when a process dies, so a
/// dead peer is noticed only when a ping times out. Raising this slows reconnection by
/// roughly the same amount.
const PING_INTERVAL: Duration = Duration::from_secs(25);

/// Which side of the network this process is. Fixed by the binary, not by config.
///
/// The server runs **two** swarms, because one listener cannot hold two contradictory
/// policies at once: strangers must be able to reach enrolment, and only members may
/// reach the services. Splitting them lets each listener have a policy that is uniformly
/// correct, so the service side can refuse an unenrolled peer during connection
/// establishment — before a single protocol is negotiated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// A user's node: dials out, punches holes, uses someone else's relay.
    Client,
    /// The service listener: relay, rendezvous, AutoNAT. Admits enrolled peers only.
    Server,
    /// The enrolment listener: `/ac/enroll/2.0.0` and nothing else. Admits anyone,
    /// because a peer that has not enrolled yet is exactly who needs to reach it.
    Enrollment,
}

impl Role {
    /// Reported by `identify`, so `ac probe` and logs can tell what a peer is running.
    fn agent_version(self) -> String {
        let side = match self {
            Role::Client => "client",
            Role::Server => "server",
            Role::Enrollment => "enrol",
        };
        format!("ac/{} ({side})", env!("CARGO_PKG_VERSION"))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SwarmError {
    #[error("could not configure the TCP transport")]
    Tcp(#[source] noise::Error),
    #[error("could not configure DNS resolution")]
    Dns(#[source] std::io::Error),
    #[error("could not configure the relay client transport")]
    Relay(#[source] noise::Error),
    #[error("none of the {attempted} configured listen addresses could be bound")]
    NoListenAddr { attempted: usize },
}

/// The protocols this node speaks.
///
/// Generic over two things. `A` is the authorization policy, so both binaries share one
/// behaviour type: the server supplies its allowlist, the client supplies
/// [`authz::AcceptAnyPeer`]. `X` is the application layer — see [`AcBehaviour::app`].
#[derive(NetworkBehaviour)]
pub struct AcBehaviour<A: PeerAuthorizer, X: NetworkBehaviour> {
    /// Caps on connection count. Listed first so a connection over budget is refused
    /// before the rest of the behaviours are asked about it.
    pub connection_limits: connection_limits::Behaviour,
    /// Backstop on memory, since a few large transfers can outweigh many idle peers.
    pub memory_limits: libp2p::memory_connection_limits::Behaviour,
    /// Identity-based admission. Meaningful on the server; permissive on clients.
    pub authz: authz::Behaviour<A>,
    /// Exchanges peer metadata and, crucially, reports the address a peer sees us at.
    /// AutoNAT and DCUtR are both built on those observed addresses, so this stays on
    /// in every role.
    pub identify: identify::Behaviour,
    /// Liveness and round-trip time — and, less obviously, the NAT keepalive.
    ///
    /// See [`PING_INTERVAL`]: this is the only traffic a quiet connection carries, so it
    /// is what keeps a UDP mapping open and what determines how fast a dead peer is
    /// noticed. Both are consequences of a setting whose name mentions neither.
    pub ping: ping::Behaviour,
    /// `/ac/enroll/2.0.0`. Present only where it belongs: outbound on a client, inbound
    /// on the enrolment listener, and **absent entirely on the service listener** — which
    /// is what lets that listener demand enrollment of everyone who connects.
    pub enroll: Toggle<request_response::cbor::Behaviour<EnrollRequest, EnrollResponse>>,

    /// `/ac/attest/1.0.0` — attestation renewal. Outbound on a client, inbound on the
    /// service listener, absent on enrolment.
    ///
    /// On the *service* listener rather than the enrolment one, which is what makes
    /// revocation self-enforcing: that listener admits enrolled peers only, so a revoked
    /// client cannot ask for a fresh attestation and the one it holds simply expires.
    pub attest: Toggle<request_response::cbor::Behaviour<AttestRequest, AttestResponse>>,

    /// `/ac/peer-attest/1.0.0` — the mutual check between two clients. Clients only.
    ///
    /// [`ProtocolSupport::Full`] on both sides because the exchange is symmetric: each peer
    /// sends its own attestation and answers with a verdict on the other's, so neither is
    /// the interrogator.
    pub peer_attest:
        Toggle<request_response::cbor::Behaviour<PeerAttestRequest, PeerAttestResponse>>,

    /// Circuit relay v2, server side. Off on clients.
    ///
    /// Left at libp2p's defaults, which cap a circuit at 128 KiB over 2 minutes with
    /// per-peer and per-IP rate limits. That is deliberate: the relay here is a
    /// *coordination* service, sized for DCUtR to agree on a hole punch, not a data pipe.
    /// Enrolment is enforced reactively on `ReservationReqAccepted` rather than by
    /// withholding the protocol, because at 128 KiB there is little worth stealing.
    ///
    /// Raising this cap to carry media in milestone 2 is the moment that stops being
    /// true, and the moment stronger gating has to arrive with it.
    pub relay: Toggle<relay::Behaviour>,

    /// Rendezvous server: the address directory. Off on clients.
    ///
    /// Namespaces are opaque strings here, which is what lets clients hash them from a
    /// group secret in stage 8 without the server's cooperation.
    pub rendezvous: Toggle<rendezvous::server::Behaviour>,

    /// AutoNAT v2 server: dials a client back so it can learn whether it is publicly
    /// reachable. Off on clients, which run the client half below.
    ///
    /// v2 rather than v1 because v1 could be induced to send far more than it received,
    /// making it a usable amplifier for reflection attacks.
    pub autonat: Toggle<autonat::v2::server::Behaviour>,

    /// Asks a gateway to forward a port. Off on servers, which are already reachable.
    ///
    /// The cheapest possible outcome: a mapped port makes this node directly dialable,
    /// so no relay and no hole punch are needed at all. Most home routers either lack
    /// IGD or have it disabled, so treat success as a bonus rather than a plan.
    pub upnp: Toggle<libp2p::upnp::tokio::Behaviour>,

    /// Asks servers to dial us back, to find out whether we are publicly reachable.
    ///
    /// Its input is the observed addresses `identify` collects; its output is a confirmed
    /// external address, which is what a relay reservation and DCUtR both build on.
    pub autonat_client: Toggle<autonat::v2::client::Behaviour>,

    /// Publishes our addresses to the server and looks up other peers'. Off on servers,
    /// which run the registry half.
    ///
    /// Registration requires at least one *external* address, so on a NATed node it
    /// cannot happen until the relay reservation has produced a circuit address.
    pub rendezvous_client: Toggle<rendezvous::client::Behaviour>,

    /// Finds peers on the local segment without the server. Off on servers, and off on
    /// clients that set `mdns = false`.
    ///
    /// The one discovery path that needs no infrastructure at all, and the one that makes
    /// the commonest case — two family devices on the same wifi — direct rather than
    /// relayed through a machine on another continent.
    pub mdns: Toggle<libp2p::mdns::tokio::Behaviour>,

    /// Upgrades a relayed connection to a direct one by hole punching. Off on servers,
    /// which are reachable already.
    ///
    /// Needs no prompting: it starts the moment a relayed connection appears, using the
    /// relay purely to exchange addresses and agree on timing. Both peers then dial each
    /// other simultaneously, so each one's outbound packet opens a path for the other's
    /// inbound. The relay carries none of the result.
    pub dcutr: Toggle<libp2p::dcutr::Behaviour>,

    /// Lets this node reserve a slot on a relay and be dialled through it.
    ///
    /// Constructed by the swarm builder rather than by us, because reserving also
    /// requires a matching transport — `/p2p-circuit` addresses have to be dialable, not
    /// just representable.
    pub relay_client: Toggle<relay::client::Behaviour>,

    /// The application layer's protocol, chosen by the binary rather than named here.
    ///
    /// # Why this is a hole and not a field
    ///
    /// Everything above is a *connectivity or admission* concern — "can we talk, and should
    /// we". What a node does over an established, verified connection is somebody else's
    /// business, and Rust only lets a field be added from the crate that defines the struct.
    /// Without this slot, every application protocol would have to be declared in `ac-net`,
    /// which would drag its wire types — and transitively its whole model — into the
    /// networking crate, and make the server compile code it never runs.
    ///
    /// So `ac-net` never names what goes here. It stores the value and lets the derive do
    /// the rest: create the handler per connection, poll it, and wrap whatever it emits as
    /// `AcBehaviourEvent::App`. A binary with no application layer passes
    /// [`libp2p::swarm::dummy::Behaviour`], whose `ToSwarm` is [`std::convert::Infallible`] —
    /// so on the server that event variant is uninhabited and the compiler, not a runtime
    /// check, proves no application event can arrive.
    ///
    /// # Two rules for whatever is mounted here
    ///
    /// **It must not refuse connections.** [`NetworkBehaviour`] exposes
    /// `handle_established_inbound_connection`, so an app behaviour *could* deny a peer. It
    /// must not: that is exactly the deadlock [`crate::authz`] spends its module docs on,
    /// where the peer able to deliver your membership proof is the one being turned away.
    /// Admission belongs to [`authz`]; the app layer authorizes data on a live connection.
    ///
    /// **Its protocol names are public.** Mounting a behaviour advertises them through
    /// `identify`, so a peer can see *that* this node runs a given application protocol. It
    /// never reveals what the node does with it, but a protocol name is not a secret.
    pub app: X,
}

impl<A: PeerAuthorizer, X: NetworkBehaviour> AcBehaviour<A, X> {
    fn new(
        keypair: &libp2p::identity::Keypair,
        config: &Config,
        role: Role,
        authorizer: A,
        relay_client: relay::client::Behaviour,
        app: X,
    ) -> Self {
        let peer_id = keypair.public().to_peer_id();
        let is_server = role == Role::Server;
        let is_client = role == Role::Client;
        // `protocol_version` is a label peers display, not a compatibility gate — libp2p
        // never rejects a connection over it. Version enforcement comes from the
        // per-protocol names (`/ac/enroll/2.0.0` and friends), which multistream-select
        // actually negotiates, so an incompatible peer fails cleanly on that protocol
        // rather than on the connection.
        // `hide_listen_addrs` drops the "here is where I can be reached" half of identify
        // while keeping `observed_addr`, the "here is how I see you" half that AutoNAT and
        // DCUtR are built on. Rendezvous is this design's address-distribution channel and
        // it is gated by enrollment; advertising the same addresses to anyone who connects
        // would be a second, ungated copy of it. External addresses — the AutoNAT-confirmed
        // public one and the relay circuit — are still sent, so reachability is unchanged.
        let identify_config = identify::Config::new("ac/0.1".to_owned(), keypair.public())
            .with_agent_version(role.agent_version())
            .with_hide_listen_addrs(true);

        // A client only ever asks to enrol and the enrolment listener only ever answers,
        // so each advertises one direction. That is not decoration: a client advertising
        // inbound support would offer to enrol other clients, which is meaningless, and
        // the asymmetry makes it impossible rather than merely unused.
        let enroll_direction = match role {
            Role::Client => Some(ProtocolSupport::Outbound),
            Role::Enrollment => Some(ProtocolSupport::Inbound),
            Role::Server => None,
        };

        // The mirror image of enrolment: a client only ever asks for an attestation, and
        // only the service listener issues one. The enrolment listener is deliberately left
        // out — it hands over the *first* attestation inside the enrolment reply, and a peer
        // that has not enrolled has nothing to renew.
        let attest_direction = match role {
            Role::Client => Some(ProtocolSupport::Outbound),
            Role::Server => Some(ProtocolSupport::Inbound),
            Role::Enrollment => None,
        };

        // mDNS needs a multicast socket, which a container or a locked-down interface may
        // refuse. That is a lost optimisation, not a reason to fail: every other discovery
        // path still works, so log it and carry on rather than taking the node down.
        let mdns = (is_client && config.mdns)
            .then(|| libp2p::mdns::tokio::Behaviour::new(libp2p::mdns::Config::default(), peer_id))
            .transpose()
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "mDNS unavailable; LAN peers will be found via the server");
                None
            });

        Self {
            connection_limits: connection_limits::Behaviour::new(limits::connection_limits()),
            memory_limits: limits::memory_limits(),
            authz: authz::Behaviour::new(authorizer),
            mdns: Toggle::from(mdns),
            identify: identify::Behaviour::new(identify_config),
            ping: ping::Behaviour::new(ping::Config::new().with_interval(PING_INTERVAL)),
            enroll: Toggle::from(enroll_direction.map(|direction| {
                request_response::cbor::Behaviour::new(
                    [(StreamProtocol::new(ENROLL_PROTOCOL), direction)],
                    request_response::Config::default(),
                )
            })),
            attest: Toggle::from(attest_direction.map(|direction| {
                request_response::cbor::Behaviour::new(
                    [(StreamProtocol::new(ATTEST_PROTOCOL), direction)],
                    request_response::Config::default(),
                )
            })),
            peer_attest: Toggle::from(is_client.then(|| {
                request_response::cbor::Behaviour::new(
                    [(
                        StreamProtocol::new(PEER_ATTEST_PROTOCOL),
                        ProtocolSupport::Full,
                    )],
                    request_response::Config::default(),
                )
            })),
            relay: Toggle::from(
                is_server.then(|| relay::Behaviour::new(peer_id, relay::Config::default())),
            ),
            rendezvous: Toggle::from(is_server.then(|| {
                rendezvous::server::Behaviour::new(rendezvous::server::Config::default())
            })),
            autonat: Toggle::from(is_server.then(autonat::v2::server::Behaviour::default)),
            upnp: Toggle::from(is_client.then(libp2p::upnp::tokio::Behaviour::default)),
            autonat_client: Toggle::from(is_client.then(autonat::v2::client::Behaviour::default)),
            rendezvous_client: Toggle::from(
                is_client.then(|| rendezvous::client::Behaviour::new(keypair.clone())),
            ),
            dcutr: Toggle::from(is_client.then(|| libp2p::dcutr::Behaviour::new(peer_id))),
            // The builder hands us this unconditionally, because the circuit transport it
            // installs is not optional. Toggling the *behaviour* off on the server is what
            // stops a server from trying to reserve a slot on someone else's relay.
            relay_client: Toggle::from(is_client.then_some(relay_client)),
            app,
        }
    }
}

/// Build a swarm and start listening on the configured addresses.
///
/// Listen failures are per-address and non-fatal: a host without IPv6 should still come
/// up on IPv4. Only failing to bind *every* address is an error, because a node that
/// listens nowhere can never be dialled and would otherwise fail silently.
///
/// `app` is the caller's application layer — see [`AcBehaviour::app`]. Pass
/// [`libp2p::swarm::dummy::Behaviour`] to mount none.
pub fn build<A: PeerAuthorizer, X: NetworkBehaviour>(
    identity: &Identity,
    config: &Config,
    role: Role,
    authorizer: A,
    app: X,
) -> Result<Swarm<AcBehaviour<A, X>>, SwarmError> {
    let mut swarm = SwarmBuilder::with_existing_identity(identity.keypair().clone())
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(SwarmError::Tcp)?
        .with_quic()
        .with_dns()
        .map_err(SwarmError::Dns)?
        // Adds the `/p2p-circuit` transport as well as the behaviour, which is why it
        // sits in the builder chain rather than being constructed alongside the others:
        // a relayed address has to be dialable, not merely parseable.
        .with_relay_client(noise::Config::new, yamux::Config::default)
        .map_err(SwarmError::Relay)?
        .with_behaviour(|keypair, relay_client| {
            AcBehaviour::new(keypair, config, role, authorizer, relay_client, app)
        })
        .map_err(|never: std::convert::Infallible| match never {})?
        .with_swarm_config(|c| c.with_idle_connection_timeout(IDLE_CONNECTION_TIMEOUT))
        .build();

    let mut bound = 0usize;
    for addr in &config.listen {
        match swarm.listen_on(addr.clone()) {
            Ok(_) => bound += 1,
            Err(e) => tracing::warn!(%addr, error = %e, "could not listen on address"),
        }
    }

    if bound == 0 {
        return Err(SwarmError::NoListenAddr {
            attempted: config.listen.len(),
        });
    }

    Ok(swarm)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity() -> Identity {
        let dir = tempfile::tempdir().unwrap();
        Identity::load_or_generate(&dir.path().join("identity.key"))
            .unwrap()
            .0
    }

    #[tokio::test]
    async fn builds_and_binds_loopback() {
        let identity = test_identity();
        let config = Config {
            listen: vec![
                "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
                "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            ],
            listen_enroll: Vec::new(),
            external: Vec::new(),
            mdns: false,
            server: None,
        };

        let swarm = build(
            &identity,
            &config,
            Role::Client,
            crate::authz::AcceptAnyPeer,
            libp2p::swarm::dummy::Behaviour,
        )
        .unwrap();
        assert_eq!(*swarm.local_peer_id(), identity.peer_id());
    }

    #[tokio::test]
    async fn binding_nothing_is_an_error_not_a_silent_success() {
        let identity = test_identity();
        // 192.0.2.0/24 is TEST-NET-1: reserved for documentation, never assigned to a
        // local interface, so binding it always fails.
        let config = Config {
            listen: vec!["/ip4/192.0.2.1/tcp/1".parse().unwrap()],
            listen_enroll: Vec::new(),
            external: Vec::new(),
            mdns: false,
            server: None,
        };

        assert!(matches!(
            build(
                &identity,
                &config,
                Role::Client,
                crate::authz::AcceptAnyPeer,
                libp2p::swarm::dummy::Behaviour,
            ),
            Err(SwarmError::NoListenAddr { attempted: 1 })
        ));
    }

    #[test]
    fn agent_version_names_the_role() {
        assert!(Role::Client.agent_version().contains("client"));
        assert!(Role::Server.agent_version().contains("server"));
    }
}
