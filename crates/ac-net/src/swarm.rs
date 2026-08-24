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
use crate::keepalive;
use crate::limits;
use crate::proto::{
    ATTEST_PROTOCOL, AttestRequest, AttestResponse, ENROLL_PROTOCOL, EnrollRequest, EnrollResponse,
    PEER_ATTEST_PROTOCOL, PRESENCE_PROTOCOL, PeerAttestRequest, PeerAttestResponse,
    PresenceRequest, PresenceResponse,
};

/// How long a connection with no active streams is held open.
const IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);

/// How often the server connection is pinged.
pub const PING_INTERVAL: Duration = Duration::from_secs(25);

/// Largest presence message either side will decode.
pub const MAX_PRESENCE_BYTES: u64 = 32 * 1024;

/// Which side of the network this process is. Fixed by the binary, not by config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
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
#[derive(NetworkBehaviour)]
pub struct AcBehaviour<A: PeerAuthorizer, X: NetworkBehaviour> {
    pub connection_limits: connection_limits::Behaviour,
    pub memory_limits: libp2p::memory_connection_limits::Behaviour,
    pub authz: authz::Behaviour<A>,
    pub identify: identify::Behaviour,
    pub ping: keepalive::Behaviour,
    pub enroll: Toggle<request_response::cbor::Behaviour<EnrollRequest, EnrollResponse>>,
    pub attest: Toggle<request_response::cbor::Behaviour<AttestRequest, AttestResponse>>,
    pub presence: Toggle<request_response::cbor::Behaviour<PresenceRequest, PresenceResponse>>,
    pub peer_attest:
        Toggle<request_response::cbor::Behaviour<PeerAttestRequest, PeerAttestResponse>>,
    pub relay: Toggle<relay::Behaviour>,
    pub rendezvous: Toggle<rendezvous::server::Behaviour>,
    pub autonat: Toggle<autonat::v2::server::Behaviour>,
    pub upnp: Toggle<libp2p::upnp::tokio::Behaviour>,
    pub autonat_client: Toggle<autonat::v2::client::Behaviour>,
    pub rendezvous_client: Toggle<rendezvous::client::Behaviour>,
    pub mdns: Toggle<libp2p::mdns::tokio::Behaviour>,
    pub dcutr: Toggle<libp2p::dcutr::Behaviour>,
    pub relay_client: Toggle<relay::client::Behaviour>,
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

        let keep_alive_with = is_client
            .then_some(config.server.as_ref())
            .flatten()
            .and_then(|addr| {
                addr.iter().find_map(|p| match p {
                    libp2p::multiaddr::Protocol::P2p(peer) => Some(peer),
                    _ => None,
                })
            });

        let identify_config = identify::Config::new("ac/0.1".to_owned(), keypair.public())
            .with_agent_version(role.agent_version())
            .with_hide_listen_addrs(true);

        let enroll_direction = match role {
            Role::Client => Some(ProtocolSupport::Outbound),
            Role::Enrollment => Some(ProtocolSupport::Inbound),
            Role::Server => None,
        };

        let service_direction = match role {
            Role::Client => Some(ProtocolSupport::Outbound),
            Role::Server => Some(ProtocolSupport::Inbound),
            Role::Enrollment => None,
        };

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
            ping: keepalive::Behaviour::new(
                keep_alive_with,
                ping::Config::new().with_interval(PING_INTERVAL),
            ),
            enroll: Toggle::from(enroll_direction.map(|direction| {
                request_response::cbor::Behaviour::new(
                    [(StreamProtocol::new(ENROLL_PROTOCOL), direction)],
                    request_response::Config::default(),
                )
            })),
            attest: Toggle::from(service_direction.clone().map(|direction| {
                request_response::cbor::Behaviour::new(
                    [(StreamProtocol::new(ATTEST_PROTOCOL), direction)],
                    request_response::Config::default(),
                )
            })),
            presence: Toggle::from(service_direction.map(|direction| {
                let codec = request_response::cbor::codec::Codec::default()
                    .set_request_size_maximum(MAX_PRESENCE_BYTES)
                    .set_response_size_maximum(MAX_PRESENCE_BYTES);
                request_response::cbor::Behaviour::with_codec(
                    codec,
                    [(StreamProtocol::new(PRESENCE_PROTOCOL), direction)],
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
                is_server.then(|| relay::Behaviour::new(peer_id, limits::relay_config())),
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
            relay_client: Toggle::from(is_client.then_some(relay_client)),
            app,
        }
    }
}

/// Build a swarm and start listening on the configured addresses.
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
            storage_root: None,
            storage_max: None,
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
            storage_root: None,
            storage_max: None,
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
