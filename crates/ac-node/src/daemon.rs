//! The client's event loop.
//!
//! `ac-net` builds the swarm and owns the protocols; this drives it. What it deliberately
//! does *not* do is decide who to talk to.
//!
//! Discovery reports every peer the server knows about, and this module dials none of
//! them. Choosing which are worth connecting to is a product decision — group membership
//! in milestone 2 — and the app layer will make it. Dialling itself is already available
//! (`Swarm::dial`), and who is currently connected is already answerable
//! (`Swarm::connected_peers`), so no interface is invented here ahead of a real caller.
//!
//! # Admission
//!
//! What it *does* decide is who may stay. Every peer connection runs a mutual attestation
//! exchange — see [`Attest`] — and one that does not complete is closed. That is an
//! authorization check on a live connection, not on the act of connecting, and the
//! distinction is the one `ac_net::authz` spends its module docs on: the credential is
//! signed by the server, so verifying it needs no prior knowledge of the peer and cannot
//! deadlock the way a locally-held trust list does.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use libp2p::futures::StreamExt;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::SwarmEvent;
use libp2p::{
    Multiaddr, PeerId, autonat, identify, mdns, ping, relay, rendezvous, request_response, upnp,
};

use ac_net::attest::{self, Attestation};
use ac_net::authz::AcceptAnyPeer;
use ac_net::config::{Config, Paths};
use ac_net::connectivity::Connectivity;
use ac_net::identity::Identity;
use ac_net::proto::{
    AttestRequest, AttestResponse, PeerAttestRequest, PeerAttestResponse, RENDEZVOUS_NAMESPACE,
};
use ac_net::swarm::{AcBehaviourEvent, Role, build};

/// This node's application layer.
///
/// Empty for now. Milestone 2 replaces it with the group protocol from `ac-groups`, which is
/// the whole reason `AcBehaviour` carries an app slot: a protocol living in another crate
/// cannot be added as a field here, so the binary supplies it instead.
type App = libp2p::swarm::dummy::Behaviour;

/// The value form of [`App`]; a type alias cannot be used as a constructor.
const APP: App = libp2p::swarm::dummy::Behaviour;

/// A convenient alias for the concrete swarm this module drives.
type ClientSwarm = libp2p::Swarm<ac_net::swarm::AcBehaviour<AcceptAnyPeer, App>>;

/// Listen, optionally dial, and run until interrupted.
///
/// The authorizer is [`AcceptAnyPeer`]: a client accepts connections from anyone, because
/// refusing by identity would prevent a peer from ever delivering the group membership
/// proof that authorizes it. Resource limits, not identity, bound what a stranger costs.
pub async fn run(
    identity: &Identity,
    config: &Config,
    paths: &Paths,
    dial: &[Multiaddr],
) -> Result<()> {
    let mut swarm =
        build(identity, config, Role::Client, AcceptAnyPeer, APP).context("building the swarm")?;

    println!("peer {}", identity.peer_id());

    for addr in dial {
        swarm
            .dial(addr.clone())
            .with_context(|| format!("dialling {addr}"))?;
        tracing::info!(%addr, "dialling");
    }

    // Each step waits for what the previous one produces — see `ServerLink`.
    let mut link = match &config.server {
        Some(server) => {
            swarm
                .dial(server.clone())
                .with_context(|| format!("dialling the server at {server}"))?;
            tracing::info!(%server, "dialling the server");
            ServerLink::for_server(server)
        }
        None => None,
    };

    // Admission. Always present, including on a node that has never enrolled: such a node
    // has nothing to verify anyone against, so it closes every peer connection rather than
    // leaving one open and unchecked.
    let mut attest = Attest::load(paths, identity.peer_id(), link.as_ref().map(|l| l.server));

    // How each peer is reachable, and why. The only record of whether milestone 1's
    // headline claim — relayed connections upgrade to direct — actually held.
    let mut connectivity = Connectivity::default();

    // One clock for both schedules the supervisor keeps — reconnection and re-discovery.
    // Neither needs sub-second precision, and a single tick is easier to reason about than
    // two futures racing in the `select!`.
    let mut tick = tokio::time::interval(HOUSEKEEPING_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = tick.tick() => {
                if let Some(link) = &mut link {
                    link.housekeeping(&mut swarm);
                }
                attest.housekeeping(&mut swarm);
            }

            event = swarm.select_next_some() => {
                track(&mut connectivity, &swarm, &event);

                // Admission runs before the `ServerLink` arm so that a peer which fails
                // the check is closed in the same turn it was seen, rather than lingering
                // for a tick. The server itself is exempt and skipped inside.
                match &event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        attest.on_connected(&mut swarm, *peer_id);
                    }
                    SwarmEvent::ConnectionClosed { peer_id, .. } => {
                        attest.on_disconnected(*peer_id, swarm.is_connected(peer_id));
                    }
                    _ => {}
                }

                if let Some(link) = &mut link {
                    match &event {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            link.reserve(&mut swarm, *peer_id);
                        }
                        SwarmEvent::ConnectionClosed { peer_id, .. } => {
                            link.on_disconnected(*peer_id, swarm.is_connected(peer_id));
                        }
                        // Registering needs an external address, and on a NATed node the
                        // first one to exist is the relay circuit. So this is both "we
                        // became reachable" and "we now have something worth publishing".
                        SwarmEvent::ExternalAddrConfirmed { .. } => {
                            link.publish(&mut swarm);
                        }
                        SwarmEvent::Behaviour(AcBehaviourEvent::RendezvousClient(
                            rendezvous::client::Event::Discovered { registrations, .. },
                        )) => {
                            report_discovered(registrations, identity.peer_id());
                        }
                        _ => {}
                    }
                }

                // Dispatched by value rather than by reference, because answering an
                // inbound request means taking ownership of its `ResponseChannel`.
                match event {
                    SwarmEvent::Behaviour(AcBehaviourEvent::PeerAttest(event)) => {
                        attest.on_peer_event(&mut swarm, event);
                    }
                    SwarmEvent::Behaviour(AcBehaviourEvent::Attest(event)) => {
                        attest.on_renewal(event);
                    }
                    other => on_event(other),
                }
            }

            _ = tokio::signal::ctrl_c() => {
                tracing::info!("interrupted, shutting down");
                return Ok(());
            }
        }
    }
}

/// Translate swarm events into connectivity transitions, and report the interesting ones.
///
/// This is the only place the two halves meet: [`Connectivity`] takes plain values so it
/// can be tested without a network, and this turns libp2p's events into those values.
fn track<A: ac_net::authz::PeerAuthorizer, X: libp2p::swarm::NetworkBehaviour>(
    connectivity: &mut Connectivity,
    swarm: &libp2p::Swarm<ac_net::swarm::AcBehaviour<A, X>>,
    event: &SwarmEvent<AcBehaviourEvent<A, X>>,
) {
    match event {
        SwarmEvent::ConnectionEstablished {
            peer_id, endpoint, ..
        } => {
            let relayed = endpoint
                .get_remote_address()
                .iter()
                .any(|p| p == Protocol::P2pCircuit);
            connectivity.connected(*peer_id, relayed);
        }

        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            // A peer holds a relayed *and* a direct connection while an upgrade settles,
            // so one closing does not mean the peer is gone. The swarm knows which.
            connectivity.disconnected(*peer_id, swarm.is_connected(peer_id));
        }

        SwarmEvent::Behaviour(AcBehaviourEvent::Dcutr(event)) => {
            let succeeded = event.result.is_ok();
            connectivity.hole_punch(event.remote_peer_id, succeeded);

            let peer = event.remote_peer_id;
            match &event.result {
                Ok(_) => {
                    let took = connectivity
                        .get(&peer)
                        .and_then(|s| s.upgrade_took())
                        .unwrap_or_default();
                    println!("direct {peer} after {:.1}s", took.as_secs_f32());
                }
                // Expected under symmetric NAT, where no amount of retrying helps. The
                // relayed connection remains and stays usable.
                Err(e) => {
                    tracing::info!(%peer, error = %e, "hole punch failed; staying relayed");
                }
            }
        }

        _ => {}
    }
}

/// Report everything the server returned, and connect to none of it.
///
/// Every peer, unfiltered — including ones this node will never want. Which of them are
/// worth a connection is a product decision, so nothing here makes it. Until the app layer
/// does, `ac run` discovers peers and dials only what `--dial` names.
///
/// Addresses arrive inside a signed `PeerRecord`, but nothing would depend on that
/// signature even when they are used: dialling `/p2p/<peer>` proves possession of the key
/// regardless, so a wrong address costs a failed dial and nothing more.
fn report_discovered(registrations: &[rendezvous::Registration], me: libp2p::PeerId) {
    for registration in registrations {
        let peer = registration.record.peer_id();
        if peer == me {
            continue;
        }

        tracing::info!(
            %peer,
            addresses = ?registration.record.addresses(),
            "discovered a peer"
        );
    }
}

/// How long a peer has to complete the mutual attestation exchange.
///
/// Swept on the housekeeping tick, so the real deadline is this plus up to one tick. Sized
/// for a relayed round trip on a slow link, not for a hole punch — nothing here waits on
/// DCUtR, because the exchange runs over whatever connection already exists.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// The mutual attestation check, and the credential it is built on.
///
/// # Why both directions
///
/// Verifying only the peer that dialled would leave the dialer talking to anyone. Both
/// sides send their own attestation and answer the other's, and a peer counts as admitted
/// only when *both* halves have passed — [`Handshake::complete`]. The two halves are
/// tracked separately because they are two independent request-response exchanges that can
/// land in either order.
///
/// # Why the server is exempt
///
/// The server does not speak `/ac/peer-attest/1.0.0` — it has no attestation of its own to
/// present, and needs none, since a client pinned its peer id at enrolment and the
/// connection handshake already proved it. Demanding one would close the very connection
/// renewal depends on, and with it the relay reservation and the registry.
struct Attest {
    /// Where our attestation is cached between runs.
    path: PathBuf,
    /// This node, for verifying that a renewal really is about us.
    me: PeerId,
    /// The only signer whose attestations mean anything here.
    ///
    /// `None` on a node that has never enrolled. Nothing can be checked without it — not
    /// a peer's attestation and not our own — so every peer connection is closed on sight.
    /// That is the honest reading of "verify before talking": a node that cannot verify
    /// does not get to talk.
    server: Option<PeerId>,
    /// `None` until the server issues one. A node in that state is admitted by nobody.
    mine: Option<Attestation>,
    /// Set while a renewal is in flight, so the tick does not queue a second one.
    renewing: bool,
    /// Per-peer exchange state. An absent entry means the exchange has not started.
    peers: HashMap<PeerId, Handshake>,
}

/// One peer's progress through the exchange.
struct Handshake {
    /// Whether our attestation has been put on the wire yet. False when the peer connected
    /// before this node had one.
    sent: bool,
    /// Their username, set once *their* attestation verified. `Some` is "they passed".
    username: Option<String>,
    /// Whether they accepted ours.
    we_passed: bool,
    /// Whether completion has already been reported.
    ///
    /// [`Handshake::complete`] stays true for the life of the entry, so it cannot on its own
    /// tell "just completed" from "completed a while ago". Nothing stops a peer sending a
    /// second attestation on the same connection, and each one re-runs the verification path
    /// — so without this latch the announcement would repeat as often as the *peer* chose.
    announced: bool,
    /// When to give up and close.
    deadline: Instant,
}

impl Handshake {
    fn new() -> Self {
        Self {
            sent: false,
            username: None,
            we_passed: false,
            announced: false,
            deadline: Instant::now() + HANDSHAKE_TIMEOUT,
        }
    }

    fn complete(&self) -> bool {
        self.username.is_some() && self.we_passed
    }
}

impl Attest {
    /// Load the cached attestation, discarding one that is no longer usable.
    ///
    /// Verified against this node's own peer id and its server, not merely decoded: a file
    /// copied from another node, or left over from a different server, has to be thrown
    /// away rather than presented and rejected by every peer in turn.
    fn load(paths: &Paths, me: PeerId, server: Option<PeerId>) -> Self {
        let path = paths.attestation_file();

        let Some(server) = server else {
            tracing::warn!(
                "this node has not enrolled, so it can verify nobody and can prove nothing \
                 about itself. Every peer connection will be closed. Run `ac join` first."
            );
            return Self {
                path,
                me,
                server: None,
                mine: None,
                renewing: false,
                peers: HashMap::new(),
            };
        };

        let mine = attest::load(&path)
            .unwrap_or_else(|e| {
                tracing::warn!(path = %path.display(), error = %e, "could not read the attestation");
                None
            })
            .filter(|a| match a.verify(&me, &server, attest::now()) {
                Ok(statement) => {
                    tracing::info!(
                        username = %statement.username,
                        expires_in_h = (statement.expires_at - attest::now()).max(0) / 3600,
                        "loaded this node's attestation"
                    );
                    true
                }
                Err(e) => {
                    tracing::warn!(error = %e, "the stored attestation is unusable; will renew");
                    false
                }
            });

        Self {
            path,
            me,
            server: Some(server),
            mine,
            renewing: false,
            peers: HashMap::new(),
        }
    }

    /// A peer connected: begin the exchange, unless it is the server.
    fn on_connected(&mut self, swarm: &mut ClientSwarm, peer: PeerId) {
        let Some(server) = self.server else {
            // Nothing to check against, and nothing to offer. Closed immediately rather
            // than left to time out, so the peer gets a reason instead of a dead socket.
            self.reject(swarm, peer, "this node has not enrolled with a server");
            return;
        };
        if peer == server {
            return;
        }
        // A peer legitimately holds a relayed *and* a direct connection while an upgrade
        // settles. It was vouched for on the first; the second proves nothing new, and
        // re-running the exchange would race the entry that already exists.
        if self.peers.get(&peer).is_some_and(Handshake::complete) {
            return;
        }

        self.peers.entry(peer).or_insert_with(Handshake::new);
        self.send_ours(swarm, peer);
    }

    /// Put our attestation on the wire, if we have one and have not already sent it.
    ///
    /// Silently does nothing when this node has no attestation yet. That is not a failure
    /// path: the peer's deadline is already running, so the exchange either completes when
    /// a renewal lands or the connection is closed for not completing.
    fn send_ours(&mut self, swarm: &mut ClientSwarm, peer: PeerId) {
        let Some(mine) = self.mine.clone() else {
            return;
        };
        let Some(handshake) = self.peers.get_mut(&peer) else {
            return;
        };
        if handshake.sent {
            return;
        }

        let Some(behaviour) = swarm.behaviour_mut().peer_attest.as_mut() else {
            return;
        };
        behaviour.send_request(&peer, PeerAttestRequest { attestation: mine });
        handshake.sent = true;
    }

    /// Handle one `/ac/peer-attest/1.0.0` event.
    fn on_peer_event(
        &mut self,
        swarm: &mut ClientSwarm,
        event: request_response::Event<PeerAttestRequest, PeerAttestResponse>,
    ) {
        match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => self.on_their_attestation(swarm, peer, request, channel),

                request_response::Message::Response { response, .. } => match response {
                    PeerAttestResponse::Accepted => {
                        if let Some(handshake) = self.peers.get_mut(&peer) {
                            handshake.we_passed = true;
                        }
                        self.settle(peer);
                    }
                    PeerAttestResponse::Rejected(why) => {
                        self.reject(swarm, peer, &format!("they rejected ours: {why}"));
                    }
                },
            },

            // They never answered, or do not speak the protocol at all. Either way this
            // peer cannot be admitted, and waiting for the deadline would only delay it.
            request_response::Event::OutboundFailure { peer, error, .. } => {
                self.reject(swarm, peer, &format!("no usable answer: {error}"));
            }

            // Their request to us failed mid-flight. Not fatal on its own — their side
            // will retry or time out — so this only stops *us* from having verified them,
            // which the deadline already covers.
            request_response::Event::InboundFailure { peer, error, .. } => {
                tracing::debug!(%peer, %error, "inbound attestation failed");
            }

            request_response::Event::ResponseSent { .. } => {}
        }
    }

    /// Verify what a peer sent, answer it, and close if it did not check out.
    fn on_their_attestation(
        &mut self,
        swarm: &mut ClientSwarm,
        peer: PeerId,
        request: PeerAttestRequest,
        channel: request_response::ResponseChannel<PeerAttestResponse>,
    ) {
        let verdict = match self.server {
            Some(server) => request
                .attestation
                .verify(&peer, &server, attest::now())
                .map(|statement| statement.username)
                .map_err(|e| e.to_string()),
            // Answered rather than ignored: the peer learns why in one round trip instead
            // of waiting out its own deadline on a connection that will never work.
            None => Err("this node has not enrolled, so it cannot verify anyone".to_owned()),
        };

        let response = match &verdict {
            Ok(_) => PeerAttestResponse::Accepted,
            Err(why) => PeerAttestResponse::Rejected(why.clone()),
        };
        if let Some(behaviour) = swarm.behaviour_mut().peer_attest.as_mut() {
            // Best effort. A rejected peer is disconnected immediately below, which can
            // truncate this — the closed connection is the message that matters, and the
            // reason string is a courtesy to whoever reads both sides' logs.
            let _ = behaviour.send_response(channel, response);
        }

        match verdict {
            Ok(username) => {
                self.peers
                    .entry(peer)
                    .or_insert_with(Handshake::new)
                    .username = Some(username);
                // They may have reached us before we had a credential, or before we saw
                // the connection at all; either way this is the moment to send ours.
                self.send_ours(swarm, peer);
                self.settle(peer);
            }
            Err(why) => self.reject(swarm, peer, &why),
        }
    }

    /// Announce a peer once both halves have passed. Returns whether this call announced it.
    ///
    /// Called from both completion paths, and latches on [`Handshake::announced`] so it fires
    /// exactly once per handshake. Completion alone is not enough to decide that: it stays
    /// true afterwards, and a peer may send a second attestation on the same connection,
    /// which re-runs the verification path and calls back in here. Guarding on `complete()`
    /// alone let a peer choose how often it was announced.
    ///
    /// The latch lives on the handshake rather than on the peer, so a genuine reconnection —
    /// where [`Attest::on_disconnected`] has dropped the entry — is announced again.
    fn settle(&mut self, peer: PeerId) -> bool {
        let Some(handshake) = self.peers.get_mut(&peer) else {
            return false;
        };
        if !handshake.complete() || handshake.announced {
            return false;
        }
        handshake.announced = true;

        let Some(username) = handshake.username.clone() else {
            return false;
        };
        println!("verified {username} {peer}");
        tracing::info!(%peer, %username, "attestation exchange complete");
        true
    }

    /// Close a peer that failed the check.
    fn reject(&mut self, swarm: &mut ClientSwarm, peer: PeerId, why: &str) {
        // The server is never subject to this. Closing it would take down renewal, the
        // relay reservation and the registry in one go — and it has already proven itself
        // by holding the key for the peer id pinned at enrolment.
        if Some(peer) == self.server {
            return;
        }
        self.peers.remove(&peer);
        tracing::warn!(%peer, why, "closing the connection: attestation refused");
        println!("refused {peer} ({why})");
        let _ = swarm.disconnect_peer_id(peer);
    }

    fn on_disconnected(&mut self, peer: PeerId, still_connected: bool) {
        if still_connected {
            return;
        }
        self.peers.remove(&peer);
    }

    /// Renew when due, send to anyone still waiting, and close whatever has timed out.
    fn housekeeping(&mut self, swarm: &mut ClientSwarm) {
        let due = self
            .mine
            .as_ref()
            .is_none_or(|a| a.needs_renewal(attest::now()));

        if let Some(server) = self.server
            && due
            && !self.renewing
            && swarm.is_connected(&server)
            && let Some(behaviour) = swarm.behaviour_mut().attest.as_mut()
        {
            behaviour.send_request(&server, AttestRequest);
            self.renewing = true;
            tracing::info!(%server, "asking for a fresh attestation");
        }

        // Peers that connected before this node had a credential.
        let waiting: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(_, h)| !h.sent)
            .map(|(peer, _)| *peer)
            .collect();
        for peer in waiting {
            self.send_ours(swarm, peer);
        }

        let now = Instant::now();
        let expired: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(_, h)| !h.complete() && now >= h.deadline)
            .map(|(peer, _)| *peer)
            .collect();
        for peer in expired {
            self.reject(
                swarm,
                peer,
                "the attestation exchange did not complete in time",
            );
        }
    }

    /// Handle the server's answer to a renewal request.
    fn on_renewal(&mut self, event: request_response::Event<AttestRequest, AttestResponse>) {
        match event {
            request_response::Event::Message {
                message: request_response::Message::Response { response, .. },
                ..
            } => {
                self.renewing = false;
                let Some(server) = self.server else {
                    // Unreachable: a request is only ever sent to a known server.
                    return;
                };
                match response {
                    AttestResponse::Issued(attestation) => {
                        // Checked before it is stored or presented, so a server that hands
                        // out something unusable is caught here rather than as an
                        // unexplained refusal from every peer.
                        match attestation.verify(&self.me, &server, attest::now()) {
                            Ok(statement) => {
                                if let Err(e) = attest::save(&self.path, &attestation) {
                                    // Not fatal: the attestation works for this run, and
                                    // the next start simply renews again.
                                    tracing::warn!(
                                        path = %self.path.display(),
                                        error = %e,
                                        "could not cache the attestation"
                                    );
                                }
                                let hours = (statement.expires_at - attest::now()).max(0) / 3600;
                                println!("attested as {} for {hours}h", statement.username);
                                self.mine = Some(attestation);
                            }
                            Err(e) => {
                                tracing::error!(
                                    error = %e,
                                    "the server issued an attestation this node cannot use"
                                );
                            }
                        }
                    }
                    AttestResponse::Refused(reason) => {
                        tracing::warn!(reason = reason.explain(), "attestation refused");
                    }
                }
            }

            request_response::Event::OutboundFailure { error, .. } => {
                // Cleared so the next tick tries again; the server link has its own
                // reconnect schedule, and this rides on whatever it recovers.
                self.renewing = false;
                tracing::warn!(%error, "could not renew the attestation");
            }

            other => tracing::trace!(?other, "attest event"),
        }
    }
}

/// First reconnect delay, doubling up to [`MAX_BACKOFF`].
const MIN_BACKOFF: Duration = Duration::from_secs(1);

/// Ceiling on the reconnect delay. A server down for hours should be retried patiently,
/// not hammered — but a minute is short enough that recovery is not something a person
/// waits out.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// How often the registry is re-read and our own registration refreshed.
///
/// A peer that comes online is invisible until the next poll, so this *is* the
/// notification latency: rendezvous has no push, and asking is the only mechanism.
///
/// Comfortably inside the server's registration TTL (two hours), so a refresh is never
/// close to lapsing.
const DISCOVERY_INTERVAL: Duration = Duration::from_secs(300);

/// How often the supervisor checks whether anything is due.
///
/// Deliberately coarser than the backoff it drives: the first retry is nominally one
/// second, but detecting a dead server takes ~25 seconds in the first place, so finer
/// granularity would buy nothing while waking the task — and polling every behaviour —
/// five times as often.
const HOUSEKEEPING_TICK: Duration = Duration::from_secs(5);

/// The link to the server, and everything needed to keep it up.
///
/// The initial handshake is a chain, and the ordering is forced rather than stylistic:
///
/// ```text
/// connect  ──► reserve a relay slot  ──► circuit address confirmed  ──► register + discover
/// ```
///
/// Reserving before the connection exists makes the relay behaviour issue its own competing
/// dial; registering before an external address exists fails with `NoExternalAddresses`.
/// Both failures are quiet, so each step waits on the event proving its precondition.
///
/// The same chain has to run **again** after any reconnection, because a reservation dies
/// with the connection that made it. That is why `reserved` and `published` are cleared on
/// disconnect rather than being one-shot latches.
struct ServerLink {
    server: libp2p::PeerId,
    /// Kept so the server can be redialled; the config is not consulted again.
    address: Multiaddr,
    circuit: Multiaddr,
    reserved: bool,
    published: bool,
    /// When to next attempt a reconnect. `None` while connected.
    retry_at: Option<Instant>,
    backoff: Duration,
    next_discovery: Instant,
}

impl ServerLink {
    /// `None` if the address carries no peer id — nothing to wait for, and a circuit
    /// address without one is rejected by the transport anyway.
    fn for_server(server: &Multiaddr) -> Option<Self> {
        let peer = server.iter().find_map(|p| match p {
            Protocol::P2p(peer) => Some(peer),
            _ => None,
        })?;

        Some(Self {
            server: peer,
            address: server.clone(),
            circuit: server.clone().with(Protocol::P2pCircuit),
            reserved: false,
            published: false,
            retry_at: None,
            backoff: MIN_BACKOFF,
            next_discovery: Instant::now() + DISCOVERY_INTERVAL,
        })
    }

    /// The server connection dropped: start over.
    ///
    /// Everything built on that connection is gone with it — the relay reservation was
    /// bound to it, and the rendezvous registration cannot be refreshed without it — so the
    /// flags reset and the whole chain reruns once a new connection lands.
    fn on_disconnected(&mut self, peer: libp2p::PeerId, still_connected: bool) {
        if peer != self.server || still_connected {
            return;
        }

        self.reserved = false;
        self.published = false;
        self.retry_at = Some(Instant::now() + self.backoff);
        tracing::warn!(
            server = %self.server,
            retry_in_s = self.backoff.as_secs(),
            "lost the server; will reconnect"
        );
    }

    /// Redial if it is due, and re-read the registry if that is due.
    ///
    /// Driven by a periodic tick rather than by per-event timers: there are two schedules
    /// and neither needs sub-second precision, so one clock is easier to reason about than
    /// two futures being polled in a `select!`.
    fn housekeeping<A: ac_net::authz::PeerAuthorizer, X: libp2p::swarm::NetworkBehaviour>(
        &mut self,
        swarm: &mut libp2p::Swarm<ac_net::swarm::AcBehaviour<A, X>>,
    ) {
        let now = Instant::now();

        if let Some(due) = self.retry_at
            && now >= due
        {
            // Backoff grows on the *attempt*, not on its failure: a dial that fails
            // silently would otherwise retry at the same rate forever.
            self.backoff = (self.backoff * 2).min(MAX_BACKOFF);
            self.retry_at = Some(now + self.backoff);

            tracing::info!(server = %self.server, "reconnecting");
            if let Err(e) = swarm.dial(self.address.clone()) {
                tracing::debug!(server = %self.server, error = %e, "reconnect dial not started");
            }
        }

        if now >= self.next_discovery {
            self.next_discovery = now + DISCOVERY_INTERVAL;
            self.discover(swarm);
        }
    }

    /// Re-read the registry.
    ///
    /// A **full** query, deliberately: the discovery cookie returns only registrations
    /// added since it was issued, so it can find a peer that arrived and never report one
    /// that left. A list built from deltas accumulates ghosts.
    fn discover<A: ac_net::authz::PeerAuthorizer, X: libp2p::swarm::NetworkBehaviour>(
        &self,
        swarm: &mut libp2p::Swarm<ac_net::swarm::AcBehaviour<A, X>>,
    ) {
        if !self.published {
            // Not registered yet, so there is nothing to refresh and the server may not
            // even know us. The initial `publish` will do the first query.
            return;
        }
        let Ok(namespace) = rendezvous::Namespace::new(RENDEZVOUS_NAMESPACE.to_owned()) else {
            return;
        };
        let Some(client) = swarm.behaviour_mut().rendezvous_client.as_mut() else {
            return;
        };

        // Re-registering as well as re-reading: a registration expires on the server's TTL,
        // and letting it lapse would make this node vanish from everyone else's view.
        if let Err(e) = client.register(namespace.clone(), self.server, None) {
            tracing::debug!(error = %e, "could not refresh the registration");
        }
        client.discover(Some(namespace), None, None, self.server);
    }

    /// Ask for the reservation, if this is the connection we were waiting for.
    fn reserve<A: ac_net::authz::PeerAuthorizer, X: libp2p::swarm::NetworkBehaviour>(
        &mut self,
        swarm: &mut libp2p::Swarm<ac_net::swarm::AcBehaviour<A, X>>,
        connected: libp2p::PeerId,
    ) {
        if self.reserved || connected != self.server {
            return;
        }
        // Reserving means listening on a `/p2p-circuit` address; there is no separate
        // call. Once per connection: renewal within a connection is the relay client
        // behaviour's job, and asking again would open a second listener for the same
        // circuit. The flag clears on disconnect, so a reconnection reserves afresh.
        self.reserved = true;

        // The server is back; stop retrying and forget how long we had been waiting, so a
        // later outage starts from a short delay rather than the last one's ceiling.
        self.retry_at = None;
        self.backoff = MIN_BACKOFF;

        match swarm.listen_on(self.circuit.clone()) {
            Ok(_) => tracing::info!(relay = %self.server, "requesting a relay reservation"),
            Err(e) => tracing::warn!(relay = %self.server, error = %e, "could not reserve"),
        }
    }

    /// Publish our addresses and ask who else is here.
    ///
    /// Called when an external address is confirmed, because registration carries a signed
    /// record of those addresses and libp2p refuses to build one from an empty set.
    ///
    /// # Address changes
    ///
    /// This runs once per connection and then short-circuits, so a *later* address — a
    /// laptop moving from wifi to ethernet, or waking from sleep — does not republish here.
    /// It does not need to: `if-watch` (inside libp2p's QUIC and TCP transports) rebinds
    /// listeners on an interface change, AutoNAT re-confirms, and [`Self::housekeeping`]
    /// re-registers on its next tick. The cost is that a moved node is stale in the
    /// registry for up to one refresh interval.
    fn publish<A: ac_net::authz::PeerAuthorizer, X: libp2p::swarm::NetworkBehaviour>(
        &mut self,
        swarm: &mut libp2p::Swarm<ac_net::swarm::AcBehaviour<A, X>>,
    ) {
        if self.published {
            return;
        }

        let namespace = match rendezvous::Namespace::new(RENDEZVOUS_NAMESPACE.to_owned()) {
            Ok(ns) => ns,
            Err(e) => {
                tracing::error!(error = %e, "the rendezvous namespace is not valid");
                return;
            }
        };

        let Some(client) = swarm.behaviour_mut().rendezvous_client.as_mut() else {
            return;
        };

        if let Err(e) = client.register(namespace.clone(), self.server, None) {
            // Most likely still no external address; a later confirmation retries.
            tracing::debug!(error = %e, "not ready to register yet");
            return;
        }
        self.published = true;

        // One discovery now. Repeating it on a schedule, so a peer that comes online
        // later is noticed, is the supervisor's job in stage 10.
        client.discover(Some(namespace), None, None, self.server);
        tracing::info!(server = %self.server, "registered and discovering");
    }
}

fn on_event(event: SwarmEvent<AcBehaviourEvent<AcceptAnyPeer, App>>) {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            // Printed rather than logged, and with the peer id appended, so the output
            // can be pasted straight into another node's `--dial`.
            println!("listening {address}");
        }

        SwarmEvent::ConnectionEstablished {
            peer_id, endpoint, ..
        } => {
            tracing::info!(
                peer = %peer_id,
                addr = %endpoint.get_remote_address(),
                role = if endpoint.is_dialer() { "dialer" } else { "listener" },
                "connected"
            );
        }

        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
            tracing::info!(peer = %peer_id, cause = ?cause, "disconnected");
        }

        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            tracing::warn!(peer = ?peer_id, %error, "outgoing connection failed");
        }

        SwarmEvent::IncomingConnectionError {
            send_back_addr,
            error,
            ..
        } => {
            tracing::warn!(from = %send_back_addr, %error, "incoming connection failed");
        }

        // What a peer reports seeing us as. Everything about NAT traversal starts here:
        // AutoNAT verifies these candidates, and DCUtR punches toward the confirmed one.
        SwarmEvent::Behaviour(AcBehaviourEvent::Identify(identify::Event::Received {
            peer_id,
            info,
            ..
        })) => {
            tracing::info!(
                peer = %peer_id,
                agent = %info.agent_version,
                observed_addr = %info.observed_addr,
                protocols = info.protocols.len(),
                // Addresses the peer advertises for itself. Expected to be zero until a
                // peer has a confirmed external address, because we ask identify to omit
                // raw listen addresses — see the config in ac_net::swarm.
                advertised_addrs = info.listen_addrs.len(),
                "identified"
            );
            // The names matter when a peer is missing a capability: a client that cannot
            // reserve a relay slot will show `/libp2p/circuit/relay/0.2.0/hop` absent
            // here, which is far quicker to spot than inferring it from a failure.
            tracing::debug!(
                peer = %peer_id,
                protocols = ?info.protocols.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
                "peer protocols"
            );
            println!("observed {} by {}", info.observed_addr, peer_id);
        }

        // The swarm has decided one of those candidates is really ours. This is the
        // reachability verdict in its most useful form: an address others can dial.
        SwarmEvent::ExternalAddrConfirmed { address } => {
            println!("external {address}");
        }

        SwarmEvent::ExternalAddrExpired { address } => {
            tracing::warn!(%address, "external address no longer valid");
        }

        // A gateway forwarded a port: the best outcome available, since it means no relay
        // and no hole punch are needed at all.
        SwarmEvent::Behaviour(AcBehaviourEvent::Upnp(upnp::Event::NewExternalAddr(address))) => {
            println!("upnp {address}");
        }

        SwarmEvent::Behaviour(AcBehaviourEvent::Upnp(event)) => {
            // The common case on home networks: no IGD, or a gateway that is itself
            // behind another NAT. Not an error, just the path we cannot take.
            tracing::info!(?event, "no port mapping available");
        }

        // AutoNAT's answer for one candidate address. `Ok` means a server dialled us back
        // successfully, which is what promotes a candidate to a confirmed external
        // address; `Err` means we are behind something that blocks unsolicited inbound.
        SwarmEvent::Behaviour(AcBehaviourEvent::AutonatClient(autonat::v2::client::Event {
            tested_addr,
            server,
            result,
            ..
        })) => match result {
            Ok(()) => println!("reachable {tested_addr}"),
            Err(e) => {
                tracing::info!(addr = %tested_addr, %server, error = %e, "address not reachable");
            }
        },

        SwarmEvent::Behaviour(AcBehaviourEvent::RelayClient(
            relay::client::Event::ReservationReqAccepted {
                relay_peer_id,
                renewal,
                limit,
            },
        )) => {
            // The reservation is what makes the circuit address usable. `limit` is the
            // relay telling us how much it will carry — 128 KiB by default, which is
            // signalling-sized on purpose.
            println!(
                "reserved via {relay_peer_id}{}",
                if renewal { " (renewed)" } else { "" }
            );
            tracing::info!(relay = %relay_peer_id, renewal, ?limit, "relay reservation");
        }

        SwarmEvent::Behaviour(AcBehaviourEvent::RelayClient(event)) => {
            tracing::info!(?event, "relay client event");
        }

        // LAN peers, found without the server. Reported, not dialled — same rule as
        // rendezvous results: whether a peer is worth connecting to is not this layer's
        // decision.
        SwarmEvent::Behaviour(AcBehaviourEvent::Mdns(mdns::Event::Discovered(found))) => {
            for (peer, addr) in found {
                tracing::info!(%peer, %addr, "discovered a peer on the local network");
            }
        }

        SwarmEvent::Behaviour(AcBehaviourEvent::Mdns(mdns::Event::Expired(gone))) => {
            for (peer, addr) in gone {
                tracing::debug!(%peer, %addr, "local peer stopped announcing");
            }
        }

        SwarmEvent::Behaviour(AcBehaviourEvent::RendezvousClient(event)) => match event {
            rendezvous::client::Event::Registered { ttl, namespace, .. } => {
                println!("registered {namespace} (ttl {ttl}s)");
            }
            rendezvous::client::Event::Discovered { registrations, .. } => {
                println!("discovered {} peer(s)", registrations.len());
            }
            rendezvous::client::Event::RegisterFailed { error, .. } => {
                tracing::warn!(?error, "the server refused our registration");
            }
            rendezvous::client::Event::DiscoverFailed { error, .. } => {
                tracing::warn!(?error, "the server refused our discovery request");
            }
            other => tracing::debug!(?other, "rendezvous client event"),
        },

        SwarmEvent::Behaviour(AcBehaviourEvent::Ping(ping::Event {
            peer,
            result: Ok(rtt),
            ..
        })) => {
            tracing::debug!(peer = %peer, rtt_ms = rtt.as_millis(), "ping");
        }

        SwarmEvent::Behaviour(AcBehaviourEvent::Ping(ping::Event {
            peer,
            result: Err(e),
            ..
        })) => {
            tracing::warn!(peer = %peer, error = %e, "ping failed");
        }

        // A listener dying is never routine — for a circuit address it means the relay
        // reservation was refused or lost, which is exactly the failure this stage exists
        // to make visible. Buried at trace level it looks like nothing happened at all.
        SwarmEvent::ListenerError { listener_id, error } => {
            tracing::warn!(?listener_id, %error, "listener error");
        }

        SwarmEvent::ListenerClosed {
            listener_id,
            addresses,
            reason,
        } => {
            tracing::warn!(?listener_id, ?addresses, ?reason, "listener closed");
        }

        other => tracing::trace!(?other, "swarm event"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> PeerId {
        libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id()
    }

    /// An [`Attest`] with no attestation and no swarm — enough to drive [`Attest::settle`],
    /// which touches neither.
    fn attest() -> Attest {
        Attest {
            path: PathBuf::from("attestation.cbor"),
            me: peer(),
            server: Some(peer()),
            mine: None,
            renewing: false,
            peers: HashMap::new(),
        }
    }

    /// Both halves passed, ready to be announced.
    fn complete_handshake() -> Handshake {
        Handshake {
            username: Some("alice".to_owned()),
            we_passed: true,
            ..Handshake::new()
        }
    }

    #[test]
    fn a_peer_is_announced_once_however_often_it_attests() {
        // Nothing stops a peer sending a second attestation on the same connection, and
        // each one re-runs the verification path. `complete()` stays true afterwards, so
        // guarding on it alone let the *peer* choose how often it was announced.
        let mut attest = attest();
        let p = peer();
        attest.peers.insert(p, complete_handshake());

        assert!(attest.settle(p), "the completing call announces");
        assert!(
            !attest.settle(p),
            "a second attestation must not announce again"
        );
        assert!(!attest.settle(p));
    }

    #[test]
    fn an_incomplete_handshake_is_not_announced() {
        // They verified us, we have not verified them. Announcing here would report a peer
        // as verified on one side's say-so.
        let mut attest = attest();
        let p = peer();
        attest.peers.insert(
            p,
            Handshake {
                we_passed: true,
                ..Handshake::new()
            },
        );

        assert!(!attest.settle(p));
    }

    #[test]
    fn a_reconnecting_peer_is_announced_again() {
        // The latch belongs to the handshake, not to the peer. `on_disconnected` drops the
        // entry, so the next connection is a fresh exchange and genuinely worth reporting —
        // a per-peer latch would silence it forever.
        let mut attest = attest();
        let p = peer();
        attest.peers.insert(p, complete_handshake());
        assert!(attest.settle(p));

        attest.on_disconnected(p, false);
        attest.peers.insert(p, complete_handshake());

        assert!(
            attest.settle(p),
            "a fresh handshake announces on its own terms"
        );
    }

    #[test]
    fn an_unknown_peer_settles_to_nothing() {
        // Ordering is not guaranteed; a result can arrive for a peer whose entry has already
        // been dropped by a close.
        assert!(!attest().settle(peer()));
    }
}
