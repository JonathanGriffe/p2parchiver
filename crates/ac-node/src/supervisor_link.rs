use std::collections::HashMap;

use anyhow::{Context, Result};
use libp2p::swarm::DialError;
use libp2p::{Multiaddr, PeerId, request_response};

use ac_net::admitted_peers::AdmittedPeers;
use ac_net::config::{Config, Paths};
use ac_net::identity::Identity;
use ac_net::proto::{PresenceRequest, PresenceResponse};

use ac_files::store::Files;
use ac_groups::store::Groups;
use ac_supervisor::sync::{Limits, Offering, PeerAction, PeerEvent, Space, Supervisor};
use ac_supervisor::wire::{SessionRequest, SessionResponse};

use crate::daemon::ClientSwarm;
use crate::dial_policy::DialPolicy;
use crate::file_link::{FileLink, RoundOutcome, TransferOutcome};
use crate::group_link::GroupLink;
use crate::status::{Bandwidth, Published};

pub struct SupervisorLink {
    supervisor: Supervisor,
    proposals: HashMap<request_response::OutboundRequestId, PeerId>,
    presence: HashMap<request_response::OutboundRequestId, Vec<PeerId>>,
    server: Option<PeerId>,
    dial: DialPolicy,
    root: std::path::PathBuf,
    status: Published,
    /// Bytes down, bytes up and the clock, as of the last publish. A rate is the difference
    /// between two of these, so the first tick after startup has nothing to compare against.
    moved_at: Option<(u64, u64, i64)>,
}

impl SupervisorLink {
    pub fn open(
        paths: &Paths,
        identity: &Identity,
        server: Option<PeerId>,
        at: i64,
    ) -> Result<Self> {
        let path = paths.db_file();
        let me = identity.peer_id();

        let files = Files::open(&path, me)
            .with_context(|| format!("opening the file index at {}", path.display()))?;
        let groups = Groups::open(&path, me)
            .with_context(|| format!("opening the group store at {}", path.display()))?;

        let config = Config::load(&paths.config_file())
            .with_context(|| format!("reading the config at {}", paths.config_file().display()))?;
        let root = config.storage_root(paths);

        Ok(Self {
            supervisor: Supervisor::new(files, groups, at).with_limits(Limits {
                storage_max: config.storage_max,
                ..Limits::default()
            }),
            proposals: HashMap::new(),
            presence: HashMap::new(),
            server,
            dial: DialPolicy::new(config.server.clone()),
            root,
            status: Published::open(&path)
                .with_context(|| format!("opening the status table at {}", path.display()))?,
            moved_at: None,
        })
    }

    /// A peer completed mutual attestation
    pub fn peer_ready(
        &mut self,
        swarm: &mut ClientSwarm,
        files: &mut FileLink,
        groups: &mut GroupLink,
        admitted_peers: &AdmittedPeers,
        peer: PeerId,
    ) {
        let actions = self.supervisor.on(PeerEvent::Verified { peer });
        self.dispatch(swarm, files, groups, admitted_peers, actions);
    }

    /// mDNS saw this peer on the local network. A liveness hint, and an address to dial.
    pub fn discovered(
        &mut self,
        peer: PeerId,
        addr: &Multiaddr,
        files: &mut FileLink,
        groups: &mut GroupLink,
        swarm: &mut ClientSwarm,
        admitted_peers: &AdmittedPeers,
    ) {
        self.dial.announced(peer, addr);
        let actions = self.supervisor.on(PeerEvent::Discovered { peer });
        self.dispatch(swarm, files, groups, admitted_peers, actions);
    }

    /// mDNS stopped announcing this address, so it is no longer dialed.
    pub fn expired(&mut self, peer: PeerId, addr: &Multiaddr) {
        self.dial.expired(peer, addr);
    }

    pub fn on_disconnected(
        &mut self,
        swarm: &mut ClientSwarm,
        files: &mut FileLink,
        groups: &mut GroupLink,
        admitted_peers: &AdmittedPeers,
        peer: PeerId,
    ) {
        let actions = self.supervisor.on(PeerEvent::Gone { peer });
        self.dispatch(swarm, files, groups, admitted_peers, actions);
    }

    pub fn dial_failed(
        &mut self,
        swarm: &mut ClientSwarm,
        files: &mut FileLink,
        groups: &mut GroupLink,
        admitted_peers: &AdmittedPeers,
        peer: PeerId,
        error: &DialError,
    ) {
        self.dial.failed(peer, error);
        let actions = self.supervisor.on(PeerEvent::DialFailed { peer });
        self.dispatch(swarm, files, groups, admitted_peers, actions);
    }

    /// Whether this peer's connection is ending by agreement rather than by accident.
    pub fn close_was_agreed(&self, peer: &PeerId) -> bool {
        self.supervisor.close_was_agreed(peer)
    }

    /// Feed the supervisor everything the other layers have finished.
    pub fn collect(
        &mut self,
        swarm: &mut ClientSwarm,
        files: &mut FileLink,
        groups: &mut GroupLink,
        admitted_peers: &AdmittedPeers,
    ) {
        for TransferOutcome {
            peer,
            group,
            path,
            result,
        } in files.drain_transfers()
        {
            let event = match result {
                Ok(()) => PeerEvent::BlobDone { peer, group, path },
                Err(why) => PeerEvent::BlobFailed {
                    peer,
                    group,
                    path,
                    terminal: why.is_terminal(),
                    why: why.to_string(),
                },
            };
            let actions = self.supervisor.on(event);
            self.dispatch(swarm, files, groups, admitted_peers, actions);
        }

        let outcomes: Vec<(Offering, RoundOutcome)> = groups
            .drain_rounds()
            .into_iter()
            .map(|o| (Offering::Chain, o))
            .chain(
                files
                    .drain_rounds()
                    .into_iter()
                    .map(|o| (Offering::Catalogue, o)),
            )
            .collect();

        for (offering, outcome) in outcomes {
            let event = match outcome {
                RoundOutcome::Settled { peer, group } => PeerEvent::Synced {
                    peer,
                    group,
                    offering,
                },
                RoundOutcome::Asked { peer } => PeerEvent::Asked { peer, offering },
                RoundOutcome::Failed { peer } => PeerEvent::AskFailed { peer },
                RoundOutcome::Holdings {
                    peer,
                    group,
                    paths,
                    held,
                } => PeerEvent::Holdings {
                    peer,
                    group,
                    paths,
                    held,
                },
                RoundOutcome::HoldingsRefused { peer, group } => {
                    PeerEvent::HoldingsRefused { peer, group }
                }
            };
            let actions = self.supervisor.on(event);
            self.dispatch(swarm, files, groups, admitted_peers, actions);
        }
    }

    /// Collect whatever is outstanding, then tick.
    pub fn housekeeping(
        &mut self,
        swarm: &mut ClientSwarm,
        files: &mut FileLink,
        groups: &mut GroupLink,
        admitted_peers: &AdmittedPeers,
        at: i64,
        space: Option<Space>,
    ) {
        self.collect(swarm, files, groups, admitted_peers);

        if let Some(space) = space {
            self.supervisor.on(PeerEvent::Space {
                free: space.free,
                held: space.held,
            });
        }

        let actions = self.supervisor.on(PeerEvent::Tick { at });
        self.dispatch(swarm, files, groups, admitted_peers, actions);

        let bandwidth = self.bandwidth(files, at);
        if let Err(e) = self
            .status
            .publish(&self.supervisor.status(), at, &bandwidth)
        {
            tracing::debug!(error = %e, "could not publish supervisor status");
        }
    }

    /// Content moved, with a rate measured across the gap since the last publish.
    ///
    /// Measured here rather than by whoever displays it: this runs on a fixed tick and never
    /// stops, where a reader can be closed, asleep or looking at another page for an hour.
    fn bandwidth(&mut self, files: &FileLink, at: i64) -> Bandwidth {
        let (down, up) = files.moved();

        let rates = match self.moved_at {
            Some((wasdown, wasup, then)) if at > then => {
                let span = (at - then) as u64;
                (
                    down.saturating_sub(wasdown) / span,
                    up.saturating_sub(wasup) / span,
                )
            }
            // Nothing to measure against yet, and a total already answers "has it moved
            // anything". Guessing a rate off one sample would just be the total again.
            _ => (0, 0),
        };
        self.moved_at = Some((down, up, at));

        Bandwidth {
            down,
            up,
            down_rate: rates.0,
            up_rate: rates.1,
        }
    }

    /// Free bytes on the storage volume, and bytes of content this node holds.
    pub fn space(&self, files: &FileLink, unsorted: u64) -> Option<Space> {
        let probe = if self.root.exists() {
            self.root.clone()
        } else {
            self.root.parent()?.to_path_buf()
        };

        let free = match fs4::available_space(&probe) {
            Ok(free) => free,
            Err(e) => {
                tracing::debug!(path = %probe.display(), error = %e, "could not measure free space");
                return None;
            }
        };
        Some(Space {
            free,
            held: files.held_bytes()?.saturating_add(unsorted),
        })
    }

    /// A peer asking whether we are finished with it, and our answers to the same question.
    pub fn on_session(
        &mut self,
        swarm: &mut ClientSwarm,
        files: &mut FileLink,
        groups: &mut GroupLink,
        admitted_peers: &AdmittedPeers,
        event: request_response::Event<SessionRequest, SessionResponse>,
    ) {
        use request_response::{Event, Message};

        let actions = match event {
            Event::Message {
                peer,
                message: Message::Request { channel, .. },
                ..
            } => {
                let ready = self.drained(&peer, files, groups, admitted_peers);
                if ready {
                    tracing::debug!(%peer, "they asked to hang up; agreed");
                } else {
                    tracing::debug!(%peer, "they asked to hang up; still busy with them");
                }
                let _ = swarm.behaviour_mut().app.sessions.send_response(
                    channel,
                    if ready {
                        SessionResponse::Ready
                    } else {
                        SessionResponse::Busy
                    },
                );
                self.supervisor.on(PeerEvent::CloseProposed { peer, ready })
            }

            Event::Message {
                peer,
                message:
                    Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                if self.proposals.remove(&request_id) != Some(peer) {
                    return;
                }
                self.supervisor.on(PeerEvent::CloseAnswered {
                    peer,
                    ready: matches!(response, SessionResponse::Ready),
                })
            }

            Event::OutboundFailure {
                peer, request_id, ..
            } => {
                self.proposals.remove(&request_id);
                self.supervisor
                    .on(PeerEvent::CloseAnswered { peer, ready: false })
            }

            _ => return,
        };

        self.dispatch(swarm, files, groups, admitted_peers, actions);
    }

    /// The server's answer to a presence query.
    pub fn on_presence(
        &mut self,
        swarm: &mut ClientSwarm,
        files: &mut FileLink,
        groups: &mut GroupLink,
        admitted_peers: &AdmittedPeers,
        event: request_response::Event<PresenceRequest, PresenceResponse>,
    ) {
        use request_response::{Event, Message};

        let (id, online) = match event {
            Event::Message {
                message:
                    Message::Response {
                        request_id,
                        response: PresenceResponse::Online(online),
                    },
                ..
            } => (request_id, online),
            Event::OutboundFailure {
                request_id, error, ..
            } => {
                tracing::debug!(%error, "the server did not answer who is online");
                self.presence.remove(&request_id);
                return;
            }
            _ => return,
        };
        let Some(asked) = self.presence.remove(&id) else {
            return;
        };

        tracing::debug!(
            asked = asked.len(),
            online = online.len(),
            "who is online, answered"
        );
        let actions = self.supervisor.on(PeerEvent::Presence { asked, online });
        self.dispatch(swarm, files, groups, admitted_peers, actions);
    }

    /// Whether this peer has any of our work outstanding.
    fn drained(
        &self,
        peer: &PeerId,
        files: &FileLink,
        groups: &GroupLink,
        admitted_peers: &AdmittedPeers,
    ) -> bool {
        admitted_peers.is_ready(peer)
            && self.supervisor.drained(*peer)
            && !files.busy_with(peer)
            && !groups.busy_with(peer)
    }

    /// The one place the swarm is driven on the supervisor's behalf.
    fn dispatch(
        &mut self,
        swarm: &mut ClientSwarm,
        files: &mut FileLink,
        groups: &mut GroupLink,
        admitted_peers: &AdmittedPeers,
        actions: Vec<PeerAction>,
    ) {
        for action in actions {
            match action {
                PeerAction::Dial { peer } => {
                    let Some(addr) = self.dial.next(peer) else {
                        tracing::debug!(%peer, "wanted to dial, but there is no server to relay through");
                        continue;
                    };
                    tracing::debug!(%peer, %addr, "dialling a member");
                    if let Err(e) = swarm.dial(addr) {
                        tracing::debug!(%peer, error = %e, "dial refused before it started");
                        let actions = self.supervisor.on(PeerEvent::DialFailed { peer });
                        self.dispatch(swarm, files, groups, admitted_peers, actions);
                    }
                }

                PeerAction::AskPresence { peers } => {
                    let Some(server) = self.server else {
                        tracing::debug!("no server yet; not asking who is online");
                        continue;
                    };
                    if !swarm.is_connected(&server) {
                        tracing::debug!("server not connected; not asking who is online");
                        continue;
                    }
                    tracing::debug!(count = peers.len(), "asking the server who is online");
                    if let Some(behaviour) = swarm.behaviour_mut().presence.as_mut() {
                        let id =
                            behaviour.send_request(&server, PresenceRequest::Who(peers.clone()));
                        self.presence.insert(id, peers);
                    }
                }

                PeerAction::Ask { peer, offering } => {
                    if groups.busy_with(&peer) {
                        tracing::debug!(%peer, ?offering, "ask deferred; a chain exchange is still outstanding");
                        let actions = self.supervisor.on(PeerEvent::AskDeferred { peer });
                        self.dispatch(swarm, files, groups, admitted_peers, actions);
                        continue;
                    }
                    match offering {
                        Offering::Chain => groups.ask(swarm, peer),
                        Offering::Catalogue => files.ask(swarm, peer),
                    }
                }

                PeerAction::AskHoldings { peer, group, paths } => {
                    files.holdings(swarm, peer, group, paths);
                }

                PeerAction::FetchBlob {
                    peer,
                    group,
                    path,
                    hash,
                } => {
                    if let Err(why) = files.fetch(peer, group, path.clone(), hash) {
                        let actions = self.supervisor.on(PeerEvent::BlobFailed {
                            peer,
                            group,
                            path,
                            terminal: false,
                            why: why.to_string(),
                        });
                        self.dispatch(swarm, files, groups, admitted_peers, actions);
                    }
                }

                PeerAction::ProposeClose { peer } => {
                    if Some(peer) == self.server {
                        continue;
                    }
                    if !self.drained(&peer, files, groups, admitted_peers) {
                        let actions = self
                            .supervisor
                            .on(PeerEvent::CloseAnswered { peer, ready: false });
                        self.dispatch(swarm, files, groups, admitted_peers, actions);
                        continue;
                    }
                    let id = swarm
                        .behaviour_mut()
                        .app
                        .sessions
                        .send_request(&peer, SessionRequest::Closing);
                    self.proposals.insert(id, peer);
                }

                PeerAction::Disconnect { peer } => {
                    if Some(peer) == self.server {
                        continue;
                    }
                    tracing::debug!(%peer, "both sides are done; closing");
                    let _ = swarm.disconnect_peer_id(peer);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ac_files::blob::FetchError;
    use ac_net::connectivity::Connectivity;
    use ac_net::throttle::{THROTTLE_BURST, Throttle};
    use ac_net::transfer::TransferEvent;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use libp2p::Multiaddr;
    use libp2p::futures::StreamExt;
    use libp2p::multiaddr::Protocol;
    use libp2p::swarm::SwarmEvent;

    use ac_net::authz::AcceptAnyPeer;
    use ac_net::config::Config;
    use ac_net::swarm::{AcBehaviourEvent, Role, build};

    use ac_files::path::RelPath;
    use ac_files::store::FileRow;
    use ac_groups::chain::Op;
    use ac_groups::id::GroupId;
    use ac_groups::standing::Position;

    use crate::daemon::{App, AppEvent, app};

    const WIRE_TIMEOUT: Duration = Duration::from_secs(30);
    const AT: i64 = 1_000_000;

    const PER_TICK: i64 = 5;

    struct Node {
        swarm: ClientSwarm,
        link: FileLink,
        groups: GroupLink,
        supervisor: SupervisorLink,
        admitted_peers: AdmittedPeers,
        peer: PeerId,
        dir: tempfile::TempDir,
        at: i64,
    }

    impl Node {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let paths = Paths::rooted_at(dir.path());
            let (identity, _) = Identity::load_or_generate(&paths.identity_file()).unwrap();

            let config = Config {
                listen: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
                listen_enroll: Vec::new(),
                external: Vec::new(),
                mdns: false,
                server: None,
                storage_root: None,
                storage_max: None,
                bandwidth_max: None,
            };

            let swarm = build(&identity, &config, Role::Client, AcceptAnyPeer, app()).unwrap();
            let down = Arc::new(Throttle::from_config(None, THROTTLE_BURST));
            let streams = swarm.behaviour().app.blobs.new_control();

            Self {
                link: FileLink::open(&paths, &identity, streams, down).unwrap(),
                swarm,
                groups: GroupLink::open(&paths, &identity).unwrap(),
                supervisor: SupervisorLink::open(&paths, &identity, None, AT).unwrap(),
                admitted_peers: AdmittedPeers::default(),
                peer: identity.peer_id(),
                dir,
                at: AT,
            }
        }

        fn key(&self) -> libp2p::identity::Keypair {
            Identity::load_or_generate(&self.dir.path().join("identity.key"))
                .unwrap()
                .0
                .keypair()
                .clone()
        }

        /// The daemon's own routing, minus admission.
        fn step(&mut self, event: SwarmEvent<AcBehaviourEvent<AcceptAnyPeer, App>>) {
            match &event {
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    self.admitted_peers.admitted(*peer_id);
                }
                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    let still = self.swarm.is_connected(peer_id);
                    if self.admitted_peers.disconnected(peer_id, still) {
                        self.supervisor.on_disconnected(
                            &mut self.swarm,
                            &mut self.link,
                            &mut self.groups,
                            &self.admitted_peers,
                            *peer_id,
                        );
                    }
                }
                _ => {}
            }

            match event {
                SwarmEvent::Behaviour(AcBehaviourEvent::App(AppEvent::Manifests(event))) => {
                    self.link
                        .on_event(&mut self.swarm, &self.admitted_peers, event);
                }
                SwarmEvent::Behaviour(AcBehaviourEvent::App(AppEvent::Groups(event))) => {
                    self.groups
                        .on_event(&mut self.swarm, &self.admitted_peers, event);
                }
                SwarmEvent::Behaviour(AcBehaviourEvent::App(AppEvent::Sessions(event))) => {
                    self.supervisor.on_session(
                        &mut self.swarm,
                        &mut self.link,
                        &mut self.groups,
                        &self.admitted_peers,
                        event,
                    );
                }
                _ => {}
            }

            self.supervisor.collect(
                &mut self.swarm,
                &mut self.link,
                &mut self.groups,
                &self.admitted_peers,
            );
        }

        /// The daemon's transfer arm.
        fn on_transfer(&mut self, event: TransferEvent<FetchError>) {
            if self.link.on_transfer(event, &self.admitted_peers) {
                self.supervisor.collect(
                    &mut self.swarm,
                    &mut self.link,
                    &mut self.groups,
                    &self.admitted_peers,
                );
            }
        }

        fn tick(&mut self) {
            self.at += PER_TICK;

            for peer in self.admitted_peers.promote(&Connectivity::default()) {
                self.supervisor.peer_ready(
                    &mut self.swarm,
                    &mut self.link,
                    &mut self.groups,
                    &self.admitted_peers,
                    peer,
                );
            }
            self.groups.housekeeping(
                &mut self.swarm,
                &self.admitted_peers,
                Instant::now(),
                self.at,
            );
            self.link.housekeeping(
                &mut self.swarm,
                &self.admitted_peers,
                Instant::now(),
                self.at,
            );
            let space = self.supervisor.space(&self.link, 0);
            self.supervisor.housekeeping(
                &mut self.swarm,
                &mut self.link,
                &mut self.groups,
                &self.admitted_peers,
                self.at,
                space,
            );
        }

        /// Hand the supervisor an address for a peer, as mDNS would.
        fn discover(&mut self, peer: PeerId, addr: Multiaddr) {
            self.supervisor.discovered(
                peer,
                &addr,
                &mut self.link,
                &mut self.groups,
                &mut self.swarm,
                &self.admitted_peers,
            );
        }

        /// Give this node a server to relay through, and return the circuit to `peer`.
        fn relay_through_server(&mut self, peer: PeerId) -> Multiaddr {
            let server: Multiaddr =
                format!("/ip4/203.0.113.1/udp/4001/quic-v1/p2p/{}", PeerId::random())
                    .parse()
                    .unwrap();
            self.supervisor.dial = DialPolicy::new(Some(server.clone()));
            server.with(Protocol::P2pCircuit).with(Protocol::P2p(peer))
        }

        /// Carry out the supervisor's decision to dial `peer`.
        fn dial(&mut self, peer: PeerId) {
            self.supervisor.dispatch(
                &mut self.swarm,
                &mut self.link,
                &mut self.groups,
                &self.admitted_peers,
                vec![PeerAction::Dial { peer }],
            );
        }

        /// The daemon's `OutgoingConnectionError` arm.
        fn dial_failed(&mut self, peer: PeerId, error: &DialError) {
            self.supervisor.dial_failed(
                &mut self.swarm,
                &mut self.link,
                &mut self.groups,
                &self.admitted_peers,
                peer,
                error,
            );
        }

        async fn listen_addr(&mut self) -> Multiaddr {
            loop {
                if let SwarmEvent::NewListenAddr { address, .. } =
                    self.swarm.select_next_some().await
                {
                    return address;
                }
            }
        }

        /// Put a file in this node's catalogue, bytes and all.
        fn add(&mut self, group: GroupId, path: &str, bytes: &[u8]) -> RelPath {
            let path = RelPath::parse(path).unwrap();
            let dir = self.link.sync().dir_of(group).unwrap();

            let src = self.dir.path().join("incoming");
            std::fs::write(&src, bytes).unwrap();

            let content = self.link.sync().content().clone();
            let staged = content.stage(&dir, &path, &src).unwrap();
            let row = FileRow {
                path: path.clone(),
                size: staged.size,
                hash: staged.hash.clone(),
                modified: AT,
                added_at: AT,
                added_by: self.peer,
                removed_at: None,
                have: true,
                seen_seq: 0,
            };
            content.commit(staged).unwrap();
            self.link
                .sync()
                .files_mut()
                .record(group, &row, true)
                .unwrap();
            path
        }

        fn row(&mut self, group: GroupId, path: &RelPath) -> Option<FileRow> {
            self.link.sync().row(group, path)
        }

        fn bytes(&mut self, group: GroupId, path: &RelPath) -> Vec<u8> {
            let dir = self.link.sync().dir_of(group).unwrap();
            std::fs::read(self.link.sync().content().locate(&dir, path)).unwrap()
        }

        /// Delete a file's bytes behind the index's back, as a stray `rm` would.
        fn lose_bytes(&mut self, group: GroupId, path: &RelPath) {
            let dir = self.link.sync().dir_of(group).unwrap();
            std::fs::remove_file(self.link.sync().content().locate(&dir, path)).unwrap();
        }
    }

    async fn run_until(
        a: &mut Node,
        b: &mut Node,
        mut done: impl FnMut(&mut Node, &mut Node) -> bool,
    ) {
        let deadline = Instant::now() + WIRE_TIMEOUT;
        while Instant::now() < deadline {
            if done(a, b) {
                return;
            }
            let (mut done_a, mut done_b) = (None, None);
            tokio::select! {
                event = a.swarm.select_next_some() => a.step(event),
                event = b.swarm.select_next_some() => b.step(event),
                event = a.link.next_transfer() => done_a = Some(event),
                event = b.link.next_transfer() => done_b = Some(event),
                _ = tokio::time::sleep(Duration::from_millis(25)) => {
                    a.tick();
                    b.tick();
                }
            }
            if let Some(outcome) = done_a {
                a.on_transfer(outcome);
            }
            if let Some(outcome) = done_b {
                b.on_transfer(outcome);
            }
        }
        let dump = |n: &mut Node| {
            let status = n.supervisor.supervisor.status();
            format!(
                "at={} connected={} groups={:?} peers={:?}",
                n.at,
                n.swarm.connected_peers().count(),
                status
                    .groups
                    .iter()
                    .map(|g| (g.missing, g.owed, g.next, g.heartbeat_at))
                    .collect::<Vec<_>>(),
                status
                    .peers
                    .iter()
                    .map(|p| (p.peer, p.connected, p.online, p.retry_at))
                    .collect::<Vec<_>>(),
            )
        };
        panic!(
            "the exchange did not finish within {WIRE_TIMEOUT:?}\n  a: {}\n  b: {}",
            dump(a),
            dump(b)
        );
    }

    /// Introduce them, then have `b` call `a`.
    async fn connect(a: &mut Node, b: &mut Node) {
        let a_addr = a.listen_addr().await.with(Protocol::P2p(a.peer));
        let b_addr = b.listen_addr().await.with(Protocol::P2p(b.peer));

        let (a_peer, b_peer) = (a.peer, b.peer);
        a.discover(b_peer, b_addr);
        b.discover(a_peer, a_addr.clone());

        b.swarm.dial(a_addr).expect("dial accepted");
    }

    /// One group both nodes belong to and have accepted.
    fn share_group(admin: &mut Node, member: &mut Node) -> GroupId {
        let admin_key = admin.key();
        let member_peer = member.peer;

        let store = admin.link.sync().groups_mut();
        let id = store.create(&admin_key, "holiday", "alice", AT).unwrap();
        store
            .author(
                &admin_key,
                id,
                Op::Add {
                    peer: member_peer.to_base58(),
                },
                AT,
            )
            .unwrap();
        let entries: Vec<_> = store.chain(id).unwrap().entries().cloned().collect();

        let member_key = member.key();
        let store = member.link.sync().groups_mut();
        store.adopt(&entries, &[], AT).unwrap();
        store
            .author_standing(&member_key, id, Position::In, "someone", AT)
            .unwrap();
        id
    }

    #[tokio::test]
    async fn a_fetch_for_a_group_with_no_directory_does_not_start() {
        let mut n = Node::new();
        let unknown = GroupId::from_bytes([9u8; 32]);
        let path = RelPath::parse("a.jpg").unwrap();

        let started = n
            .link
            .fetch(PeerId::random(), unknown, path, "00".repeat(32));
        assert_eq!(started, Err(crate::file_link::NotStarted::NoDirectory));
    }

    /// Poll the swarm until a dial fails, and return what it reported.
    async fn next_dial_failure(
        n: &mut Node,
        other: Option<&mut Node>,
    ) -> (Option<PeerId>, DialError) {
        let wait = async {
            let mut other = other;
            loop {
                let event = match other.as_mut() {
                    Some(o) => tokio::select! {
                        event = n.swarm.select_next_some() => event,
                        _ = o.swarm.select_next_some() => continue,
                    },
                    None => n.swarm.select_next_some().await,
                };
                if let SwarmEvent::OutgoingConnectionError { peer_id, error, .. } = event {
                    return (peer_id, error);
                }
            }
        };
        tokio::time::timeout(WIRE_TIMEOUT, wait)
            .await
            .expect("the dial failed")
    }

    #[tokio::test]
    async fn a_lan_address_that_refuses_reports_the_peer_and_the_next_attempt_is_relayed() {
        let mut n = Node::new();
        let them = PeerId::random();
        let relayed = n.relay_through_server(them);

        // A port nothing listens on, so the connection is refused at once.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        n.discover(them, format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap());

        n.dial(them);
        let (peer, error) = next_dial_failure(&mut n, None).await;
        assert_eq!(peer, Some(them), "the failure names the peer");
        assert!(matches!(error, DialError::Transport(_)), "{error:?}");

        n.dial_failed(them, &error);
        assert_eq!(n.supervisor.dial.next(them), Some(relayed));
    }

    #[tokio::test]
    async fn a_lan_address_now_held_by_someone_else_sends_the_next_attempt_through_the_relay() {
        let (mut n, mut stranger) = (Node::new(), Node::new());
        let them = PeerId::random();
        let relayed = n.relay_through_server(them);

        let addr = stranger.listen_addr().await;
        n.discover(them, addr);

        n.dial(them);
        let (peer, error) = next_dial_failure(&mut n, Some(&mut stranger)).await;
        assert_eq!(peer, Some(them));
        assert!(matches!(error, DialError::WrongPeerId { .. }), "{error:?}");

        n.dial_failed(them, &error);
        assert_eq!(n.supervisor.dial.next(them), Some(relayed));
    }

    #[tokio::test]
    async fn a_catalogue_crosses_a_real_connection_without_its_bytes() {
        let (mut alice, mut bob) = (Node::new(), Node::new());
        let id = share_group(&mut alice, &mut bob);
        let path = alice.add(id, "photos/beach.jpg", b"a photograph");

        connect(&mut alice, &mut bob).await;
        let want = path.clone();
        run_until(&mut alice, &mut bob, |_, b| b.row(id, &want).is_some()).await;

        let learned = bob.row(id, &path).unwrap();
        assert_eq!(learned.hash, alice.row(id, &path).unwrap().hash);
        assert!(
            !learned.have,
            "the catalogue arrives on its own; bytes are asked for separately"
        );
    }

    #[tokio::test]
    async fn a_file_transfers_over_a_stream_and_is_verified() {
        // Bigger than one copy buffer, so the read loop runs more than once.
        let content: Vec<u8> = (0..200_000).map(|i| (i % 251) as u8).collect();

        let (mut alice, mut bob) = (Node::new(), Node::new());
        let id = share_group(&mut alice, &mut bob);
        let path = alice.add(id, "media/big.bin", &content);

        connect(&mut alice, &mut bob).await;
        let want = path.clone();
        run_until(&mut alice, &mut bob, |_, b| b.row(id, &want).is_some()).await;

        let want = path.clone();
        run_until(&mut alice, &mut bob, |_, b| {
            b.row(id, &want).is_some_and(|r| r.have)
        })
        .await;

        assert_eq!(bob.bytes(id, &path), content, "byte for byte");
        assert_eq!(
            bob.row(id, &path).unwrap().hash,
            alice.row(id, &path).unwrap().hash
        );

        // The counters the Status page reports saw the same transfer the index did. Neither
        // node has a limit configured, which is the case that would have gone unmeasured had
        // the count lived under the throttle's early return.
        assert_eq!(
            bob.link.moved().0,
            content.len() as u64,
            "bob counted every byte he fetched"
        );
        assert_eq!(
            alice.link.moved().1,
            content.len() as u64,
            "and alice counted every byte she served"
        );
    }

    #[tokio::test]
    async fn a_file_indexed_but_missing_is_refused_rather_than_promised() {
        let (mut alice, mut bob) = (Node::new(), Node::new());
        let id = share_group(&mut alice, &mut bob);
        let path = alice.add(id, "gone.bin", b"these bytes will vanish");

        connect(&mut alice, &mut bob).await;
        let want = path.clone();
        run_until(&mut alice, &mut bob, |_, b| b.row(id, &want).is_some()).await;

        // Alice's index still says she holds it; her disk disagrees.
        alice.lose_bytes(id, &path);
        assert!(
            alice.row(id, &path).unwrap().have,
            "the index has not noticed yet"
        );

        // Long enough for many retries if the loop still exists.
        let deadline = Instant::now() + Duration::from_secs(8);
        while Instant::now() < deadline {
            tokio::select! {
                event = alice.swarm.select_next_some() => alice.step(event),
                event = bob.swarm.select_next_some() => bob.step(event),
                event = alice.link.next_transfer() => alice.on_transfer(event),
                event = bob.link.next_transfer() => bob.on_transfer(event),
                _ = tokio::time::sleep(Duration::from_millis(25)) => {
                    alice.tick();
                    bob.tick();
                }
            }
        }

        assert!(
            !bob.row(id, &path).unwrap().have,
            "bob cannot have acquired bytes that do not exist"
        );
        assert!(
            !alice.row(id, &path).unwrap().have,
            "alice corrects her own index rather than going on claiming it to everyone"
        );
        assert!(
            !alice.row(id, &path).unwrap().is_removed(),
            "the bytes being absent here is local; the file is not deleted from the group"
        );
    }

    #[tokio::test]
    async fn a_non_member_is_served_no_bytes() {
        // The authorization runs in the serving task, from its own database handles, so it is
        // worth proving over a real stream rather than only against `may_serve`.
        let (mut alice, mut bob) = (Node::new(), Node::new());
        let id = share_group(&mut alice, &mut bob);
        let path = alice.add(id, "secret.jpg", b"not for strangers");

        let mut carol = Node::new();
        connect(&mut alice, &mut carol).await;

        // Carol invents the row rather than learning it: nobody would have told her.
        carol.link.sync().groups_mut().adopt(&[], &[], AT).ok();
        carol
            .link
            .sync()
            .files_mut()
            .record(
                id,
                &FileRow {
                    path: path.clone(),
                    size: 17,
                    hash: alice.row(id, &path).unwrap().hash,
                    modified: AT,
                    added_at: AT,
                    added_by: alice.peer,
                    removed_at: None,
                    have: false,
                    seen_seq: 0,
                },
                true,
            )
            .unwrap();

        // Long enough for a transfer to have happened if it were going to.
        let deadline = Instant::now() + Duration::from_secs(6);
        while Instant::now() < deadline {
            tokio::select! {
                event = alice.swarm.select_next_some() => alice.step(event),
                event = carol.swarm.select_next_some() => carol.step(event),
                event = alice.link.next_transfer() => alice.on_transfer(event),
                event = carol.link.next_transfer() => carol.on_transfer(event),
                _ = tokio::time::sleep(Duration::from_millis(25)) => {
                    alice.tick();
                    carol.tick();
                }
            }
        }

        assert!(
            !carol.row(id, &path).unwrap().have,
            "a group she is not in yields nothing, however exactly she names the file"
        );
    }

    #[tokio::test]
    async fn a_mirror_arrives_unasked_and_then_the_call_ends() {
        // The milestone in one test, and the two halves have to be checked together: a node
        // that mirrors but never hangs up looks fine until someone counts open connections,
        // and a node that hangs up before mirroring looks fine until someone counts files.
        let (mut alice, mut bob) = (Node::new(), Node::new());
        let id = share_group(&mut alice, &mut bob);
        let path = alice.add(id, "photos/beach.jpg", b"a photograph nobody asked for");

        connect(&mut alice, &mut bob).await;

        let want = path.clone();
        run_until(&mut alice, &mut bob, |_, b| {
            b.row(id, &want).is_some_and(|r| r.have)
        })
        .await;

        assert_eq!(
            bob.bytes(id, &path),
            b"a photograph nobody asked for",
            "byte for byte, with nobody having asked"
        );

        let bob_peer = bob.peer;
        run_until(&mut alice, &mut bob, |a, _| {
            !a.swarm.is_connected(&bob_peer)
        })
        .await;

        assert!(
            alice.supervisor.supervisor.drained(bob_peer),
            "alice hung up because she was drained, not because something went wrong"
        );
    }

    #[tokio::test]
    async fn a_peer_whose_catalogue_read_is_queued_is_not_proposed_a_hang_up() {
        let mut n = Node::new();
        let member = || {
            libp2p::identity::Keypair::generate_ed25519()
                .public()
                .to_peer_id()
        };
        let (bob, carol, dave) = (member(), member(), member());

        let key = n.key();
        let store = n.link.sync().groups_mut();
        let mut ids = Vec::new();
        for _ in 0..ac_files::sync::MAX_INFLIGHT {
            let id = store.create(&key, "holiday", "alice", AT).unwrap();
            for peer in [bob, carol, dave] {
                store
                    .author(
                        &key,
                        id,
                        Op::Add {
                            peer: peer.to_base58(),
                        },
                        AT,
                    )
                    .unwrap();
            }
            ids.push(id);
        }
        for peer in [bob, carol, dave] {
            n.admitted_peers.admitted(peer);
        }
        n.admitted_peers.promote(&Connectivity::default());

        // Bob's catalogues differ from ours and take every read slot, so carol's read waits.
        let heads = |named: &[GroupId]| {
            named
                .iter()
                .map(|&group| ac_files::wire::FileHead {
                    group,
                    digest: [7u8; 32],
                    count: 1,
                })
                .collect::<Vec<_>>()
        };
        for (peer, named) in [(bob, &ids[..]), (carol, &ids[..1])] {
            n.link.sync().on(
                ac_files::sync::FileEvent::Heads {
                    peer,
                    heads: heads(named),
                },
                &n.admitted_peers,
            );
        }

        assert!(
            n.supervisor
                .drained(&dave, &n.link, &n.groups, &n.admitted_peers),
            "a peer with nothing outstanding may be hung up on"
        );
        assert!(
            !n.supervisor
                .drained(&bob, &n.link, &n.groups, &n.admitted_peers)
        );
        assert!(
            !n.supervisor
                .drained(&carol, &n.link, &n.groups, &n.admitted_peers),
            "a read still waiting to go out is work outstanding with carol"
        );

        n.supervisor.dispatch(
            &mut n.swarm,
            &mut n.link,
            &mut n.groups,
            &n.admitted_peers,
            vec![PeerAction::ProposeClose { peer: carol }],
        );
        assert!(
            n.supervisor.proposals.is_empty(),
            "carol is not asked to hang up"
        );
    }

    #[tokio::test]
    async fn the_supervisor_publishes_what_it_is_waiting_on() {
        let (mut alice, mut bob) = (Node::new(), Node::new());
        let id = share_group(&mut alice, &mut bob);
        alice.add(id, "photos/beach.jpg", b"a photograph");

        connect(&mut alice, &mut bob).await;

        // Wait for the mirror first. Waiting only for the *hang-up* would return before they
        // ever met, since "not connected" is also true a millisecond after the dial goes out.
        let want = RelPath::parse("photos/beach.jpg").unwrap();
        run_until(&mut alice, &mut bob, |_, b| {
            b.row(id, &want).is_some_and(|r| r.have)
        })
        .await;

        let alice_peer = alice.peer;
        run_until(&mut alice, &mut bob, |_, b| {
            !b.swarm.is_connected(&alice_peer)
        })
        .await;

        // The status file is written on a tick, and the mirror lands between two of them:
        // whether one follows before the hang-up is down to how the machine schedules, so
        // ask for one rather than read whatever the last one happened to say.
        bob.tick();

        let db = Paths::rooted_at(bob.dir.path()).db_file();
        let snapshot = Published::open(&db).unwrap().read().unwrap();

        assert_eq!(
            snapshot.at,
            Some(bob.at),
            "stamped with the tick that wrote it"
        );

        let group = snapshot
            .groups
            .iter()
            .find(|g| g.group == id)
            .expect("the shared group is reported");
        assert_eq!(
            group.missing, 0,
            "bob mirrored it, so nothing is outstanding"
        );
        assert_eq!(group.source, None, "and no pull is still assigned");

        assert!(
            snapshot.peers.iter().any(|p| p.peer == alice_peer),
            "a member we might call is listed whether or not we are talking to them"
        );
    }
}
