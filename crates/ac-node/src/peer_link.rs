use std::collections::HashMap;

use anyhow::{Context, Result};
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId, request_response};

use ac_net::config::{Config, Paths};
use ac_net::identity::Identity;
use ac_net::proto::{PresenceRequest, PresenceResponse};
use ac_net::roster::Roster;

use ac_files::content::Content;
use ac_files::store::Files;
use ac_groups::store::Groups;
use ac_peers::sync::{Limits, Offering, PeerAction, PeerEvent, Peers};
use ac_peers::wire::{SessionRequest, SessionResponse};

use crate::blob::{self, Transfers};
use crate::daemon::ClientSwarm;
use crate::file_link::{FileLink, RoundOutcome};
use crate::group_link::GroupLink;
use crate::status::Published;

pub struct PeerLink {
    peers: Peers,
    transfers: Transfers,
    proposals: HashMap<request_response::OutboundRequestId, PeerId>,
    presence: HashMap<request_response::OutboundRequestId, Vec<PeerId>>,
    server: Option<PeerId>,
    relay: Option<Multiaddr>,
    direct: HashMap<PeerId, Multiaddr>,
    content: Content,
    root: std::path::PathBuf,
    status: Published,
}

impl PeerLink {
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
        let content = Content::new(root.clone());

        Ok(Self {
            peers: Peers::new(files, groups, at).with_limits(Limits {
                storage_max: config.storage_max,
                ..Limits::default()
            }),
            transfers: Transfers::new(path.clone(), me),
            proposals: HashMap::new(),
            presence: HashMap::new(),
            server,
            relay: config.server.clone(),
            direct: HashMap::new(),
            content,
            root,
            status: Published::open(&path)
                .with_context(|| format!("opening the status table at {}", path.display()))?,
        })
    }

    /// A peer completed mutual attestation
    pub fn peer_ready(
        &mut self,
        swarm: &mut ClientSwarm,
        files: &mut FileLink,
        groups: &mut GroupLink,
        roster: &Roster,
        peer: PeerId,
    ) {
        let actions = self.peers.on(PeerEvent::Verified { peer });
        self.dispatch(swarm, files, groups, roster, actions);
    }

    /// Discovery saw this peer. A liveness hint, and possibly an address worth preferring.
    pub fn discovered(
        &mut self,
        peer: PeerId,
        addresses: &[Multiaddr],
        files: &mut FileLink,
        groups: &mut GroupLink,
        swarm: &mut ClientSwarm,
        roster: &Roster,
    ) {
        if let Some(addr) = addresses
            .iter()
            .find(|a| !a.iter().any(|p| matches!(p, Protocol::P2pCircuit)))
        {
            self.direct.insert(peer, addr.clone());
        }
        let actions = self.peers.on(PeerEvent::Discovered { peer });
        self.dispatch(swarm, files, groups, roster, actions);
    }

    pub fn on_disconnected(
        &mut self,
        swarm: &mut ClientSwarm,
        files: &mut FileLink,
        groups: &mut GroupLink,
        roster: &Roster,
        peer: PeerId,
    ) {
        let actions = self.peers.on(PeerEvent::Gone { peer });
        self.dispatch(swarm, files, groups, roster, actions);
    }

    pub fn dial_failed(
        &mut self,
        swarm: &mut ClientSwarm,
        files: &mut FileLink,
        groups: &mut GroupLink,
        roster: &Roster,
        peer: PeerId,
    ) {
        let actions = self.peers.on(PeerEvent::DialFailed { peer });
        self.dispatch(swarm, files, groups, roster, actions);
    }

    /// Wait for a transfer to end.
    pub async fn next_transfer(&mut self) -> Option<PeerEvent> {
        self.transfers.finished().await
    }

    pub fn on_transfer(
        &mut self,
        swarm: &mut ClientSwarm,
        files: &mut FileLink,
        groups: &mut GroupLink,
        roster: &Roster,
        event: PeerEvent,
    ) {
        let actions = self.peers.on(event);
        self.dispatch(swarm, files, groups, roster, actions);
    }

    /// Feed the supervisor everything the other layers have finished.
    pub fn collect(
        &mut self,
        swarm: &mut ClientSwarm,
        files: &mut FileLink,
        groups: &mut GroupLink,
        roster: &Roster,
    ) {
        for outcome in self.transfers.collect() {
            let actions = self.peers.on(outcome);
            self.dispatch(swarm, files, groups, roster, actions);
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
            let actions = self.peers.on(event);
            self.dispatch(swarm, files, groups, roster, actions);
        }
    }

    /// Collect whatever is outstanding, then tick.
    pub fn housekeeping(
        &mut self,
        swarm: &mut ClientSwarm,
        files: &mut FileLink,
        groups: &mut GroupLink,
        roster: &Roster,
        at: i64,
    ) {
        self.collect(swarm, files, groups, roster);

        if let Some((free, held)) = self.disk(files) {
            self.peers.on(PeerEvent::Space { free, held });
        }

        let actions = self.peers.on(PeerEvent::Tick { at });
        self.dispatch(swarm, files, groups, roster, actions);

        if let Err(e) = self.status.publish(&self.peers.status(), at) {
            tracing::debug!(error = %e, "could not publish supervisor status");
        }
    }

    /// Free bytes on the storage volume, and bytes of content this node holds.
    fn disk(&self, files: &FileLink) -> Option<(u64, u64)> {
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
        Some((free, files.held_bytes()?))
    }

    /// A peer asking whether we are finished with it, and our answers to the same question.
    pub fn on_session(
        &mut self,
        swarm: &mut ClientSwarm,
        files: &mut FileLink,
        groups: &mut GroupLink,
        roster: &Roster,
        event: request_response::Event<SessionRequest, SessionResponse>,
    ) {
        use request_response::{Event, Message};

        let actions = match event {
            Event::Message {
                peer,
                message: Message::Request { channel, .. },
                ..
            } => {
                let ready = self.drained(&peer, files, groups, roster);
                let _ = swarm.behaviour_mut().app.sessions.send_response(
                    channel,
                    if ready {
                        SessionResponse::Ready
                    } else {
                        SessionResponse::Busy
                    },
                );
                self.peers.on(PeerEvent::CloseProposed { peer })
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
                self.peers.on(PeerEvent::CloseAnswered {
                    peer,
                    ready: matches!(response, SessionResponse::Ready),
                })
            }

            Event::OutboundFailure {
                peer, request_id, ..
            } => {
                self.proposals.remove(&request_id);
                self.peers
                    .on(PeerEvent::CloseAnswered { peer, ready: false })
            }

            _ => return,
        };

        self.dispatch(swarm, files, groups, roster, actions);
    }

    /// The server's answer to a presence query.
    pub fn on_presence(
        &mut self,
        swarm: &mut ClientSwarm,
        files: &mut FileLink,
        groups: &mut GroupLink,
        roster: &Roster,
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
        let actions = self.peers.on(PeerEvent::Presence { asked, online });
        self.dispatch(swarm, files, groups, roster, actions);
    }

    /// Whether this peer has any of our work outstanding.
    fn drained(
        &self,
        peer: &PeerId,
        files: &FileLink,
        groups: &GroupLink,
        roster: &Roster,
    ) -> bool {
        roster.is_ready(peer)
            && self.transfers.running_with(peer) == 0
            && self.peers.drained(*peer)
            && !files.busy_with(peer)
            && !groups.busy_with(peer)
    }

    /// The one place the swarm is driven on the supervisor's behalf.
    fn dispatch(
        &mut self,
        swarm: &mut ClientSwarm,
        files: &mut FileLink,
        groups: &mut GroupLink,
        roster: &Roster,
        actions: Vec<PeerAction>,
    ) {
        for action in actions {
            match action {
                PeerAction::Dial { peer } => {
                    let Some(addr) = self.address_of(&peer) else {
                        tracing::debug!(%peer, "wanted to dial, but there is no server to relay through");
                        continue;
                    };
                    tracing::debug!(%peer, %addr, "dialling a member");
                    if let Err(e) = swarm.dial(addr) {
                        tracing::debug!(%peer, error = %e, "dial refused before it started");
                        let actions = self.peers.on(PeerEvent::DialFailed { peer });
                        self.dispatch(swarm, files, groups, roster, actions);
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
                        let actions = self.peers.on(PeerEvent::AskDeferred { peer });
                        self.dispatch(swarm, files, groups, roster, actions);
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
                    let Some(dir) = files.dir_of(group) else {
                        continue;
                    };
                    let started = self.transfers.fetch(
                        swarm.behaviour().app.blobs.new_control(),
                        self.content.clone(),
                        blob::Wanted {
                            peer,
                            group,
                            path: path.clone(),
                            hash,
                            dir,
                        },
                    );
                    if !started {
                        let actions = self.peers.on(PeerEvent::BlobFailed {
                            peer,
                            group,
                            path,
                            terminal: false,
                            why: "the transfer pool was full".to_owned(),
                        });
                        self.dispatch(swarm, files, groups, roster, actions);
                    }
                }

                PeerAction::ProposeClose { peer } => {
                    if Some(peer) == self.server {
                        continue;
                    }
                    if !self.drained(&peer, files, groups, roster) {
                        let actions = self
                            .peers
                            .on(PeerEvent::CloseAnswered { peer, ready: false });
                        self.dispatch(swarm, files, groups, roster, actions);
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

    /// Where to dial this peer.
    fn address_of(&self, peer: &PeerId) -> Option<Multiaddr> {
        if let Some(addr) = self.direct.get(peer) {
            return Some(addr.clone());
        }
        Some(
            self.relay
                .clone()?
                .with(Protocol::P2pCircuit)
                .with(Protocol::P2p(*peer)),
        )
    }

    /// The supervisor's own view, for `ac peer status` and for tests.
    #[cfg(test)]
    pub(crate) fn peers(&self) -> &Peers {
        &self.peers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ac_net::connectivity::Connectivity;
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
        peers: PeerLink,
        blobs: libp2p_stream::IncomingStreams,
        roster: Roster,
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
            };

            let mut swarm = build(&identity, &config, Role::Client, AcceptAnyPeer, app()).unwrap();
            let blobs = FileLink::accept_blobs(&mut swarm).unwrap();

            Self {
                swarm,
                link: FileLink::open(&paths, &identity).unwrap(),
                groups: GroupLink::open(&paths, &identity).unwrap(),
                peers: PeerLink::open(&paths, &identity, None, AT).unwrap(),
                blobs,
                roster: Roster::default(),
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
                    self.roster.admitted(*peer_id);
                }
                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    let still = self.swarm.is_connected(peer_id);
                    if self.roster.disconnected(peer_id, still) {
                        self.peers.on_disconnected(
                            &mut self.swarm,
                            &mut self.link,
                            &mut self.groups,
                            &self.roster,
                            *peer_id,
                        );
                    }
                }
                _ => {}
            }

            match event {
                SwarmEvent::Behaviour(AcBehaviourEvent::App(AppEvent::Manifests(event))) => {
                    self.link.on_event(&mut self.swarm, &self.roster, event);
                }
                SwarmEvent::Behaviour(AcBehaviourEvent::App(AppEvent::Groups(event))) => {
                    self.groups.on_event(&mut self.swarm, &self.roster, event);
                }
                SwarmEvent::Behaviour(AcBehaviourEvent::App(AppEvent::Sessions(event))) => {
                    self.peers.on_session(
                        &mut self.swarm,
                        &mut self.link,
                        &mut self.groups,
                        &self.roster,
                        event,
                    );
                }
                _ => {}
            }

            self.peers.collect(
                &mut self.swarm,
                &mut self.link,
                &mut self.groups,
                &self.roster,
            );
        }

        fn on_transfer(&mut self, outcome: PeerEvent) {
            self.peers.on_transfer(
                &mut self.swarm,
                &mut self.link,
                &mut self.groups,
                &self.roster,
                outcome,
            );
        }

        fn tick(&mut self) {
            self.at += PER_TICK;

            for peer in self.roster.promote(&Connectivity::default()) {
                self.peers.peer_ready(
                    &mut self.swarm,
                    &mut self.link,
                    &mut self.groups,
                    &self.roster,
                    peer,
                );
            }
            self.groups
                .housekeeping(&mut self.swarm, &self.roster, Instant::now(), self.at);
            self.link
                .housekeeping(&mut self.swarm, &self.roster, Instant::now(), self.at);
            self.peers.housekeeping(
                &mut self.swarm,
                &mut self.link,
                &mut self.groups,
                &self.roster,
                self.at,
            );
        }

        /// Hand the supervisor an address for a peer, as mDNS or the rendezvous sweep would.
        fn discover(&mut self, peer: PeerId, addr: Multiaddr) {
            self.peers.discovered(
                peer,
                std::slice::from_ref(&addr),
                &mut self.link,
                &mut self.groups,
                &mut self.swarm,
                &self.roster,
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
            let dir = self.link.dir_of(group).unwrap();

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
            let dir = self.link.dir_of(group).unwrap();
            std::fs::read(self.link.sync().content().locate(&dir, path)).unwrap()
        }

        /// Delete a file's bytes behind the index's back, as a stray `rm` would.
        fn lose_bytes(&mut self, group: GroupId, path: &RelPath) {
            let dir = self.link.dir_of(group).unwrap();
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
                Some((peer, stream)) = a.blobs.next() => a.link.on_inbound_blob(peer, stream),
                Some((peer, stream)) = b.blobs.next() => b.link.on_inbound_blob(peer, stream),
                Some(outcome) = a.peers.next_transfer() => done_a = Some(outcome),
                Some(outcome) = b.peers.next_transfer() => done_b = Some(outcome),
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
            let status = n.peers.peers().status();
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
                    username: "bob".into(),
                },
                AT,
            )
            .unwrap();
        let entries: Vec<_> = store.chain(id).unwrap().entries().cloned().collect();

        let member_key = member.key();
        let store = member.link.sync().groups_mut();
        store.adopt(&entries, &[], AT).unwrap();
        store
            .author_standing(&member_key, id, Position::In, AT)
            .unwrap();
        id
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
                Some((p, s)) = alice.blobs.next() => alice.link.on_inbound_blob(p, s),
                Some((p, s)) = bob.blobs.next() => bob.link.on_inbound_blob(p, s),
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
                Some((p, s)) = alice.blobs.next() => alice.link.on_inbound_blob(p, s),
                Some((p, s)) = carol.blobs.next() => carol.link.on_inbound_blob(p, s),
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
            alice.peers.peers().drained(bob_peer),
            "alice hung up because she was drained, not because something went wrong"
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
