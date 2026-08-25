//! Where the swarm and `ac-peers` meet.
//!
//! The third and last of the adapters, and the one with the widest reach: the supervisor
//! decides *who to call*, so this is the only module that turns a decision into a `dial`.
//!
//! `ac-peers` names no address, no connection and no request id — it does not depend on libp2p,
//! so the compiler enforces it — which is what lets a fifty-member group, a week-long absence
//! or a peer that never answers be set up in a test in microseconds. The price is that everything libp2p
//! knows and the policy does not has to be supplied here:
//!
//! - **How to reach a peer.** [`PeerAction::Dial`] carries only a peer id. Most nodes publish
//!   nothing but a circuit address, so the default is `config.server + /p2p-circuit + /p2p/…`,
//!   built exactly as `cmd::probe` builds it and — per that module's note — **without waiting
//!   on our own relay reservation**, which makes *us* reachable and has nothing to do with
//!   dialling out. A direct address is used only when discovery has offered a non-circuit one
//!   this session.
//! - **Request correlation**, for holdings queries, presence and close proposals alike.
//! - **Every word a person reads**, so `ac-peers` returns a typed `Notice` and its tests
//!   assert on meaning rather than phrasing.
//!
//! Waiting for a connection to settle is *not* among them any more: that is
//! [`ac_net::roster::Roster`]'s, which every layer asks rather than tracking for itself.
//!
//! # Two behaviours, three owners
//!
//! Holdings queries go over the *manifest* protocol, which [`crate::file_link`] also uses. Both
//! send through the same behaviour, so request ids are unique across the pair; the daemon
//! offers each manifest event here first and passes on whatever this does not claim. Rounds go
//! the other way — the supervisor decides *when*, and `FileLink` knows *what* to say.

use std::collections::HashMap;

use anyhow::{Context, Result};
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId, request_response};

use ac_net::config::{Config, Paths};
use ac_net::identity::Identity;
use ac_net::proto::{PresenceRequest, PresenceResponse};
use ac_net::roster::Roster;

use ac_files::content::Content;
use ac_files::path::RelPath;
use ac_files::store::Files;
use ac_files::wire::{ManifestRequest, ManifestResponse, holds};
use ac_groups::id::GroupId;
use ac_groups::store::Groups;
use ac_peers::sync::{Limits, Offering, PeerAction, PeerEvent, Peers};
use ac_peers::wire::{SessionRequest, SessionResponse};

use crate::blob::{self, Transfers};
use crate::daemon::ClientSwarm;
use crate::file_link::{FileLink, RoundOutcome};
use crate::group_link::GroupLink;
use crate::status::Published;

/// A holdings query we sent, kept so the bitmap can be matched to the paths it answers.
///
/// The paths have to be remembered rather than re-derived: `next_missing` reads the store, and
/// by the time the answer arrives the store may have moved. A bitmap lined up against a
/// different list would attribute one file's answer to another.
struct Query {
    peer: PeerId,
    group: GroupId,
    paths: Vec<RelPath>,
}

/// The only place a swarm and `ac-peers` are named together.
pub struct PeerLink {
    peers: Peers,
    /// Blob transfers in flight, keyed by peer so "is a transfer running with P" is answerable.
    transfers: Transfers,
    holdings: HashMap<request_response::OutboundRequestId, Query>,
    /// Close proposals outstanding, so a bare `Ready`/`Busy` names the peer it is about.
    proposals: HashMap<request_response::OutboundRequestId, PeerId>,
    /// Presence queries outstanding, and who each asked about. The answer is a filter, so
    /// without the question it cannot be applied to anything.
    presence: HashMap<request_response::OutboundRequestId, Vec<PeerId>>,
    /// The server: never proposed to, and the only peer presence can be asked of.
    server: Option<PeerId>,
    /// Where the server is, for building circuit addresses.
    relay: Option<Multiaddr>,
    /// Non-circuit addresses discovery has offered this session.
    ///
    /// In memory on purpose. A stored address outlives the lease behind it, and dialling a
    /// corpse costs one of the circuits a client is allowed.
    direct: HashMap<PeerId, Multiaddr>,
    content: Content,
    /// The storage root, whose volume is the one whose free space bounds mirroring.
    ///
    /// Kept rather than re-derived: it may be a mount of its own, so asking about the data
    /// directory instead would police the wrong disk.
    root: std::path::PathBuf,
    /// Where the volatile half of this module's state is published for `ac peer status`.
    ///
    /// Everything above is in memory and invisible to another process, which is the whole
    /// reason a person cannot otherwise be told why a dial is not happening.
    status: Published,
}

impl PeerLink {
    pub fn open(paths: &Paths, identity: &Identity, server: Option<PeerId>) -> Result<Self> {
        let path = paths.db_file();
        let me = identity.peer_id();

        let files = Files::open(&path, me)
            .with_context(|| format!("opening the file index at {}", path.display()))?;
        // A fourth handle on the same database, for the same reason as everywhere else here:
        // nothing in this workspace shares a connection behind a lock.
        let groups = Groups::open(&path, me)
            .with_context(|| format!("opening the group store at {}", path.display()))?;

        let config = Config::load(&paths.config_file())
            .with_context(|| format!("reading the config at {}", paths.config_file().display()))?;
        let root = config.storage_root(paths);
        let content = Content::new(root.clone());

        Ok(Self {
            // `storage_max` is a byte count in the file, so there is nothing to parse and no
            // way for it to be malformed without `Config::load` having already refused it.
            // `None` means no ceiling beyond the free-space floor `Limits::default` carries.
            peers: Peers::new(files, groups).with_limits(Limits {
                storage_max: config.storage_max,
                ..Limits::default()
            }),
            transfers: Transfers::new(path.clone(), me),
            holdings: HashMap::new(),
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

    /// A peer completed mutual attestation. It is not usable to the supervisor yet.
    /// The roster promoted this peer: admitted, and its connection has stopped changing shape.
    ///
    /// The only one of the three layers that still wants telling. `FileSync` and `GroupSync`
    /// read the roster where they need it, but this arm does work no poll could reproduce —
    /// it resets the peer's backoff and *puts the question* that starts a pull.
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
        // A circuit address tells us nothing we could not rebuild ourselves, and preferring it
        // over the one we would construct only risks pinning a stale relay.
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

    /// Collect finished transfers and round outcomes, then tick.
    pub fn housekeeping(
        &mut self,
        swarm: &mut ClientSwarm,
        files: &mut FileLink,
        groups: &mut GroupLink,
        roster: &Roster,
        at: i64,
    ) {
        // Transfers run in their own tasks, so their outcomes arrive on a channel rather than
        // as swarm events. Drained before the tick so a finished download frees its slot in
        // the same turn.
        for outcome in self.transfers.collect() {
            let actions = self.peers.on(outcome);
            self.dispatch(swarm, files, groups, roster, actions);
        }

        // Exchanges the two layers finished on our behalf. Before the tick, so a settled one is
        // counted before the next is chosen.
        //
        // Both report the same three outcomes; which protocol they came from is what says
        // whether membership or the catalogue was reconciled, and only the matching half of the
        // supervisor's record may be written from it.
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
            };
            let actions = self.peers.on(event);
            self.dispatch(swarm, files, groups, roster, actions);
        }

        // Before the tick, so the decision to fetch is made against the disk as it is now
        // rather than as it was five seconds ago — and so a transfer that has just landed is
        // counted before the next batch is chosen.
        if let Some((free, held)) = self.disk(files) {
            self.peers.on(PeerEvent::Space { free, held });
        }

        let actions = self.peers.on(PeerEvent::Tick { at });
        self.dispatch(swarm, files, groups, roster, actions);

        // Published last, so what a person reads is the state the tick left behind rather than
        // the one it started from. A failure here is worth a line and nothing more: this is a
        // diagnostic, and a node that stopped syncing because it could not write its own
        // status report would be a poor trade.
        if let Err(e) = self.status.publish(&self.peers.status(), at) {
            tracing::debug!(error = %e, "could not publish supervisor status");
        }
    }

    /// Free bytes on the storage volume, and bytes of content this node holds.
    ///
    /// `None` when either cannot be answered, which leaves the supervisor's previous view in
    /// place. That is the right failure: a storage root on a network mount that is briefly
    /// unavailable should not read as "no free space" and stop mirroring.
    fn disk(&self, files: &FileLink) -> Option<(u64, u64)> {
        // The root may not exist yet on a node that has never held anything, so fall back to
        // its parent rather than reporting a disk that cannot be measured.
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

    /// Take a manifest event if it answers one of *our* requests, or hand it back.
    ///
    /// `FileLink` owns the manifest protocol's other users, and both send through the same
    /// behaviour — so ids are unique across the pair and this is a claim, not a race.
    pub fn claim_manifest(
        &mut self,
        swarm: &mut ClientSwarm,
        files: &mut FileLink,
        groups: &mut GroupLink,
        roster: &Roster,
        event: request_response::Event<ManifestRequest, ManifestResponse>,
    ) -> Option<request_response::Event<ManifestRequest, ManifestResponse>> {
        use request_response::{Event, Message};

        let id = match &event {
            Event::Message {
                message: Message::Response { request_id, .. },
                ..
            } => *request_id,
            Event::OutboundFailure { request_id, .. } => *request_id,
            _ => return Some(event),
        };
        // Not ours. Handed back rather than dropped — `?` here would swallow every offer and
        // every page the file layer is waiting for, which looks exactly like a peer that never
        // answers.
        let Some(query) = self.holdings.remove(&id) else {
            return Some(event);
        };

        let actions = match event {
            Event::Message {
                peer,
                message: Message::Response { response, .. },
                ..
            } if peer == query.peer => match response {
                ManifestResponse::Holdings { group, held } if group == query.group => {
                    let held: Vec<bool> = (0..query.paths.len()).map(|i| holds(&held, i)).collect();
                    self.peers.on(PeerEvent::Holdings {
                        peer,
                        group,
                        paths: query.paths,
                        held,
                    })
                }
                // Refused, or an answer about a group we did not ask about. Either way they
                // told us nothing, which reads the same as holding none of it — the peer is
                // spent for this group and the rotation moves on.
                _ => self.peers.on(PeerEvent::Holdings {
                    peer,
                    group: query.group,
                    held: vec![false; query.paths.len()],
                    paths: query.paths,
                }),
            },
            _ => self.peers.on(PeerEvent::Holdings {
                peer: query.peer,
                group: query.group,
                held: vec![false; query.paths.len()],
                paths: query.paths,
            }),
        };

        self.dispatch(swarm, files, groups, roster, actions);
        None
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
                // Answered here, in the same turn, while the channel is still on the stack —
                // the same discipline `FileLink` follows, so a channel can never be stranded.
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
                // Unanswered is not agreement. Leaving the connection up costs a socket; the
                // proposal is made again the next time this peer looks idle.
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
                // Not worth reacting to beyond forgetting the question: the previous answer
                // stands, and the worst case is dialling someone who has since gone away. Worth
                // saying out loud, though — an unanswered presence query is invisible from
                // outside and looks exactly like a supervisor that has decided to do nothing.
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
    ///
    /// Deliberately a question about the *peer* and not about any group. Under auto-mirror a
    /// group is behind most of the time, so a group-shaped test is permanently false and every
    /// exhausted peer would be held for ever — which fills `MAX_PEER_CONNECTIONS` with peers
    /// known to be useless and leaves no room to dial one that is not.
    /// All three layers, not just the supervisor's own.
    ///
    /// `Peers` counts the rounds and transfers *it* started, and that is not everything a
    /// connection is carrying: membership arrives over `/ac/group/3.0.0`, which it never sees,
    /// and `FileSync` still starts catalogue offers of its own. Asking only the supervisor made
    /// a freshly verified peer look idle within milliseconds — so a node hung up before the
    /// group it had just been invited to had reached it, and nothing ever mirrored.
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
                    // **After the chain, not beside it.** A catalogue offer is gated on
                    // membership the other side may not have yet: a newly added member answers
                    // our file heads before the op that adds us has arrived, omits the group,
                    // and we learn nothing. So while anything about membership is stale for
                    // this peer the supervisor asks for `Chain`, and the catalogue follows on a
                    // later tick — by which time they know who we are.
                    //
                    // Deferring while the group layer is mid-exchange covers the rest: its own
                    // on-connect announce, and any fetch it started off the back of one.
                    if groups.busy_with(&peer) {
                        let actions = self.peers.on(PeerEvent::AskDeferred { peer });
                        self.dispatch(swarm, files, groups, roster, actions);
                        continue;
                    }
                    // Each layer knows what to say; the supervisor decided when and which. If
                    // we share no group with them at all the offer never happened, and saying
                    // so keeps the record honest.
                    match offering {
                        Offering::Chain => groups.ask(swarm, peer),
                        Offering::Catalogue => files.ask(swarm, peer),
                    }
                }

                PeerAction::AskHoldings { peer, group, paths } => {
                    let id = files.holdings(
                        swarm,
                        peer,
                        group,
                        paths.iter().map(|p| p.to_string()).collect(),
                    );
                    self.holdings.insert(id, Query { peer, group, paths });
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
                        // The supervisor paces itself below the blob layer's ceiling, so this is
                        // a disagreement between the two rather than an expected outcome. Report
                        // it as a retryable failure: nothing is held against the peer, the file
                        // stays missing, and the count of what is running stays true — which is
                        // the whole point, since a fetch nobody hears about again is a slot the
                        // supervisor waits on for ever.
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
                    // The server is never proposed to: closing it would take down renewal, the
                    // relay reservation and the registry at once. The same carve-out
                    // `ac_net::admission` makes.
                    if Some(peer) == self.server {
                        continue;
                    }
                    // Another layer is mid-exchange with them. Reported back as a refusal
                    // rather than dropped, so the proposal is forgotten now and re-offered
                    // when things are actually quiet, instead of sitting out `CLOSE_TIMEOUT`.
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
    ///
    /// A direct address if discovery offered one this session, otherwise a circuit through the
    /// server. Nothing is stored across runs: an address outlives the lease behind it, and the
    /// commonest shape of this bug — dialling the corpse of a restarted peer — costs one of the
    /// circuits a client is allowed.
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

    // The wire-level tests for the whole file path, supervisor included. `ac_files::sync`
    // proves the reconciliation policy and `ac_peers::sync` proves the dial and fetch policy,
    // both against in-process buses. Neither can prove anything about the wire: that four
    // protocols are mounted and reachable through one app slot, that a real file's bytes
    // survive a libp2p stream, that the inbound stream is authorized from a task holding its
    // own database handles, or that a bare reply is correlated back to the request that caused
    // it — across *two* links that share the manifest behaviour.
    //
    // They live here rather than beside `FileLink` because a node now needs both adapters to
    // fetch anything: the file layer knows what exists, the supervisor decides what to ask for.
    // In-crate rather than in `tests/` because `ac-node` is a binary with no library target.

    const WIRE_TIMEOUT: Duration = Duration::from_secs(30);
    const AT: i64 = 1_000_000;

    /// Wall-clock seconds each tick reports, on top of the 25ms it really takes.
    ///
    /// The supervisor batches an editing session before it shares a catalogue, so a clock
    /// frozen at [`AT`] never gets a catalogue out of the door at all. Five seconds a tick
    /// crosses that pause in twenty-odd ticks — half a second of real time — while staying
    /// far below the backoff a failed dial waits out, so nothing here is paced by chance.
    const PER_TICK: i64 = 5;

    struct Node {
        swarm: ClientSwarm,
        link: FileLink,
        // The group layer, present so "is this peer busy" can be asked of it — a peer that
        // looks idle to the supervisor may be mid-way through being told what group it is in.
        groups: GroupLink,
        peers: PeerLink,
        blobs: libp2p_stream::IncomingStreams,
        roster: Roster,
        peer: PeerId,
        dir: tempfile::TempDir,
        /// The clock the tick reports, advanced by [`PER_TICK`] each time round.
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
                // No server in these tests, so the supervisor has no relay to build a circuit
                // through and no one to ask about presence. It does not need either: both
                // nodes are dialled directly, and `Verified` is what marks a peer usable.
                peers: PeerLink::open(&paths, &identity, None).unwrap(),
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
        ///
        /// Attestation is bypassed — the peer is put in the roster straight off the
        /// connection — so these tests exercise the file path without also standing up a
        /// server to issue credentials.
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
                    // The daemon's own routing: the supervisor claims its holdings queries,
                    // the file layer gets everything else.
                    if let Some(event) = self.peers.claim_manifest(
                        &mut self.swarm,
                        &mut self.link,
                        &mut self.groups,
                        &self.roster,
                        event,
                    ) {
                        self.link.on_event(&mut self.swarm, &self.roster, event);
                    }
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
        }

        fn tick(&mut self) {
            self.at += PER_TICK;

            // The daemon's order: promote once, then groups, then files, then the supervisor
            // — which sees the round outcomes the file layer produced in the same turn.
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

    /// Drive both nodes until `done`, ticking regularly and accepting inbound blob streams.
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
            tokio::select! {
                event = a.swarm.select_next_some() => a.step(event),
                event = b.swarm.select_next_some() => b.step(event),
                Some((peer, stream)) = a.blobs.next() => a.link.on_inbound_blob(peer, stream),
                Some((peer, stream)) = b.blobs.next() => b.link.on_inbound_blob(peer, stream),
                _ = tokio::time::sleep(Duration::from_millis(25)) => {
                    a.tick();
                    b.tick();
                }
            }
        }
        // What each side is still waiting on. A bare timeout says only that nothing happened,
        // and the difference between "never called" and "called and was refused" is the whole
        // of the diagnosis.
        let dump = |n: &mut Node| {
            let status = n.peers.peers().status();
            format!(
                "at={} connected={} groups={:?} peers={:?}",
                n.at,
                n.swarm.connected_peers().count(),
                status
                    .groups
                    .iter()
                    .map(|g| (g.missing, g.unheard, g.next, g.heartbeat_at))
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
    ///
    /// Both halves matter. The dial is what gets the first exchange going; the introduction is
    /// what lets either of them call *back*. These nodes have no relay and no discovery, so
    /// without an address the supervisor's own dial is dropped on the floor — and since it hangs
    /// up the moment a peer is drained, everything it decides to say after that first call is
    /// simply never said. A real node always has one or the other.
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

        // Ask for the bytes exactly as `ac file get` does: through the store.
        bob.link.sync().files_mut().want(id, &path).unwrap();

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
        assert!(
            bob.link.sync().files().wants().unwrap().is_empty(),
            "the want is cleared once it is satisfied"
        );
    }

    #[tokio::test]
    async fn a_file_indexed_but_missing_is_refused_rather_than_promised() {
        // The milestone 4 bug. `Sending` was written before the file was opened, so a stale
        // `have` promised N bytes and delivered none — which from the other end looks exactly
        // like a relay circuit being cut, and is therefore retried. For ever.
        //
        // The assertion is on the *attempt count*, not on eventual success: the broken
        // version also "eventually" does something, namely retry until the test times out.
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

        bob.link.sync().files_mut().want(id, &path).unwrap();

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
        carol.link.sync().files_mut().want(id, &path).unwrap();

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
        //
        // Nobody runs `ac file get` here. Bob acquires the bytes because auto-mirror wants
        // every file in every shared group, which is what the index's missing count reports and
        // what the holdings query then resolves to a peer that actually holds them.
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

        // And now that neither has anything for the other, the connection goes away on its
        // own. Inside `WIRE_TIMEOUT`, which is half of `IDLE_CONNECTION_TIMEOUT` — so this
        // can only be the close handshake and never the idle reaper.
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
        // `ac peer status` reads this and nothing else, so what matters is that the snapshot
        // reaches a *separate* connection and describes the world the tick actually left
        // behind — not the one it started from.
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

        // Then to the hang-up, which is several ticks later — so the published snapshot cannot
        // still be describing a transfer in flight.
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
