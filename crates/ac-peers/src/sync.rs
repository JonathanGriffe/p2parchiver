use std::collections::{HashMap, HashSet, VecDeque};

use ac_files::path::RelPath;
use ac_files::store::Files;
use ac_groups::id::GroupId;
use ac_groups::store::{Groups, State};
use ac_net::PeerId;

use crate::missing::{PeersError, next_missing};

pub const PRESENCE_INTERVAL: i64 = 300;

/// How long a group may go without asking anybody what they have.
pub const HEARTBEAT: i64 = 4 * 3600;

pub const MIN_BACKOFF: i64 = 15;
pub const MAX_BACKOFF: i64 = 30 * 60;

/// Dials to one member before they are taken off the lists they are on.
pub const DIAL_ATTEMPTS: usize = 3;

/// Circuits opened for *news* in one tick.
///
/// The pacing that keeps one change in a large group from becoming one dial per member. It used
/// to fall out of the loop shape — one peer per group per tick — and is stated here now that the
/// queue is peer-shaped. Peers already connected are not counted: reaching them costs no circuit,
/// and spreading the news to everyone we can already talk to is the point.
pub const DIALS_PER_ROUND: usize = 1;

/// After a full rotation in which no member could help.
pub const MIN_CONTENT_BACKOFF: i64 = 30;
pub const MAX_CONTENT_BACKOFF: i64 = 30 * 60;

pub const SHARE_AFTER_CHANGES: u64 = 1000;

/// How long a group's catalogue must be still before it is shared.
pub const SHARE_AFTER_IDLE: i64 = 120;

/// Transfers running at once, across every peer and group.
pub const MAX_TRANSFERS: usize = 8;

/// Concurrent content pulls overall, and **at most one per group**.
pub const MAX_CONTENT_PEERS: usize = 2;

/// Connections to hold at once.
pub const MAX_PEER_CONNECTIONS: usize = 16;

/// How long a close proposal may go unanswered before it is forgotten.
pub const CLOSE_TIMEOUT: i64 = 30;

/// Circuits this node may open in [`DIAL_WINDOW`], matching what the relay actually allows.
pub const DIALS_PER_WINDOW: usize = 16;

/// The window [`DIALS_PER_WINDOW`] is measured over. Matches the server's, deliberately.
pub const DIAL_WINDOW: i64 = 60;

/// How long a question may be outstanding before it is written off.
pub const ROUND_TIMEOUT: i64 = 60;

/// Free space this node will not eat into, whatever the configured budget says.
pub const MIN_FREE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// What the node is allowed to fill.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub min_free: u64,
    pub storage_max: Option<u64>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            min_free: MIN_FREE_BYTES,
            storage_max: None,
        }
    }
}

/// What the disk last looked like, as the daemon reported it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Space {
    free: u64,
    held: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoRoom {
    Floor { held: u64, limit: u64 },
    Budget { held: u64, limit: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerAction {
    Dial {
        peer: PeerId,
    },
    AskPresence {
        peers: Vec<PeerId>,
    },
    Ask {
        peer: PeerId,
        offering: Offering,
    },
    /// "Of these paths, which do you hold?"
    AskHoldings {
        peer: PeerId,
        group: GroupId,
        paths: Vec<RelPath>,
    },
    FetchBlob {
        peer: PeerId,
        group: GroupId,
        path: RelPath,
        hash: String,
    },
    ProposeClose {
        peer: PeerId,
    },
    Disconnect {
        peer: PeerId,
    },
}

/// Everything the machine reacts to.
#[derive(Debug, Clone)]
pub enum PeerEvent {
    Discovered {
        peer: PeerId,
    },
    Presence {
        asked: Vec<PeerId>,
        online: Vec<PeerId>,
    },
    Verified {
        peer: PeerId,
    },
    Gone {
        peer: PeerId,
    },
    DialFailed {
        peer: PeerId,
    },
    Synced {
        peer: PeerId,
        group: GroupId,
        offering: Offering,
    },
    Asked {
        peer: PeerId,
        offering: Offering,
    },
    AskDeferred {
        peer: PeerId,
    },
    AskFailed {
        peer: PeerId,
    },
    Holdings {
        peer: PeerId,
        group: GroupId,
        paths: Vec<RelPath>,
        held: Vec<bool>,
    },
    BlobDone {
        peer: PeerId,
        group: GroupId,
        path: RelPath,
    },
    BlobFailed {
        peer: PeerId,
        group: GroupId,
        path: RelPath,
        terminal: bool,
        why: String,
    },
    CloseProposed {
        peer: PeerId,
    },
    CloseAnswered {
        peer: PeerId,
        ready: bool,
    },
    Space {
        free: u64,
        held: u64,
    },
    Tick {
        at: i64,
    },
}

/// What the supervisor is waiting on, for somebody to read.
#[derive(Debug, Clone)]
pub struct Status {
    pub groups: Vec<GroupStatus>,
    pub peers: Vec<PeerStatus>,
}

#[derive(Debug, Clone)]
pub struct GroupStatus {
    pub group: GroupId,
    pub missing: u64,
    pub owed: usize,
    pub next: Option<PeerId>,
    pub source: Option<PeerId>,
    pub content_until: i64,
    pub heartbeat_at: i64,
}

#[derive(Debug, Clone)]
pub struct PeerStatus {
    pub peer: PeerId,
    pub connected: bool,
    pub online: bool,
    pub retry_at: i64,
    pub rounds: usize,
    pub transfers: usize,
    pub closing: bool,
}

/// What a group is waiting on, and where its rotation has got to.
#[derive(Debug)]
struct GroupState {
    sent: Snapshot,
    heartbeat_at: i64,
    rotation: usize,
    source: Option<PeerId>,
    spent: HashSet<PeerId>,
    content_until: i64,
    content_backoff: i64,
}

impl GroupState {
    fn new(at: i64) -> Self {
        Self {
            sent: Snapshot::default(),
            heartbeat_at: at,
            rotation: 0,
            source: None,
            spent: HashSet::new(),
            content_until: 0,
            content_backoff: MIN_CONTENT_BACKOFF,
        }
    }
}

/// Which of the two a question is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offering {
    Chain,
    Catalogue,
}

/// What we have yet to ask this peer about one group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Owed {
    chain: bool,
    catalogue: bool,
}

impl Owed {
    fn nothing(&self) -> bool {
        !self.chain && !self.catalogue
    }
}

/// Everything about one group that another node could be behind on. See `Peers::current`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Snapshot {
    seq: u64,
    head: u64,
    standings: [u8; 32],
}

/// A question we put: what our state was per group when it went out, and when that was.
#[derive(Debug, Clone)]
struct InFlight {
    carried: HashMap<GroupId, Snapshot>,
    at: i64,
    offering: Offering,
}

#[derive(Debug, Default)]
struct PeerState {
    retry_at: i64,
    backoff: i64,
    attempts: usize,
    /// When this peer may be offered to again, and the gap to use next. Zero means now.
    ///
    /// **Per peer, not per group.** One ask names every group shared with them, so one failure
    /// is one failure — its cause is a connection that has just broken, which no group is more
    /// or less subject to than another. This used to be keyed by group and every failure wrote
    /// the same pair under each of them.
    failed: (i64, i64),
    transfers: usize,
    denied: HashMap<GroupId, HashSet<RelPath>>,
    closing: Option<i64>,
}

pub struct Peers {
    files: Files,
    groups: Groups,
    me: PeerId,

    state: HashMap<GroupId, GroupState>,
    peers: HashMap<PeerId, PeerState>,

    connected: HashSet<PeerId>,
    online: HashSet<PeerId>,
    started: HashMap<PeerId, InFlight>,
    /// Who we still owe a knock to, and which half. **The whole of the propagation state.**
    ///
    /// A work list rather than a comparison, and the difference is what makes "only the author
    /// propagates" fall out for nothing: a local change fills this, and merging somebody else's
    /// change fills nothing.
    ///
    /// **Keyed by peer, not by group**, because that is the shape of the wire: one ask names
    /// every group shared with the peer, and one settled exchange discharges all of them.
    ///
    /// Not a dial queue, though dialling is what usually drains it: a peer already connected is
    /// on it too and is simply asked. What it really holds is the obligation, which outlives any
    /// one attempt — a dial refused for want of a circuit, or an exchange that failed, leaves
    /// the peer owed and ready for the next tick. Empty means this node has nothing to say to
    /// anybody, which is the whole of the quiescence condition.
    pending: HashMap<PeerId, Owed>,
    seen: HashMap<GroupId, Snapshot>,
    queued: HashMap<PeerId, VecDeque<(GroupId, RelPath)>>,
    dialed_at: Vec<i64>,
    dialing: HashSet<PeerId>,
    next_presence: i64,
    refresh_presence: bool,
    now: i64,
    limits: Limits,
    space: Option<Space>,
    cramped: bool,
}

impl Peers {
    pub fn new(files: Files, groups: Groups) -> Self {
        let me = files.me();
        Self {
            files,
            groups,
            me,
            state: HashMap::new(),
            peers: HashMap::new(),
            connected: HashSet::new(),
            online: HashSet::new(),
            started: HashMap::new(),
            pending: HashMap::new(),
            seen: HashMap::new(),
            queued: HashMap::new(),
            dialed_at: Vec::new(),
            dialing: HashSet::new(),
            next_presence: 0,
            refresh_presence: false,
            now: 0,
            limits: Limits::default(),
            space: None,
            cramped: false,
        }
    }

    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    pub fn files(&self) -> &Files {
        &self.files
    }

    pub fn files_mut(&mut self) -> &mut Files {
        &mut self.files
    }

    pub fn groups_mut(&mut self) -> &mut Groups {
        &mut self.groups
    }

    pub fn me(&self) -> PeerId {
        self.me
    }

    pub fn on(&mut self, event: PeerEvent) -> Vec<PeerAction> {
        match event {
            // When we update the space on housekeeping tick
            PeerEvent::Space { free, held } => {
                self.space = Some(Space { free, held });
                Vec::new()
            }

            PeerEvent::Tick { at } => self.tick(at),

            PeerEvent::Discovered { peer } => {
                self.online.insert(peer);

                self.owe_invitation(peer);
                Vec::new()
            }

            PeerEvent::Presence { asked, online } => {
                let up: HashSet<PeerId> = online.into_iter().collect();
                let mut returned = false;
                for peer in asked {
                    if up.contains(&peer) {
                        returned |= self.online.insert(peer);
                    } else {
                        self.online.remove(&peer);
                    }
                }

                if returned {
                    self.reconsider_content();
                }

                for peer in up {
                    self.owe_invitation(peer);
                }
                Vec::new()
            }

            PeerEvent::Verified { peer } => {
                self.dialing.remove(&peer);
                self.connected.insert(peer);
                self.online.insert(peer);
                let state = self.peers.entry(peer).or_default();
                state.retry_at = 0;
                state.backoff = MIN_BACKOFF;
                state.attempts = 0;

                self.pending.insert(
                    peer,
                    Owed {
                        chain: true,
                        catalogue: true,
                    },
                );
                Vec::new()
            }

            PeerEvent::Gone { peer } => {
                self.dialing.remove(&peer);
                self.connected.remove(&peer);
                self.peers.remove(&peer);
                self.started.remove(&peer);
                self.queued.remove(&peer);
                for group in self.state.values_mut() {
                    if group.source == Some(peer) {
                        group.source = None;
                    }
                }
                Vec::new()
            }

            PeerEvent::DialFailed { peer } => {
                self.dialing.remove(&peer);
                if self
                    .peers
                    .get(&peer)
                    .is_some_and(|s| s.attempts >= DIAL_ATTEMPTS)
                {
                    self.give_up(peer);
                }
                Vec::new()
            }

            PeerEvent::Synced {
                peer,
                group,
                offering,
            } => {
                let mut carried = None;
                if let Some(flight) = self.started.get_mut(&peer)
                    && flight.offering == offering
                {
                    carried = flight.carried.remove(&group);
                    if flight.carried.is_empty() {
                        self.started.remove(&peer);
                    }
                }

                if let Some(state) = self.peers.get_mut(&peer) {
                    state.failed = (0, 0);
                }
                if let Some(recorded) = carried.or_else(|| self.current(group).ok()) {
                    let seen = self.seen.entry(group).or_default();
                    match offering {
                        Offering::Chain => {
                            seen.head = recorded.head;
                            seen.standings = recorded.standings;
                        }
                        Offering::Catalogue => seen.seq = recorded.seq,
                    }
                    let seen = *seen;
                    if let Some(state) = self.state.get_mut(&group) {
                        state.sent = seen;
                    }
                }
                Vec::new()
            }

            PeerEvent::Asked { peer, offering } => {
                self.started.remove(&peer);
                if let Some(entry) = self.pending.get_mut(&peer) {
                    match offering {
                        Offering::Chain => entry.chain = false,
                        Offering::Catalogue => entry.catalogue = false,
                    }
                    if entry.nothing() {
                        self.pending.remove(&peer);
                    }
                }
                Vec::new()
            }

            PeerEvent::AskDeferred { peer } => {
                self.started.remove(&peer);
                Vec::new()
            }

            PeerEvent::AskFailed { peer } => {
                if self.started.remove(&peer).is_none() {
                    return Vec::new();
                }
                // Nothing arrived, so nothing is recorded as held — but neither is this the
                // peer's doing, and re-offering on the very next tick would hammer a member
                // whose connection has just broken. The dial backoff paces the reconnection,
                // and the decline backoff paces the retry once reconnected.
                let now = self.now;
                let state = self.peers.entry(peer).or_default();
                let backoff = if state.failed.1 == 0 {
                    MIN_BACKOFF
                } else {
                    state.failed.1
                };
                state.failed = (now + backoff, (backoff * 2).min(MAX_BACKOFF));
                Vec::new()
            }

            PeerEvent::Holdings {
                peer,
                group,
                paths,
                held,
            } => self.on_holdings(peer, group, paths, held),

            PeerEvent::BlobDone { peer, group, path } => {
                if let Some(state) = self.peers.get_mut(&peer) {
                    state.transfers = state.transfers.saturating_sub(1);
                }
                // `mark_have` is redundant with what the transfer task already wrote through
                // its own handle, and cheap enough to be worth doing anyway: it means a test
                // can drive this machine to convergence without a real download.
                let _ = self.files.mark_have(group, &path, true);
                let _ = self.files.unwant(group, &path);

                // A slot has just come free, so the next queued file starts now — that is what
                // keeps eight running until the offer is exhausted rather than eight ever.
                tracing::info!(%group, %path, "got a file");
                let mut actions = Vec::new();
                actions.extend(self.pump(peer));
                actions.extend(self.resolve_stalled(peer));
                actions.extend(self.continue_pull(peer));
                actions
            }

            PeerEvent::BlobFailed {
                peer,
                group,
                path,
                terminal,
                why,
            } => {
                if let Some(state) = self.peers.get_mut(&peer) {
                    state.transfers = state.transfers.saturating_sub(1);
                }
                if !terminal {
                    // A severed relay circuit, which is routine. The partial is parked and the
                    // next attempt resumes; nothing is held against the peer, and the path
                    // stays missing so the next query offers it again.
                    let mut actions = self.pump(peer);
                    actions.extend(self.resolve_stalled(peer));
                    actions.extend(self.continue_pull(peer));
                    return actions;
                }

                // They claimed it and could not deliver. Believing the claim again would mean
                // opening another stream for bytes that are not there.
                self.peers
                    .entry(peer)
                    .or_default()
                    .denied
                    .entry(group)
                    .or_default()
                    .insert(path.clone());

                tracing::info!(%peer, %group, %path, "claimed a file it could not deliver");
                let mut actions = Vec::new();
                actions.extend(self.pump(peer));
                actions.extend(self.resolve_stalled(peer));
                if why.contains("hash") {
                    // Wrong bytes are misbehaviour, not misfortune, and are worded as such.
                    tracing::warn!(%peer, why, "ignored something from a peer");
                }
                actions.extend(self.continue_pull(peer));
                actions
            }

            PeerEvent::CloseProposed { peer: _ } => {
                // Answering is the daemon's job — it holds the channel — and there is
                // deliberately nothing to do here.
                //
                // In particular our *own* outstanding proposal is left alone. Clearing it
                // livelocked the commonest case there is: two peers that finish together
                // propose to each other within the same tick, each cancels its own proposal on
                // receiving the other's, and each then finds `closing` already taken when the
                // answer arrives — so neither disconnects, both re-propose on the next tick,
                // and the connection is held for ever while both sides report being drained.
                //
                // Both sides disconnecting is not a race worth avoiding: it is one connection
                // and the second call finds it already gone.
                Vec::new()
            }

            PeerEvent::CloseAnswered { peer, ready } => {
                let proposed = self
                    .peers
                    .get_mut(&peer)
                    .and_then(|state| state.closing.take())
                    .is_some();

                // Re-checked *now*, not when we proposed: work may have arrived in between,
                // and hanging up on it would waste whatever is in flight.
                if proposed && ready && self.drained(peer) {
                    return vec![PeerAction::Disconnect { peer }];
                }
                Vec::new()
            }
        }
    }

    // ---- the tick ----

    fn tick(&mut self, at: i64) -> Vec<PeerAction> {
        self.now = at;
        let mut actions = Vec::new();

        self.sweep_closes(at);
        self.sweep_rounds(at);
        actions.extend(self.presence(at));

        let groups: Vec<GroupId> = self
            .groups
            .list()
            .unwrap_or_default()
            .into_iter()
            .filter(|row| row.state == State::Active)
            .map(|row| row.id)
            .collect();

        for group in &groups {
            self.arm(*group, at);
        }
        actions.extend(self.start_rounds());
        actions.extend(self.pump_queues());

        // Catalogues are exchanged whatever the disk looks like: knowing what exists costs
        // kilobytes, and a node that stopped syncing its index when it ran out of room would
        // also stop being able to *say* what it is missing.
        match self.room() {
            Some(why) => {
                // Said once per transition, not once per tick: a node at its ceiling refuses
                // every fetch it considers, and one line per file would bury everything else.
                if !self.cramped {
                    self.cramped = true;
                    match why {
                        NoRoom::Floor { held, limit } => tracing::warn!(
                            held,
                            min_free = limit,
                            "stopped mirroring: too little free space on the storage volume. \
                             Nothing was deleted; free some space and it resumes"
                        ),
                        NoRoom::Budget { held, limit } => tracing::warn!(
                            held,
                            storage_max = limit,
                            "stopped mirroring: at the storage_max the config allows. Nothing \
                             was deleted; raise storage_max in config.toml to continue"
                        ),
                    }
                }
            }
            None => {
                self.cramped = false;
                actions.extend(self.content_pulls(&groups, at));
            }
        }

        actions.extend(self.closes());
        actions
    }

    /// Ask who is online: on the interval, or once because the member list moved.
    ///
    /// There used to be a third reason and a second clock to pace it — "we have something to do
    /// and not one member looks callable". That question no longer exists, because nothing is
    /// blocked on the answer: news is delivered by calling the member who is owed it, whatever
    /// the registry last said. What is left is a *choice* between members, which is a reasonable
    /// thing to make on an answer up to an interval old, and worth refreshing on the one event
    /// that changes who the candidates are.
    fn presence(&mut self, at: i64) -> Vec<PeerAction> {
        // Peers we hold a connection to are skipped, so the answer is a filter over the rest and
        // never a replacement for what we know. See `PeerEvent::Presence`.
        let peers: Vec<PeerId> = self
            .members_of_shared_groups()
            .into_iter()
            .filter(|p| !self.connected.contains(p))
            .collect();

        if peers.is_empty() {
            // Nobody to ask about, so the refresh has nothing to refresh. Cleared rather than
            // held, or it would fire the moment somebody disconnected for an unrelated reason.
            self.refresh_presence = false;
            return Vec::new();
        }
        if at < self.next_presence && !self.refresh_presence {
            return Vec::new();
        }

        self.refresh_presence = false;
        self.next_presence = at + PRESENCE_INTERVAL;
        vec![PeerAction::AskPresence { peers }]
    }

    /// Notice what has changed about this group, and decide whether to tell anybody.
    fn arm(&mut self, group: GroupId, at: i64) {
        let Ok(current) = self.current(group) else {
            return;
        };
        let state = self
            .state
            .entry(group)
            .or_insert_with(|| GroupState::new(at));

        // News also retires the content backoff. "Nobody had anything for us" was a conclusion
        // about a catalogue that has since moved, and the rows that moved it are exactly the
        // ones we do not hold — so continuing to suppress the pull answers the wrong question.
        //
        // Missing this is what left a file `remote` on a node that knew perfectly well it
        // existed: the group had exhausted its rotation during the initial mirror, doubled its
        // way to a multi-minute backoff, and was still serving that sentence when the new file
        // arrived. It looked like a stalled download and was a gag order.
        if current != state.sent {
            state.content_until = 0;
            state.content_backoff = MIN_CONTENT_BACKOFF;
            state.spent.clear();
        }

        // **This decides who to dial, not what to say.** The pull governs what crosses a
        // connection: a question carries nothing, so asking a peer delivers nothing *to* them —
        // they learn our state by asking for it themselves. What is still ours to decide is
        // whose door to knock on, and a change of ours is exactly the reason to knock. Without
        // this the author does nothing at all, and the change reaches the group only when other
        // nodes' heartbeats happen to pick us out of the rotation.
        // What is ours to tell, and what we have merely received.
        let seen = self.seen.get(&group).copied();
        let membership_moved =
            seen.is_none_or(|s| current.head != s.head || current.standings != s.standings);
        let catalogue_moved = seen.is_none_or(|s| current.seq != s.seq);

        // *Moved*, not *differs*. A catalogue differs from what peers have been told from the
        // edit until the moment it is shared, so a difference is a state and not an event —
        // reading the pause off it pushed the start of the pause forward on every tick and
        // stopped it elapsing at all. `note_change` answers the event question, once per edit,
        // and records the answer where a restart cannot lose it.
        let changed_at = self.files.note_change(group, at).unwrap_or(at);

        // Changes since the group was last told, which is the counter's whole job: the offer
        // recorded the position it went out at, so the arithmetic needs nothing remembered here.
        let changes = current.seq - seen.map(|s| s.seq).unwrap_or(0).min(current.seq);

        // Membership goes at once; the catalogue waits for the group to be still, or for enough
        // to have piled up that waiting longer is worse than the dialling.
        let share_catalogue = catalogue_moved
            && (changes >= SHARE_AFTER_CHANGES || at - changed_at >= SHARE_AFTER_IDLE);

        if membership_moved {
            // Enqueued at once, and asked about in parallel rather than first. This is the one
            // change that alters the member list, so it is also the one moment the answer in
            // hand is certainly about the wrong set of people — but that is a reason to refresh
            // it, not to hold the news behind it. Holding it cost the change entirely whenever
            // the query never went out, which is what a group with every member connected looks
            // like: `presence` skips those, finds nobody to ask, and the answer that was going
            // to release the enqueue never comes.
            self.enqueue(group, true, false);
            self.refresh_presence = true;
        }
        if share_catalogue {
            self.enqueue(group, false, true);
        }

        tracing::debug!(
            %group,
            membership_moved,
            catalogue_moved,
            share_catalogue,
            changes,
            idle_for = at - changed_at,
            owed = self.pending.len(),
            "armed"
        );

        if membership_moved || share_catalogue {
            // Accounted for. Anything after this is somebody else's, until we change it again.
            let mut recorded = self.seen.get(&group).copied().unwrap_or_default();
            if membership_moved {
                recorded.head = current.head;
                recorded.standings = current.standings;
            }
            if share_catalogue {
                recorded.seq = current.seq;
            }
            self.seen.insert(group, recorded);
        }

        // **One peer, not everybody.** It is a check that we are not adrift, not a broadcast:
        // an exchange with any one member reconciles both directions, so if we are missing
        // something they have it comes back on the same round trip. And because a question names
        // every group we share with that peer, a peer already queued for another group settles
        // this one too — so a node in six groups with the same five people spends one exchange
        // on all six, not six.
        if at >= self.state[&group].heartbeat_at {
            let jitter = jitter_for(HEARTBEAT);
            if let Some(state) = self.state.get_mut(&group) {
                state.heartbeat_at = at + jitter;
            }

            // One ask names every group shared with the peer, so a member of this group already
            // queued — for any reason — will carry this group's question too.
            let covered = self
                .members_of(group)
                .into_iter()
                .any(|peer| self.pending.contains_key(&peer));

            if !covered && let Some(peer) = self.peek_member(group) {
                self.pending.insert(
                    peer,
                    Owed {
                        chain: true,
                        catalogue: true,
                    },
                );
            }
        }
    }

    /// Put every member we could actually call on the list.
    ///
    /// **Reachable ones only** — connected, or vouched for by discovery or the registry. A
    /// member who is switched off used to go on the list too and come off it three refused
    /// circuits later, so a change in a group of twenty with three online cost fifty-one dials
    /// against an allowance of sixteen a minute.
    ///
    /// The cost of the filter is that a member who comes online *after* this runs is not on the
    /// list for this change. What brings them back is `PeerEvent::Verified` if they call us, and
    /// the heartbeat otherwise. `online` is up to five minutes stale and the registry can omit
    /// people, so this is a trade: circuits spent on the absent, against news that waits for one
    /// of those two.
    fn enqueue(&mut self, group: GroupId, chain: bool, catalogue: bool) {
        for peer in self.members_of(group) {
            if !self.connected.contains(&peer) && !self.online.contains(&peer) {
                tracing::debug!(%group, %peer, "not enqueued: nothing says they are reachable");
                continue;
            }
            let entry = self.pending.entry(peer).or_insert(Owed {
                chain: false,
                catalogue: false,
            });
            entry.chain |= chain;
            entry.catalogue |= catalogue;
        }
    }

    /// Put **one question per peer** to everybody on the list.
    ///
    /// Both protocols: membership and the catalogue are separate exchanges over the same
    /// connections, and choosing between them is part of the decision rather than a separate
    /// loop. The chain goes first while a peer is owed it, since a catalogue answer is gated on
    /// membership they may not hold yet.
    ///
    /// Peer-shaped throughout, because the wire is: one question covers every group shared with
    /// that peer, so three groups owing the same member cost one request between them. This used
    /// to loop groups and take one member each, which needed a rotation to be fair to the rest
    /// and a dedupe afterwards to avoid asking the same peer twice.
    ///
    /// **Connections are free, circuits are not.** Everyone already connected is asked, because
    /// spreading the news to whoever we can reach is the whole point and it costs nothing. While
    /// any of them is owed, no circuit is opened at all: the lab spent a whole allowance dialling
    /// members who could not help while an idle connection to one who could was held and then
    /// hung up on. Asking discharges them, so the next tick dials.
    ///
    /// When there is nobody to ask, dialling is capped at [`DIALS_PER_ROUND`] — the pacing that
    /// stops one change in a large group becoming one dial per member, which used to fall out of
    /// taking one peer per group. **Strangers first**, since a cap means order decides who waits:
    /// a member who has never answered an invitation is either newly added or has never had it
    /// delivered, and is exactly who a round should spend its circuit on.
    ///
    /// Nobody is dropped from the list by not being reached this tick: an unreached peer is
    /// still owed, and the next tick takes the next one.
    fn start_rounds(&mut self) -> Vec<PeerAction> {
        // Everyone on the list except those we agreed to leave alone for a while: a peer whose
        // last exchange failed stays owed, but is not asked again until its backoff expires. One
        // already mid-exchange is left alone too — that question covers every shared group.
        let (connected, absent): (Vec<PeerId>, Vec<PeerId>) = self
            .pending
            .keys()
            .copied()
            .filter(|p| {
                !self.started.contains_key(p)
                    && self.peers.get(p).is_none_or(|s| self.now >= s.failed.0)
            })
            .partition(|p| self.connected.contains(p));

        tracing::debug!(
            pending = self.pending.len(),
            connected_owed = connected.len(),
            absent_owed = absent.len(),
            connected_total = self.connected.len(),
            started = self.started.len(),
            "rounds"
        );

        let mut actions = Vec::new();
        let none_to_ask = connected.is_empty();

        // Strangers first here too: with everyone asked the set is the same, but the order is
        // what a caller watching the first question sees.
        let mut connected = connected;
        connected.sort_by_key(|p| self.unanswered_invites(p).is_empty());
        for peer in connected {
            // **Membership before contents.** A catalogue offer is gated on membership the other
            // side may not have yet, so while anything about who is in a group is stale for this
            // peer, that is what goes — and the file heads follow on a later tick, by which time
            // they know who we are.
            let offering = if self.chain_stale_for(&peer) {
                Offering::Chain
            } else {
                Offering::Catalogue
            };
            actions.push(self.ask(peer, offering));
        }

        if !none_to_ask {
            return actions;
        }

        // Strangers first, then whoever the map hands over. `dial` refuses on its own account
        // too — a peer inside its backoff, one already being dialled, or the relay's allowance
        // spent — so the cap is a ceiling and not a quota.
        let mut absent = absent;
        absent.sort_by_key(|p| self.unanswered_invites(p).is_empty());

        let mut opened = 0;
        for peer in absent {
            if opened >= DIALS_PER_ROUND {
                break;
            }
            let dialled = self.dial(peer);
            if !dialled.is_empty() {
                opened += 1;
            }
            actions.extend(dialled);
        }
        actions
    }

    /// Whether any group owes this peer membership.
    fn chain_stale_for(&self, peer: &PeerId) -> bool {
        self.pending.get(peer).is_some_and(|o| o.chain)
    }

    /// Record what an offer to this peer carries, and ask for it.
    ///
    /// Every group shared with them, not merely the group that prompted it: the request names
    /// them all, so they are all told, and recording anything less would leave the supervisor
    /// believing it still owes news it has already delivered.
    fn ask(&mut self, peer: PeerId, offering: Offering) -> PeerAction {
        // The same set the layer being offered will actually put on the wire, or the
        // supervisor would go on believing it still owed news it has already delivered. The
        // chain half discusses invitations too; the catalogue half needs our consent.
        let named = match offering {
            Offering::Chain => self.groups.log_shared_with(&peer),
            Offering::Catalogue => self.groups.shared_with(&peer),
        };
        let carried = named
            .unwrap_or_default()
            .into_iter()
            .filter_map(|head| Some((head.group, self.current(head.group).ok()?)))
            .collect();

        self.started.insert(
            peer,
            InFlight {
                carried,
                at: self.now,
                offering,
            },
        );
        PeerAction::Ask { peer, offering }
    }

    fn content_pulls(&mut self, groups: &[GroupId], at: i64) -> Vec<PeerAction> {
        let mut actions = Vec::new();

        for group in groups {
            if self.content_peers() >= MAX_CONTENT_PEERS {
                break;
            }
            if self.state.get(group).is_some_and(|s| at < s.content_until) {
                continue;
            }
            // One source per group, so a large group cannot take every slot.
            if self.state.get(group).is_some_and(|s| s.source.is_some()) {
                continue;
            }

            // Only the content half of `behind`, and asked for directly. Going through the whole
            // predicate meant computing the catalogue digest — a scan of every row in the group,
            // per group, per tick — to produce a `News` verdict this loop then discarded. The
            // number of missing rows is an indexed count.
            if self.files.missing_count(*group).unwrap_or(0) == 0 {
                continue;
            }

            let spent = self
                .state
                .get(group)
                .map(|s| s.spent.clone())
                .unwrap_or_default();

            // Nobody to ask yet. Not exhaustion — arming the backoff here would suppress the
            // pull for minutes *and* report every missing file unobtainable, on the strength of
            // never having asked anyone. The dial loop brings members; this waits for them.
            let reachable = self.reachable(*group);
            if reachable.is_empty() {
                continue;
            }
            if reachable.iter().all(|p| spent.contains(p)) {
                // Everyone we can reach has been asked and none of them helped.
                actions.extend(self.exhaust_group(*group, at));
                continue;
            }

            // A source, not an obligation. `next_member` no longer consults the registry — the
            // catalogue loop must be able to call a member it has never heard of — so the
            // judgement is made here, where it belongs, by passing over everybody `reachable`
            // left out. Anyone chosen is somebody the server, discovery, or a live connection
            // has vouched for.
            let mut skip = spent.clone();
            skip.extend(
                self.members_of(*group)
                    .into_iter()
                    .filter(|p| !reachable.contains(p)),
            );
            let Some(peer) = self.next_member(*group, &skip) else {
                continue;
            };

            if self.connected.contains(&peer) {
                if let Some(state) = self.state.get_mut(group) {
                    state.source = Some(peer);
                }
                actions.extend(self.ask_holdings(peer, *group));
            } else {
                actions.extend(self.dial(peer));
            }
        }
        actions
    }

    /// Why there is no room for more content, or `None` if there is.
    ///
    /// Public because *which* limit stopped the mirror is a fact about this node, not a message
    /// about it — `ac peer status` and this crate's tests both need the answer, and neither can
    /// read a log line.
    ///
    /// Absent a report we assume there is room. The daemon sends one immediately before every
    /// tick, so the only window is startup — and refusing to fetch because nothing has told us
    /// the disk size yet would be a worse failure than briefly not knowing.
    pub fn room(&self) -> Option<NoRoom> {
        let space = self.space?;

        if space.free < self.limits.min_free {
            return Some(NoRoom::Floor {
                held: space.held,
                limit: self.limits.min_free,
            });
        }
        match self.limits.storage_max {
            Some(max) if space.held >= max => Some(NoRoom::Budget {
                held: space.held,
                limit: max,
            }),
            _ => None,
        }
    }

    /// Whether one more file of this size fits inside both limits.
    ///
    /// Checked per file as well as per tick because the coarse gate only knows we are *near*
    /// the line: a node with 3 GiB free passes it and would still bury the floor by fetching a
    /// 4 GiB film.
    fn room_for(&self, size: u64) -> bool {
        let Some(space) = self.space else {
            return true;
        };
        if space.free.saturating_sub(size) < self.limits.min_free {
            return false;
        }
        match self.limits.storage_max {
            Some(max) => space.held.saturating_add(size) <= max,
            None => true,
        }
    }

    /// Book the space a fetch is about to use.
    ///
    /// Between disk reports the machine would otherwise start every file in a batch believing
    /// the whole budget was free, and a 512-file batch would blow straight through it. The
    /// daemon's next report corrects this either way, so an optimistic count is safe in the
    /// direction that matters: it can only refuse a fetch, never allow one it should not.
    fn reserve(&mut self, size: u64) {
        if let Some(space) = &mut self.space {
            space.held = space.held.saturating_add(size);
            space.free = space.free.saturating_sub(size);
        }
    }

    /// A batch of transfers finished. Ask this source for the next one, or let it go.
    ///
    /// **Without this a pull stops after one batch.** `content_pulls` skips any group that
    /// already has a source, so once one is assigned the tick loop never looks at that group
    /// again — a group with more missing files than one holdings query can name would fetch
    /// the first `MAX_HOLDINGS_QUERY` of them and stall for ever. Worse, the source is never
    /// released, so the peer never counts as drained and the connection is held open with
    /// nothing happening on it.
    ///
    /// Driven from the transfer outcome rather than from the tick, because that is the moment
    /// the answer changes: what is still missing is exactly what did not just arrive.
    fn continue_pull(&mut self, peer: PeerId) -> Vec<PeerAction> {
        // Still working. Asking now would query about files that are on their way — or waiting
        // their turn, which the queue makes a distinct case: a peer with hundreds of files left
        // to give has nothing running the instant one ends, and asking then would page over the
        // same answer it is still working through.
        if self.peers.get(&peer).is_some_and(|s| s.transfers > 0) {
            return Vec::new();
        }
        if self
            .queued
            .get(&peer)
            .is_some_and(|queue| !queue.is_empty())
        {
            return Vec::new();
        }

        let groups: Vec<GroupId> = self
            .state
            .iter()
            .filter(|(_, state)| state.source == Some(peer))
            .map(|(group, _)| *group)
            .collect();

        groups
            .into_iter()
            .flat_map(|group| self.ask_holdings(peer, group))
            .collect()
    }

    fn ask_holdings(&mut self, peer: PeerId, group: GroupId) -> Vec<PeerAction> {
        let denied = self
            .peers
            .get(&peer)
            .and_then(|s| s.denied.get(&group))
            .cloned()
            .unwrap_or_default();

        let paths: Vec<RelPath> =
            next_missing(&self.files, group, ac_files::wire::MAX_HOLDINGS_QUERY)
                .unwrap_or_default()
                .into_iter()
                .map(|(path, _)| path)
                .filter(|path| !denied.contains(path))
                .collect();

        if paths.is_empty() {
            // Nothing left to ask about: either we now hold the lot, or everything we still
            // need is something this peer has already failed to deliver. Both mean they are
            // done for this group, and both release the source so the peer can be closed.
            return self.spend_peer(peer, group);
        }
        vec![PeerAction::AskHoldings { peer, group, paths }]
    }

    fn on_holdings(
        &mut self,
        peer: PeerId,
        group: GroupId,
        paths: Vec<RelPath>,
        held: Vec<bool>,
    ) -> Vec<PeerAction> {
        let denied = self
            .peers
            .get(&peer)
            .and_then(|s| s.denied.get(&group))
            .cloned()
            .unwrap_or_default();

        let wanted: Vec<RelPath> = paths
            .into_iter()
            .enumerate()
            // A short answer reads as "not held", so a peer withholds rather than invents.
            .filter(|(i, path)| held.get(*i).copied().unwrap_or(false) && !denied.contains(path))
            .map(|(_, path)| path)
            .collect();

        if wanted.is_empty() {
            return self.spend_peer(peer, group);
        }

        // Queued whole and started a few at a time. What comes back may name hundreds of files
        // and only `MAX_TRANSFERS` can run; the rest wait here rather than being issued into a
        // blob layer that would refuse them.
        self.queued
            .entry(peer)
            .or_default()
            .extend(wanted.into_iter().map(|path| (group, path)));

        let actions = self.pump(peer);
        if actions.is_empty() && self.running_transfers() == 0 {
            // Nothing could be started and nothing is running, so no completion will come back
            // to drive the queue. Decide here or the group stalls holding a source.
            return if self.space.is_some() && !self.queued.get(&peer).is_none_or(|q| q.is_empty()) {
                // Our disk, not their shortcoming.
                self.resolve_stalled(peer)
            } else {
                // They claimed rows that have since vanished from our own catalogue.
                self.spend_peer(peer, group)
            };
        }
        actions
    }

    /// Start as many queued files as there is room to run, and no more.
    ///
    /// Called when a queue is filled and again whenever a transfer ends, which is what keeps the
    /// pipe full: one finishes, the next starts. The alternative — issuing the whole queue and
    /// letting the blob layer take what it can — is what silently lost 292 of 300 files, since
    /// the ones it refused were counted as running by a supervisor that then waited for them.
    ///
    /// Each entry is re-checked at the front rather than when it was queued: minutes may pass,
    /// and the file may have arrived from another member, been deleted from the group, or been
    /// denied by this very peer on an earlier attempt.
    fn pump(&mut self, peer: PeerId) -> Vec<PeerAction> {
        let mut actions = Vec::new();

        while self.running_transfers() < MAX_TRANSFERS {
            let Some((group, path)) = self
                .queued
                .get_mut(&peer)
                .and_then(|queue| queue.pop_front())
            else {
                break;
            };

            let denied = self
                .peers
                .get(&peer)
                .is_some_and(|s| s.denied.get(&group).is_some_and(|d| d.contains(&path)));
            if denied {
                continue;
            }

            // Gone from the catalogue, or already here by another route.
            let Ok(Some(row)) = self.files.get(group, &path) else {
                continue;
            };
            if row.have || row.removed_at.is_some() {
                continue;
            }

            if !self.room_for(row.size) {
                // Not their fault and not permanent. Put it back so it is the first thing tried
                // when space appears, and stop: the queue is ordered and nothing behind a file
                // too big to fit is any more likely to fit.
                if let Some(queue) = self.queued.get_mut(&peer) {
                    queue.push_front((group, path));
                }
                break;
            }

            self.reserve(row.size);
            self.peers.entry(peer).or_default().transfers += 1;
            actions.push(PeerAction::FetchBlob {
                peer,
                group,
                path,
                hash: row.hash,
            });
        }

        actions
    }

    /// Let go of the groups this peer sources but can no longer be driven for.
    fn resolve_stalled(&mut self, peer: PeerId) -> Vec<PeerAction> {
        // Still working, or waiting on a slot rather than on space
        if self.peers.get(&peer).is_some_and(|s| s.transfers > 0)
            || self.running_transfers() >= MAX_TRANSFERS
        {
            return Vec::new();
        }

        let stalled: HashSet<GroupId> = self
            .queued
            .get(&peer)
            .map(|queue| queue.iter().map(|(group, _)| *group).collect())
            .unwrap_or_default();

        stalled
            .into_iter()
            .flat_map(|group| self.release_source(peer, group))
            .collect()
    }

    /// Drive every waiting queue, not just the one a transfer came back on.
    fn pump_queues(&mut self) -> Vec<PeerAction> {
        let waiting: Vec<PeerId> = self
            .queued
            .iter()
            .filter(|(_, queue)| !queue.is_empty())
            .map(|(peer, _)| *peer)
            .collect();

        let mut actions = Vec::new();
        for peer in waiting {
            actions.extend(self.pump(peer));
            actions.extend(self.resolve_stalled(peer));
        }
        actions
    }

    /// Transfers running across every peer, which is what [`MAX_TRANSFERS`] bounds.
    fn running_transfers(&self) -> usize {
        self.peers.values().map(|s| s.transfers).sum()
    }

    /// Forget what this peer had offered for this group. Whatever we were queued to fetch from
    /// them is no longer theirs to supply.
    fn drop_queued(&mut self, peer: PeerId, group: GroupId) {
        if let Some(queue) = self.queued.get_mut(&peer) {
            queue.retain(|(g, _)| *g != group);
        }
    }

    /// Stop pulling this group through this peer, without holding it against them.
    fn release_source(&mut self, peer: PeerId, group: GroupId) -> Vec<PeerAction> {
        self.drop_queued(peer, group);
        if let Some(state) = self.state.get_mut(&group)
            && state.source == Some(peer)
        {
            state.source = None;
        }
        Vec::new()
    }

    /// This peer has nothing more for this group. Rotate.
    fn spend_peer(&mut self, peer: PeerId, group: GroupId) -> Vec<PeerAction> {
        self.drop_queued(peer, group);
        if let Some(state) = self.state.get_mut(&group) {
            state.spent.insert(peer);
            if state.source == Some(peer) {
                state.source = None;
            }
        }
        Vec::new()
    }

    /// Every member has been asked and none could help.
    fn exhaust_group(&mut self, group: GroupId, at: i64) -> Vec<PeerAction> {
        // Said once per unproductive rotation, so "nobody reachable has this" is
        // distinguishable from "still downloading" — which otherwise look identical.
        if let Ok(missing) = next_missing(&self.files, group, 1)
            && let Some((path, _)) = missing.into_iter().next()
        {
            tracing::info!(%group, %path, "nobody reachable has this; it stays wanted");
        }

        if let Some(state) = self.state.get_mut(&group) {
            state.content_until = at + state.content_backoff;
            state.content_backoff = (state.content_backoff * 2).min(MAX_CONTENT_BACKOFF);
            state.spent.clear();
            state.source = None;
        }
        Vec::new()
    }

    // ---- closing ----

    /// Nothing left that *this peer* can do for us.
    ///
    /// Peer-scoped, deliberately. Tying it to whether the group is still behind would be
    /// permanently false under auto-mirror, so a rotation through five members would leave all
    /// five connections held for ever — each one having already said it could not help.
    /// A snapshot of everything a person would need to answer "why is it not doing anything".
    ///
    /// `&self`, deliberately: `next_member` advances the rotation as a side effect of choosing,
    /// so asking it here would make looking at the supervisor change what it does next.
    /// [`GroupStatus::next`] therefore reads the cursor rather than consulting it.
    pub fn status(&self) -> Status {
        let groups = self
            .groups
            .list()
            .unwrap_or_default()
            .into_iter()
            .filter(|row| row.state == State::Active)
            .map(|row| {
                let state = self.state.get(&row.id);
                GroupStatus {
                    group: row.id,
                    missing: self.files.missing_count(row.id).unwrap_or(0),
                    owed: self
                        .members_of(row.id)
                        .into_iter()
                        .filter(|p| self.pending.contains_key(p))
                        .count(),
                    next: self.peek_member(row.id),
                    source: state.and_then(|s| s.source),
                    content_until: state.map(|s| s.content_until).unwrap_or(0),
                    heartbeat_at: state.map(|s| s.heartbeat_at).unwrap_or(0),
                }
            })
            .collect();

        // Everyone we might call, whether or not we have ever heard from them — a member with
        // no state at all is exactly the case worth showing, since "we have never reached
        // them" and "we are backing off from them" look the same from outside.
        let peers = self
            .members_of_shared_groups()
            .into_iter()
            .map(|peer| {
                let state = self.peers.get(&peer);
                PeerStatus {
                    peer,
                    connected: self.connected.contains(&peer),
                    online: self.online.contains(&peer),
                    retry_at: state.map(|s| s.retry_at).unwrap_or(0),
                    rounds: usize::from(self.offer_open(&peer)),
                    transfers: state.map(|s| s.transfers).unwrap_or(0),
                    closing: state.is_some_and(|s| s.closing.is_some()),
                }
            })
            .collect();

        Status { groups, peers }
    }

    /// Let every group try again: whoever we gave up on, the set of members has changed.
    fn reconsider_content(&mut self) {
        for state in self.state.values_mut() {
            state.content_until = 0;
            state.content_backoff = MIN_CONTENT_BACKOFF;
            state.spent.clear();
        }
    }

    /// This group's members, ourselves excepted. Empty if the group is unknown.
    fn members_of(&self, group: GroupId) -> Vec<PeerId> {
        self.groups
            .members(group)
            .unwrap_or_default()
            .iter()
            .map(|m| m.peer)
            .filter(|p| *p != self.me)
            .collect()
    }

    /// Who has answered this group's invitation, one way or the other.
    ///
    /// **A standing, not a sync cursor.** A standing is signed by the member themselves and is
    /// the only thing that says "I know about this group". Its absence is therefore the one fact
    /// that means the invitation was never delivered — which is not what an empty file cursor
    /// says. A member can have accepted months ago and still never have exchanged a catalogue
    /// with *us*, and a member we have swapped catalogues with can still never have accepted.
    ///
    /// The single definition of a stranger, and it is deliberately single: `Discovered` and
    /// `Presence` both decide who is owed an undelivered invitation by it, and `next_member`
    /// decides who to call first by it. When those disagreed, the peer one of them enqueued
    /// urgently was the peer the other put last in the rotation.
    ///
    /// Read from the chain rather than remembered, so nothing has to be kept in step: the moment
    /// their standing arrives, they stop counting as a stranger everywhere at once.
    ///
    /// **Any** standing counts, `Position::Unanswered` included. Answering is about whether they
    /// have the chain, not about what they decided — a node that holds an invitation and has not
    /// made up its mind has still received everything we were trying to deliver, and dialling it
    /// again every five minutes until a human clicks accept is work with no possible outcome.
    fn answered_invite(&self, group: GroupId) -> HashSet<PeerId> {
        self.groups
            .standings(group)
            .unwrap_or_default()
            .iter()
            .filter_map(|standing| standing.subject().ok())
            .collect()
    }

    /// Groups where the chain says this peer is a member and they have never answered.
    fn unanswered_invites(&self, peer: &PeerId) -> Vec<GroupId> {
        self.groups
            .list()
            .unwrap_or_default()
            .into_iter()
            .filter(|row| row.state == State::Active)
            .map(|row| row.id)
            .filter(|group| {
                self.members_of(*group).contains(peer)
                    && !self.answered_invite(*group).contains(peer)
            })
            .collect()
    }

    /// For a peer that just came online, queue dialing them if they are owed an invitation to a group.
    fn owe_invitation(&mut self, peer: PeerId) {
        if !self.unanswered_invites(&peer).is_empty() {
            self.pending.insert(
                peer,
                Owed {
                    chain: true,
                    catalogue: true,
                },
            );
        }
    }

    /// Whose turn it is, without taking it.
    fn peek_member(&self, group: GroupId) -> Option<PeerId> {
        let members: Vec<PeerId> = self
            .groups
            .members(group)
            .ok()?
            .iter()
            .map(|m| m.peer)
            .filter(|p| *p != self.me)
            .collect();
        if members.is_empty() {
            return None;
        }
        let at = self.state.get(&group).map(|s| s.rotation).unwrap_or(0);
        members.get(at % members.len()).copied()
    }

    pub fn drained(&self, peer: PeerId) -> bool {
        let busy = self.peers.get(&peer).is_some_and(|s| s.transfers > 0) || self.offer_open(&peer);
        let assigned = self.state.values().any(|s| s.source == Some(peer));
        !busy && !assigned
    }

    fn closes(&mut self) -> Vec<PeerAction> {
        let ready: Vec<PeerId> = self
            .connected
            .iter()
            .copied()
            .filter(|peer| {
                self.drained(*peer) && self.peers.get(peer).is_none_or(|s| s.closing.is_none())
            })
            .collect();

        let now = self.now;
        ready
            .into_iter()
            .map(|peer| {
                self.peers.entry(peer).or_default().closing = Some(now);
                PeerAction::ProposeClose { peer }
            })
            .collect()
    }

    /// Write off rounds nobody ever answered.
    ///
    /// The slot matters more than the round: only [`MAX_CATALOGUE_ROUNDS`] may run at once, so
    /// one that never ends is one this node can never use again. Treated exactly like a round
    /// that failed — the peer had its turn, the burst moves on — because from here the two are
    /// indistinguishable and the expensive mistake is to keep waiting.
    fn sweep_rounds(&mut self, at: i64) {
        let stale: Vec<PeerId> = self
            .started
            .iter()
            .filter(|(_, flight)| at - flight.at >= ROUND_TIMEOUT)
            .map(|(peer, _)| *peer)
            .collect();

        for peer in stale {
            self.on(PeerEvent::AskFailed { peer });
        }
    }

    fn sweep_closes(&mut self, at: i64) {
        for state in self.peers.values_mut() {
            if state
                .closing
                .is_some_and(|since| at - since >= CLOSE_TIMEOUT)
            {
                // Forgotten, not escalated: an unanswered proposal leaves the connection
                // alone and is simply re-offered when we are idle again.
                state.closing = None;
            }
        }
    }

    // ---- helpers ----

    /// Call this peer, if there is anything left to spend on them.
    ///
    /// **The registry is not consulted.** It was, and the answer was worth less than what it
    /// cost: at most five minutes old, about the moment it was taken, and — because a peer it
    /// omitted was never called — able to silence this node entirely rather than merely slow it
    /// down. The two failures in the lab were the same failure twice: a member added seconds
    /// earlier who had never appeared in any answer, and a member who had reconnected since the
    /// last one. Neither was ever dialled.
    ///
    /// Calling somebody who is not there costs one refused circuit out of sixteen a minute, and
    /// the refusal arrives in seconds. Not calling somebody who *is* there costs the propagation.
    /// What paces it instead is the per-peer backoff, and what ends it is [`DIAL_ATTEMPTS`].
    fn dial(&mut self, peer: PeerId) -> Vec<PeerAction> {
        if self.connected.len() + self.dialing.len() >= MAX_PEER_CONNECTIONS
            || self.dialing.contains(&peer)
        {
            return Vec::new();
        }

        let now = self.now;

        // Before anything is charged to the peer: have we a circuit to spend at all? Refused
        // here the peer is untouched and simply waits its turn; refused by the relay it would
        // be backed off for a minute for a fault of ours.
        self.dialed_at.retain(|at| now - *at < DIAL_WINDOW);
        if self.dialed_at.len() >= DIALS_PER_WINDOW {
            return Vec::new();
        }

        let state = self.peers.entry(peer).or_default();
        if now < state.retry_at {
            return Vec::new();
        }

        // Advanced on the *attempt*, not the failure. A dial whose failure is never observed
        // must still back off, or it retries at full speed for ever. The count of attempts is
        // kept the same way and for the same reason.
        state.backoff = if state.backoff == 0 {
            MIN_BACKOFF
        } else {
            (state.backoff * 2).min(MAX_BACKOFF)
        };
        state.retry_at = now + state.backoff;
        state.attempts += 1;

        self.dialing.insert(peer);
        self.dialed_at.push(now);
        vec![PeerAction::Dial { peer }]
    }

    /// Take this peer off every group's list, three failed dials having got us nowhere.
    ///
    /// The end of the patience [`DIAL_ATTEMPTS`] describes, and deliberately the *only* thing
    /// that ends it — nothing here decides they are offline, marks them absent, or writes
    /// anything down about them. A member who is switched off simply stops being counted as owed,
    /// so the group reports itself quiet, stops spending circuits, and puts them back on the list
    /// the next time we have something to say.
    ///
    /// The attempts are cleared with the entry, so that next time is three fresh tries. What is
    /// *not* cleared is the backoff: it keeps doubling towards [`MAX_BACKOFF`], which is what
    /// stops a node that edits constantly from re-dialling a dead member every few minutes.
    fn give_up(&mut self, peer: PeerId) {
        self.pending.remove(&peer);
        if let Some(state) = self.peers.get_mut(&peer) {
            state.attempts = 0;
        }
    }

    /// The next member worth talking to about this group.
    ///
    /// **Strangers first.** A member who has never answered the invitation is either newly added
    /// or has never had it delivered, and round-robin would put them last in a large group —
    /// which is exactly the case where being told promptly matters. Stranger means what
    /// `answered_invite` says it means, and not "no file cursor with us": the two disagree about
    /// a member who accepted long ago and one we have swapped catalogues with but who never
    /// accepted, and the second of those is the one being enqueued as urgent elsewhere.
    fn next_member(&mut self, group: GroupId, skip: &HashSet<PeerId>) -> Option<PeerId> {
        let members: Vec<PeerId> = self
            .groups
            .members(group)
            .ok()?
            .iter()
            .map(|m| m.peer)
            // A dial already in flight is this peer being reached; choosing them again produces
            // nothing and, since the stranger branch below returns the first match rather than
            // advancing the rotation, it produces nothing *for ever* — the group pins on one
            // member while the rest are never considered.
            .filter(|p| *p != self.me && !skip.contains(p) && !self.dialing.contains(p))
            .collect();

        if members.is_empty() {
            return None;
        }

        // Read once, not once per member: this is a store query, and it is asked inside two
        // linear scans below.
        let answered = self.answered_invite(group);
        let stranger = |p: &PeerId| !answered.contains(p);

        // **Someone we are already talking to comes first.** Circuits are the scarce thing
        // here — two a minute, server-enforced — and an open connection costs none at all.
        // Without this a node spends its whole allowance dialling members who may not even
        // answer while a perfectly good connection to one who can help sits idle and is then
        // hung up on. That is exactly how a file stayed `remote` on one member of a
        // three-member group in the lab: it had learned the file existed, and spent six
        // refused circuits on the two peers that did not have it.
        //
        // Strangers still come first among equals, so a newly added member is not left last.
        if let Some(peer) = members
            .iter()
            .find(|p| self.connected.contains(p) && stranger(p))
            .or_else(|| members.iter().find(|p| self.connected.contains(p)))
        {
            return Some(*peer);
        }

        if let Some(stranger) = members.iter().find(|p| self.callable(p) && stranger(p)) {
            return Some(*stranger);
        }

        let start = self.state.get(&group).map(|s| s.rotation).unwrap_or(0);
        for i in 0..members.len() {
            let at = (start + i) % members.len();
            if self.callable(&members[at]) {
                if let Some(state) = self.state.get_mut(&group) {
                    state.rotation = (at + 1) % members.len();
                }
                return Some(members[at]);
            }
        }
        None
    }

    /// Whether this peer may be called right now — the dial backoff, and nothing else.
    ///
    /// It used to also require that somebody had vouched for them, which made one predicate
    /// answer two unrelated questions: *may we call them yet*, and *do we believe they are
    /// there*. The first is about this peer and our own last attempt. The second is about a
    /// registry answer up to five minutes old, and letting it veto a dial is what silenced nodes
    /// in the lab — a member it left out was not called, so the news was never theirs to receive.
    ///
    /// A peer we are already talking to needs no dial and no permission, whatever the registry
    /// last said. That is what keeps a stale or empty answer able to slow this node down but
    /// never to stop it.
    fn callable(&self, peer: &PeerId) -> bool {
        self.connected.contains(peer) || self.peers.get(peer).is_none_or(|s| self.now >= s.retry_at)
    }

    /// Members of this group worth pulling content through, spent or not.
    ///
    /// **The only place the registry's answer is still read**, and the reason it is still worth
    /// having. Pulling gigabytes is a choice between candidates rather than an obligation to a
    /// named member, so a peer the server saw a minute ago is a better bet than one nothing has
    /// mentioned — which is exactly the judgement a presence answer is good for, and exactly the
    /// judgement `callable` must not make on the catalogue loop's behalf.
    ///
    /// Separate from [`Self::next_member`] because the two answer different questions and
    /// conflating them cost this design a real bug: "nobody is reachable" is not the same as
    /// "everybody has been asked and none of them could help", and treating the first as the
    /// second armed the content backoff — saying nobody reachable had it — for a group
    /// whose members simply had not been dialled yet.
    fn reachable(&self, group: GroupId) -> Vec<PeerId> {
        self.groups
            .members(group)
            .unwrap_or_default()
            .iter()
            .map(|m| m.peer)
            .filter(|p| {
                *p != self.me
                    && self.callable(p)
                    && (self.connected.contains(p) || self.online.contains(p))
            })
            .collect()
    }

    fn members_of_shared_groups(&self) -> Vec<PeerId> {
        let mut out = HashSet::new();
        for row in self.groups.list().unwrap_or_default() {
            if row.state != State::Active {
                continue;
            }
            if let Ok(members) = self.groups.members(row.id) {
                out.extend(members.iter().map(|m| m.peer).filter(|p| *p != self.me));
            }
        }
        out.into_iter().collect()
    }

    /// What "up to date with us" means for this group, right now.
    ///
    /// Three facts, because three different things make a peer worth telling. The **file
    /// counter** moves when the catalogue does. The **chain head** moves when the admin adds or
    /// removes somebody. The **standings digest** moves when a member accepts or leaves — which
    /// the head does not cover, since a standing is signed by the member rather than the admin,
    /// and somebody joining while already connected is the commonest way a group grows.
    ///
    /// Three index lookups. This is asked once per group per tick and again for every group an
    /// offer names, so what it costs is what the supervisor costs when nothing is happening.
    fn current(&self, group: GroupId) -> Result<Snapshot, PeersError> {
        let seq = self.files.seq(group)?;
        let row = self.groups.get(group)?;
        Ok(Snapshot {
            seq,
            head: row.as_ref().map(|r| r.head_seq).unwrap_or(0),
            standings: row.map(|r| r.standings_digest).unwrap_or([0u8; 32]),
        })
    }

    /// Whether an offer we sent this peer is still outstanding.
    ///
    /// Read from `started` rather than counted alongside it. A peer has at most one offer in
    /// flight, so a counter could only ever say what this says — and unlike a counter it cannot
    /// drift, which is how two exchanges that ended without saying so once cost a node its
    /// ability to gossip at all.
    fn offer_open(&self, peer: &PeerId) -> bool {
        self.started.contains_key(peer)
    }

    fn content_peers(&self) -> usize {
        self.state.values().filter(|s| s.source.is_some()).count()
    }
}

/// A heartbeat interval spread over ±25%.
///
/// Fifty members who joined a group together would otherwise fire within seconds of each other
/// for ever. Entropy rather than a hash of the peer id, because the spread should differ per
/// group as well as per node.
fn jitter_for(base: i64) -> i64 {
    let mut bytes = [0u8; 2];
    if getrandom::fill(&mut bytes).is_err() {
        return base;
    }
    let fraction = u16::from_le_bytes(bytes) as i64 % 1000;
    base * 3 / 4 + base * fraction / 2000
}
