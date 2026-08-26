use std::collections::{HashMap, HashSet, VecDeque};

use ac_files::path::RelPath;
use ac_files::store::Files;
use ac_groups::id::GroupId;
use ac_groups::store::{Groups, State};
use ac_net::PeerId;

use crate::missing::next_missing;

pub const PRESENCE_INTERVAL: i64 = 300;

/// How long a group may go without asking anybody what they have.
pub const HEARTBEAT: i64 = 4 * 3600;

pub const MIN_BACKOFF: i64 = 15;
pub const MAX_BACKOFF: i64 = 30 * 60;

/// Dials to one member before they are taken off the lists they are on.
pub const DIAL_ATTEMPTS: usize = 3;

/// Circuits opened for *news* in one tick.
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
    HoldingsRefused {
        peer: PeerId,
        group: GroupId,
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

/// A question we put: which groups it named, when it went out, and on which protocol.
#[derive(Debug, Clone)]
struct InFlight {
    outstanding: HashSet<GroupId>,
    at: i64,
    offering: Offering,
}

#[derive(Debug, Default)]
struct PeerState {
    retry_at: i64,
    backoff: i64,
    attempts: usize,
    transfers: usize,
    denied: HashMap<GroupId, HashSet<RelPath>>,
    asked: HashMap<GroupId, RelPath>,
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
    pending: HashSet<PeerId>,
    reconciled: HashSet<(PeerId, GroupId)>,
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
    pub fn new(files: Files, groups: Groups, at: i64) -> Self {
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
            pending: HashSet::new(),
            reconciled: HashSet::new(),
            queued: HashMap::new(),
            dialed_at: Vec::new(),
            dialing: HashSet::new(),
            next_presence: 0,
            refresh_presence: false,
            now: at,
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

                vec![self.ask(peer, Offering::Chain)]
            }

            PeerEvent::Gone { peer } => {
                self.reconciled.retain(|(p, _)| *p != peer);
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
                if let Some(flight) = self.started.get_mut(&peer)
                    && flight.offering == offering
                {
                    flight.outstanding.remove(&group);
                    if flight.outstanding.is_empty() {
                        self.started.remove(&peer);
                    }
                }

                if offering == Offering::Catalogue {
                    self.reconciled.insert((peer, group));
                    return self.open_pull(peer, group);
                }
                Vec::new()
            }

            PeerEvent::Asked { peer, offering } => {
                self.started.remove(&peer);
                match offering {
                    Offering::Chain if self.connected.contains(&peer) => {
                        vec![self.ask(peer, Offering::Catalogue)]
                    }
                    Offering::Catalogue => {
                        self.pending.remove(&peer);
                        Vec::new()
                    }
                    Offering::Chain => Vec::new(),
                }
            }

            PeerEvent::AskDeferred { peer } => {
                self.started.remove(&peer);
                Vec::new()
            }

            PeerEvent::AskFailed { peer } => {
                self.started.remove(&peer);
                Vec::new()
            }

            PeerEvent::Holdings {
                peer,
                group,
                paths,
                held,
            } => self.on_holdings(peer, group, paths, held),

            PeerEvent::HoldingsRefused { peer, group } => self.release_source(peer, group),

            PeerEvent::BlobDone { peer, group, path } => {
                if let Some(state) = self.peers.get_mut(&peer) {
                    state.transfers = state.transfers.saturating_sub(1);
                }
                let _ = self.files.mark_have(group, &path, true);

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
                    let mut actions = self.pump(peer);
                    actions.extend(self.resolve_stalled(peer));
                    actions.extend(self.continue_pull(peer));
                    return actions;
                }

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
                    tracing::warn!(%peer, why, "ignored something from a peer");
                }
                actions.extend(self.continue_pull(peer));
                actions
            }

            PeerEvent::CloseProposed { peer: _ } => Vec::new(),

            PeerEvent::CloseAnswered { peer, ready } => {
                if !ready {
                    return Vec::new();
                }

                let proposed = self
                    .peers
                    .get_mut(&peer)
                    .and_then(|state| state.closing.take())
                    .is_some();

                if proposed && self.drained(peer) {
                    return vec![PeerAction::Disconnect { peer }];
                }
                Vec::new()
            }
        }
    }

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
        actions.extend(self.queue_dials());
        actions.extend(self.pump_queues());

        match self.room() {
            Some(why) => {
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
    fn presence(&mut self, at: i64) -> Vec<PeerAction> {
        let peers: Vec<PeerId> = self
            .members_of_shared_groups()
            .into_iter()
            .filter(|p| !self.connected.contains(p))
            .collect();

        if peers.is_empty() {
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
        self.state
            .entry(group)
            .or_insert_with(|| GroupState::new(at));

        if self.files.wanted_news(group).unwrap_or(0) > 0
            && let Some(state) = self.state.get_mut(&group)
        {
            let _ = self.files.wanted_seen(group);
            for peer in self.peers.values_mut() {
                peer.asked.remove(&group);
            }
            state.content_until = 0;
            state.content_backoff = MIN_CONTENT_BACKOFF;
            state.spent.clear();
        }

        let membership_moved = self.groups.news(group).unwrap_or(0) > 0;

        let (changes, changed_at) = self.files.local_news(group).unwrap_or((0, at));
        let catalogue_moved = changes > 0;

        let share_catalogue = catalogue_moved
            && (changes >= SHARE_AFTER_CHANGES || at - changed_at >= SHARE_AFTER_IDLE);

        if membership_moved || share_catalogue {
            self.enqueue(group);
        }
        if membership_moved {
            self.refresh_presence = true;
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

        if share_catalogue {
            let _ = self.files.news_told(group);
        }
        if membership_moved {
            let _ = self.groups.news_told(group);
        }

        if at >= self.state[&group].heartbeat_at {
            if let Some(state) = self.state.get_mut(&group) {
                state.heartbeat_at = at + HEARTBEAT;
            }

            let covered = self
                .members_of(group)
                .into_iter()
                .any(|peer| self.pending.contains(&peer));

            if !covered && let Some(peer) = self.peek_member(group) {
                self.pending.insert(peer);
            }
        }
    }

    /// Put every member we could actually call on the list.
    fn enqueue(&mut self, group: GroupId) {
        for peer in self.members_of(group) {
            if !self.connected.contains(&peer) && !self.online.contains(&peer) {
                tracing::debug!(%group, %peer, "not enqueued: nothing says they are reachable");
                continue;
            }
            self.pending.insert(peer);
        }
    }

    /// Call peers in pending
    fn queue_dials(&mut self) -> Vec<PeerAction> {
        let mut peers_to_dial: Vec<PeerId> = self
            .pending
            .iter()
            .copied()
            .filter(|p| !self.connected.contains(p))
            .collect();

        tracing::debug!(
            pending = self.pending.len(),
            peers_to_dial = peers_to_dial.len(),
            connected_total = self.connected.len(),
            started = self.started.len(),
            "rounds"
        );

        // Strangers first
        peers_to_dial.sort_by_key(|p| self.unanswered_invites(p).is_empty());

        let mut actions = Vec::new();
        let mut opened = 0;
        for peer in peers_to_dial {
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

    /// Record what an offer to this peer carries, and ask for it.
    fn ask(&mut self, peer: PeerId, offering: Offering) -> PeerAction {
        let named = match offering {
            Offering::Chain => self.groups.log_shared_with(&peer),
            Offering::Catalogue => self.groups.shared_with(&peer),
        };
        let outstanding = named
            .unwrap_or_default()
            .into_iter()
            .map(|head| head.group)
            .collect();

        self.started.insert(
            peer,
            InFlight {
                outstanding,
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
            if self.state.get(group).is_some_and(|s| s.source.is_some()) {
                continue;
            }

            if self.files.missing_count(*group).unwrap_or(0) == 0 {
                continue;
            }

            let spent = self
                .state
                .get(group)
                .map(|s| s.spent.clone())
                .unwrap_or_default();

            let reachable = self.reachable(*group);
            if reachable.is_empty() {
                continue;
            }
            if reachable.iter().all(|p| spent.contains(p)) {
                actions.extend(self.exhaust_group(*group, at));
                continue;
            }

            let ready = self.members_of(*group).into_iter().find(|p| {
                self.connected.contains(p)
                    && !spent.contains(p)
                    && self.reconciled.contains(&(*p, *group))
            });
            if let Some(peer) = ready {
                actions.extend(self.open_pull(peer, *group));
                continue;
            }

            if self.members_of(*group).iter().any(|p| {
                self.dialing.contains(p) || (self.connected.contains(p) && !spent.contains(p))
            }) {
                continue;
            }

            let mut skip = spent.clone();
            skip.extend(
                self.members_of(*group)
                    .into_iter()
                    .filter(|p| !reachable.contains(p)),
            );
            let Some(peer) = self.next_member(*group, &skip) else {
                continue;
            };

            actions.extend(self.dial(peer));
        }
        actions
    }

    /// Claim this group's pull for a peer whose catalogue has just reconciled, and ask.
    fn open_pull(&mut self, peer: PeerId, group: GroupId) -> Vec<PeerAction> {
        if self.content_peers() >= MAX_CONTENT_PEERS {
            return Vec::new();
        }
        let state = self.state.get(&group);
        if state.is_some_and(|s| s.source.is_some() || s.spent.contains(&peer)) {
            return Vec::new();
        }
        if state.is_some_and(|s| self.now < s.content_until) {
            return Vec::new();
        }
        if self.files.missing_count(group).unwrap_or(0) == 0 {
            return Vec::new();
        }
        if self.room().is_some() {
            return Vec::new();
        }

        if let Some(state) = self.state.get_mut(&group) {
            state.source = Some(peer);
        }
        self.ask_holdings(peer, group)
    }

    /// Why there is no room for more content, or `None` if there is.
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
    fn reserve(&mut self, size: u64) {
        if let Some(space) = &mut self.space {
            space.held = space.held.saturating_add(size);
            space.free = space.free.saturating_sub(size);
        }
    }

    /// A batch of transfers finished. Ask this source for the next one, or let it go.
    fn continue_pull(&mut self, peer: PeerId) -> Vec<PeerAction> {
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
            .groups
            .list()
            .unwrap_or_default()
            .into_iter()
            .filter(|row| row.state == State::Active)
            .map(|row| row.id)
            .filter(|group| self.members_of(*group).contains(&peer))
            .collect();

        let mut actions = Vec::new();
        for group in groups {
            if self
                .state
                .get(&group)
                .is_some_and(|s| s.source == Some(peer))
            {
                actions.extend(self.ask_holdings(peer, group));
            } else {
                actions.extend(self.open_pull(peer, group));
            }
        }
        actions
    }

    fn ask_holdings(&mut self, peer: PeerId, group: GroupId) -> Vec<PeerAction> {
        let denied = self
            .peers
            .get(&peer)
            .and_then(|s| s.denied.get(&group))
            .cloned()
            .unwrap_or_default();

        let limit = ac_files::wire::MAX_HOLDINGS_QUERY;
        loop {
            let after = self
                .peers
                .get(&peer)
                .and_then(|s| s.asked.get(&group))
                .cloned();
            let page = next_missing(&self.files, group, after.as_ref(), limit).unwrap_or_default();
            let ended = page.len() < limit;

            if let Some((last, _)) = page.last() {
                self.peers
                    .entry(peer)
                    .or_default()
                    .asked
                    .insert(group, last.clone());
            }

            let paths: Vec<RelPath> = page
                .into_iter()
                .map(|(path, _)| path)
                .filter(|path| !denied.contains(path))
                .collect();

            if !paths.is_empty() {
                return vec![PeerAction::AskHoldings { peer, group, paths }];
            }
            if ended {
                return self.spend_peer(peer, group);
            }
        }
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
            .filter(|(i, path)| held.get(*i).copied().unwrap_or(false) && !denied.contains(path))
            .map(|(_, path)| path)
            .collect();

        if wanted.is_empty() {
            return self.ask_holdings(peer, group);
        }

        self.queued
            .entry(peer)
            .or_default()
            .extend(wanted.into_iter().map(|path| (group, path)));

        let actions = self.pump(peer);
        if actions.is_empty() && self.running_transfers() == 0 {
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

            let Ok(Some(row)) = self.files.get(group, &path) else {
                continue;
            };
            if row.have || row.removed_at.is_some() {
                continue;
            }

            if !self.room_for(row.size) {
                // Not their fault and not permanent
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

    /// Forget what this peer had offered for this group.
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
        if let Some(state) = self.peers.get_mut(&peer) {
            state.asked.remove(&group);
        }
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
        if let Ok(missing) = next_missing(&self.files, group, None, 1)
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
                        .filter(|p| self.pending.contains(p))
                        .count(),
                    next: self.peek_member(row.id),
                    source: state.and_then(|s| s.source),
                    content_until: state.map(|s| s.content_until).unwrap_or(0),
                    heartbeat_at: state.map(|s| s.heartbeat_at).unwrap_or(0),
                }
            })
            .collect();

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
            self.pending.insert(peer);
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

    /// Nothing left that *this peer* can do for us.
    pub fn drained(&self, peer: PeerId) -> bool {
        let busy = self.peers.get(&peer).is_some_and(|s| s.transfers > 0) || self.offer_open(&peer);
        !busy && !self.may_still_help(&peer)
    }

    /// Whether any group could still pull content through this peer.
    fn may_still_help(&self, peer: &PeerId) -> bool {
        self.groups
            .list()
            .unwrap_or_default()
            .into_iter()
            .filter(|row| row.state == State::Active)
            .any(|row| {
                let state = self.state.get(&row.id);
                state.is_none_or(|s| self.now >= s.content_until && !s.spent.contains(peer))
                    && self.members_of(row.id).contains(peer)
                    && self.files.missing_count(row.id).unwrap_or(0) > 0
            })
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
                state.closing = None;
            }
        }
    }

    /// Call this peer, if there is anything left to spend on them.
    fn dial(&mut self, peer: PeerId) -> Vec<PeerAction> {
        if self.connected.contains(&peer) {
            return Vec::new();
        }

        if self.connected.len() + self.dialing.len() >= MAX_PEER_CONNECTIONS
            || self.dialing.contains(&peer)
        {
            return Vec::new();
        }

        let now = self.now;

        self.dialed_at.retain(|at| now - *at < DIAL_WINDOW);
        if self.dialed_at.len() >= DIALS_PER_WINDOW {
            return Vec::new();
        }

        let state = self.peers.entry(peer).or_default();
        if now < state.retry_at {
            return Vec::new();
        }

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

    /// Take this peer off every group's list
    fn give_up(&mut self, peer: PeerId) {
        self.pending.remove(&peer);
        if let Some(state) = self.peers.get_mut(&peer) {
            state.attempts = 0;
        }
    }

    /// The next member worth talking to about this group.
    fn next_member(&mut self, group: GroupId, skip: &HashSet<PeerId>) -> Option<PeerId> {
        let members: Vec<PeerId> = self
            .groups
            .members(group)
            .ok()?
            .iter()
            .map(|m| m.peer)
            .filter(|p| *p != self.me && !skip.contains(p) && !self.dialing.contains(p))
            .collect();

        if members.is_empty() {
            return None;
        }

        let answered = self.answered_invite(group);
        let stranger = |p: &PeerId| !answered.contains(p);

        // Strangers still come first among equals, so a newly added member is not left last.
        if let Some(peer) = members
            .iter()
            .find(|p| self.connected.contains(p) && !stranger(p))
            .or_else(|| members.iter().find(|p| self.connected.contains(p)))
        {
            return Some(*peer);
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

    /// Whether this peer may be called right now, the dial backoff, and nothing else.
    fn callable(&self, peer: &PeerId) -> bool {
        self.connected.contains(peer) || self.peers.get(peer).is_none_or(|s| self.now >= s.retry_at)
    }

    /// Members of this group worth pulling content through, spent or not.
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

    /// Whether an offer we sent this peer is still outstanding.
    fn offer_open(&self, peer: &PeerId) -> bool {
        self.started.contains_key(peer)
    }

    fn content_peers(&self) -> usize {
        self.state.values().filter(|s| s.source.is_some()).count()
    }
}
