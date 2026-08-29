use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use ac_net::PeerId;
use ac_net::budget::TickBudget;
use ac_net::identity::Keypair;
use ac_net::roster::Roster;

use crate::chain::Op;
use crate::id::GroupId;
use crate::standing::Position;
use crate::store::{Applied, GroupRow, Groups, State, StoreError};
use crate::wire::{GroupHead, GroupRequest, GroupResponse, MAX_HEADS_PER_ANSWER};

/// How long a fetch may be outstanding before the episode is abandoned.
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Requests we will *answer* from one peer between ticks.
const ANSWERS_PER_TICK: u32 = 8;

/// Fetches we will have outstanding at once, across all peers and groups.
pub const MAX_INFLIGHT: usize = 8;

/// Groups waiting for a slot
pub const MAX_DEFERRED: usize = 256;

/// How long a group we were invited to but never accepted is kept once the chain has stopped
/// naming us. Long enough that a slow human is not punished for it.
const PENDING_TTL: i64 = 30 * 24 * 3600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupEvent {
    Heads {
        peer: PeerId,
        heads: Vec<GroupHead>,
    },
    Entries {
        peer: PeerId,
        group: GroupId,
        from: u64,
        entries: Vec<crate::chain::Entry>,
        standings: Vec<crate::standing::Standing>,
    },
    Unavailable {
        peer: PeerId,
        group: GroupId,
    },
    FetchFailed {
        peer: PeerId,
        group: GroupId,
    },
    AskFailed {
        peer: PeerId,
    },
    Tick {
        now: Instant,
        at: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupAction {
    Fetch {
        peer: PeerId,
        group: GroupId,
        from: u64,
    },
}

/// One outstanding fetch. Keyed by group, so there is one episode per group at a time.
#[derive(Debug, Clone)]
struct InFlight {
    peer: PeerId,
    from: u64,
    deadline: Instant,
}

pub struct GroupSync {
    store: Groups,
    me: PeerId,
    key: Keypair,
    /// What this node calls itself, written into every standing it authors. Supplied by the
    /// caller because it comes from the attestation, which this crate knows nothing about.
    username: String,
    inflight: HashMap<GroupId, InFlight>,
    deferred: VecDeque<(PeerId, GroupId)>,
    budget: TickBudget,
    now_at: i64,
}

impl GroupSync {
    pub fn new(store: Groups, key: Keypair, username: String) -> Self {
        let me = key.public().to_peer_id();
        Self {
            store,
            me,
            key,
            username,
            inflight: HashMap::new(),
            deferred: VecDeque::new(),
            budget: TickBudget::new(ANSWERS_PER_TICK),
            now_at: 0,
        }
    }

    /// Read-only access, for reporting what this node holds.
    pub fn store(&self) -> &Groups {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut Groups {
        &mut self.store
    }

    /// Answer an inbound request.
    pub fn on_request(
        &mut self,
        peer: PeerId,
        request: GroupRequest,
        roster: &Roster,
    ) -> (GroupResponse, Vec<GroupAction>) {
        if !roster.is_admitted(&peer) || !self.budget.spend(peer) {
            return (GroupResponse::Unavailable, Vec::new());
        }

        match request {
            GroupRequest::Ask => {
                let ours = self
                    .store
                    .log_shared_with(&peer)
                    .unwrap_or_default()
                    .into_iter()
                    .take(MAX_HEADS_PER_ANSWER)
                    .collect();
                (GroupResponse::Heads(ours), Vec::new())
            }
            GroupRequest::Fetch { group, from } => {
                let response = match self.store.entries_for(group, &peer, from) {
                    Ok(Some(entries)) => GroupResponse::Entries {
                        group,
                        from,
                        entries,
                        standings: self.store.standings(group).unwrap_or_default(),
                    },
                    _ => GroupResponse::Unavailable,
                };
                (response, Vec::new())
            }
        }
    }

    pub fn on(&mut self, event: GroupEvent, roster: &Roster) -> Vec<GroupAction> {
        let mut actions = match event {
            GroupEvent::Heads { peer, heads } => {
                if !roster.is_ready(&peer) {
                    return Vec::new();
                }
                self.on_heads(peer, heads)
            }

            GroupEvent::Entries {
                peer,
                group,
                from,
                entries,
                standings,
            } => self.on_entries(peer, group, from, &entries, &standings),

            GroupEvent::Unavailable { peer, group } | GroupEvent::FetchFailed { peer, group } => {
                self.finish(group, peer);
                Vec::new()
            }

            GroupEvent::AskFailed { .. } => Vec::new(),

            GroupEvent::Tick { now, at } => self.tick(now, at, roster),
        };

        self.drain_deferred(&mut actions, roster);
        actions
    }

    /// Decide what to fetch from the heads a peer named, and from what they left out.
    fn on_heads(&mut self, peer: PeerId, heads: Vec<GroupHead>) -> Vec<GroupAction> {
        let heads: Vec<GroupHead> = heads.into_iter().take(MAX_HEADS_PER_ANSWER).collect();
        let named: HashSet<GroupId> = heads.iter().map(|h| h.group).collect();
        let mut actions = Vec::new();

        for head in &heads {
            match self.store.get(head.group) {
                // A group we have never seen. Take it from the top; `adopt` decides whether
                // it is one we are entitled to keep.
                Ok(None) => self.fetch(&mut actions, peer, head.group, 0),
                Ok(Some(row)) => {
                    // Behind on entries, or holding a different set of standings. The digest
                    // is what catches the second case: heads can match exactly while one side
                    // is missing a departure.
                    if head.head_seq > row.head_seq || head.standings != row.standings_digest {
                        self.fetch(&mut actions, peer, head.group, row.head_seq);
                    }
                }
                Err(e) => {
                    tracing::warn!(group = %head.group, error = %e, "could not read a group");
                }
            }
        }

        // A group we hold that names this peer, which they did not mention, is
        // a discrepancy worth one question: either they removed us, or they have left it
        // themselves. Either way we only learn by asking, since nobody offers a group to
        // someone the offerer no longer counts as a member.
        for group in self.silently_omitted(peer, &named) {
            let from = self
                .store
                .get(group)
                .ok()
                .flatten()
                .map_or(0, |r| r.head_seq);
            self.fetch(&mut actions, peer, group, from);
        }

        actions
    }

    /// Groups we hold whose chain names `peer`, but which `peer` did not offer us.
    fn silently_omitted(&self, peer: PeerId, named: &HashSet<GroupId>) -> Vec<GroupId> {
        let Ok(rows) = self.store.list() else {
            return Vec::new();
        };
        rows.into_iter()
            .filter(|row| !named.contains(&row.id))
            .filter(|row| {
                self.store
                    .members(row.id)
                    .map(|m| m.contains(&peer))
                    .unwrap_or(false)
            })
            .map(|row| row.id)
            .collect()
    }

    fn on_entries(
        &mut self,
        peer: PeerId,
        group: GroupId,
        from: u64,
        entries: &[crate::chain::Entry],
        standings: &[crate::standing::Standing],
    ) -> Vec<GroupAction> {
        // Late, duplicated or unsolicited responses are dropped rather than applied: only the
        // request we are actually waiting on may move our head.
        let expected = matches!(
            self.inflight.get(&group),
            Some(f) if f.peer == peer && f.from == from
        );
        if !expected {
            return Vec::new();
        }
        self.inflight.remove(&group);

        let known = matches!(self.store.get(group), Ok(Some(_)));
        let at = self.now_at;
        let outcome = if known {
            self.store.put(group, from, entries, standings, at)
        } else {
            self.store.adopt(entries, standings, at)
        };

        let mut actions = Vec::new();
        let applied = match outcome {
            Ok(applied) => applied,
            Err(StoreError::Gap { want, .. }) => {
                // Our head moved between asking and answering. Ask again from where we are.
                self.fetch(&mut actions, peer, group, want);
                return actions;
            }
            Err(e) => {
                tracing::warn!(%group, %peer, error = %e, "refused a peer's group data");
                return actions;
            }
        };

        self.report(group, &applied);
        self.answer_invitation(group, at);
        self.ratify(group, &applied, at);

        actions
    }

    /// Say what changed, where it changed.
    fn report(&self, group: GroupId, applied: &Applied) {
        let name = self
            .store
            .get(group)
            .ok()
            .flatten()
            .map(|r| r.name)
            .unwrap_or_default();

        if applied.we_joined {
            tracing::info!(%group, %name, "invited to a group; accept it with `ac group accept`");
        }
        if applied.we_lost {
            tracing::info!(%group, %name, "removed from a group by its admin");
        }
        if !applied.added.is_empty() || !applied.removed.is_empty() {
            tracing::info!(
                %group,
                added = applied.added.len(),
                removed = applied.removed.len(),
                "group membership changed"
            );
        }
        for peer in &applied.departed {
            tracing::info!(%group, %peer, "a member has left");
        }
    }

    /// Author a "pending" invitation to mark we have received an invitation to a group.
    fn answer_invitation(&mut self, group: GroupId, at: i64) {
        let pending = matches!(self.store.get(group), Ok(Some(row)) if row.state == State::Pending);
        let named = matches!(self.store.members(group), Ok(m) if m.contains(&self.me));
        let spoken = matches!(self.store.my_standing_seq(group), Ok(Some(_)));
        if !pending || !named || spoken {
            return;
        }
        if let Err(e) =
            self.store
                .author_standing(&self.key, group, Position::Unanswered, &self.username, at)
        {
            tracing::warn!(%group, error = %e, "could not record an unanswered invitation");
        }
    }

    /// If we admin this group, make a departure official.
    fn ratify(&mut self, group: GroupId, applied: &Applied, at: i64) {
        if applied.departed.is_empty() {
            return;
        }
        let we_admin = matches!(self.store.get(group), Ok(Some(row)) if row.admin == self.me);
        if !we_admin {
            return;
        }

        for peer in &applied.departed {
            let op = Op::Remove {
                peer: peer.to_base58(),
            };
            match self.store.author(&self.key, group, op, at) {
                Ok(_) => tracing::info!(%group, %peer, "recorded a member's departure"),
                Err(e) => {
                    tracing::warn!(%group, peer = %peer, error = %e, "could not ratify a departure");
                }
            }
        }
    }

    fn tick(&mut self, now: Instant, at: i64, roster: &Roster) -> Vec<GroupAction> {
        self.now_at = at;
        self.budget.reset();

        // Abandon episodes that can no longer finish, so the group is free to try again
        self.inflight
            .retain(|_, f| now < f.deadline && roster.is_ready(&f.peer));
        self.deferred.retain(|(peer, _)| roster.is_admitted(peer));

        let actions = Vec::new();

        let rows = self.store.list().unwrap_or_default();
        self.expire_pending(&rows, at);
        actions
    }

    /// Forget invitations that were never accepted and no longer name us.
    fn expire_pending(&mut self, rows: &[GroupRow], at: i64) {
        for row in rows {
            if row.state != State::Pending || at - row.first_seen < PENDING_TTL {
                continue;
            }
            let ours = self
                .store
                .members(row.id)
                .map(|m| m.contains(&self.me))
                .unwrap_or(true);
            if !ours {
                let _ = self.store.forget(row.id);
            }
        }
    }

    /// Queue a fetch, unless this group already has an episode running or we are at capacity.
    fn fetch(&mut self, actions: &mut Vec<GroupAction>, peer: PeerId, group: GroupId, from: u64) {
        if self.inflight.contains_key(&group) {
            return;
        }

        if self.inflight.len() >= MAX_INFLIGHT {
            self.defer(peer, group);
            return;
        }
        self.inflight.insert(
            group,
            InFlight {
                peer,
                from,
                deadline: Instant::now() + FETCH_TIMEOUT,
            },
        );
        actions.push(GroupAction::Fetch { peer, group, from });
    }

    /// Remember a group there was no room to read yet.
    fn defer(&mut self, peer: PeerId, group: GroupId) {
        if self.deferred.iter().any(|(_, g)| *g == group) {
            return;
        }
        if self.deferred.len() >= MAX_DEFERRED {
            tracing::debug!(%group, "no room to read this group and no room to remember it");
            return;
        }
        tracing::debug!(%peer, %group, "no room to read this group yet; queued");
        self.deferred.push_back((peer, group));
    }

    /// Start whatever the freed slots have room for.
    fn drain_deferred(&mut self, actions: &mut Vec<GroupAction>, roster: &Roster) {
        while self.inflight.len() < MAX_INFLIGHT {
            let Some((peer, group)) = self.deferred.pop_front() else {
                return;
            };

            if !roster.is_admitted(&peer) || self.inflight.contains_key(&group) {
                continue;
            }

            let from = self
                .store
                .get(group)
                .ok()
                .flatten()
                .map_or(0, |row| row.head_seq);
            self.fetch(actions, peer, group, from);
        }
    }

    fn finish(&mut self, group: GroupId, peer: PeerId) {
        if matches!(self.inflight.get(&group), Some(f) if f.peer == peer) {
            self.inflight.remove(&group);
        }
    }
}
