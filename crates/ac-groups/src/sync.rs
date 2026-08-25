use std::collections::{HashMap, HashSet};
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
const MAX_INFLIGHT: usize = 8;

/// How long a group we were invited to but never accepted is kept once the chain has stopped
/// naming us. Long enough that a slow human is not punished for it.
const PENDING_TTL: i64 = 30 * 24 * 3600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    Invited {
        group: GroupId,
        name: String,
    },
    RemovedByAdmin {
        group: GroupId,
        name: String,
    },
    MembershipChanged {
        group: GroupId,
        added: usize,
        removed: usize,
    },
    Departed {
        group: GroupId,
        peer: PeerId,
    },
    Ratified {
        group: GroupId,
        peer: PeerId,
    },
    Rejected {
        group: GroupId,
        peer: PeerId,
        why: String,
    },
    Trouble {
        why: String,
    },
}

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
    Note(Notice),
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
    inflight: HashMap<GroupId, InFlight>,
    budget: TickBudget,
    now_at: i64,
}

impl GroupSync {
    pub fn new(store: Groups, key: Keypair) -> Self {
        let me = key.public().to_peer_id();
        Self {
            store,
            me,
            key,
            inflight: HashMap::new(),
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
        if !roster.is_ready(&peer) || !self.budget.spend(peer) {
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
        match event {
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
        }
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
                Err(e) => actions.push(GroupAction::Note(Notice::Trouble { why: e.to_string() })),
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
                actions.push(GroupAction::Note(Notice::Rejected {
                    group,
                    peer,
                    why: e.to_string(),
                }));
                return actions;
            }
        };

        self.report(&mut actions, group, &applied);
        self.answer_invitation(&mut actions, group, at);
        self.ratify(&mut actions, group, &applied, at);

        actions
    }

    /// Turn what changed into something a person would want to read.
    fn report(&self, actions: &mut Vec<GroupAction>, group: GroupId, applied: &Applied) {
        let name = self
            .store
            .get(group)
            .ok()
            .flatten()
            .map(|r| r.name)
            .unwrap_or_default();

        if applied.we_joined {
            actions.push(GroupAction::Note(Notice::Invited {
                group,
                name: name.clone(),
            }));
        }
        if applied.we_lost {
            actions.push(GroupAction::Note(Notice::RemovedByAdmin {
                group,
                name: name.clone(),
            }));
        }
        if !applied.added.is_empty() || !applied.removed.is_empty() {
            actions.push(GroupAction::Note(Notice::MembershipChanged {
                group,
                added: applied.added.len(),
                removed: applied.removed.len(),
            }));
        }
        for peer in &applied.departed {
            actions.push(GroupAction::Note(Notice::Departed { group, peer: *peer }));
        }
    }

    /// Author a "pending" invitation to mark we have received an invitation to a group.
    fn answer_invitation(&mut self, actions: &mut Vec<GroupAction>, group: GroupId, at: i64) {
        let pending = matches!(self.store.get(group), Ok(Some(row)) if row.state == State::Pending);
        let named = matches!(self.store.members(group), Ok(m) if m.contains(&self.me));
        let spoken = matches!(self.store.my_standing_seq(group), Ok(Some(_)));
        if !pending || !named || spoken {
            return;
        }
        if let Err(e) = self
            .store
            .author_standing(&self.key, group, Position::Unanswered, at)
        {
            actions.push(GroupAction::Note(Notice::Trouble {
                why: format!("could not record an unanswered invitation: {e}"),
            }));
        }
    }

    /// If we admin this group, make a departure official.
    fn ratify(
        &mut self,
        actions: &mut Vec<GroupAction>,
        group: GroupId,
        applied: &Applied,
        at: i64,
    ) {
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
                Ok(_) => actions.push(GroupAction::Note(Notice::Ratified { group, peer: *peer })),
                Err(e) => actions.push(GroupAction::Note(Notice::Trouble {
                    why: format!("could not ratify a departure: {e}"),
                })),
            }
        }
    }

    fn tick(&mut self, now: Instant, at: i64, roster: &Roster) -> Vec<GroupAction> {
        self.now_at = at;
        self.budget.reset();

        // Abandon episodes that can no longer finish, so the group is free to try again
        self.inflight
            .retain(|_, f| now < f.deadline && roster.is_ready(&f.peer));

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
        if self.inflight.contains_key(&group) || self.inflight.len() >= MAX_INFLIGHT {
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

    fn finish(&mut self, group: GroupId, peer: PeerId) {
        if matches!(self.inflight.get(&group), Some(f) if f.peer == peer) {
            self.inflight.remove(&group);
        }
    }
}
