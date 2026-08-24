use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use ac_net::PeerId;
use ac_net::identity::Keypair;

use crate::chain::Op;
use crate::id::GroupId;
use crate::standing::Position;
use crate::store::{Applied, GroupRow, Groups, State, StoreError};
use crate::wire::{GroupHead, GroupRequest, GroupResponse, MAX_HEADS_PER_OFFER};

/// How long a fetch may be outstanding before the episode is abandoned.
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Requests we will *answer* from one peer between ticks.
const ANSWERS_PER_TICK: u32 = 8;

/// Fetches we will have outstanding at once, across all peers and groups.
const MAX_INFLIGHT: usize = 8;

/// How long a group we were invited to but never accepted is kept once the chain has stopped
/// naming us. Long enough that a slow human is not punished for it.
const PENDING_TTL: i64 = 30 * 24 * 3600;

/// Something worth telling a person
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
    /// A peer completed mutual attestation *and* its connection settled — see the daemon.
    PeerVerified {
        peer: PeerId,
    },
    PeerGone {
        peer: PeerId,
    },
    /// Heads a peer named to us, from an offer they sent as a response.
    Offered {
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
    OfferFailed {
        peer: PeerId,
    },
    /// The only clock this machine has. `now` sweeps deadlines; `at` timestamps what we sign.
    ///
    /// It picks up changes *we* made — including from the CLI in another process — and clears
    /// stalled episodes. It never polls a peer: see "When syncing happens" above.
    Tick {
        now: Instant,
        at: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupAction {
    Offer {
        peer: PeerId,
        heads: Vec<GroupHead>,
    },
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
    verified: HashSet<PeerId>,
    inflight: HashMap<GroupId, InFlight>,
    /// Which groups each peer has named to us this connection — fetch rule 1.
    offered: HashMap<PeerId, HashSet<GroupId>>,
    /// Requests left for each peer until the next tick.
    budget: HashMap<PeerId, u32>,
    /// The wall clock, as of the last tick. The machine reads no clock of its own, so
    /// everything it signs is timestamped from an event and tests stay deterministic.
    now_at: i64,
}

impl GroupSync {
    pub fn new(store: Groups, key: Keypair) -> Self {
        let me = key.public().to_peer_id();
        Self {
            store,
            me,
            key,
            verified: HashSet::new(),
            inflight: HashMap::new(),
            offered: HashMap::new(),
            budget: HashMap::new(),
            now_at: 0,
        }
    }

    /// Read-only access, for reporting what this node holds.
    pub fn store(&self) -> &Groups {
        &self.store
    }

    /// Write access, for setting up a scenario in tests.
    ///
    /// Not how the daemon works: the CLI writes through its *own* handle in another process,
    /// and the machine notices on the next tick. Reaching for this in the daemon would mean
    /// a change nobody announces.
    /// What we would name to this peer: every group whose log we will discuss with them,
    /// including ones we have been invited to and not yet accepted.
    ///
    /// The one shape an offer comes in. Public because the supervisor decides *when* to offer
    /// and this layer decides *what* — the same split `ac-files` makes.
    pub fn heads_for(&self, peer: &PeerId) -> Vec<GroupHead> {
        self.store
            .log_shared_with(peer)
            .unwrap_or_default()
            .into_iter()
            .take(MAX_HEADS_PER_OFFER)
            .collect()
    }

    pub fn store_mut(&mut self) -> &mut Groups {
        &mut self.store
    }

    /// Answer an inbound request.
    ///
    /// Total: **exactly one response, always**. That is why [`GroupAction`] has no `Respond`
    /// variant — the daemon holds the channel across this call and consumes it here, so a
    /// channel can never be stranded and there is no "wanted to answer nothing" case to
    /// handle. Every refusal collapses into [`GroupResponse::Unavailable`].
    pub fn on_request(
        &mut self,
        peer: PeerId,
        request: GroupRequest,
    ) -> (GroupResponse, Vec<GroupAction>) {
        if !self.verified.contains(&peer) || !self.spend(peer) {
            return (GroupResponse::Unavailable, Vec::new());
        }

        match request {
            GroupRequest::Offer(heads) => {
                // Answer with our own view, then act on theirs. A store error yields an empty
                // offer rather than `Unavailable`, which would imply a group-specific refusal.
                let ours = self.store.log_shared_with(&peer).unwrap_or_default();
                let actions = self.on_heads(peer, heads);
                (GroupResponse::Offer(ours), actions)
            }
            GroupRequest::Fetch { group, from } => {
                let response = match self.store.entries_for(group, &peer, from) {
                    Ok(Some(entries)) => GroupResponse::Entries {
                        group,
                        from,
                        entries,
                        standings: self.store.standings(group).unwrap_or_default(),
                    },
                    // Refused and unknown are the same answer on purpose: telling them apart
                    // would turn a guessed group id into a membership oracle.
                    _ => GroupResponse::Unavailable,
                };
                (response, Vec::new())
            }
        }
    }

    pub fn on(&mut self, event: GroupEvent) -> Vec<GroupAction> {
        match event {
            GroupEvent::PeerVerified { peer } => {
                // Noted, not acted on. The supervisor decides when to talk to a peer — including
                // the moment one arrives, where its record for them is empty and therefore
                // stale. Offering from here as well meant every fresh connection carried a
                // duplicate of the request it was about to send.
                self.verified.insert(peer);
                Vec::new()
            }

            GroupEvent::PeerGone { peer } => {
                self.verified.remove(&peer);
                self.offered.remove(&peer);
                self.budget.remove(&peer);
                self.inflight.retain(|_, f| f.peer != peer);
                Vec::new()
            }

            // An offer *response*. Provokes fetches only — answering an offer with an offer
            // would have two peers volleying forever.
            GroupEvent::Offered { peer, heads } => {
                if !self.verified.contains(&peer) {
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

            GroupEvent::OfferFailed { .. } => Vec::new(),

            GroupEvent::Tick { now, at } => self.tick(now, at),
        }
    }

    /// Decide what to fetch from the heads a peer named, and from what they left out.
    fn on_heads(&mut self, peer: PeerId, heads: Vec<GroupHead>) -> Vec<GroupAction> {
        let heads: Vec<GroupHead> = heads.into_iter().take(MAX_HEADS_PER_OFFER).collect();
        let named: HashSet<GroupId> = heads.iter().map(|h| h.group).collect();
        self.offered.entry(peer).or_default().extend(named.iter());

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

        // Fetch rule 2. A group we hold that names this peer, which they did not mention, is
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

        // Nothing is passed onward from here either. Applying entries moves our own head, and
        // the supervisor's record of what each peer has seen is compared against exactly that —
        // so every member becomes stale by the same comparison that notices a local change, and
        // is offered to on the ordinary loop. One mechanism, whether the news was ours or
        // somebody else's.
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

    /// Say once, in writing, that we hold an invitation we have not answered.
    ///
    /// A pending node that says nothing is indistinguishable from one that never received the
    /// chain at all, so every other member goes on treating the invitation as undelivered and
    /// re-offering it on every discovery hint — forever, since nothing else ever changes.
    /// `Unanswered` is the smallest true thing we can say, it is self-signed like any other
    /// standing, and it travels the same way: the digest moves, so the next exchange carries it
    /// and it spreads through the group.
    ///
    /// Only once. A standing of our own already on file means we have spoken — whether to say
    /// this, to accept, or to leave — and re-authoring would spend a seq per sync.
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

    fn tick(&mut self, now: Instant, at: i64) -> Vec<GroupAction> {
        self.now_at = at;
        self.budget.clear();

        // Abandon stalled episodes so the group is free to try again.
        let stalled: Vec<GroupId> = self
            .inflight
            .iter()
            .filter(|(_, f)| now >= f.deadline)
            .map(|(g, _)| *g)
            .collect();
        for group in stalled {
            self.inflight.remove(&group);
        }

        let actions = Vec::new();

        // **Nothing is offered from here.** Deciding when to talk to a peer belongs to the
        // supervisor, which knows who is online, what the relay will allow, and whether a peer
        // has just declined to discuss a group. This layer knows none of that, and there is no
        // reason for the chain to spread by a different mechanism than the catalogue: they are
        // the same question about the same groups, and answering it twice meant two records
        // that could disagree — this one keyed per *group*, and written when a request was
        // dispatched rather than when it was answered.
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

    /// Take one answer's worth of this peer's inbound budget, or refuse.
    fn spend(&mut self, peer: PeerId) -> bool {
        let left = self.budget.entry(peer).or_insert(ANSWERS_PER_TICK);
        if *left == 0 {
            return false;
        }
        *left -= 1;
        true
    }
}
