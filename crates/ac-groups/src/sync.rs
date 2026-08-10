//! The sync policy, as a state machine.
//!
//! Consumes [`GroupEvent`]s and returns [`GroupAction`]s. It never sees a `Swarm`, a
//! connection, or a request id — `ac-node`'s daemon translates in both directions and is the
//! only code that touches both worlds. That is what lets the whole of this file be tested
//! against an in-memory store with no socket, no tokio, and no timing.
//!
//! # The two rules that decide what goes on the wire
//!
//! **Offering.** [`crate::store::Groups::shared_with`] is the only thing that may build a
//! [`GroupHead`] bound for a peer. Nothing here constructs one any other way.
//!
//! **Fetching.** We may ask a peer for a group only if either
//!
//! 1. they named it to us in an offer, or
//! 2. we hold it and *our own* copy of its chain names them as a member.
//!
//! Rule 2 is what lets a node that has been removed, or that has left, still find out where it
//! stands: nobody will offer them the group, so they have to ask. It discloses nothing —
//! the peer being asked already knows they were in it, because their own chain says so.
//!
//! # When syncing happens
//!
//! On connection, and when our own log changes. **Not** periodically.
//!
//! A change made *during* a connection therefore reaches the other side at the next one. That
//! is deliberate. Enforcement is local and immediate — a node stops serving the moment it
//! removes someone, and stops participating the moment it leaves, both from its own state with
//! nothing in flight. What propagation affects is when the two sides agree on the *story*:
//! whose name shows up in `ac group show`, and when the admin gets round to ratifying a
//! departure. Paying a message a minute on every idle connection to keep a display fact fresh
//! is a poor trade, and an earlier draft made it.
//!
//! The on-connect exchange covers everything that accumulated while apart, in both directions:
//! a member added, a member removed (served their own chain up to the entry that removed them,
//! which is proof and nothing more), a departure to collect, and a standings digest that
//! drifted with no chain change to hang off.
//!
//! # No chunking
//!
//! One `Fetch` is answered by one response carrying everything the responder will give. If a
//! response does not advance our head the episode simply ends; there is no progress flag to
//! police and so nothing for a peer to lie about.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use ac_net::PeerId;
use libp2p::identity::Keypair;

use crate::chain::Op;
use crate::id::GroupId;
use crate::store::{Applied, GroupRow, Groups, State, StoreError};
use crate::wire::{GroupHead, GroupRequest, GroupResponse, MAX_HEADS_PER_OFFER};

/// How long a fetch may be outstanding before the episode is abandoned.
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Requests we will *answer* from one peer between ticks.
///
/// Inbound only. Outbound work is bounded separately by [`MAX_INFLIGHT`] — sharing one
/// counter would let a chatty peer starve our own syncing, which is the opposite of what a
/// rate limit is for.
const ANSWERS_PER_TICK: u32 = 8;

/// Fetches we will have outstanding at once, across all peers and groups.
///
/// One episode per group already caps the common case; this caps the pathological one, where
/// a peer offers hundreds of groups we have never heard of and we would otherwise chase every
/// one at once.
const MAX_INFLIGHT: usize = 8;

/// How long a group we were invited to but never accepted is kept once the chain has stopped
/// naming us. Long enough that a slow human is not punished for it.
const PENDING_TTL: i64 = 30 * 24 * 3600;

/// Something worth telling a person. A typed value rather than a string, so tests assert on
/// meaning and the daemon owns every word the user sees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    /// We have been added to a group we had not seen. Needs `ac group accept`.
    Invited { group: GroupId, name: String },
    /// The admin removed us. Learned by asking, since nobody offers a group to a non-member.
    RemovedByAdmin { group: GroupId, name: String },
    MembershipChanged {
        group: GroupId,
        added: usize,
        removed: usize,
    },
    /// A member told us they have left. On the admin's node this is followed by `Ratified`.
    Departed { group: GroupId, peer: PeerId },
    /// We are the admin and have written the `Remove` that makes a departure official.
    Ratified { group: GroupId, peer: PeerId },
    /// Two entries claim one position. The group is now inert and needs a human.
    Forked { group: GroupId, seq: u64 },
    /// A peer sent something that did not check out.
    Rejected {
        group: GroupId,
        peer: PeerId,
        why: String,
    },
    /// Something failed that is nobody's fault and needs no action.
    Trouble { why: String },
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
    /// What we last told peers about each group, so a change made by `ac group add` in another
    /// process is noticed on the next tick. SQLite is the only channel between them.
    announced: HashMap<GroupId, (u64, [u8; 32])>,
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
            announced: HashMap::new(),
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
                let ours = self.store.shared_with(&peer).unwrap_or_default();
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
                self.verified.insert(peer);
                let heads = self.store.shared_with(&peer).unwrap_or_default();
                self.offer(peer, heads)
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
                Ok(Some(row)) if row.is_quarantined() => {}
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
            .filter(|row| !row.is_quarantined() && !named.contains(&row.id))
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
            Err(StoreError::Fork { seq, .. }) => {
                actions.push(GroupAction::Note(Notice::Forked { group, seq }));
                return actions;
            }
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
        self.ratify(&mut actions, group, &applied, at);

        // Anything new is worth passing on, but never back to whoever just told us.
        if applied.accepted > 0 {
            let onward = self.announce(group);
            actions.extend(onward.into_iter().filter(|a| !targets(a, peer)));
        }
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

    /// If we admin this group, make a departure official.
    ///
    /// A departure is only ever a signal: it says what a member wants, and a `Remove` is what
    /// makes every other member agree. Guarded on the peer still being in the fold, so
    /// re-ingesting the same standing — from a restart, a re-offer, or a digest repair —
    /// writes exactly one `Remove` per departure rather than one per delivery.
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

        let mut actions = Vec::new();

        // Pick up whatever the CLI did in another process. Both the head and the standings
        // digest matter: `ac group add` moves the first, `ac group leave` only the second.
        let rows = self.store.list().unwrap_or_default();
        for row in &rows {
            let current = (row.head_seq, row.standings_digest);
            if self.announced.get(&row.id) != Some(&current) {
                self.announced.insert(row.id, current);
                actions.extend(self.announce(row.id));
            }
        }

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

    /// Tell every verified peer that shares this group about our new head.
    fn announce(&mut self, group: GroupId) -> Vec<GroupAction> {
        let peers: Vec<PeerId> = self.verified.iter().copied().collect();
        let mut actions = Vec::new();

        for peer in peers {
            let heads = self.store.shared_with(&peer).unwrap_or_default();
            if heads.iter().any(|h| h.group == group) {
                actions.extend(self.offer(peer, heads));
            }
        }
        actions
    }

    fn offer(&mut self, peer: PeerId, heads: Vec<GroupHead>) -> Vec<GroupAction> {
        vec![GroupAction::Offer { peer, heads }]
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

/// Whether an action is aimed at a particular peer.
fn targets(action: &GroupAction, peer: PeerId) -> bool {
    match action {
        GroupAction::Offer { peer: p, .. } | GroupAction::Fetch { peer: p, .. } => *p == peer,
        GroupAction::Note(_) => false,
    }
}
