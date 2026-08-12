//! The file sync policy, as a state machine.
//!
//! Consumes [`FileEvent`]s and returns [`FileAction`]s. It never sees a `Swarm`, a connection,
//! or a request id — `ac-node`'s daemon translates in both directions and is the only code
//! that touches both worlds. That is what lets the whole of this file be tested against
//! in-memory stores with no socket, no tokio, and no timing.
//!
//! The shape is deliberately the same as `ac_groups::sync`, because the problems are the same
//! and having two different answers to them would be worse than either.
//!
//! # What decides what goes on the wire
//!
//! `ac_groups::store::Groups::shared_with` is the only thing that may name a group to a peer,
//! here exactly as there. That is why this machine holds a `Groups` handle it never writes:
//! the gate belongs inside the policy, where a test can reach it, rather than in the daemon
//! where it would be a rule someone could forget.
//!
//! A blob is served under three conditions, all of which must hold: the group is shared with
//! that peer, the row exists and is live, and we actually have the bytes. Failing any of them
//! is one indistinguishable refusal, because telling a stranger *why* would answer questions
//! they should not be able to ask.
//!
//! # Cursors, digests, and which one is in charge
//!
//! A catalogue is reconciled by reading the peer's own change log from where we left off, and
//! the digest is what says whether that worked. The cursor is an optimisation; the digest is
//! the correctness check. When they disagree the digest wins and the cursor is rebuilt from
//! zero — so a bug in the cursor logic costs a slow sync rather than a missing file.
//!
//! A cursor only ever advances to a position the peer itself reported. Never to a count, a
//! clock reading, or anything derived from our own state: a cursor past rows we never received
//! would skip them for good.
//!
//! # When syncing happens
//!
//! On connection, and when our own catalogue changes. **Not** periodically — the same
//! reasoning `ac_groups::sync` sets out at length.
//!
//! # This machine is catalogue-only
//!
//! Learning that a file exists and fetching its bytes are separate questions, and only the
//! first is answered here. **Deciding what to download belongs to `ac_peers::sync`**, which is
//! the only place that can decide it correctly: what to fetch, who to fetch it from, and
//! whether the connection it would arrive on is worth holding are one question asked at three
//! moments, and two implementations of it would drift.
//!
//! This machine used to own the fetching half, and the seam showed. It picked a holder by
//! taking the first verified member that shared the group — `have` is local and never travels,
//! so that was a guess — and it had no way to tell "this peer cannot give me this" from "the
//! circuit was cut", so a peer that could not help was asked again for ever.
//!
//! What is left here is everything about *what exists*: offers, changes, cursors, digests, the
//! merge rules, and serving both catalogue pages and blob authorization. `file_wants` is still
//! written by `ac file get` and still read — by `ac_peers::missing::next_missing`, where it now
//! means "fetch this next" rather than "fetch only this".

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use ac_groups::id::GroupId;
use ac_groups::store::Groups;
use ac_net::PeerId;

use crate::content::Content;
use crate::path::RelPath;
use crate::store::{FileRow, Files, Merged};
use crate::wire::{
    FileHead, MAX_ENTRIES_PER_RESPONSE, MAX_HEADS_PER_OFFER, MAX_HOLDINGS_QUERY, ManifestEntry,
    ManifestRequest, ManifestResponse,
};

/// How long a request may be outstanding before the episode is abandoned.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Requests we will *answer* from one peer between ticks.
///
/// Inbound only. Outbound work is bounded separately by [`MAX_INFLIGHT`] — sharing one counter
/// would let a chatty peer starve our own syncing, which is the opposite of what a rate limit
/// is for.
const ANSWERS_PER_TICK: u32 = 8;

/// Catalogue reads outstanding at once, across all peers and groups.
const MAX_INFLIGHT: usize = 8;

/// Something worth telling a person. A typed value rather than a string, so tests assert on
/// meaning and the daemon owns every word the user sees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    /// A group's catalogue grew or changed.
    Learned { group: GroupId, count: usize },
    /// Two different files wanted one name. Both were kept; one was renamed.
    Conflicted {
        group: GroupId,
        kept: RelPath,
        moved: RelPath,
    },
    /// The same content was held at two paths, and the later one gave way.
    Deduplicated {
        group: GroupId,
        kept: RelPath,
        dropped: RelPath,
    },
    /// A peer sent something that did not check out.
    Rejected { peer: PeerId, why: String },
    /// Something failed that is nobody's fault and needs no action.
    Trouble { why: String },
}

/// What the machine wants done. The daemon is the only thing that can do any of it.
#[derive(Debug, Clone, PartialEq)]
pub enum FileAction {
    Offer {
        peer: PeerId,
        heads: Vec<FileHead>,
    },
    FetchChanges {
        peer: PeerId,
        group: GroupId,
        after: u64,
    },
    /// One group's catalogue is reconciled with one peer, and there is nothing further to read
    /// from them about it.
    ///
    /// Not something the daemon *does* — it is the one fact this machine knows that the
    /// supervisor cannot work out for itself. `ac_peers::sync` counts a round as finished on
    /// this, which is what lets it record the digest it put on the wire, decide the peer is
    /// drained of news, and stop holding the connection open for it.
    ///
    /// Emitted per group rather than per exchange, because reconciliation finishes per group:
    /// an offer naming five may settle four of them at once and leave the fifth reading pages
    /// for another minute.
    Settled {
        peer: PeerId,
        group: GroupId,
    },
    Note(Notice),
}

/// Everything the machine reacts to.
#[derive(Debug, Clone)]
pub enum FileEvent {
    /// A peer completed mutual attestation *and* its connection settled — see the daemon.
    PeerVerified {
        peer: PeerId,
    },
    PeerGone {
        peer: PeerId,
    },
    /// Catalogues a peer named to us, from an offer they sent **as a response**.
    Offered {
        peer: PeerId,
        heads: Vec<FileHead>,
    },
    /// A page of a peer's change log.
    Changes {
        peer: PeerId,
        group: GroupId,
        after: u64,
        entries: Vec<ManifestEntry>,
        next: u64,
        more: bool,
        digest: [u8; 32],
    },
    Unavailable {
        peer: PeerId,
        group: GroupId,
    },
    RequestFailed {
        peer: PeerId,
        group: Option<GroupId>,
    },
    /// The only clock this machine has. `now` sweeps deadlines; `at` timestamps what we write.
    ///
    /// It also picks up changes *we* made — including from the CLI in another process — and
    /// clears stalled episodes. It never polls a peer.
    Tick {
        now: Instant,
        at: i64,
    },
}

/// Whether these stores say a peer may have this file's bytes, and how many.
///
/// Free-standing because a blob is served from a spawned task holding its *own* database
/// handles — nothing here is shared behind a lock — so the check cannot go through
/// [`FileSync`]. Keeping it in this module keeps the rule in one place: the group is shared
/// with them, the row is live, and we hold the content. `None` for all three, because saying
/// which failed would answer a question a stranger should not be able to ask.
///
/// Note what is *not* checked: attestation. A stream only exists on a connection that already
/// passed it, and the caller confirms the peer is one the daemon admitted.
pub fn may_serve(
    files: &Files,
    groups: &Groups,
    peer: &PeerId,
    group: GroupId,
    path: &RelPath,
) -> Option<u64> {
    let shared = groups.shared_with(peer).unwrap_or_default();
    if !shared.iter().any(|h| h.group == group) {
        return None;
    }
    let row = files.get(group, path).ok().flatten()?;
    (!row.is_removed() && row.have).then_some(row.size)
}

/// One outstanding catalogue read. Keyed by group, so there is one episode per group at a time.
#[derive(Debug, Clone)]
struct InFlight {
    peer: PeerId,
    after: u64,
    /// Set once a full re-read has already been tried this episode, so a peer that keeps
    /// disagreeing costs one extra round rather than an unbounded loop.
    retried: bool,
    deadline: Instant,
}

pub struct FileSync {
    files: Files,
    /// Never written. Held so `shared_with` — the one function allowed to name a group to a
    /// peer — is applied inside the policy rather than by the caller.
    groups: Groups,
    content: Content,
    /// The group directory names, resolved once each and then reused.
    dirs: HashMap<GroupId, String>,
    me: PeerId,
    verified: HashSet<PeerId>,
    inflight: HashMap<GroupId, InFlight>,
    budget: HashMap<PeerId, u32>,
    now_at: i64,
}

impl FileSync {
    pub fn new(files: Files, groups: Groups, content: Content) -> Self {
        let me = files.me();
        Self {
            files,
            groups,
            content,
            dirs: HashMap::new(),
            me,
            verified: HashSet::new(),
            inflight: HashMap::new(),
            budget: HashMap::new(),
            now_at: 0,
        }
    }

    pub fn files(&self) -> &Files {
        &self.files
    }

    /// Write access, for setting up a scenario in tests.
    ///
    /// Not how the daemon works: the CLI writes through its *own* handle in another process,
    /// and the machine notices on the next tick.
    pub fn files_mut(&mut self) -> &mut Files {
        &mut self.files
    }

    pub fn groups_mut(&mut self) -> &mut Groups {
        &mut self.groups
    }

    pub fn content(&self) -> &Content {
        &self.content
    }

    /// The directory a group's files live in, resolved once.
    pub fn dir_of(&mut self, group: GroupId) -> Option<String> {
        if let Some(dir) = self.dirs.get(&group) {
            return Some(dir.clone());
        }
        let name = self.groups.get(group).ok().flatten()?.name;
        let dir = self.files.dir_for(group, &name).ok()?;
        self.dirs.insert(group, dir.clone());
        Some(dir)
    }

    /// Answer an inbound request.
    ///
    /// Total: **exactly one response, always**. That is why [`FileAction`] has no `Respond`
    /// variant — the daemon holds the channel across this call and consumes it here, so a
    /// channel can never be stranded. Every refusal collapses into
    /// [`ManifestResponse::Unavailable`].
    pub fn on_request(
        &mut self,
        peer: PeerId,
        request: ManifestRequest,
    ) -> (ManifestResponse, Vec<FileAction>) {
        if !self.verified.contains(&peer) || !self.spend(peer) {
            return (ManifestResponse::Unavailable, Vec::new());
        }

        match request {
            ManifestRequest::Offer(theirs) => {
                // Ours is built first, from our own view. A store error yields an empty offer
                // rather than `Unavailable`, which would imply a group-specific refusal.
                let ours = self.heads_for(&peer);
                let actions = self.on_heads(peer, theirs);
                (ManifestResponse::Offer(ours), actions)
            }

            ManifestRequest::Changes { group, after } => {
                if !self.shares(&peer, group) {
                    return (ManifestResponse::Unavailable, Vec::new());
                }
                match self.page(group, after) {
                    Some(response) => (response, Vec::new()),
                    None => (ManifestResponse::Unavailable, Vec::new()),
                }
            }

            ManifestRequest::Holdings { group, paths } => {
                if !self.shares(&peer, group) {
                    return (ManifestResponse::Unavailable, Vec::new());
                }

                // One bit per path asked, in the order asked. A path we cannot parse, or have
                // never heard of, answers `false` — the same as not holding it, which is true.
                let held =
                    crate::wire::pack_holdings(paths.iter().take(MAX_HOLDINGS_QUERY).map(|raw| {
                        RelPath::parse(raw).is_ok_and(|path| {
                            self.files
                                .get(group, &path)
                                .ok()
                                .flatten()
                                .is_some_and(|row| row.have && !row.is_removed())
                        })
                    }));
                (ManifestResponse::Holdings { group, held }, Vec::new())
            }
        }
    }

    /// Whether we would serve this peer this file's bytes.
    ///
    /// Three conditions, and which one failed is never disclosed: the group is shared with
    /// them, the row is live, and we hold the content. Returns the size so the daemon can
    /// announce it before streaming.
    pub fn may_serve(&mut self, peer: PeerId, group: GroupId, path: &RelPath) -> Option<u64> {
        if !self.verified.contains(&peer) {
            return None;
        }
        may_serve(&self.files, &self.groups, &peer, group, path)
    }

    pub fn on(&mut self, event: FileEvent) -> Vec<FileAction> {
        match event {
            FileEvent::PeerVerified { peer } => {
                // Noted, not acted on. The supervisor decides when to talk to a peer — including
                // the moment one arrives, where its record for them is empty and therefore
                // stale. Offering from here as well meant every fresh connection carried a
                // duplicate of the request it was about to send.
                self.verified.insert(peer);
                Vec::new()
            }

            FileEvent::PeerGone { peer } => {
                self.verified.remove(&peer);
                self.budget.remove(&peer);
                self.inflight.retain(|_, f| f.peer != peer);
                Vec::new()
            }

            // An offer *response*. Provokes reads only — answering an offer with an offer
            // would have two peers volleying for ever.
            FileEvent::Offered { peer, heads } => {
                if !self.verified.contains(&peer) {
                    return Vec::new();
                }
                self.on_heads(peer, heads)
            }

            FileEvent::Changes {
                peer,
                group,
                after,
                entries,
                next,
                more,
                digest,
            } => self.on_changes(peer, group, after, entries, next, more, digest),

            // A refusal ends the round as surely as agreement does, and has to say so.
            //
            // Clearing the busy flag is not enough: the supervisor counts a round as running
            // until something reports it settled, and a reading refused part-way through
            // reported nothing at all. Two of those — a member who has not accepted the group
            // yet answers exactly this way — filled `MAX_CATALOGUE_ROUNDS` with rounds that
            // could never end, and the node stopped gossiping entirely while looking idle.
            FileEvent::Unavailable { peer, group } => {
                self.finish(group, peer);
                vec![FileAction::Settled { peer, group }]
            }

            FileEvent::RequestFailed { peer, group } => {
                let Some(group) = group else {
                    return Vec::new();
                };
                self.finish(group, peer);
                vec![FileAction::Settled { peer, group }]
            }

            FileEvent::Tick { now, at } => self.tick(now, at),
        }
    }

    // ---- inbound ----

    fn on_heads(&mut self, peer: PeerId, heads: Vec<FileHead>) -> Vec<FileAction> {
        let mut actions = Vec::new();

        for head in heads.into_iter().take(MAX_HEADS_PER_OFFER) {
            // Only groups we agree we share. A peer naming a group we do not share with them
            // learns nothing by it.
            if !self.shares(&peer, head.group) {
                continue;
            }
            let ours = self.files.digest(head.group).unwrap_or([0u8; 32]);
            let started = ours != head.digest && {
                let after = self.files.cursor(head.group, &peer).unwrap_or(0);
                self.read(&mut actions, peer, head.group, after, false)
            };

            // Nothing was asked, either because we already agree — the *common* case under
            // auto-mirror, and the one that transfers nothing — or because another episode
            // already owns this group. Both mean there is nothing further to read from them
            // right now, and saying so is what lets the round be counted as finished.
            if !started {
                actions.push(FileAction::Settled {
                    peer,
                    group: head.group,
                });
            }
        }
        actions
    }

    #[allow(clippy::too_many_arguments)]
    fn on_changes(
        &mut self,
        peer: PeerId,
        group: GroupId,
        after: u64,
        entries: Vec<ManifestEntry>,
        next: u64,
        more: bool,
        digest: [u8; 32],
    ) -> Vec<FileAction> {
        // Late, duplicated or unsolicited responses are dropped: only the request we are
        // actually waiting on may move our cursor.
        let expected = matches!(
            self.inflight.get(&group),
            Some(f) if f.peer == peer && f.after == after
        );
        if !expected {
            return Vec::new();
        }
        let retried = self.inflight.get(&group).is_some_and(|f| f.retried);
        self.inflight.remove(&group);

        let Some(dir) = self.dir_of(group) else {
            return vec![FileAction::Note(Notice::Trouble {
                why: format!("no directory for group {}", group.short()),
            })];
        };

        let mut actions = Vec::new();
        let mut applied = 0usize;

        for entry in entries.into_iter().take(MAX_ENTRIES_PER_RESPONSE) {
            let Some(row) = entry.into_row() else {
                // A path that will not parse, or a peer id that will not. Refused at the edge
                // rather than stored and dealt with later.
                actions.push(FileAction::Note(Notice::Rejected {
                    peer,
                    why: "a catalogue entry was unusable".to_owned(),
                }));
                continue;
            };

            match self.files.merge(group, &row, &self.content, &dir) {
                Ok(Merged::Unchanged | Merged::Rejected) => {}
                Ok(Merged::Applied) => applied += 1,
                Ok(Merged::Conflicted { moved }) => {
                    applied += 1;
                    actions.push(FileAction::Note(Notice::Conflicted {
                        group,
                        kept: row.path.clone(),
                        moved,
                    }));
                }
                Ok(Merged::Deduplicated { kept, dropped }) => {
                    applied += 1;
                    actions.push(FileAction::Note(Notice::Deduplicated {
                        group,
                        kept,
                        dropped,
                    }));
                }
                Err(e) => actions.push(FileAction::Note(Notice::Trouble { why: e.to_string() })),
            }
        }

        // The cursor moves only to a position the peer reported.
        if let Err(e) = self.files.set_cursor(group, &peer, next) {
            actions.push(FileAction::Note(Notice::Trouble { why: e.to_string() }));
        }

        if applied > 0 {
            actions.push(FileAction::Note(Notice::Learned {
                group,
                count: applied,
            }));
        }

        if more && self.read(&mut actions, peer, group, next, retried) {
            return actions;
        }

        // Drained. The digest is what says whether the cursor told the truth.
        let ours = self.files.digest(group).unwrap_or([0u8; 32]);
        if ours != digest && !retried {
            // Rebuild from the beginning rather than trusting a cursor that evidently skipped
            // something. Once per episode, so a peer changing under us costs one extra round.
            let _ = self.files.set_cursor(group, &peer, 0);
            if self.read(&mut actions, peer, group, 0, true) {
                return actions;
            }
        }

        // Nothing further to read from them about this group — whether because we agree, or
        // because we have already re-read once and still do not. The second case is a peer
        // changing under us rather than a round left hanging, and reporting it as settled is
        // what stops the supervisor holding a connection open waiting for news that has
        // already arrived.
        actions.push(FileAction::Settled { peer, group });
        actions
    }

    /// One page of our own log, plus where we stand.
    fn page(&mut self, group: GroupId, after: u64) -> Option<ManifestResponse> {
        let (rows, next) = self
            .files
            .changes_since(group, after, MAX_ENTRIES_PER_RESPONSE)
            .ok()?;
        let more = self.files.has_changes_after(group, next).unwrap_or(false);
        let digest = self.files.digest(group).ok()?;

        Some(ManifestResponse::Changes {
            group,
            entries: rows.iter().filter_map(ManifestEntry::of).collect(),
            next,
            more,
            digest,
        })
    }

    // ---- outbound ----

    /// Ask a peer for the next page of one group, unless that group is already busy.
    ///
    /// Answers whether anything was asked. **The `false` case has to be handled by every
    /// caller**, or a round hangs: an exchange that neither reads nor settles leaves the
    /// supervisor above counting a round that will never finish, so the peer never looks
    /// drained and its connection is held open for ever. That happened with two rounds in
    /// flight for one group — perfectly ordinary at `MAX_CATALOGUE_ROUNDS = 2` — where the
    /// second found the group busy and returned in silence.
    fn read(
        &mut self,
        actions: &mut Vec<FileAction>,
        peer: PeerId,
        group: GroupId,
        after: u64,
        retried: bool,
    ) -> bool {
        if self.inflight.contains_key(&group) || self.inflight.len() >= MAX_INFLIGHT {
            return false;
        }
        self.inflight.insert(
            group,
            InFlight {
                peer,
                after,
                retried,
                deadline: Instant::now() + REQUEST_TIMEOUT,
            },
        );
        actions.push(FileAction::FetchChanges { peer, group, after });
        true
    }

    fn tick(&mut self, now: Instant, at: i64) -> Vec<FileAction> {
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

        // **Nothing is offered from here.** Deciding when to talk to a peer belongs to the
        // supervisor, which knows who is online, what the relay will allow, and whether a peer
        // has just refused to discuss a group — none of which this layer can see.
        //
        // There used to be a loop here that offered whenever our digest or our view of who
        // shares a group had moved, keyed per pair. It was right about *what* to track and it
        // is the reason the supervisor tracks the same thing; but with both of them offering,
        // one record was written when a request was dispatched and the other when an exchange
        // reconciled, and neither was authoritative. Every fresh connection cost a duplicate
        // request, and a peer that declined an offer stayed recorded here as having received
        // it, with nothing to correct that until the catalogue happened to move.
        Vec::new()
    }

    /// What we would name to this peer: the catalogues of the groups we share with them.
    ///
    /// The only shape an offer comes in. A single-group form used to exist for the supervisor,
    /// which counted rounds per group and so needed a request that named exactly one — but it
    /// was answered with every shared group regardless, so the supervisor counted one and
    /// silently received the rest. Naming them all is both cheaper and honest.
    pub fn heads_for(&mut self, peer: &PeerId) -> Vec<FileHead> {
        let shared = self.groups.shared_with(peer).unwrap_or_default();
        shared
            .into_iter()
            .take(MAX_HEADS_PER_OFFER)
            .filter_map(|head| {
                Some(FileHead {
                    group: head.group,
                    digest: self.files.digest(head.group).ok()?,
                    count: self.files.count(head.group).unwrap_or(0),
                })
            })
            .collect()
    }

    /// Whether `shared_with` names this group for this peer — the one gate.
    fn shares(&self, peer: &PeerId, group: GroupId) -> bool {
        self.groups
            .shared_with(peer)
            .unwrap_or_default()
            .iter()
            .any(|h| h.group == group)
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

    /// A row we hold, for the daemon to check a finished transfer against.
    pub fn row(&self, group: GroupId, path: &RelPath) -> Option<FileRow> {
        self.files.get(group, path).ok().flatten()
    }

    pub fn me(&self) -> PeerId {
        self.me
    }

    pub fn now_at(&self) -> i64 {
        self.now_at
    }
}
