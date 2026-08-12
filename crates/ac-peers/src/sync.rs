//! The supervisor, as a state machine.
//!
//! Consumes [`PeerEvent`]s and returns [`PeerAction`]s. It never sees a `Swarm`, an address, or
//! a request id — `ac-node` translates in both directions — which is what lets a fifty-member
//! group, a peer that never answers, or a four-hour heartbeat be set up in a test in
//! microseconds.
//!
//! # Two loops, both over groups
//!
//! A **catalogue round** is kilobytes and matters for correctness. A **content pull** is
//! gigabytes and saturates a link. They get separate budgets so a long download in one group
//! can never delay the small exchange that tells another group a file was deleted.
//!
//! Both iterate groups. A peer appears only as the means of resolving a group's need, which is
//! what keeps dials proportional to how many groups this node is in rather than to how many
//! people are in them.
//!
//! # The clock is wall time, and it is an input
//!
//! Everything here is scheduled on `at` — unix seconds, arriving on [`PeerEvent::Tick`]. No
//! `Instant`, unlike the layers below, because every interval here is minutes to hours and a
//! single clock is easier to reason about than two. A backwards clock jump postpones work; a
//! forward one does a burst early. Both recover, and neither can lose anything.

use std::collections::{HashMap, HashSet, VecDeque};

use ac_files::path::RelPath;
use ac_files::store::Files;
use ac_groups::id::GroupId;
use ac_groups::store::{Groups, State};
use ac_net::PeerId;

use crate::missing::{PeersError, next_missing};

// A change is told to **every member who has not heard it**, and there is deliberately no
// fanout constant rationing that.
//
// An epidemic was the right answer to a budget of two circuits a minute: telling everyone was
// unaffordable, so each node told three and relied on them to pass it on. The budget was the
// problem. A circuit was priced for bulk transfer, so a two-hundred-byte offer cost what 64 MiB
// cost, and the client had to ration accordingly. With the relay's unit resized — same bandwidth
// ceiling, sixteen circuits a minute instead of two — telling everyone is simply affordable, and
// one hop beats several: fewer messages in total, no dependence on intermediaries staying up,
// and nothing to reason about regarding who has already been told on our behalf.
//
// What remains bounded is bounded by things that already existed: `MAX_PEER_CONNECTIONS`,
// `DIALS_PER_WINDOW`, and the fact that a member already connected costs no circuit at all.
// Members who are offline are not chased; they catch up by offering to everyone they meet when
// they return, since nothing about a round is remembered across a restart.

/// How long a group may go with nothing exchanged before it is worth a round on its own.
///
/// The only timer that provokes a dial, and it exists for one case: a peer that can accept our
/// dial but whose own never land, whose removals would otherwise never reach us. Everything
/// else is covered by an exact signal, so this is hours.
pub const HEARTBEAT: i64 = 4 * 3600;

/// How often to ask the server who is actually online.
///
/// Matched to `ServerLink`'s discovery interval: presence is no more useful than discovery is
/// fresh, and asking more often would only sharpen an answer nothing else can keep up with.
///
/// The answer now has exactly one consumer — choosing which member to pull content through. The
/// catalogue loop dials what it owes news to without consulting it, which is what let the
/// urgent, off-interval re-ask go: every question that existed to answer promptly is now
/// answered by dialling instead of by asking.
pub const PRESENCE_INTERVAL: i64 = 300;

/// Per-peer dial backoff.
///
/// Far more patient than `ServerLink`'s 1s–60s. That is one server this node depends on; these
/// are many peers who are usually asleep, and each attempt spends one of the two relay circuits
/// a client is allowed per minute.
pub const MIN_BACKOFF: i64 = 30;
pub const MAX_BACKOFF: i64 = 30 * 60;

/// Dials to one member before they are taken off the lists they are on.
///
/// The whole of what replaces asking the registry before calling. Three attempts, paced by
/// [`MIN_BACKOFF`] doubling — 0s, 30s, 90s on the clock the backoff runs on, and about two
/// minutes end to end, since a dial takes time to fail as well as time to be allowed.
///
/// Both halves matter. Dropping a member on the *first* failure is the same mistake as never
/// calling them: a node that is restarting, reconnecting to the relay, or missing from a
/// five-minute-old presence answer is unreachable for a few seconds and has done nothing to
/// deserve being written off until the next thing we happen to change. Never dropping them is
/// the other failure — a member who is switched off would keep a group looking as though it had
/// something outstanding for ever, and keep spending circuits to prove it.
///
/// Three failures is not a judgement about the peer and nothing persists it: the backoff carries
/// what was learned, and the next thing we have to say puts them back on the list.
pub const DIAL_ATTEMPTS: usize = 3;

/// After a full rotation in which no member could help.
///
/// Not an optimisation — the thing that stops a permanent dial loop. Wanting a file no online
/// member holds is the *normal* state of a mirror, and without this a node rotates the member
/// list for ever, spending a circuit each time.
pub const MIN_CONTENT_BACKOFF: i64 = 30;
pub const MAX_CONTENT_BACKOFF: i64 = 30 * 60;

// There is deliberately no cap on concurrent catalogue offers. An offer is one small
// request/response that transfers nothing at all when the digests agree, and the number that can
// be outstanding is already bounded twice: by `MAX_PEER_CONNECTIONS`, and beneath that by the
// relay allowance. A separate limit of two bought nothing and cost a
// great deal — being a *held* resource rather than a deadline, any exchange that ended without
// saying so took a slot for good, and two of those stopped the node gossiping while it reported
// itself idle. What bounds propagation now is `MAX_PEER_CONNECTIONS` and the dial allowance,
// both of which bound the thing that is actually scarce.

/// Changes to a group's catalogue that will be shared without waiting for a pause.
///
/// The other half of [`SHARE_AFTER_IDLE`]: a safety valve so a long unbroken stream of edits
/// cannot sit unshared indefinitely.
pub const SHARE_AFTER_CHANGES: u64 = 1000;

/// How long a group's catalogue must be still before it is shared.
///
/// Editing arrives in sessions, not in single events. Sorting photographs by hand is one every
/// twenty seconds for half an hour, and telling everybody after each one means dialling the
/// whole group ninety times to deliver what is really one afternoon's work — at two minutes of
/// quiet, it is one round instead.
///
/// **Membership is not delayed by this.** A chain or standings change is shared at once: it is
/// rare, it is small, and it is the precondition for a catalogue reaching anybody, so making a
/// newly added member wait out an editing session would be the one delay that matters.
pub const SHARE_AFTER_IDLE: i64 = 120;

/// Transfers running at once, across every peer and group.
///
/// A depth, not a ceiling to be issued up to and forgotten. A holdings answer may name hundreds
/// of files a peer holds, and firing all of them at once does not download them faster — the
/// blob layer starts eight and refuses the rest, so the surplus was counted as running by a
/// supervisor that then waited for outcomes which could never arrive. That left the group with a
/// source it could not release, one of two content slots held for good, and a connection open
/// with nothing on it.
///
/// So the offer is kept as a queue and drained by completions: one finishes, the next starts,
/// and the number in flight is the number of tasks that actually exist. Matched to
/// `blob::MAX_CONCURRENT`, which remains as a backstop that now refuses out loud.
pub const MAX_TRANSFERS: usize = 8;

/// Concurrent content pulls overall, and **at most one per group**.
///
/// Both halves are needed. Without the per-group cap a group of ten thousand files takes every
/// slot and holds them for hours, and a group of ten never pulls anything at all.
pub const MAX_CONTENT_PEERS: usize = 2;

/// Connections to hold at once.
///
/// Well under `ac_net::limits::MAX_ESTABLISHED_TOTAL`, and mindful that a relayed dial spends
/// one of the relay's sixteen server-wide circuits.
pub const MAX_PEER_CONNECTIONS: usize = 16;

/// How long a close proposal may go unanswered before it is forgotten.
pub const CLOSE_TIMEOUT: i64 = 30;

/// Circuits this node may open in [`DIAL_WINDOW`], matching what the relay actually allows.
///
/// Mirrors the server's `CIRCUITS_PER_PEER_PER_WINDOW`, and pacing to it is not politeness —
/// it is the difference between choosing who to call and having the choice made for us. Dials
/// beyond the allowance are refused by the relay with "resource limit exceeded", and that
/// refusal charges the *peer's* backoff for a fault entirely our own: the member is then not
/// retried for thirty seconds, then a minute, while remaining perfectly reachable.
///
/// The lab showed the cost exactly. A node spent both of its circuits in one tick — one on a
/// member that had been stopped, one on a member that held nothing — and its two dials to the
/// only peer with the file it wanted were both refused. It then reported the file unobtainable
/// having never once asked the node holding it.
pub const DIALS_PER_WINDOW: usize = 16;

/// The window [`DIALS_PER_WINDOW`] is measured over. Matches the server's, deliberately.
pub const DIAL_WINDOW: i64 = 60;

/// How long an offer may be outstanding before it is written off.
///
/// With no global cap left, this no longer guards a scarce slot — it guards the *peer*. A peer
/// may have one offer in flight, and until it ends that peer is neither offered to again nor
/// counted as drained, so an exchange that finishes without saying so would hold one member out
/// of the rotation and one connection open indefinitely. Expiry is the only ending that cannot
/// be forgotten, which is why it exists at all: the paths that report an ending have been wrong
/// twice already, and there is no reason to think a future one cannot be.
///
/// Generous, because a legitimate exchange may read several pages of catalogue over a relay.
pub const ROUND_TIMEOUT: i64 = 60;

/// Free space this node will not eat into, whatever the configured budget says.
///
/// This protects the **machine**, not the archive. A mirror that takes the last gigabyte of
/// someone's root disk breaks everything else running on it, and a person who set no budget
/// has not agreed to that. Two gigabytes is enough for a desktop to keep functioning while
/// somebody notices and does something about it.
pub const MIN_FREE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// What the node is allowed to fill.
///
/// Two limits doing different jobs: [`MIN_FREE_BYTES`] protects the machine and is not
/// negotiable, `storage_max` honours what the user actually asked for and may be absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Free bytes to leave on the volume holding the storage root.
    pub min_free: u64,
    /// Stop mirroring once this node holds this much. `None` means no ceiling beyond the floor.
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

/// Something worth telling a person. Typed, so tests assert on meaning and `ac-node` owns the
/// wording.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    /// A file finished transferring and its content matched what was asked for.
    ///
    /// Lives here rather than in `ac_files::sync` because that machine no longer knows a
    /// transfer happened: it is catalogue-only, and `have` changing is not a catalogue change.
    Downloaded { group: GroupId, path: RelPath },
    /// Wanted, and no reachable member has it. Distinguishes "nobody can supply this" from
    /// "still downloading", which otherwise look identical from the outside.
    Unobtainable { group: GroupId, path: RelPath },
    /// A peer claimed a file in its holdings and could not deliver it.
    Undelivered {
        peer: PeerId,
        group: GroupId,
        path: RelPath,
    },
    /// A peer sent bytes that did not match the hash asked for. Misbehaviour, not misfortune.
    Rejected { peer: PeerId, why: String },
    /// There is no room for more content, so mirroring has stopped.
    ///
    /// Emitted once per transition rather than per refused file: a node at its ceiling refuses
    /// every fetch it considers, and saying so each time would bury everything else.
    OutOfSpace {
        held: u64,
        /// What stopped it — the configured budget, or the free-space floor.
        limit: u64,
        floor: bool,
    },
    /// Nobody's fault and nothing to do.
    Trouble { why: String },
}

/// What the machine wants done. `ac-node` is the only thing that can do any of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerAction {
    /// Reach this peer. *How* is the daemon's business: a cached direct address if it has one,
    /// otherwise a circuit through the server.
    Dial {
        peer: PeerId,
    },
    /// Ask the server which of these are connected right now.
    AskPresence {
        peers: Vec<PeerId>,
    },
    /// Exchange catalogues with this peer, for **every group we share with them**.
    ///
    /// Peer-shaped because the message is: an offer names every shared group, and the answer
    /// does too, so a request about one group and a request about all of them cost exactly the
    /// same. The earlier single-group variant named one and was answered with all of them
    /// anyway — the only difference was that the supervisor counted one group and quietly
    /// received the rest, which is where its accounting drifted from what the wire did.
    ///
    /// A node is expected to be in a few groups and unlikely to exceed twenty, so an offer
    /// never approaches `MAX_HEADS_PER_OFFER` and there is no case where naming one group is
    /// the only way to be sure it is named.
    Offer {
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
    Note(Notice),
}

/// Everything the machine reacts to.
#[derive(Debug, Clone)]
pub enum PeerEvent {
    /// Seen on the network. A liveness hint that complements presence — mDNS in particular
    /// means "reachable on this LAN right now", which the server cannot know.
    Discovered {
        peer: PeerId,
    },
    /// The server's answer to [`PeerAction::AskPresence`].
    ///
    /// Carries **what was asked** as well as what came back, because the answer is a filter
    /// and says nothing whatever about anyone else. The daemon has the asked set already — it
    /// correlated the reply — so this costs nothing and makes the event self-describing rather
    /// than dependent on which query is outstanding.
    Presence {
        asked: Vec<PeerId>,
        online: Vec<PeerId>,
    },
    /// Attested *and* settled — the daemon holds a peer until its connection stops changing
    /// shape, so this is later than "connected".
    Verified {
        peer: PeerId,
    },
    Gone {
        peer: PeerId,
    },
    DialFailed {
        peer: PeerId,
    },
    /// An exchange for this group finished with this peer, on the named protocol.
    ///
    /// Reported for exchanges *they* started as well as ours. Both carry our heads — theirs in
    /// the answer we sent — so either way they have seen where we are, and recording it stops
    /// us telling somebody what they have just told us.
    Synced {
        peer: PeerId,
        group: GroupId,
        offering: Offering,
    },
    /// A peer left this group out of its answer. See `PeerState::declined`.
    Declined {
        peer: PeerId,
        group: GroupId,
    },
    /// The offer was never sent, because the group layer was still talking to this peer.
    ///
    /// Not a failure and not a refusal: nothing went out, so nothing is recorded either way and
    /// the ordinary loop tries again on the next tick.
    OfferDeferred {
        peer: PeerId,
    },
    /// An offer failed outright, so the slot is free but nothing was learned.
    ///
    /// Peer-shaped like the offer itself: a request that never arrived, or was answered with a
    /// refusal, failed for every group it named at once. There is no such thing as one group of
    /// an offer failing.
    OfferFailed {
        peer: PeerId,
    },
    /// Their answer to a holdings query, in the order asked.
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
    /// A transfer failed. `terminal` separates "this peer cannot give me this" from "the
    /// connection broke" — see [`Peers::on`].
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
    /// What the disk looks like now, reported by the daemon before each tick.
    ///
    /// An input rather than something read here, for the same reason the clock is: `statvfs`
    /// needs a filesystem, and a policy that called it could not be driven through a full disk
    /// from a test.
    Space {
        /// Free bytes on the volume holding the storage root.
        free: u64,
        /// Bytes of content this node holds, across every group.
        held: u64,
    },
    /// The only clock. Unix seconds.
    Tick {
        at: i64,
    },
}

/// What the supervisor is waiting on, for somebody to read.
///
/// The first question anyone asks about a component like this is *why is it not doing
/// anything*, and until this existed nothing could answer it: every reason lives in memory in
/// the running daemon — a backoff that has not expired, a member believed offline, a content
/// pull suspended after a fruitless rotation — and none of it is derivable from the database.
///
/// Read-only, and nothing acts on it. Taking a snapshot must not advance the rotation or spend
/// a budget, so [`Peers::status`] takes `&self` and reports where the rotation stands rather
/// than asking it to move.
#[derive(Debug, Clone)]
pub struct Status {
    pub groups: Vec<GroupStatus>,
    pub peers: Vec<PeerStatus>,
}

#[derive(Debug, Clone)]
pub struct GroupStatus {
    pub group: GroupId,
    /// Live rows we do not hold.
    pub missing: u64,
    /// Members who have not been told the current news. Zero means everyone has it.
    pub unheard: usize,
    /// The member whose turn it is, if the rotation has anywhere to go.
    pub next: Option<PeerId>,
    /// The member this group's files are currently being pulled through.
    pub source: Option<PeerId>,
    /// Content pulling for this group is suspended until here, after a rotation in which no
    /// member could help. Unix seconds; zero means not suspended.
    pub content_until: i64,
    /// When this group next owes a round on the timer alone. Unix seconds.
    pub heartbeat_at: i64,
}

#[derive(Debug, Clone)]
pub struct PeerStatus {
    pub peer: PeerId,
    /// Verified *and* settled — not merely connected.
    pub connected: bool,
    /// Believed reachable, from the last presence answer or from discovery since.
    pub online: bool,
    /// Not worth dialling before here. Unix seconds; zero means dialable now.
    pub retry_at: i64,
    pub rounds: usize,
    pub transfers: usize,
    /// A close proposal is outstanding with them.
    pub closing: bool,
}

/// What a group is waiting on, and where its rotation has got to.
#[derive(Debug)]
struct GroupState {
    /// Counter, head and standings as of our last completed round.
    sent: Snapshot,
    /// When the heartbeat is next due. Absolute, and already jittered.
    heartbeat_at: i64,
    /// Cursor into the member list.
    rotation: usize,
    /// The member we are currently pulling this group's files through.
    source: Option<PeerId>,
    /// Members that had nothing we needed, this rotation.
    spent: HashSet<PeerId>,
    /// Set while the whole rotation has been tried and none of it helped.
    content_until: i64,
    content_backoff: i64,
}

impl GroupState {
    fn new(at: i64, jitter: i64) -> Self {
        Self {
            // Zeroed, so a group nothing is known about reports news on the first tick. That
            // is what makes a node returning after a week sync at once, despite an unchanged
            // catalogue and nothing missing that it knows of.
            sent: Snapshot::default(),
            heartbeat_at: at + jitter,
            rotation: 0,
            source: None,
            spent: HashSet::new(),
            content_until: 0,
            content_backoff: MIN_CONTENT_BACKOFF,
        }
    }
}

/// Which of the two catalogues an offer is about.
///
/// The membership chain and the file catalogue spread by the same mechanism and are decided by
/// the same record — but they are two protocols and two messages, and the chain must go first:
/// a peer cannot be offered a catalogue for a group it does not yet know it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offering {
    /// `/ac/group/…` — who is in the group.
    Chain,
    /// `/ac/manifest/…` — what files are in it.
    Catalogue,
}

/// What a peer has yet to be told about one group.
///
/// Both may be owed at once — a new member is owed the chain and everything in it — and the
/// chain is always sent first, since a catalogue cannot be offered to somebody the group does
/// not yet say is a member.
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
///
/// Not a record of who holds what — that is `pending`, and it is a work list rather than a
/// comparison. This is only used to notice that something moved, and to tell apart which of the
/// three things moved, since membership and contents travel on different protocols.
///
/// **The catalogue is a counter here, not a digest.** Every comparison made with this is against
/// another value of our own, so what is needed is "did it move", and `Files::seq` answers that
/// with an index seek where the digest answered it by hashing every row in the group — twice a
/// tick, per group. The digest remains the only thing that may be compared with a *peer*: two
/// nodes holding identical catalogues agree on it and disagree on their counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Snapshot {
    seq: u64,
    head: u64,
    standings: [u8; 32],
}

/// An offer we asked for: what it carried, per group, and when it went out.
///
/// One entry per peer rather than per group, because one request is what went out. Groups drop
/// out of `carried` as they settle, and the entry is done when it empties — or when the deadline
/// passes, which is the only ending that cannot be forgotten.
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
    /// Dials issued since we last reached them, counted on the attempt for the same reason the
    /// backoff is: a dial whose failure is never reported must still be paid for. Reset by
    /// [`PeerEvent::Verified`], and by giving up — see [`DIAL_ATTEMPTS`].
    attempts: usize,
    /// Groups this peer would not discuss, and when it is worth asking again.
    ///
    /// A peer that does not share a group simply leaves it out of its answer — refusals explain
    /// nothing, deliberately, since telling "never heard of it" from "you are not a member"
    /// would make a group id guessable into a membership oracle. So the silence covers six
    /// different situations at once: invited and not yet accepted, or the chain that adds us
    /// not arrived, both of which resolve in seconds; and left, removed, quarantined or
    /// forgotten, none of which ever will.
    ///
    /// Since the wire cannot say which, the answer is to record neither agreement nor defeat:
    /// do not mark them told, do not ask again immediately, and widen the gap each time.
    /// Keyed by group: when to ask again, the gap to use next, and the chain head we held when
    /// they refused — so a membership change since then retires the refusal at once.
    declined: HashMap<GroupId, (i64, i64, u64)>,
    /// Transfers outstanding with this peer, half of "is it drained". The other half — whether
    /// an offer is open — is read from `started` rather than counted here, because a count that
    /// can drift from the thing it counts is precisely what went wrong before.
    transfers: usize,
    /// Paths this peer claimed and could not deliver, per group.
    ///
    /// In memory and cleared on disconnect. Nothing finer is possible: a peer *acquiring* a
    /// file moves no digest, so there is no signal that would let us forget a denial sooner.
    denied: HashMap<GroupId, HashSet<RelPath>>,
    /// When a close proposal went out.
    closing: Option<i64>,
}

pub struct Peers {
    files: Files,
    /// Never written. Held so `shared_with` — the one function allowed to name a group to a
    /// peer — is applied inside the policy, where a test can reach it.
    groups: Groups,
    me: PeerId,

    state: HashMap<GroupId, GroupState>,
    peers: HashMap<PeerId, PeerState>,

    /// Verified and settled.
    connected: HashSet<PeerId>,
    /// Peers believed reachable: the last presence answer, plus anyone seen since.
    ///
    /// **Read by the content pull and by nothing else.** Pulling gigabytes is a choice between
    /// members — which of them to spend a link on — and a five-minute-old answer is a reasonable
    /// basis for a choice. Delivering news is not a choice: the obligation is to a named member,
    /// and the only way to discharge it is to call them. Gating that on this set is what silenced
    /// nodes in the lab, since a member the registry left out was never called at all.
    online: HashSet<PeerId>,
    /// Offers this node asked for, by peer, against what each carried.
    ///
    /// Two jobs, both learned from the lab. Its presence is the initiator's half of the gossip
    /// rule: settling is reported for both sides of an exchange and only ours may spend the
    /// news, see [`PeerEvent::Synced`]. Its contents are what the offer actually put on the
    /// wire, captured when it was sent rather than read back when it settles.
    started: HashMap<PeerId, InFlight>,
    /// Who we still owe news to, per group. **The whole of the propagation state.**
    ///
    /// A work list rather than a comparison, and the difference is what makes "only the author
    /// propagates" fall out for nothing: a local change fills this, and merging somebody else's
    /// change fills nothing. There is no provenance to track, because nothing that arrives from
    /// a peer ever enqueues anybody.
    ///
    /// A peer leaves the list when an exchange with them settles — proof they have it — and is
    /// left in it, behind a backoff, when one fails or is declined. Empty everywhere means this
    /// node has nothing to say to anybody, which is the whole of the quiescence condition.
    pending: HashMap<GroupId, HashMap<PeerId, Owed>>,
    /// Each group as of the last state we have accounted for, either by enqueueing it or by
    /// receiving it from somebody else.
    ///
    /// Only used to notice that *we* changed something. A merge updates it, so what it detects
    /// afterwards is local by construction — and because the obligation lives in `pending`
    /// rather than in this comparison, a merge landing mid-propagation cannot cancel news we
    /// have already taken responsibility for.
    seen: HashMap<GroupId, Snapshot>,
    /// Files a peer said it holds and we have not begun fetching yet, oldest first.
    ///
    /// The whole of a holdings answer, kept rather than issued: see [`MAX_TRANSFERS`]. Entries
    /// are re-checked when they reach the front, because a file may have arrived from somewhere
    /// else, been deleted, or been denied by this peer in the meantime.
    queued: HashMap<PeerId, VecDeque<(GroupId, RelPath)>>,
    /// When we last opened circuits, so the allowance is spent deliberately. See
    /// [`DIALS_PER_WINDOW`].
    dialed_at: Vec<i64>,
    dialing: HashSet<PeerId>,
    next_presence: i64,
    /// The member list moved, so the answer in hand is about the wrong set of people.
    ///
    /// Asks once, off the interval. Not a second clock and needing no floor to pace it: `arm`
    /// raises this only when membership actually moves, and moves `seen` in the same breath, so
    /// it fires once per change rather than once per tick that a change is outstanding.
    ///
    /// **Nothing waits on the answer.** That is the whole difference from what this replaced:
    /// the news is enqueued and dialled immediately, and this refreshes who is worth pulling
    /// content through — a member who has just joined being a likely source for the files that
    /// arrive with them.
    refresh_presence: bool,
    now: i64,

    limits: Limits,
    /// The last disk report. `None` until the daemon sends one.
    space: Option<Space>,
    /// Whether we have already said we are out of room, so it is said once per transition.
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

    /// Set the disk limits. The floor is not optional; the budget comes from `config.toml`.
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
            PeerEvent::Space { free, held } => {
                self.space = Some(Space { free, held });
                Vec::new()
            }

            PeerEvent::Tick { at } => self.tick(at),

            PeerEvent::Discovered { peer } => {
                // A hint, not an invitation: it makes the peer a candidate, and the ordinary
                // loop decides whether there is anything to say to them.
                self.online.insert(peer);

                // Except for one case, which nothing else covers — see `owe_invitation`. Seeing
                // them at all is the signal, and it is the same signal the registry's answer
                // gives, decided the same way.
                self.owe_invitation(peer);
                Vec::new()
            }

            PeerEvent::Presence { asked, online } => {
                // Applied **only to what was asked**, never as a replacement.
                //
                // The query deliberately skips peers we are already connected to, so a
                // wholesale replacement dropped every one of them the instant an answer
                // arrived — and `next_member` then found nobody worth calling. A node whose
                // members were all connected, or whose server answered with an empty list, went
                // permanently silent: no dials, no pulls, and `ac peer status` reporting
                // everybody as "not seen" while sitting in a conversation with them.
                let up: HashSet<PeerId> = online.into_iter().collect();
                let mut returned = false;
                for peer in asked {
                    if up.contains(&peer) {
                        returned |= self.online.insert(peer);
                    } else {
                        self.online.remove(&peer);
                    }
                }

                // Somebody who was not here is here now, so "nobody has this" is a conclusion
                // about a set of members that has changed. The plan asks for the backoff to be
                // reset on exactly this and on the catalogue moving, since `have` is local and
                // a peer acquiring a file changes nothing on the wire: re-asking is the only
                // way any of it is ever discovered.
                if returned {
                    self.reconsider_content();
                }

                // Somebody the chain says is a member and who has never answered the invitation
                // is told again, now that we know they are there — see `owe_invitation`. This is
                // the reason the query still earns its round trip now that nothing else waits on
                // it, and it is what discovery does with the same news.
                for peer in up {
                    self.owe_invitation(peer);
                }
                Vec::new()
            }

            PeerEvent::Verified { peer } => {
                self.dialing.remove(&peer);
                self.connected.insert(peer);
                self.online.insert(peer);
                // Reset here rather than on `Connected`: a peer that connects and then fails
                // attestation must not be retried at full speed.
                let state = self.peers.entry(peer).or_default();
                state.retry_at = 0;
                state.backoff = MIN_BACKOFF;
                state.attempts = 0;
                Vec::new()
            }

            PeerEvent::Gone { peer } => {
                self.dialing.remove(&peer);
                self.connected.remove(&peer);
                self.peers.remove(&peer);
                // An offer to them can no longer settle, so nothing may wait on it — and neither
                // may anything they had queued to give us.
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
                // The backoff already advanced when the dial was issued, and that is the whole
                // of the response. Notably we do *not* conclude they are away: most dials here
                // are relayed, and the commonest failure is the relay refusing the circuit
                // because this node has spent its circuit allowance — which says nothing
                // whatever about the peer. Treating that as absence cost a full presence round
                // on top of the backoff before anyone tried again: in the lab, a member added a
                // moment earlier waited ninety seconds rather than thirty.
                //
                // What we do conclude, and only after three of these, is that there is no point
                // holding a group's list open for them — see `give_up`.
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
                // An exchange settled, so this peer has seen our heads for that group — whether
                // we asked or they did, since our answer carries them either way. Only the half
                // that was on the wire is discharged: a chain exchange says nothing about the
                // file heads, which were not in the message.
                if let Some(owed) = self.pending.get_mut(&group) {
                    if let Some(entry) = owed.get_mut(&peer) {
                        match offering {
                            Offering::Chain => entry.chain = false,
                            Offering::Catalogue => entry.catalogue = false,
                        }
                        if entry.nothing() {
                            owed.remove(&peer);
                        }
                    }
                    if owed.is_empty() {
                        self.pending.remove(&group);
                    }
                }

                // An exchange we asked for is done when the last group it named has settled, and
                // what it *carried* for that group is taken with it — see below.
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
                    // They discussed it, so whatever they would not discuss before is settled.
                    state.declined.remove(&group);
                }
                // What was on the wire is no longer news: `seen` moves with it so this exchange
                // is not mistaken for a local change on the next tick.
                //
                // **Only the half that was on the wire**, exactly as the queue above discharges
                // only that half. Recording both retired the catalogue on the strength of a
                // chain round, and since `seen` is also what decides there is anything to say,
                // nothing ever revisited it: a member added and a file added in the same minute
                // got the membership and never the file, until the four-hour heartbeat.
                //
                // **What the request carried, not what the store holds now.** They are not the
                // same when the catalogue moved while the offer was in flight, and the
                // difference was never sent — recording it as delivered retires news nobody has
                // heard, and nothing afterwards corrects it, since our counter then matches what
                // we believe they hold. `carried` is the snapshot taken when the offer went out;
                // there is none when *they* asked, and then the answer we sent them did carry
                // our heads as of now.
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

            PeerEvent::Declined { peer, group } => {
                // They answered, and left this group out. The exchange is over for that group —
                // free it so the offer can complete — but nothing was delivered, so nothing is
                // recorded as delivered. See `PeerState::declined` for what the silence covers.
                if let Some(flight) = self.started.get_mut(&peer) {
                    flight.carried.remove(&group);
                    if flight.carried.is_empty() {
                        self.started.remove(&peer);
                    }
                }

                let now = self.now;
                let head = self.head_of(group);
                let state = self.peers.entry(peer).or_default();
                let (_, backoff, _) =
                    state
                        .declined
                        .get(&group)
                        .copied()
                        .unwrap_or((0, MIN_BACKOFF, head));
                state
                    .declined
                    .insert(group, (now + backoff, (backoff * 2).min(MAX_BACKOFF), head));
                Vec::new()
            }

            PeerEvent::OfferDeferred { peer } => {
                // Nothing went out, so nothing is owed and nothing is known. The offer is simply
                // forgotten and the next tick decides afresh.
                self.started.remove(&peer);
                Vec::new()
            }

            PeerEvent::OfferFailed { peer } => {
                let Some(flight) = self.started.remove(&peer) else {
                    return Vec::new();
                };
                // Nothing arrived, so nothing is recorded as held — but neither is this the
                // peer's doing, and re-offering on the very next tick would hammer a member
                // whose connection has just broken. The dial backoff paces the reconnection,
                // and the decline backoff paces the retry once reconnected.
                let now = self.now;
                let heads: Vec<(GroupId, u64)> = flight
                    .carried
                    .keys()
                    .map(|group| (*group, self.head_of(*group)))
                    .collect();
                let state = self.peers.entry(peer).or_default();
                for (group, head) in heads {
                    let (_, backoff, _) =
                        state
                            .declined
                            .get(&group)
                            .copied()
                            .unwrap_or((0, MIN_BACKOFF, head));
                    state
                        .declined
                        .insert(group, (now + backoff, (backoff * 2).min(MAX_BACKOFF), head));
                }
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
                let mut actions = vec![PeerAction::Note(Notice::Downloaded { group, path })];
                actions.extend(self.pump(peer));
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

                let mut actions = vec![PeerAction::Note(Notice::Undelivered { peer, group, path })];
                actions.extend(self.pump(peer));
                if why.contains("hash") {
                    // Wrong bytes are misbehaviour, not misfortune, and are worded as such.
                    actions.push(PeerAction::Note(Notice::Rejected { peer, why }));
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
            .filter(|row| !row.is_quarantined() && row.state == State::Active)
            .map(|row| row.id)
            .collect();

        for group in &groups {
            self.arm(*group, at);
        }
        actions.extend(self.catalogue_rounds(&groups));

        // Catalogues are exchanged whatever the disk looks like: knowing what exists costs
        // kilobytes, and a node that stopped syncing its index when it ran out of room would
        // also stop being able to *say* what it is missing.
        match self.room() {
            Some(note) => {
                if !self.cramped {
                    self.cramped = true;
                    actions.push(PeerAction::Note(note));
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
    ///
    /// **Only what we did ourselves is propagated.** `seen` is updated whenever something
    /// reaches us from a peer, so a difference against it is by construction a local change —
    /// our own `ac file add`, our own `ac group add`, our own standing. Merging somebody else's
    /// change enqueues nobody: they are telling the group themselves, and a member neither of
    /// us can reach is not made reachable by a second node trying.
    ///
    /// What that costs is bounded and understood: a member the author never reaches waits for
    /// their own heartbeat. What it saves is every node in the group re-telling every other,
    /// which is the difference between one message per member and one per member per member.
    fn arm(&mut self, group: GroupId, at: i64) {
        let Ok(current) = self.current(group) else {
            return;
        };
        let jitter = jitter_for(HEARTBEAT);
        let state = self
            .state
            .entry(group)
            .or_insert_with(|| GroupState::new(at, jitter));

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

        // Membership moved since they refused, so the refusal may no longer stand: a peer that
        // had not yet learned we are a member may have learned it since. Compared against the
        // head *they* refused under, not against our last successful exchange — the latter does
        // not advance while they keep refusing, which would retire the backoff every tick and
        // hammer them.
        for peer in self.peers.values_mut() {
            if peer
                .declined
                .get(&group)
                .is_some_and(|(_, _, head)| *head != current.head)
            {
                peer.declined.remove(&group);
            }
        }

        // The heartbeat is the one timer, and it exists for a case no exact signal covers: a
        // peer that can accept our dial but whose own never land, and — since only the author
        // propagates — a member the author never reached.
        //
        // **One peer, not everybody.** It is a check that we are not adrift, not a broadcast:
        // an exchange with any one member reconciles both directions, so if we are missing
        // something they have it comes back on the same round trip. And because an offer names
        // every group we share with that peer, a peer already queued for another group settles
        // this one too — so a node in six groups with the same five people spends one exchange
        // on all six, not six.
        if at >= self.state[&group].heartbeat_at {
            if let Some(state) = self.state.get_mut(&group) {
                state.heartbeat_at = at + jitter;
            }

            let already = self
                .pending
                .values()
                .flat_map(|owed| owed.keys())
                .copied()
                .collect::<HashSet<PeerId>>();
            let covered = self
                .members_of(group)
                .into_iter()
                .any(|peer| already.contains(&peer));

            if !covered && let Some(peer) = self.peek_member(group) {
                self.pending.entry(group).or_default().insert(
                    peer,
                    Owed {
                        chain: true,
                        catalogue: true,
                    },
                );
            }
        }
    }

    /// Put **every** member on this group's list.
    ///
    /// Not only the ones the registry vouched for. Filtering here was the same mistake as
    /// filtering in `dial`, one step earlier: a member left out of a five-minute-old answer was
    /// never enqueued, so nothing ever tried to call them and nothing ever noticed they had come
    /// back — the news simply was not theirs to receive.
    ///
    /// What made the filter look necessary was that an unreachable member would otherwise leave
    /// the group looking as though it had something outstanding for ever. That is now answered
    /// where it belongs, by the dialling giving up after [`DIAL_ATTEMPTS`] rather than by
    /// deciding in advance who is worth telling.
    fn enqueue(&mut self, group: GroupId, chain: bool, catalogue: bool) {
        let members = self.members_of(group);
        let owed = self.pending.entry(group).or_default();
        for peer in members {
            let entry = owed.entry(peer).or_insert(Owed {
                chain: false,
                catalogue: false,
            });
            entry.chain |= chain;
            entry.catalogue |= catalogue;
        }
    }

    /// Decide per group who still needs telling, then send **one offer per peer**.
    ///
    /// The decision stays group-shaped: each group asks who has not heard its news. The sending
    /// does not, because an offer carries every shared group — so three groups that all choose
    /// the same member cost one request between them, and every group riding along is genuinely
    /// told rather than merely reconciled by accident.
    ///
    /// The queue is drained one peer per tick per group, and a group with an empty queue is
    /// quiet. Nothing is compared and nothing is counted — being on the list *is* the obligation.
    fn catalogue_rounds(&mut self, groups: &[GroupId]) -> Vec<PeerAction> {
        let mut chosen: Vec<PeerId> = Vec::new();
        let mut actions = Vec::new();

        for group in groups {
            // Everyone on the list except those we agreed to leave alone for a while: a peer
            // that declined stays owed, but is not asked again until its backoff expires.
            let waiting: Vec<PeerId> = self
                .pending
                .get(group)
                .map(|owed| owed.keys().copied().collect())
                .unwrap_or_default();
            if waiting.is_empty() {
                continue;
            }
            let skip: HashSet<PeerId> = self
                .members_of(*group)
                .into_iter()
                .filter(|p| {
                    !waiting.contains(p)
                        || self.peers.get(p).is_some_and(|s| {
                            s.declined
                                .get(group)
                                .is_some_and(|(until, _, _)| self.now < *until)
                        })
                })
                .collect();
            // Anyone owed the news, whatever the registry thinks of them: `next_member` asks
            // only whether they may be called yet, and the skip set above is about what they
            // have already been told rather than about where they are.
            let Some(peer) = self.next_member(*group, &skip) else {
                // Somebody has not heard and not one of them is callable, which now means one
                // thing only: they are all inside a dial backoff, which time alone fixes.
                continue;
            };

            if !self.connected.contains(&peer) {
                actions.extend(self.dial(peer));
                continue;
            }
            // Already going to them this tick: their offer will carry this group too.
            if !chosen.contains(&peer) && !self.started.contains_key(&peer) {
                chosen.push(peer);
            }
        }

        for peer in chosen {
            // **Membership before contents.** A catalogue offer is gated on membership the
            // other side may not have yet, so while anything about who is in a group is stale
            // for this peer, that is what goes — and the file heads follow on a later tick, by
            // which time they know who we are.
            let offering = if self.chain_stale_for(&peer) {
                Offering::Chain
            } else {
                Offering::Catalogue
            };
            actions.push(self.offer(peer, offering));
        }
        actions
    }

    /// Whether any group owes this peer membership.
    fn chain_stale_for(&self, peer: &PeerId) -> bool {
        self.pending
            .values()
            .any(|owed| owed.get(peer).is_some_and(|o| o.chain))
    }

    /// Record what an offer to this peer carries, and ask for it.
    ///
    /// Every group shared with them, not merely the group that prompted it: the request names
    /// them all, so they are all told, and recording anything less would leave the supervisor
    /// believing it still owes news it has already delivered.
    fn offer(&mut self, peer: PeerId, offering: Offering) -> PeerAction {
        let carried = self
            .groups
            .shared_with(&peer)
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
        PeerAction::Offer { peer, offering }
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
    /// Absent a report we assume there is room. The daemon sends one immediately before every
    /// tick, so the only window is startup — and refusing to fetch because nothing has told us
    /// the disk size yet would be a worse failure than briefly not knowing.
    fn room(&self) -> Option<Notice> {
        let space = self.space?;

        if space.free < self.limits.min_free {
            return Some(Notice::OutOfSpace {
                held: space.held,
                limit: self.limits.min_free,
                floor: true,
            });
        }
        match self.limits.storage_max {
            Some(max) if space.held >= max => Some(Notice::OutOfSpace {
                held: space.held,
                limit: max,
                floor: false,
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
                // Our disk, not their shortcoming. Release the source without marking them
                // spent, so they are the first place we look once there is room again — marking
                // them spent would rotate through every member to discover the same thing, and
                // then report the file unobtainable, which it is not.
                self.release_source(peer, group)
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
        let mut actions = Vec::new();

        // Said once per unproductive rotation, so "nobody reachable has this" is
        // distinguishable from "still downloading" — which otherwise look identical.
        if let Ok(missing) = next_missing(&self.files, group, 1)
            && let Some((path, _)) = missing.into_iter().next()
        {
            actions.push(PeerAction::Note(Notice::Unobtainable { group, path }));
        }

        if let Some(state) = self.state.get_mut(&group) {
            state.content_until = at + state.content_backoff;
            state.content_backoff = (state.content_backoff * 2).min(MAX_CONTENT_BACKOFF);
            state.spent.clear();
            state.source = None;
        }
        actions
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
            .filter(|row| !row.is_quarantined() && row.state == State::Active)
            .map(|row| {
                let state = self.state.get(&row.id);
                GroupStatus {
                    group: row.id,
                    missing: self.files.missing_count(row.id).unwrap_or(0),
                    unheard: self.pending.get(&row.id).map(|o| o.len()).unwrap_or(0),
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
            .filter(|row| !row.is_quarantined() && row.state == State::Active)
            .map(|row| row.id)
            .filter(|group| {
                self.members_of(*group).contains(peer)
                    && !self.answered_invite(*group).contains(peer)
            })
            .collect()
    }

    /// Put this peer on every list where their invitation is still undelivered.
    ///
    /// The one case nothing else covers, and the reason both the discovery hint and the presence
    /// answer bother to do anything at all. They cannot ask for a group they do not know exists;
    /// under author-only propagation no other member will offer it; and if they were away for
    /// our three attempts they have already dropped off the list. Being seen is the whole signal.
    ///
    /// **Both halves.** The chain is what they are missing and the catalogue is what is useless
    /// to them until they have it. Ordering is not at risk — `catalogue_rounds` sends the chain
    /// first while any is owed.
    fn owe_invitation(&mut self, peer: PeerId) {
        for group in self.unanswered_invites(&peer) {
            self.pending.entry(group).or_default().insert(
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
            self.on(PeerEvent::OfferFailed { peer });
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
        self.pending.retain(|_, owed| {
            owed.remove(&peer);
            !owed.is_empty()
        });
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
    /// second armed the content backoff — with a `Notice::Unobtainable` to match — for a group
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
            if row.is_quarantined() || row.state != State::Active {
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

    /// The group's chain head, without the catalogue digest that comes with a whole snapshot.
    ///
    /// The head lives in `ac-groups` and has nothing to do with the file catalogue, so reading it
    /// through `current` meant hashing every row in the group to fetch one integer out of another
    /// store. The backoff bookkeeping that wants it runs on every decline and every failed offer.
    fn head_of(&self, group: GroupId) -> u64 {
        self.groups
            .get(group)
            .ok()
            .flatten()
            .map(|r| r.head_seq)
            .unwrap_or(0)
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
