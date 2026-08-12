//! The supervisor: who to call, what to ask them for, and when to hang up.
//!
//! The layers below each answer one question and wait to be told what to do. `ac-net` answers
//! *can we talk*, `ac-groups` answers *who may have what*, `ac-files` answers *what exists*.
//! None of them decides **who to talk to** — so before this crate, two members of a group
//! never met unless a person introduced them with `--dial`.
//!
//! # One question, asked at three moments
//!
//! Dialling, fetching and closing are the same question — *is there work here* — asked when
//! disconnected, while connected, and when deciding to stop.
//!
//! There was one predicate answering all three. It did not survive contact with what the three
//! actually need: dialling and closing turn on *who has been told what*, which is per peer and
//! lives in `sync`'s work list, while fetching turns on what the index is missing, which is a
//! count. Sharing an answer between them meant computing a catalogue digest for callers that
//! wanted neither — so the shared implementation is gone, and what is left of it is
//! [`next_missing`].
//!
//! # The loop is group-shaped, not peer-shaped
//!
//! The obvious design iterates peers: for each one, is there work with them? It is wrong, and
//! expensively so. Under auto-mirror the files missing from a group are the same set whichever
//! member you ask, so every member of a fifty-person group looks equally worth dialling, and a
//! staleness timer over all pairs costs ~2,450 dials per interval across that group to
//! discover that nothing changed. `ac_node::contacts` states the rule this violates: *"A group
//! of two hundred does not mean two hundred dials."*
//!
//! So the loop iterates **groups**, and a peer is only the means of resolving a group's need.
//!
//! **The author tells everyone; nobody relays.** A change is enqueued for every member of its
//! group and worked through one per tick, so a fifty-member group costs forty-nine messages —
//! not the two and a half thousand that every node re-telling every other would cost. What it
//! gives up is the epidemic property: a member the author never reaches is not covered by some
//! other member noticing, and waits for a heartbeat. That cost is bounded and deliberate, and
//! `sync::arm` is where it is argued.
//!
//! The heartbeat is the one place *one member* really is sufficient, because an exchange
//! reconciles both directions at once: if we are missing something they have, it comes back on
//! the same round trip.
//!
//! # Restraint is most of the design
//!
//! This is the first component here that spends someone else's bandwidth on a schedule, and
//! two ceilings bound it. `ac_net::swarm` allows a client **two relayed circuits per minute**,
//! server-enforced, which is the real budget — not the connection limits. And the relay allows
//! sixteen circuits across all clients at once.
//!
//! What makes that affordable is that having news is **level-triggered, not edge-triggered per
//! change**: what is compared is where the catalogue is now against where it was when the group
//! was last told, so importing a thousand files costs one round rather than a thousand. The unit
//! is a *convergence*, not an edit. `sync::SHARE_AFTER_IDLE` then holds even that back until the
//! editing stops, so an afternoon of sorting photographs is one round and not ninety.
//!
//! # The cost this accepts
//!
//! Auto-mirror over a relay means the server carries one full copy of every file, for every
//! member that cannot hole-punch. A 4 GiB file in a twenty-member group is ~76 GiB through the
//! server, and for each receiving node it is 64 circuits at `MAX_CIRCUIT_BYTES`, which the
//! rate limit stretches to roughly half an hour — bound by the limit, not by bandwidth.
//!
//! That is accepted, not mitigated. The caps mean the relay can be made slow but never
//! overrun, and DCUtR takes most pairs off the server entirely when hole punching works. An
//! operator running this for twenty people should expect to buy bandwidth.

// The workspace warns on unwrap/expect because a panic in the event loop takes the whole
// daemon down. In tests a panic *is* the failure report, so let them through.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod missing;
pub mod sync;
pub mod wire;

pub use missing::{PeersError, next_missing};
pub use sync::{GroupStatus, Notice, PeerAction, PeerEvent, PeerStatus, Peers, Status};
