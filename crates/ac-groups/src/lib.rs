//! Groups: who may have what, decided among peers rather than by a server.
//!
//! `ac-net` answers "can we talk, and should we" — transport, reachability, and admission via
//! server-signed attestations. This crate answers "what about": which peers belong to which
//! group, agreed between members with no coordinator.
//!
//! # The shape, and why
//!
//! A group is an **append-only log signed by one admin** — the node that created it.
//! [`chain::Chain`] is the only path to a validated log, exactly as `Attestation::verify` is
//! the only path to a trusted statement in `ac-net`.
//!
//! One writer is what makes this tractable. A hash chain cannot legitimately fork, so merging
//! is "extend the prefix we hold" rather than conflict resolution, and two entries at one
//! position mean something is wrong rather than something needs deciding. The cost is that a
//! lost admin device freezes a group; the benefit is that removal actually removes, which a
//! flat group where everyone can add cannot promise — any removal there is undone by the
//! removed peer re-adding themselves.
//!
//! Members do get one thing they need no authority for: **leaving**. A
//! [`standing::Standing`] is self-signed and can only ever speak for its signer, and it lives
//! in its own per-member sequence space so that granting it does not make the chain
//! multi-writer.
//!
//! # Signed bytes are carried verbatim
//!
//! [`chain::Entry`] and [`standing::Standing`] both hold `body: Vec<u8>` — the CBOR exactly as
//! it was signed — rather than a decoded struct. Verification runs over those bytes, and the
//! typed view is decoded from them afterwards.
//!
//! Re-encoding a decoded body before verifying it would be the bug: two encoders (or two
//! versions of one) can disagree on map ordering, integer width, or how an absent field is
//! written, and any such difference turns a valid signature into an invalid one, or — far
//! worse, if the check is made lenient to compensate — lets a body verify that is not the body
//! that was signed. So no code path here ever re-encodes before checking. `ac-net`'s
//! `Attestation` takes the same approach for the same reason.
//!
//! `prev` therefore hashes the previous **body**, making an entry's hash a pure function of the
//! bytes on the wire.
//!
//! # A fork stops the group; it does not resolve it
//!
//! Two different entries at one `seq` cannot happen legitimately, because exactly one key may
//! write. Seeing it means a restored backup, a copied admin key, or two admin processes racing
//! — all of which want a human, not a merge rule. So [`store::Groups::put`] writes nothing,
//! records `forked_at`, and the group goes silent: it is neither offered nor served, and no
//! entry is accepted for it again.
//!
//! There is deliberately no repair command. Picking a winner would mean discarding entries the
//! admin signed, and any automatic choice is a rule an attacker with a stolen key can aim at.
//! Recovery is a fresh group.
//!
//! # Revocation, in four workflows
//!
//! These are easy to conflate, so they are stated once, here.
//!
//! | | Trigger | Writes | Effective when | Bounded? |
//! |---|---|---|---|---|
//! | **1. Admin removes** | `ac group remove` | [`Op::Remove`] | each peer applies it on next sync | no |
//! | **2. Member leaves** | `ac group leave` | a self-signed [`Standing`] | **immediately** for the leaver, advisory for everyone else | no |
//! | **3. Admin ratifies** | automatic, on ingesting (2) | [`Op::Remove`] | promotes (2) to (1) | no |
//! | **4. Server revokes** | `ac-server client revoke` | nothing in any chain | the peer can no longer complete peer-attest with **anyone**, so every group becomes unreachable | **yes — one attestation lifetime** |
//!
//! Three things follow.
//!
//! **Only (4) has a deadline.** Group-layer revocation travels over connections that happen to
//! exist, and nothing here dials, so a peer that never reconnects never learns it was removed.
//! Attestations expire, which is why (4) is the only workflow with a worst case — and also why
//! it is the blunt one, removing the peer from every group at once.
//!
//! **(2) is total for the leaver and advisory for everyone else.** A departed node refuses to
//! serve because its own [`State`] says so, and no fold anyone holds can override that. Until
//! (3) lands, other members still list them and still offer; the departed node ignores it.
//!
//! **None of them revokes content.** Removal means "nothing further" in every row. Taking back
//! access to bytes already shared needs per-object encryption with key rotation — a data-plane
//! concern that stacks on top of this rather than competing with it.
//!
//! # This is not a connection gate
//!
//! `ac_net::authz` spends its module docs on why a peer must not decide who to *connect* to
//! from a list it holds: membership changes while someone is offline, and the peer who could
//! deliver the newcomer's proof is the one being refused. Nothing here may become such a gate.
//! Clients keep accepting anyone; this decides what a connected, verified peer may *obtain*.
//!
//! Syncing the log is deliberately offered before any group check, filtered by the *offerer's*
//! view — never by the receiver's.
//!
//! # Layering
//!
//! Nothing in this crate may name a libp2p networking type. `PeerId`, `Keypair` and
//! `PublicKey` are fine — they are identity rather than networking, and they come from
//! `ac_net`, which re-exports all three. `Swarm`, `SwarmEvent`, `NetworkBehaviour`,
//! `ResponseChannel`, request ids and `Multiaddr` appear nowhere. The sync half is a state
//! machine that consumes events and returns actions, and `ac-node`'s daemon is the only code
//! that touches both worlds.
//!
//! Stated positively: **`libp2p` is named nowhere in this crate**, not even in [`wire`], and it
//! is not a dependency — so a networking type is unnameable and rustc refuses it. `wire` used to
//! be the exception, because it declared the `request_response` behaviour; it now declares the
//! protocol name, the messages and the size ceilings, and `ac-node` builds what carries them.
//! That is how `ac_files::wire::BLOB_PROTOCOL` always worked.
//!
//! `tests/layering.rs` still greps the source, but as a second line: the rule that matters is
//! the absent dependency, which it checks in `Cargo.toml`. A reviewer will not catch a re-added
//! `use`, and will not catch a re-added dependency either.
//!
//! # Where to look
//!
//! | Question | Module |
//! |---|---|
//! | what a valid log is, and what an admin may write | [`chain`] |
//! | how a member speaks for themselves | [`standing`] |
//! | who is in the group right now | [`members`] |
//! | what is on disk, and the rules for accepting a batch | [`store`] |
//! | **when we talk to a peer, and what we will say** | [`sync`] |
//! | the messages themselves | [`wire`] |
//!
//! [`sync`] is the one to read first if the question is behavioural — it carries the reasoning
//! for the two wire rules, and for why nothing here polls.

// The workspace warns on unwrap/expect because a panic in the event loop takes the whole
// daemon down. In tests a panic *is* the failure report, so let them through.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod bytes;
pub mod chain;
pub mod id;
pub mod members;
pub mod standing;
pub mod store;
pub mod sync;
pub mod wire;

pub use chain::{Chain, ChainError, Entry, EntryBody, Op};
pub use id::{EntryHash, GroupId};
pub use members::{Member, Members};
pub use standing::{Standing, StandingBody, StandingError, StandingSet};
pub use store::{Applied, GroupRow, Groups, Resolved, State, StoreError};
pub use sync::{GroupAction, GroupEvent, GroupSync, Notice};
pub use wire::{GROUP_PROTOCOL, GroupHead, GroupRequest, GroupResponse};
