//! Shared networking foundation for the `ac` client and the `ac-server` daemon.
//!
//! Everything both binaries need lives here: the node's cryptographic identity, its
//! on-disk configuration, the wire types they exchange, and (from stage 2 onward) the
//! libp2p swarm they both drive. This crate holds no policy — who may talk to whom is
//! decided by the binaries through the `PeerAuthorizer` trait.

// The workspace warns on unwrap/expect because a panic in the event loop takes the whole
// daemon down. In tests a panic *is* the failure report, so let them through.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod admission;
pub mod attest;
pub mod authz;
pub mod config;
pub mod connectivity;
pub mod identity;
pub mod limits;
pub mod link;
pub mod proto;
pub mod swarm;

/// The name a node is known by, everywhere above this crate.
///
/// Re-exported because a peer id is not really a networking type here: it is the durable
/// identity a group member, a manifest's owner and the subject of a signed statement are all
/// named by, and [`identity::public_key_of`] recovers the verification key straight out of it.
/// So the layers above deal in peer ids constantly while knowing nothing about transports.
///
/// `Multiaddr` is deliberately **not** re-exported alongside it. *Where* to reach a peer is
/// exactly the concern those layers are meant to be free of — `ac-groups`, `ac-files` and
/// `ac-peers` name it nowhere, and their `tests/layering.rs` fail if that ever changes.
/// Addresses belong to this crate and to the binaries that own configuration and dialling,
/// both of which depend on libp2p directly and can say `libp2p::Multiaddr`.
pub use libp2p::PeerId;
