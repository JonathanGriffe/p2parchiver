//! Shared networking foundation for the `ac` client and the `ac-server` daemon.
//!
//! Everything both binaries need lives here: the node's cryptographic identity, its
//! on-disk configuration, the wire types they exchange, and (from stage 2 onward) the
//! libp2p swarm they both drive. This crate holds no policy — who may talk to whom is
//! decided by the binaries through the `PeerAuthorizer` trait.

// The workspace warns on unwrap/expect because a panic in the event loop takes the whole
// daemon down. In tests a panic *is* the failure report, so let them through.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod authz;
pub mod config;
pub mod connectivity;
pub mod identity;
pub mod limits;
pub mod proto;
pub mod swarm;

pub use libp2p::{Multiaddr, PeerId};
