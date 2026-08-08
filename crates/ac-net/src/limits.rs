//! Resource limits — what actually protects a node from an unknown peer.
//!
//! Since clients accept connections from anyone (see [`crate::authz`]), the remaining
//! threat is not access but exhaustion: a peer opening connections until the node runs
//! out of file descriptors or memory. Identity is the wrong tool for that; caps are the
//! right one, and they apply equally to peers we know and peers we do not.

use libp2p::connection_limits;

/// Simultaneous connections we will hold.
///
/// A friend-scale group is single digits of peers, but a node also talks to the server
/// and may briefly hold both a relayed and a direct connection to the same peer while
/// DCUtR upgrades one to the other. 256 leaves room for that without being a useful
/// amount of leverage for anyone trying to exhaust us.
const MAX_ESTABLISHED_TOTAL: u32 = 256;

/// Connections per peer. Above one direct plus one relayed, extra connections to the
/// same peer are duplicated work; a peer opening many is misbehaving.
const MAX_ESTABLISHED_PER_PEER: u32 = 8;

/// In-flight connection attempts. Handshakes cost CPU, so this bounds how much a peer can
/// force us to spend before any of it is established.
const MAX_PENDING: u32 = 64;

/// Fraction of system memory the swarm may occupy before new connections are refused.
///
/// A cap in bytes would be wrong on both a 2 GB VPS and a 64 GB desktop; the same
/// binary runs on each.
const MAX_MEMORY_FRACTION: f64 = 0.15;

// Checked at compile time rather than in tests: these are relationships between
// constants, so a bad edit should fail the build, not a test run.

/// A single peer must not be able to consume the whole budget on its own.
const _: () = assert!(MAX_ESTABLISHED_PER_PEER < MAX_ESTABLISHED_TOTAL);

/// During a hole punch a peer legitimately holds a relayed and a direct connection at
/// once, so a per-peer limit of 1 would break the very upgrade it is meant to allow.
const _: () = assert!(MAX_ESTABLISHED_PER_PEER >= 2);

/// A percentage, not a byte count.
const _: () = assert!(MAX_MEMORY_FRACTION > 0.0 && MAX_MEMORY_FRACTION < 1.0);

/// Caps for a node's swarm.
pub fn connection_limits() -> connection_limits::ConnectionLimits {
    connection_limits::ConnectionLimits::default()
        .with_max_established(Some(MAX_ESTABLISHED_TOTAL))
        .with_max_established_per_peer(Some(MAX_ESTABLISHED_PER_PEER))
        .with_max_pending_incoming(Some(MAX_PENDING))
        .with_max_pending_outgoing(Some(MAX_PENDING))
}

/// Memory-based backstop, in case the connection count alone is not the binding
/// constraint — a few connections moving large media can outweigh many idle ones.
pub fn memory_limits() -> libp2p::memory_connection_limits::Behaviour {
    libp2p::memory_connection_limits::Behaviour::with_max_percentage(MAX_MEMORY_FRACTION)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_are_constructible() {
        let _ = connection_limits();
        let _ = memory_limits();
    }
}
