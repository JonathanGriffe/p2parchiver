use std::num::NonZeroU32;
use std::time::Duration;

use libp2p::{connection_limits, relay};

/// Simultaneous connections we will hold.
const MAX_ESTABLISHED_TOTAL: u32 = 256;

/// Connections per peer
const MAX_ESTABLISHED_PER_PEER: u32 = 8;

/// In-flight connection attempts
const MAX_PENDING: u32 = 64;

/// Fraction of system memory the swarm may occupy before new connections are refused.
const MAX_MEMORY_FRACTION: f64 = 0.15;

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

pub fn memory_limits() -> libp2p::memory_connection_limits::Behaviour {
    libp2p::memory_connection_limits::Behaviour::with_max_percentage(MAX_MEMORY_FRACTION)
}

/// Data one circuit may carry before it is closed.
const MAX_CIRCUIT_BYTES: u64 = 8 * 1024 * 1024;

/// Wall-clock ceiling on one circuit, independent of bytes. A slow trickle is still a held
/// resource.
const MAX_CIRCUIT_DURATION: Duration = Duration::from_secs(600);

/// Circuits in flight across all clients.
const MAX_CIRCUITS: usize = 64;

/// Circuits in flight for one client.
const MAX_CIRCUITS_PER_PEER: usize = 4;

/// Circuits one client may *open* per [`RATE_WINDOW`].
const CIRCUITS_PER_PEER_PER_WINDOW: NonZeroU32 = NonZeroU32::new(16).expect("nonzero");

/// Circuits one source IP may open per [`RATE_WINDOW`], across every peer id behind it.
const CIRCUITS_PER_IP_PER_WINDOW: NonZeroU32 = NonZeroU32::new(64).expect("nonzero");

/// Window for the two allowances above.
const RATE_WINDOW: Duration = Duration::from_secs(60);

const fn refill(per_window: NonZeroU32) -> Duration {
    match RATE_WINDOW.checked_div(per_window.get()) {
        Some(interval) => interval,
        None => unreachable!(),
    }
}

/// A window that does not divide evenly would silently round the sustained rate.
const _: () = assert!(
    refill(CIRCUITS_PER_PEER_PER_WINDOW).as_nanos() * CIRCUITS_PER_PEER_PER_WINDOW.get() as u128
        == RATE_WINDOW.as_nanos()
);
const _: () = assert!(
    refill(CIRCUITS_PER_IP_PER_WINDOW).as_nanos() * CIRCUITS_PER_IP_PER_WINDOW.get() as u128
        == RATE_WINDOW.as_nanos()
);

/// One IP must not be held to less than one client's share.
const _: () = assert!(CIRCUITS_PER_IP_PER_WINDOW.get() >= CIRCUITS_PER_PEER_PER_WINDOW.get());

const _: () = assert!(
    MAX_CIRCUIT_BYTES * CIRCUITS_PER_PEER_PER_WINDOW.get() as u64 == 128 * 1024 * 1024,
    "one client's ceiling is 128 MiB per window"
);

/// One client must not be able to take every circuit on the server.
const _: () = assert!(MAX_CIRCUITS_PER_PEER < MAX_CIRCUITS);

/// The whole server's exposure
const _: () = assert!(MAX_CIRCUITS as u64 * MAX_CIRCUIT_BYTES == 512 * 1024 * 1024);

/// How much relaying one client may ask this server to do.
pub fn relay_config() -> relay::Config {
    relay::Config {
        max_circuit_bytes: MAX_CIRCUIT_BYTES,
        max_circuit_duration: MAX_CIRCUIT_DURATION,
        max_circuits: MAX_CIRCUITS,
        max_circuits_per_peer: MAX_CIRCUITS_PER_PEER,
        circuit_src_rate_limiters: Vec::new(),
        ..relay::Config::default()
    }
    .circuit_src_per_peer(
        CIRCUITS_PER_PEER_PER_WINDOW,
        refill(CIRCUITS_PER_PEER_PER_WINDOW),
    )
    .circuit_src_per_ip(
        CIRCUITS_PER_IP_PER_WINDOW,
        refill(CIRCUITS_PER_IP_PER_WINDOW),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_are_constructible() {
        let _ = connection_limits();
        let _ = memory_limits();
        let _ = relay_config();
    }

    #[test]
    fn the_allowance_is_per_window_not_per_interval() {
        assert_eq!(
            refill(CIRCUITS_PER_PEER_PER_WINDOW),
            Duration::from_millis(3750)
        );
        assert_eq!(
            refill(CIRCUITS_PER_IP_PER_WINDOW),
            Duration::from_nanos(937_500_000)
        );
    }
}
