//! The admission layer names no swarm, enforced by reading the source.
//!
//! `ac-net` as a whole is the networking crate, so most of it may name whatever libp2p offers.
//! [`ac_net::admission`] is the exception: it holds the policy deciding who is let in, and that
//! is worth being able to test without standing up two real nodes. It could not be, before —
//! which is how it carried a live double-fire bug and a reconnection bug at the same time.
//!
//! The counterpart rule for the group layer lives in `ac-groups/tests/layering.rs`.
//!
//! [`ac_net::link`] is deliberately *not* covered. Its whole job is driving the swarm, and
//! wrapping three libp2p calls in a private vocabulary would cost more than it returns — see
//! its module docs.

// An integration test is its own crate, so the library's test-only allow does not reach here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

const FORBIDDEN: &[&str] = &[
    "Swarm",
    "SwarmEvent",
    "NetworkBehaviour",
    "ResponseChannel",
    "OutboundRequestId",
    "InboundRequestId",
    "Multiaddr",
    "send_request",
    "send_response",
];

/// Source with line comments removed: the rule is about what the code names, and the module
/// docs explain at length that it never sees a `Swarm`.
fn code(source: &str) -> String {
    source
        .lines()
        .map(|line| match line.find("//") {
            Some(at) => &line[..at],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn admission_names_no_swarm() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/admission.rs");
    let source = std::fs::read_to_string(&path).expect("reading admission.rs");
    let code = code(&source);

    for needle in FORBIDDEN {
        assert!(
            !code.contains(needle),
            "admission.rs names `{needle}`. Admission decides who may stay; it must say so in \
             actions and let the daemon carry them out, or it stops being testable without a \
             network — which is the whole reason it lives here."
        );
    }
}
