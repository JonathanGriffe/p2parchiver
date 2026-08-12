//! The layering rule, enforced by reading the source.
//!
//! `ac-peers` decides who to call, what to ask them, and when to stop. It may reason about
//! groups, files, peers and clocks, and it may not know that a `Swarm` exists — the daemon in
//! `ac-node` is the only code that touches both worlds.
//!
//! That matters more here than in the crates below. This is the largest state machine in the
//! workspace and the one whose bugs are hardest to see: an over-eager dial loop looks fine in
//! production until someone counts the circuits. Keeping it free of networking types is what
//! lets a fifty-member group, a week-long absence, or a peer that never answers be set up in a
//! test in microseconds, with no sockets and no sleeping.
//!
//! It is deliberately crude: a grep over the crate's own source, checking identifiers rather
//! than parsing Rust. A reviewer will not catch a re-added `use`.

// An integration test is its own crate, so the library's test-only allow does not reach here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

/// Types that name libp2p's *networking*. None of these may appear anywhere in this crate.
///
/// `libp2p_stream` is on the list for the same reason it is in `ac-files`: moving bytes needs a
/// runtime and a task per transfer, and both belong to `ac-node`.
const FORBIDDEN: &[&str] = &[
    "Swarm",
    "SwarmEvent",
    "NetworkBehaviour",
    "ResponseChannel",
    "OutboundRequestId",
    "InboundRequestId",
    "ConnectionId",
    "libp2p_stream",
    // Addresses too. The policy decides *who* to call; how to reach them is `ac-node`'s
    // business, since that is where `config.server` lives and where discovery results arrive.
    // Keeping `Multiaddr` out means a dial decision can be asserted without inventing one.
    "Multiaddr",
];

/// Types that speak a protocol. Confined to `wire.rs`, the seam by design.
const WIRE_ONLY: &[&str] = &["request_response", "StreamProtocol"];

/// The crate's *production* source: comments removed, and everything from the test module
/// onwards discarded.
///
/// Two exclusions, for two different reasons. Comments, because the rule is about what the
/// code names and this crate's docs discuss dialling and circuits at length. And the
/// `#[cfg(test)]` module, because a test legitimately mints peer ids and reads clocks to build
/// the scenarios these rules exist to make cheap — holding test code to a rule about what
/// ships would mean the guard punishes exactly the thing it is protecting.
fn code(source: &str) -> String {
    let production = match source.find("#[cfg(test)]") {
        Some(at) => &source[..at],
        None => source,
    };
    production
        .lines()
        .map(|line| match line.find("//") {
            Some(at) => &line[..at],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn sources() -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("reading src/") {
        let path = entry.expect("a dir entry").path();
        if path.extension().is_some_and(|e| e == "rs") {
            let name = path
                .file_name()
                .expect("a file name")
                .to_string_lossy()
                .into_owned();
            out.push((
                name,
                std::fs::read_to_string(&path).expect("reading a source"),
            ));
        }
    }
    assert!(!out.is_empty(), "found no sources to check");
    out
}

#[test]
fn no_module_names_a_libp2p_networking_type() {
    for (name, source) in sources() {
        let code = code(&source);
        for needle in FORBIDDEN {
            assert!(
                !code.contains(needle),
                "{name} names `{needle}`. The supervisor decides; the daemon acts. If this is \
                 genuinely needed, the action it belongs to is missing."
            );
        }
    }
}

#[test]
fn only_wire_speaks_a_protocol() {
    for (name, source) in sources() {
        if name == "wire.rs" {
            continue;
        }
        let code = code(&source);
        for needle in WIRE_ONLY {
            assert!(
                !code.contains(needle),
                "{name} names `{needle}`, which belongs in wire.rs. Everything else works in \
                 terms of the message types, not the transport that carries them."
            );
        }
    }
}

#[test]
fn the_predicate_never_names_a_peer() {
    // The mistake this crate exists to avoid, made checkable.
    //
    // An earlier design asked "is there work with *this peer*", which under auto-mirror
    // answers the same for every member of a group — so all forty-nine members of a
    // fifty-person group looked equally worth dialling. The work is a property of the group;
    // the peer is only how it gets resolved. If `missing.rs` ever takes a `PeerId`, that
    // distinction has quietly collapsed again.
    let (_, missing) = sources()
        .into_iter()
        .find(|(name, _)| name == "missing.rs")
        .expect("missing.rs exists");

    assert!(
        !code(&missing).contains("PeerId"),
        "missing.rs names `PeerId`. What a group still needs does not depend on who is asked \
         for it, and making it look as though it does is how the dial loop stops scaling."
    );
}

#[test]
fn nothing_here_reads_a_clock() {
    // Every deadline arrives as an argument, as it does in `ac_net::admission` and
    // `ac_files::sync`. A machine that reads the clock itself cannot be driven through a
    // four-hour heartbeat or a thirty-minute backoff without actually waiting.
    for (name, source) in sources() {
        let code = code(&source);
        for needle in ["Instant::now", "SystemTime::now", "attest::now"] {
            assert!(
                !code.contains(needle),
                "{name} calls `{needle}`. The clock is an input here — otherwise the backoff \
                 and heartbeat schedules can only be tested by sleeping through them."
            );
        }
    }
}
