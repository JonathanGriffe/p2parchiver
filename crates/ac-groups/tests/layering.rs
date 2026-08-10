//! The layering rule, enforced by reading the source.
//!
//! `ac-groups` is the group layer: it may reason about peers, keys and chains, and it may not
//! know that a `Swarm` exists. The whole of [`ac_groups::sync`] is therefore drivable with no
//! socket, which is what lets its policy be tested exhaustively and cheaply.
//!
//! A reviewer will not catch a re-added `use`, so this does. It is deliberately crude: a grep
//! over the crate's own source, checking identifiers rather than parsing Rust.

// An integration test is its own crate, so the library's test-only allow does not reach here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

/// Types that name libp2p's *networking*. None of these may appear anywhere in this crate.
const FORBIDDEN: &[&str] = &[
    "Swarm",
    "SwarmEvent",
    "NetworkBehaviour",
    "ResponseChannel",
    "OutboundRequestId",
    "InboundRequestId",
    "ConnectionId",
    "Multiaddr",
];

/// Types that speak the wire protocol. Confined to `wire.rs`, which is the seam by design:
/// the messages have to be defined somewhere, and everything else stays ignorant of them.
const WIRE_ONLY: &[&str] = &["request_response", "StreamProtocol"];

/// Source with line comments removed.
///
/// The rule is about what the code *names*, not what the prose mentions — several modules
/// explain at length that they never touch a `Swarm`, and that sentence must not trip this.
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
                "{name} names `{needle}`. The group layer must not know a swarm exists — \
                 the daemon in ac-node is the only code that touches both worlds. If this is \
                 genuinely needed, the event or action it belongs to is missing."
            );
        }
    }
}

#[test]
fn only_wire_speaks_request_response() {
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
fn wire_is_still_the_seam() {
    // Guards the guard: if wire.rs were renamed or emptied, the exemption above would silently
    // start covering nothing and the test would pass for the wrong reason.
    let (_, wire) = sources()
        .into_iter()
        .find(|(name, _)| name == "wire.rs")
        .expect("wire.rs exists");
    assert!(
        code(&wire).contains("request_response"),
        "wire.rs no longer speaks request_response; the exemption is now vacuous"
    );
}
