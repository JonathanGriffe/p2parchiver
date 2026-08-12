//! The layering rule, enforced by reading the source.
//!
//! `ac-files` is the content layer: it may reason about groups, peers, paths and bytes, and it
//! may not know that a `Swarm` exists. Everything here is therefore drivable with a temp
//! directory and no socket, which is what lets the awkward cases — a hostile group name, an
//! interrupted write, a symlink inside the root — be tested exhaustively and cheaply.
//!
//! # This guard is now load-bearing
//!
//! It did not used to be. `libp2p` was a dev-dependency, so `Swarm` and friends were
//! unnameable in `src/` and the compiler refused them before any grep ran; a second test
//! watched for that changing and said so when it did.
//!
//! It changed. `wire.rs` declares the two protocols, which needs `libp2p` for real, and every
//! forbidden name below is now reachable from anywhere in this crate. The grep is the only
//! thing keeping them out — so `wire.rs` is exempted narrowly, and
//! `wire_is_still_the_seam` guards the exemption from going vacuous, exactly as `ac-groups`
//! does.
//!
//! `libp2p-stream` is a separate matter and stays out of this crate entirely: moving bytes
//! needs an async runtime and a spawned task, so it lives in `ac-node`. Nothing here may name
//! a stream, and the list below says so.
//!
//! It is deliberately crude: a grep over the crate's own source, checking identifiers rather
//! than parsing Rust. A reviewer will not catch a re-added `use`.

// An integration test is its own crate, so the library's test-only allow does not reach here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

/// Types that name libp2p's *networking*. None of these may appear anywhere in this crate.
///
/// `libp2p_stream` is on the list because carrying bytes is `ac-node`'s job: it needs a
/// runtime and a task per transfer, and admitting either here would drag async into a crate
/// whose whole value is being drivable from a test with no socket.
const FORBIDDEN: &[&str] = &[
    "Swarm",
    "SwarmEvent",
    "NetworkBehaviour",
    "ResponseChannel",
    "OutboundRequestId",
    "InboundRequestId",
    "ConnectionId",
    "Multiaddr",
    "libp2p_stream",
];

/// Types that speak a protocol. Confined to `wire.rs`, which is the seam by design: the
/// messages have to be defined somewhere, and everything else stays ignorant of them.
const WIRE_ONLY: &[&str] = &["request_response", "StreamProtocol"];

/// Source with line comments removed.
///
/// The rule is about what the code *names*, not what the prose mentions — the modules here
/// explain what they never touch, and that sentence must not trip this.
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
                "{name} names `{needle}`. The content layer must not know a swarm exists — \
                 the daemon in ac-node is the only code that touches both worlds. If this is \
                 genuinely needed, the operation it belongs to is missing."
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

#[test]
fn moving_bytes_stays_in_the_binary() {
    // `libp2p-stream` must not become a dependency of this crate. A blob transfer needs a
    // runtime and a task per stream, and the moment either lands here the store, the paths and
    // the sync policy stop being testable without one.
    let raw = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .expect("reading Cargo.toml");

    // The manifest's own comment explains why the dependency is absent, so it is stripped for
    // the same reason the source is.
    let manifest: String = raw
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        !manifest.contains("libp2p-stream"),
        "ac-files has taken a dependency on libp2p-stream. Streaming belongs in ac-node, \
         which is the only crate here allowed an async runtime."
    );
}
