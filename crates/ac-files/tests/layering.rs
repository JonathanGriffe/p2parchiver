//! The layering rule, enforced by reading the source.
//!
//! `ac-files` is the content layer: it may reason about groups, peers, paths and bytes, and it
//! may not know that a `Swarm` exists. Everything here is therefore drivable with a temp
//! directory and no socket, which is what lets the awkward cases — a hostile group name, an
//! interrupted write, a symlink inside the root — be tested exhaustively and cheaply.
//!
//! # What is actually holding the line today
//!
//! Mostly the dependency graph, not this file. `libp2p` is a dev-dependency only, so `Swarm`
//! and friends are unnameable in `src/` and the compiler refuses them before any grep runs.
//! The one exception is `Multiaddr`, which `ac-net` re-exports and which this crate could
//! therefore reach.
//!
//! That changes in the next milestone: transfer needs wire types, wire types need `libp2p`,
//! and the moment it becomes a real dependency this grep is the only thing left. So the second
//! test watches for exactly that, and fails when it happens — the point is to hand the next
//! author the decision rather than let the guard quietly become load-bearing unnoticed.
//!
//! It is deliberately crude: a grep over the crate's own source, checking identifiers rather
//! than parsing Rust. A reviewer will not catch a re-added `use`.

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
    "request_response",
    "StreamProtocol",
];

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
fn libp2p_is_not_a_direct_dependency_yet() {
    // Guards the guard, the other way round from `ac-groups`. There, `wire_is_still_the_seam`
    // checks an exemption has not gone vacuous. Here the whole grep is nearly vacuous *by
    // construction*, and this says so out loud — so that the milestone which changes it has to
    // notice, rather than inheriting a test that looks stronger than it is.
    let raw = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .expect("reading Cargo.toml");

    // The manifest's own comment explains that libp2p is deliberately absent, so it has to be
    // stripped for the same reason the source is.
    let manifest: String = raw
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");

    let (deps, dev) = manifest
        .split_once("[dev-dependencies]")
        .expect("a dev-dependencies section");

    assert!(
        !deps.contains("libp2p"),
        "libp2p is now a real dependency of ac-files, which is expected once this crate \
         carries wire types. The grep above just became the only thing keeping a `Swarm` out \
         of it — check it still covers what it should, then delete this test."
    );
    assert!(
        dev.contains("libp2p"),
        "the dev-dependency went away; this test no longer describes the situation"
    );
}
