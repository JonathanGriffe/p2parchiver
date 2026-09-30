# CLAUDE.md

archiverclient keeps a group's photos and videos mirrored across its members' machines, peer to peer, with a server only for enrolment, attestation, discovery, presence and relaying. It is a Rust workspace with one crate per layer. These notes apply to every agent working here, whether triaging, coding or reviewing.

## Read the docs first

Before triaging a ticket, writing code or reviewing a change, read:
- `docs/ARCHITECTURE.md`: the layers, the trust model and the known limits.
- `docs/NON-FUNCTIONAL-REQUIREMENTS.md`: the properties the system must keep to work at all.
- `docs/<crate>.md` for every crate the task touches, such as `docs/ac-files.md`.

Then read the code. The docs say what the code does and why. Where they disagree with the code, trust the code and fix the doc.

## Respect the design

A change must fit the design those docs describe. If a task cannot be done without breaking it, stop and say so rather than working around it. Breaking the design includes:
- a dependency against the layering: `ac-net` ← `ac-groups` ← `ac-files` ← `ac-peers` ← `ac-node` ← `ac-desktop`, with `ac-import` depending on nothing and `ac-server` only on `ac-net`;
- libp2p used outside `ac-net`, `ac-node` and `ac-server`;
- IO inside a sync machine or the supervisor: they take events and return actions, and `ac-node`'s links do the networking;
- group or file logic in the server, which stays at the network layer;
- the desktop app bypassing `ac-node`'s operations, or anything reaching the daemon other than through `state.sqlite`;
- weakening or dropping a non-functional requirement.

Details change all the time, and the docs change with them. Changing the design itself is the maintainer's decision, not an agent's.

## Keep the docs current

A change to behaviour, a protocol, a limit, a table or an on-disk file updates the matching doc in the same change, and a new or changed guarantee updates `docs/NON-FUNCTIONAL-REQUIREMENTS.md`. Crate docs keep the same sections: an intro, Features, Design, On-disk files and Database. Describe the code as it is, in plain words, without line numbers, which go stale.

## Conventions

- Pre-release, with no users: a schema change edits the `CREATE TABLE` directly, with no migration. The `ALTER TABLE` in `ac-server`'s store is a leftover, not a pattern.
- Changing a wire message bumps its protocol's version, such as `/ac/group/5.0.0`.
- Comments are short. A one-line doc comment saying what a function does is welcome. Inside a function, comment only what is not obvious. No long rationale blocks for new code.
- The desktop UI has no explanatory labels: placeholders, buttons, section titles and the shared message line carry it. Confirm dialogs before destructive actions are the exception.
- Commit subjects follow conventional commits (`feat:`, `fix:`, …), since they set the version and are the release notes.
- Edit files with edit tools rather than `sed` or heredocs, so every change shows in the diff.

## Build and test

- CI runs `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test --workspace` on Linux and Windows.
- If a build fails for lack of disk space, delete `target/debug/incremental` before anything else.
- `scripts/mirror-lab.sh` runs release builds end to end on loopback. Hole punching cannot be exercised on loopback and has to be tested on real networks.

## Pitfall: the connection that outlives a restart

When a node restarts, its peers keep the old, dead connection for 10–15 s beside the new one, and anything addressed per peer rather than per connection can pick the dead one. This has caused bugs in the server's relay and in admission. When something works on first connect but not after a restart, suspect this first. A failure on one connection is not a verdict on the peer, and tearing down every connection to a peer because one failed is almost always too broad.
