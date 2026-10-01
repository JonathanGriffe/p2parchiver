# Architecture

## Overview

This project builds to two apps :
- **The node** (ie the `ac-desktop` crate), runs the peer and the desktop app.
- **The server** (ie the `ac-server` crate) enrols nodes, grants attestation, and helps them connect:
  rendezvous for discovery, a relay and AutoNAT for NAT traversal, and answer presence queries.


## Assumptions

In this project, we assume the following about the context of use.

**Scale**
- The network has about 50 max users.
- Every user is part of about 20 max groups.
- Every group has about 20 max users.

**Data**
- Content is photos and videos: written once, rarely edited.
- Membership changes are rare.

**Environment**
- One node per machine.
- Nodes are online intermittently, and we accept that sync is eventual.

## High-level network design

In this project, the server is only involved in a couple aspects:
- Enrollment: registering users with an invite code, and only letting enrolled users use the following features
- Attestation: giving attestations (ie certificates) to enrolled users so they can verify they only communicate with enrolled users
- Discovery and presence: seeing which peer ids are online.
- Relay and AutoNAT: helping peers do NAT traversal and relaying connections if it doesn't work

Notably, the server is not involved in the following:
- Identities: they are determined only by the client's keys and peer id, which the server does not control (it only attest them)
- Groups and file sharing: the server is only involved at the network layer, and not in groups and file sharing.

This design achieves a peer to peer network where each peer is verified by the server, while keeping full control of their identity. The network layer is implemented using libp2p.

## Trust model

Three kinds of authority, each backed by its own signature and checked by every node:

| Authority | Signs | Decides | Checked |
| --- | --- | --- | --- |
| The server | Attestations: a peer id and its username, valid 24 h | Who is enrolled | On every connection with the server and between two nodes |
| A group's admin | The group's chain: creation, adds, removals | Who is in the group | On every group operation (membership and file sharing) |
| Each member | Its own standing: not answered yet, in, or out | Whether it takes part, and the name it shows in the group | On every standing a node receives |

Identity belongs to the node: its key is generated locally and never leaves the machine, and
the server only vouches for it. The server's own key is the root of trust. The invite token
carries it, the node pins it at enrolment, and from then on only attestations signed by it
are accepted.

## Crates

The design is implemented with the following crate structure :
```
ac-desktop ─► ac-node ─┬─► ac-peers ─► ac-files ─► ac-groups ─► ac-net
                       └─► ac-import                              ▲
                                                   ac-server ─────┘
```

- `ac-net` is the network layer of the project, which is why it is one of the only crates (with ac-node and ac-server) which depends on libp2p. It implements every network layer service used by both the client and server, such as attestation and presence protocols. It allows layers on top of it to mount protocols, and also moves bulk bytes and caps bandwidth for them.
- `ac-server` is the crate implementing the server for this network. As it only participates in the network layer, it only depends on the `ac-net` crate.
- `ac-groups` adds the group layer, which allows creating groups, inviting and removing users from them. This is the first of the three middle layers, which are separate from the network layer, and therefore depend only on the lower layers and not libp2p.
- `ac-files` adds file sharing through groups, as well as the per-group file catalogue and syncing method.
- `ac-peers` is the supervisor, which decides what actions to take, such as dialing, what files to fetch and when to hang up.
- `ac-import` is the crate for importing files from sources. It is not part of the peer to peer network, instead it allows connecting sources such as a google drive and pulling media from them automatically, so that they might be shared in the p2p network later. As such, it depends on nothing in the workspace.
- `ac-node` runs the client's daemon and includes the node CLI, and therefore depends on all lower layers and ac-import, as well as libp2p.
- `ac-desktop` is the desktop app, and uses `ac-node` to run the daemon and connect to the p2p network.

## Database

The node keeps all its state in one SQLite file, `state.sqlite` in its home directory. Each
store opens its own connection to it (groups, files, the import ledger, contacts, status), and
so does every process: the daemon, the `ac` CLI and the desktop app.

- **Concurrency.** Every connection uses WAL mode and a 5 s busy timeout, so readers never block
  and writers take turns, across threads and processes alike.
- **The database is the interface to the daemon.** There is no socket. The CLI and the desktop
  app write through `ac_node::ops`, and the running daemon picks the change up on its next tick.
  In the other direction, the daemon rewrites the `supervisor_*` tables on every 5 s tick. A
  snapshot older than 60 s means the daemon is not running.
- **Sensitive.** `sources.config` holds import credentials, such as the Google Drive refresh
  token, in plain text.

The server has its own `state.sqlite`.

## Known limits

These are deliberate for now:

- **No chain compaction.** A group's chain is sent whole, in one response of at most 1 MiB
  that also carries the standings. At roughly 340 bytes an entry, that is about 3,000
  membership changes before a new member can no longer fetch it. The test
  `a_chain_transfers_at_a_size_that_leaves_room_for_real_history` pins the per-entry cost.
- **One permanent admin per group**, with no transfer, removal or key rotation.
- **Revocation reaches other nodes only through expiry**, up to 24 h later.
- **One rendezvous namespace per server**, so every enrolled client can discover every other.
- **Platform gaps.** The tray, start at login and "show in folder" work only on Linux and Windows, and ffmpeg
  is vendored only for x86_64 Linux and Windows.
- **Import backoff lives in memory**, so a restart scans again.

## Testing

- Unit tests sit next to the code.
- Integration tests in `crates/*/tests/`
- `scripts/mirror-lab.sh` runs release builds end to end on loopback: a server, several
  nodes, and the desktop app with `--headless`. It checks 11 behaviours, from "they find
  each other, unprompted" to "one daemon per home". Loopback cannot exercise NAT traversal,
  and no automated test does.

## Build, CI and release

- `cargo build` and `cargo test --workspace`. The toolchain is pinned to stable in
  `rust-toolchain.toml`.
- CI (`.github/workflows/ci.yml`) runs fmt, clippy with `-D warnings`, and the tests on Linux
  and Windows.
- On `main`, `scripts/tag.sh` picks the version from conventional commit subjects:
  `BREAKING CHANGE` bumps major, `feat:` bumps minor, anything else bumps patch. The
  `ac-server` image is published and deployed by bumping its chart in the infra repository.
  Desktop packages (deb, AppImage, NSIS) are built with cargo-packager. Commit subjects are
  the release notes. Details are in [`deploy/README.md`](../deploy/README.md).
