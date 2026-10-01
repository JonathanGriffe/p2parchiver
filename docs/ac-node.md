# ac-node

The client node, built as the `ac` binary. It runs the daemon, which puts every layer onto one libp2p swarm and carries out what their state machines decide, and it holds the operations, the actions on a node's home that the CLI and the desktop app both call. It depends on every other client crate (`ac-net`, `ac-groups`, `ac-files`, `ac-import` and `ac-peers`), and only `ac-desktop` builds on it.

Paths below are relative to `crates/ac-node/`.

## Features

- **CLI**: the `ac` binary and its commands (`id`, `join`, `run`, `probe`, `peer`, `group`, `file` and `import`) in `src/main.rs` and `src/cmd/`.
- **Daemon**: the event loop that drives the swarm and every layer in `src/daemon.rs`.
- **Links**: connect each layer's state machine to the swarm: chains in `src/group_link.rs`, catalogues and inbound file transfers in `src/file_link.rs`, the supervisor in `src/peer_link.rs`, and imports in `src/import_link.rs`.
- **File transfers**: the `/ac/blob/1.0.0` protocol in `src/blob.rs`.
- **Bandwidth**: the shared download and upload limits, built on `ac-net`'s rate limiter.
- **Operations**: the actions the CLI and the desktop app share in `src/ops/`: joining a server, groups, files, contacts and status, imports, and the node lock.
- **Contacts**: peers named by hand in `src/contacts.rs`, merged with fellow group members into one list of names in `src/directory.rs`.
- **Status**: the supervisor's snapshot, published for the CLI and the desktop app, in `src/status.rs`.
- **Diagnostics**: `ac probe`, a 20 s connectivity check covering UPnP, AutoNAT, a relay reservation and optionally a hole punch to one peer, in `src/cmd/probe.rs`.

## Design

### Daemon

The daemon is a single task waiting on the 5 s housekeeping tick, swarm events, finished imports, finished file transfers, inbound file streams and Ctrl-C. It owns every link and passes them where they are needed, so nothing needs a lock.
The daemon is event-driven when possible to avoid unneccesary delays, and the housekeeping tick is only used when no event is available for the feature. 

On each tick it:
- runs the server link's and admission's housekeeping;
- promotes the peers that are admitted and settled, and tells the supervisor about them;
- ticks every layer;
- measures free and held space once, and hands the same numbers to the supervisor and the import scheduler, so downloads and imports share one storage budget.

After every swarm event it feeds the supervisor what the chain and catalogue rounds finished.

The layers only decide, and the links carry it out. Each link takes the actions its state machine returns, sends the requests they call for, and turns the answers back into events. No layer's state machine touches the swarm.

### CLI and desktop app

The CLI and the desktop app call the same operations, each of which opens what it needs from the node's home, so both behave and word things the same way. They reach a running daemon only through `state.sqlite`: an action is written there and the daemon picks it up on its next tick, and the daemon publishes the supervisor's status there on every tick. A status older than 60 s means the daemon is not running. Logs go to stderr, so stdout stays parseable.

Only one daemon may run on a home. `ac run` and the desktop app take a lock on `node.lock`, since two daemons would share an identity and a database without knowing it.

### File transfers

A download sends the group, the path, the hash and the offset to resume from, framed as a 4-byte length followed by CBOR. The peer answers with the number of bytes it will send, or refuses, then streams the raw bytes in 64 KiB chunks.
- **Resuming.** The receiver resumes from what it staged on an earlier attempt, and keeps the partial when a transfer ends early.
- **Final failures.** More bytes than announced, or bytes that do not hash to what was asked, are final: the supervisor does not ask that peer for that file again. A wrong hash also discards the partial.
- **Serving.** A node serves a file only to a ready peer the group is shared with, and only if it holds that exact hash. A file its index claims but that is missing on disk is refused, and the index is corrected so it is fetched again.
- **Limits.** At most 8 downloads and 64 uploads at once. Past 64, a request is refused.
- **Imports first.** Before downloading, the node looks in `.unsorted`. If the bytes were imported and not yet sorted, they are moved into the group instead. Any failure there falls back to downloading.

### Bandwidth

`bandwidth_max` in the config caps downloads and uploads separately. The download limit is shared by transfers from peers and by imports. Each limit is a token bucket with a burst of two 64 KiB chunks. A foreground `ac import fetch` has a limit of its own, since it assumes no daemon runs beside it.

### Imports

The import link runs the import workflow described in `ac-import` from the daemon's tick:
- **Scans.** One at a time, stalest source first, on a blocking thread. A failed scan backs off from 60 s, doubling up to 16 h, and an absent source is tried again after 5 minutes. Both are kept in memory, so a restart scans again.
- **Fetches.** Up to 8 workers, each claiming 8 references at a time so that a short queue is shared out. Only one goes looking when the queue was last found empty. Workers stop between files, never during one, when the disk is full or the node shuts down.
- **Tidying.** Each tick removes one-shot sources once all their files are sorted or dropped.

Sorting moves the bytes into the group, copying them if the group is on another disk, and only then records the file. Dropping only marks the file, so it can be undone until the session ends, and its bytes are deleted when the daemon next starts. Undoing a sort takes the file back out of its group as a removal, so the group's other members learn it left. `ac import drop` deletes the bytes at once, since the CLI has no undo.

### Joining, groups and files

`ac join` decodes the invite token and enrols with the server under the chosen username, giving up after 30 s. It checks the attestation it gets back against this node and the server's peer id from the token. Then it keeps one of the server's service addresses as `server` in the config, preferring the same host over QUIC, then the same host, then QUIC, then the first offered. From then on, the node trusts only that server.

Creating or accepting a group needs the username from the attestation, and adding or removing members needs to be the admin. An admin cannot leave a group. Forgetting one drops it and its file index from this node, tells nobody, and leaves its files on disk.

Adding a file copies it in before recording it, and refuses a second copy of bytes the group already holds. `ac file verify` marks files whose bytes are missing as not held, which puts them back on the download list: it repairs, not just reports. At startup, partial downloads untouched for an hour are swept, unless a transfer could still resume them.

## On-disk files

The node's home is `--home`, `AC_HOME`, or the per-OS data directory `archiverclient`.
- `node.lock`: the lock that keeps a second daemon off this home.
- `identity.key`, `attestation.cbor`, `config.toml` and `state.sqlite` belong to `ac-net`.
- `files/`, the storage root: one directory per group, owned by `ac-files`, and `.unsorted/` for imports waiting to be sorted.

## Database

`ac-node` opens every other crate's store on `state.sqlite`, and owns four tables of its own, in WAL mode with a 5 s busy timeout:
- `contacts`: peers named by hand. `peer_id` (primary key) and `label`.
- `supervisor_at`: a single row (`id` 0) with when the snapshot was taken (`at`), the bytes moved since the daemon started (`down`, `up`), and the current rates in bytes per second (`down_rate`, `up_rate`).
- `supervisor_groups`: one row per active group, keyed by `group_id`, with `missing`, `owed`, `next_peer`, `source`, `content_until` and `heartbeat_at`.
- `supervisor_peers`: one row per member of an active group, keyed by `peer`, with `connected`, `online`, `retry_at`, `rounds`, `transfers` and `closing`.

The three `supervisor_` tables are rewritten whole on every tick, in one `IMMEDIATE` transaction. They hold nothing that cannot be recomputed, so a table with an older shape is dropped rather than migrated.
