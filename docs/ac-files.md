# ac-files

The application's content layer. It keeps each group's catalogue, the list of files the group holds, reconciles catalogues between members over `/ac/manifest/3.0.0`, and stores the files' bytes on disk. It decides and records but never moves bytes between peers itself: `ac-node` does the I/O, including the `/ac/blob/1.0.0` transfers whose messages are defined here. It depends on `ac-net` and `ac-groups`, and `ac-peers` and `ac-node` build on it.

Paths below are relative to `crates/ac-files/`.

## Features

- **Paths**: validates group-relative paths so they stay inside their group, and derives conflict names, in `src/path.rs`.
- **Directory names**: turns a group's name into a safe directory name in `src/dirname.rs`.
- **Content**: stores, resumes, moves and removes files' bytes on disk in `src/content.rs`.
- **Catalogue**: records local files and merges rows from peers, resolving collisions and duplicates, in `src/store/mod.rs`, with the rules for picking a winner in `src/store/row.rs`.
- **Change log**: each group's log, how far each peer has read it, the catalogue digest, and the counters the supervisor reads, in `src/store/log.rs`.
- **Sync**: the state machine that reconciles catalogues with peers, and the check for whether a peer may download a file, in `src/sync.rs`.
- **Wire**: the manifest and blob messages and size limits in `src/wire.rs`.

## Design

### Catalogue

A group's catalogue has one row per path, with the file's size, SHA-256 hash, modification time, when and by whom it was added, and when it was removed. A removed file keeps its row as a tombstone, so a peer still holding the file cannot hand it back. Each row also records whether this node holds the bytes, which is local and never shared.

### Change log and digest

Every write to the catalogue stamps the row with the next position in the group's log. Peers read each other's log from a cursor, so a file learned late is still new to a third member, however long ago it was added. Positions are counted rather than read off the rows, so a number is never handed out twice.

Each catalogue also has a digest: a hash of every row's path, hash, and added and removed times, tombstones included. Whether the bytes are held is left out, so two peers with the same catalogue but different downloads still agree. The digest is cached against the log position and recomputed once it moves, including when another process wrote.

### Reconciliation

1. A node asks a peer for its heads: the digest and row count of each group they share, at most 128. The sync machine never asks itself, as the supervisor in `ac-peers` decides who to ask.
2. A group whose digests match is settled. Otherwise the node reads the peer's log from its stored cursor, a page of up to 2048 rows at a time, merging each row and moving the cursor to where the peer said the page ended.
3. Once the log is drained, the digests are compared again. If they still differ, the cursor is reset and the whole log is read once more: the cursor is an optimisation, the digest is the check.

A group is read from one peer at a time, with at most 8 reads in flight and up to 256 more queued. Reads time out after 30 s, and a page that does not match the outstanding read is dropped. A failed request frees the slot but does not settle the group, since nothing said there was nothing left to read.

### Merging

Every rule depends only on the rows, so peers converge without coordinating.
- Same path, same hash: the earliest added time and the latest removal are kept.
- Same path, both live, different hashes: the most recently changed row keeps the path, with the hash breaking ties. The other is kept under `<stem>.conflict-<hash prefix><ext>`, a name every peer derives the same way.
- Same path, one live and one removed: the most recently changed row wins, so a stale re-add cannot bring back a tombstone.
- Same hash under two live paths of one group: the path added first is kept and the other is tombstoned. The bytes are moved over if only the dropped path held them, so dedup never deletes the only copy. Dedup never crosses groups, since two groups are two membership boundaries.

### Removal

Removing a file tombstones its row if the row may have left the node. A row that was never served to anyone has nobody to hand it back, so it is deleted outright, though its log position is still spent so the digest changes. The caller deletes the bytes.

### News and wanted

The store keeps two counters for the supervisor: the changes this node made itself and has not told the group yet, and the new rows whose bytes it does not hold. Rows merged from peers are not news, so members do not re-announce what they were just told. Marking bytes as held or missing is not a change either, so a download is not announced to the group.

### Who sees what

Only admitted peers get answers, at most 8 per peer per tick, and heads are only acted on from ready peers. A group's catalogue and bytes only go to peers `ac-groups` shares the group's content with: fellow members, while the group is active here. To anyone else the group does not exist. A file's bytes are only served if its row is live and held.

### Paths

A path must be relative, `/`-separated, at most 1024 bytes with components of at most 255, and free of empty, `.` or `..` components, backslashes and control characters. Paths from peers are checked as their rows arrive, so a hostile path is rejected.

### Storage

Each group's files live in their own directory under the storage root, named after the group. The name may come from a remote admin, so separators and control characters are replaced and dots and whitespace trimmed from both ends, so it can neither escape the root nor hide. When two groups end up with the same name, a widening prefix of the group id is appended, so someone reading a backup can tell which group a directory belongs to.

Bytes are first written to the group's `.staging` directory and fsynced, then renamed into place, and the parent directory is fsynced so the rename survives a crash. An interrupted download resumes from its partial file if its length matches where the transfer restarts, and starts over otherwise. Partials no transfer still wants are swept once idle.

### Wire

Requests are capped at 64 KiB and responses at 1 MiB, and tests check that a full page of 2048 rows, 128 heads and a 512-path holdings query all fit. A holdings query asks which of a list of paths a peer holds, and is answered with a bitmap. Hashes travel as raw bytes.

## On-disk files

- `files/`: the storage root, unless `storage_root` in the node's config says otherwise. It holds one directory per group, each with a `.staging` directory for partial files. The `.unsorted/` directory, where imports wait to be filed, belongs to `ac-node`.
- Its tables live in the node's `state.sqlite`, which `ac-node` opens for it.

## Database

The tables are prefixed with `file` because `state.sqlite` is shared with other crates. The database is in WAL mode with a 5 s busy timeout, and every write runs in an `IMMEDIATE` transaction, so the CLI and a running daemon can use it at once. Hashes are stored as hex, peer ids as base58, and times as Unix seconds.
- `file_roots`: each group's directory under the storage root. `group_id` (primary key) and `dir` (unique).
- `files`: the catalogues. One row per file, keyed by `(group_id, path)`, with `size`, `hash`, `modified`, `added_at`, `added_by`, `removed_at`, `have` (whether the bytes are on this disk) and `seen_seq` (its position in the log). Indexed on `hash` and on `(group_id, seen_seq)`.
- `file_sync`: how far this node has read each peer's log. `cursor`, keyed by `(group_id, peer)`.
- `file_state`: one row per group, only touched by `src/store/log.rs`. `seq` (the last log position handed out), `served_seq` (the highest position ever served), `digest` and `digest_seq` (the cached digest and the position it was computed at), `changes` and `last_change` (this node's untold changes), and `wanted` (new rows whose bytes are missing).

Forgetting a group deletes its rows from all four tables.
