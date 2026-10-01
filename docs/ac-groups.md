# ac-groups

The application's group layer. It defines what a group is, a log of membership changes signed by the group's admin (the "chain"), alongside each member's own signed statement of where it stands (its "standing"). It verifies both, stores them, and syncs them with peers over `/ac/group/5.0.0`. It depends on `ac-net` only, and `ac-files`, `ac-supervisor` and `ac-node` build on it.

Paths below are relative to `crates/ac-groups/`.

## Features

- **Ids**: group ids and entry hashes in `src/id.rs`.
- **Chain**: the admin-signed membership log, its validation rules, and folding it into the current members in `src/chain.rs`.
- **Members**: membership at a point in the chain, and the digest of members' standings, in `src/members.rs`.
- **Standings**: a member's signed statement of where it stands, and which of two statements wins, in `src/standing.rs`.
- **Store**: stores groups in SQLite and decides what to ingest and what to serve to whom in `src/store.rs`.
- **Sync**: the state machine that exchanges chains and standings with peers in `src/sync.rs`.
- **Wire**: the protocol's messages and size limits in `src/wire.rs`, and serde adapters that encode byte arrays as CBOR byte strings in `src/bytes.rs`.

## Design

### Chain

A group is a hash-linked log of `Create`, `Add` and `Remove` operations, and only the admin named in its first entry, the genesis, can sign entries. The admin cannot be removed, since that would leave the group with no writer.

A group's id is the hash of its genesis. The genesis cannot contain its own id, so its group field is zero, and every later entry must carry the real id. A random nonce in the genesis keeps two otherwise identical groups apart.

Each new entry must have the next seq, point to the current head, belong to the group and be signed by the admin. An `Add` is refused for a peer whose public key cannot be recovered from its id, because such a peer could never sign a standing and so could never leave. A `Remove` must name a current member. An entry's size is capped at 4 KiB and checked before anything is parsed. A batch of entries is applied all or nothing.

Order comes from the seq, never from the timestamp, so a clock running backwards does not reorder membership.

Entries and standings are kept as the exact bytes that were signed and never re-encoded, so their signatures and hashes survive the trip over the wire.

### Standings

Membership comes from the chain alone. On top of it, each member signs a standing for each group: `Unanswered`, `In` or `Out`, along with its username. A member saying `Out` prompts the admin to write a `Remove`. Until then the chain still lists the member, and the member's own local state keeps it from taking part.

Between two standings from the same peer, the higher seq wins, and on a tie the smaller body wins, so every node settles on the same one without coordinating. A node's own seq always climbs past the highest it holds, so restoring from a backup does not reuse one.

A standing is only accepted about a peer the chain has mentioned at some point, so peers cannot fill the database with statements about strangers. Once a peer is no longer a member, its standing is deleted, since the `Remove` is now the record. Otherwise its old `Out` would beat the fresh standing of the same peer re-added later.

### Heads

Peers compare groups by their head: the last seq and hash, and a digest of the members' standings, usernames included. Heads can match while one side is missing a departure, and the digest catches that. Only current members' standings go into the digest, so stray rows cannot cause endless re-syncs.

### Consent

Each node records its own consent to each group: `Pending` when invited, `Active` once accepted, `Left` once it left. Only the node changes it, never the admin, so a node re-added after leaving stays `Left` until it accepts again.

### Who sees what

A group is only named to a peer if both are members, so a non-member does not learn it exists.
- Content is shared only in `Active` groups.
- Chains are offered in `Active` and `Pending` groups, because staying silent while pending would look like a refusal.
- Current members get the whole chain. Former members get it up to their removal, so they learn they were removed and nothing after. Strangers get nothing, so a guessed group id reveals nothing.

A node that is pending or has left still answers fetches, since it holds the only copy of its own standing. A node the chain does not name serves nothing.

### Sync

The sync machine does no IO: it takes events and returns the fetches to send, and is handed `AdmittedPeers` on every call, to know who is admitted and who is ready. It never asks for heads itself, as `ac-supervisor` decides who to ask.
- Requests are answered only for admitted peers, at most 8 per peer per tick.
- From a peer's heads, it fetches groups it has never seen from the start, and known groups where the peer is ahead or the digests differ.
- A group it holds that names the peer, but that the peer did not offer, gets one fetch too. That is how a removal is learned, since nobody offers a group to someone they no longer count as a member.
- A group is fetched from one peer at a time, with at most 8 fetches in flight and up to 256 more queued. Fetches time out after 30 s, and a response that does not match the outstanding fetch is dropped.
- A new group is stored, as `Pending`, only once its whole chain has been verified, so an offer alone never creates a row.

After ingesting, a pending node named by the group writes an `Unanswered` standing if it has not spoken yet, so others stop re-offering the chain. If the node is the admin, it writes a `Remove` for each member whose newly winning standing is `Out`.

An invitation that was never accepted and no longer names the node is forgotten after 30 days.

### News

The store counts the membership changes this node made itself and has not told the group yet, which the supervisor uses to decide who to call. Changes adopted from peers do not count, so a node does not tell a group what it just learned from it.

### Wire

Serde encodes byte arrays as arrays of integers by default. `src/bytes.rs` encodes them as CBOR byte strings instead, because entry size limits how much history a group can carry. Requests are capped at 64 KiB, responses at 1 MiB, and an answer at 128 heads.

## On-disk files

None of its own. Its tables live in the node's `state.sqlite`, which `ac-node` opens for it.

## Database

The tables are prefixed with `group_` because `state.sqlite` is shared with other crates. The database is in WAL mode with a 5 s busy timeout. Every write runs in an `IMMEDIATE` transaction, and the head moves by compare-and-swap, so a concurrent writer is detected. Ids and hashes are stored as hex, peer ids as base58, and times as Unix seconds.
- `groups`: one row per group held. `group_id` (primary key), `name`, `admin`, `state` (`pending`, `active` or `left`), `head_seq`, `head_hash`, `standings_digest`, `first_seen`, `last_synced` and `news`.
- `group_entries`: the chains. One row per entry, keyed by `(group_id, seq)`, with its `hash` and the signed `body` and `signature`.
- `group_standings`: each current member's winning standing, keyed by `(group_id, peer)`, with its `seq`, `position` and the signed `body` and `signature`. The username is read from the body rather than stored in a column, so the only copy is the signed one.
- `group_members`: a cache of the membership folded from the chain, keyed by `(group_id, peer)`, with `username` and `is_admin`, and indexed on `peer`. It is rebuilt in the same transaction that changes the chain.

Forgetting a group deletes its rows from all four tables and tells nobody.
