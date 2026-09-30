# ac-server

The server binary, run by the network's operator. It hands out single-use invites, enrols clients that redeem one, issues and renews the attestations clients show each other, and serves enrolled clients as a relay, rendezvous point, AutoNAT server and presence oracle. It depends on `ac-net` only: it holds no files and mounts no application protocol, so groups, files and imports are never compiled into it.

Paths below are relative to `crates/ac-server/`.

## Features

- **CLI**: parses the commands (`init`, `run`, `invite new|list`, `client list|revoke|unrevoke`) and picks the data directory in `src/main.rs`. Each command lives in `src/cmd/`.
- **Init**: creates the identity, the database and a starter config in `src/cmd/init.rs`.
- **Invites**: generates and hashes invite codes in `src/invite.rs`, and builds the invite token in `src/cmd/invite.rs`.
- **Enrollment**: redeems an invite in `src/store.rs` and answers enrollment requests in `src/daemon.rs`.
- **Attestation**: signs attestations at enrollment and renews them in `src/daemon.rs`.
- **Presence**: answers which of a list of peers are connected in `src/daemon.rs`.
- **Relay, rendezvous and AutoNAT**: mounted by `ac-net`'s swarm builder. The server only logs their events and counts relay circuits in `src/daemon.rs`.
- **Authorizing connections**: the policy for each listener in `src/store.rs`.
- **Revocation**: revoking and restoring clients in `src/cmd/client.rs`, and disconnecting revoked clients in `src/daemon.rs`.
- **Event loop**: drives both swarms in `src/daemon.rs`.

## Design

### Two listeners

One listener cannot both admit strangers so they can enrol and require enrollment so the services are protected. The server therefore runs two swarms from the same identity, each with its own port and policy:
- The service listener, port 4001 over QUIC and TCP, serves relay, rendezvous, AutoNAT, attestation renewal and presence. It accepts enrolled clients that are not revoked.
- The enrollment listener, port 4002 over QUIC only, serves enrollment and nothing else. It accepts anyone except revoked clients.

Policies are checked while the connection is being established, so a refused peer cannot negotiate a single protocol.

A single tokio task drives both swarms and a 5 s housekeeping tick, so there are no locks.

### Fixed ports

Clients learn the service address once, at enrollment, and store it permanently, so an ephemeral port would orphan every client on the next restart. `run` warns if a service address uses port 0.

The server announces the `external` addresses from its config, or its bound addresses when none are set. Link-local IPv6 addresses are never announced.

### Invites and enrollment

An invite token holds a 16-byte random code along with the server's enrollment address and peer id, so it enrols against this server and no other. Only the SHA-256 hash of the code is stored, so a leaked backup holds no live invite, and the token is shown once and cannot be recovered.

To enrol a client, the server:
1. Checks the code's length.
2. Normalises the username. This happens before the invite is touched, so a bad username does not consume it.
3. Redeems the invite in one transaction. Unknown, used and expired codes are refused, as are usernames held by another peer. A taken username does not burn the invite, and a client re-enrolling keeps its own name.
4. Signs a 24 h attestation over the peer id and username, and replies with it, the normalised username and the service addresses.

`init` prints the server's peer id. Clients pin it on first contact, so the operator can compare it with what `ac join` reports.

### Attestation renewal

Clients renew their attestation on the service listener. The request carries no username: the server signs the one stored at enrollment.

### Revocation

Revoking sets the client's `revoked_at` and takes effect without a restart:
- The database is in WAL mode, so the admin CLI can write while the server runs, and both policies query it on every new connection.
- On every housekeeping tick, the server closes the connections, and the circuits on them, of clients revoked since they connected.
- A revoked client cannot renew its attestation.

A revoked client cannot reach enrollment either, so a new invite does not bring it back. `client unrevoke` does.

### One connection per client

When a client reconnects, the server closes its previous connection so relay circuits reach the live one. The old connection's close arrives after the new one is recorded, so it must not clear the record.

### Presence

The server answers which of the peers asked about (at most 256) are connected to it. It never lists who is connected.

### Logging

Logs go to stderr so stdout stays parseable for commands that print a peer id or a token. Relay use is summed up once per tick, naming the busiest client, and nothing is logged while idle.

## On-disk files

They live under `--home`, `AC_SERVER_HOME`, or the per-OS data directory `archiverclient-server`, kept distinct from the client's so both can run on one host. The file names come from `ac-net`.
- `identity.key`: the server's keypair, written by `ac-net`.
- `config.toml`: `listen`, `listen_enroll` and `external`. `init` writes a commented starter config and never overwrites an existing one, so an operator's edits survive a re-init.
- `state.sqlite`: the database below.

## Database

`state.sqlite`, in WAL mode. `run` opens three connections to it: one for the request handlers and one for each listener's policy. Times are Unix seconds.
- `invites`: one row per invite. `code_hash` (primary key, hex SHA-256 of the code), `label` (the operator's note on who it is for), `expires_at`, `redeemed_by` and `redeemed_at`.
- `clients`: one row per enrolled client. `peer_id` (primary key), `username` (unique when set), `enrolled_at`, `revoked_at`, and `label`, left over from before usernames. Opening the store upgrades such databases by adding `username` and copying `label` into it.
