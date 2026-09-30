# ac-import

The application's sources. It brings photos and videos in from outside the network, such as a local folder, Google Drive or a phone on the same Wi-Fi, so they can be sorted adn shared into groups. It defines the `Source` trait every source implements, the registry of sources built in, and the ledger that records what each source offered and what became of every imported file. It depends on nothing in the workspace. `ac-node` drives the imports, and `ac-desktop` builds its Sources page from the registry.

Paths below are relative to `crates/ac-import/`.

## Features

- **Sources**: the `Source` trait, what a source offers, the checksum check and the media filter in `src/source.rs`.
- **Registry**: the table of sources built in, generated from `src/sources/` by `build.rs`, in `src/registry.rs`.
- **Settings**: the fields a source declares and the answers stored for them in `src/config.rs`.
- **Ledger**: the configured sources, the files still owed, and the history of imported files in `src/ledger.rs`.
- **Verdict**: what to do with a file once its hash is known in `src/verdict.rs`.
- **Sign-in and HTTP**: OAuth sign-in and token refresh in `src/oauth.rs`, and timeouts for HTTP calls in `src/http.rs`.
- **Folder source**: a one-time import of a local file or folder in `src/sources/folder.rs`.
- **Drive source**: Google Drive, read-only, in `src/sources/drive.rs`.
- **Phone source**: a companion app on the same Wi-Fi in `src/sources/phone.rs`, and the listener phones pair and check in with in `src/sources/phone/listener.rs`.

## Design

### Import workflow

```
scan ─► each file ─┬─► new ─────────────────────────────┬─► owed ─► claim ─► fetch ─► check ─┬─► new content: keep
                   ├─► fetch previously failed 3 times ─┤                                    ├─► imported before: discard
                   ├─► already queued ──────────────────┘                                    ├─► held by a group: discard
                   ├─► already fetched ─────────────────┬─► not owed                         ├─► failed: retried in 1 h
                   └─► not a photo or video ────────────┘                                    └─► gone: forgotten
```

1. **Scan.** A source lists what it offers a page at a time: for each file a reference that stays the same across scans, a name, the folder it sits in, and optionally a size and a checksum. Each file is then compared with what the ledger holds for that source:
   - **new**: a reference the ledger has no row for. It becomes owed.
   - **fetch previously failed 3 times**: still owed, but its fetch failed 3 times, the most allowed between two scans, so claims have been skipping it. The source still offers it, and the failure may have passed, such as a phone leaving the Wi-Fi mid-transfer, so it gets 3 fresh attempts. A file that never downloads correctly therefore costs up to 3 attempts per scan, for as long as the source lists it.
   - **already queued**: still owed, with attempts left. It is already waiting to be claimed, so nothing changes.
   - **already fetched**: settled, so nothing changes. A file edited at the source under the same reference is therefore not fetched again.
   - **not a photo or video**: judged by extension, since the choice has to be made from a listing before anything downloads. `ac-node` applies this filter, so no source can forget it.

   After a complete scan, references whose fetch failed 3 times and that the scan did not offer again are retired, since the source no longer has them.
2. **Claim.** The node claims a batch of owed references, and the claim counts the attempt in the same write, so two claims never take the same reference. A claim left behind by a crash comes back an hour later.
3. **Fetch and check.** The bytes are written under `.unsorted` as they arrive, hashed on the way, and checked against the size and checksum the source promised at scan time. Bytes that fail the check, or a fetch that fails, are thrown away, and the reference is tried again an hour later, 3 times at most. A reference the source says is gone is forgotten, until a scan offers it again.
4. **Verdict.** Once the bytes pass the check, their hash decides:
   - **imported before**: the hash is in `imported`, because this node imported the same content before, from any source, whether it is still waiting, was sorted into a group, or was dropped. This wins over the next case, so content that was dropped, or later removed from its group, does not come back.
   - **held by a group**: never imported, but a group on this node already has these bytes on disk, for example because a member shared them.
   - **new content**: anything else. It is kept in `.unsorted`, until someone files it into a group or drops it.

   Either way the reference is settled with the hash.

### Imported files

An imported file is `unsorted` until it is filed into a group, `sorted`, or thrown away, `dropped`. The state only moves forward. The one exception is undoing a move just made, while its bytes are still there. A dropped file keeps its row for good, since that row is what stops it coming back.

Removing a source deletes what it still owes but keeps the history of what it brought in. Its directory under `.unsorted` stays reserved while files are still waiting in it.

### Sources

A source is driven according to its kind:
- **One-shot**, like a folder, runs once when asked.
- **Remote**, like Google Drive, is scanned every 16 h.
- **Intermittent**, like a phone, is scanned on the same schedule but only while present. Being absent is not recorded as a failure, and an absent source stays due, so it is scanned as soon as it is back.

A backoff after failures can delay a scan but never bring it forward.

Adding a source means adding a file to `src/sources/` that implements `RegisteredSource`: `build.rs` registers every file there, and fails the build if there are none. Each source declares its settings, shared by every source of that kind, such as Drive's OAuth client, and its config, specific to each configured source. Some config is filled by signing in rather than typed, such as Drive's refresh token or a phone's certificate. Answers are stored as `key = value` lines, readable and editable by hand, and secrets are never shown or logged.

All network calls are blocking and run on threads that cannot be cancelled, so every stage up to the first byte of an answer has a timeout: 10 s to resolve and connect, 30 s to send and to receive the headers. A download's body has no total timeout, since a video takes as long as it takes.

### Folder

A one-time import of one absolute path, a file or a folder. Symlinks and anything that is not a regular file are skipped and reported. Files are listed in a fixed order, 500 per page, and a reference cannot climb out of the chosen folder.

### Google Drive

Read-only. Signing in goes through the browser, with OAuth redirecting to a local port and PKCE. The refresh token is kept, and access tokens are refreshed a minute before they expire. A scan walks the chosen folder a folder at a time, 200 files per page, carrying its position in the cursor. Google Docs, Sheets and other Google-native files are skipped, since they have no stable bytes to hash, and so are shortcuts. Drive's MD5 checksum is checked on download.

### Phone

A companion app on the same Wi-Fi runs a server, and the node reads from it like any other source.
- **Pairing.** The node shows a QR code holding its address, its listener's port and certificate fingerprint, its peer id and a single-use token, and waits up to 3 minutes. The phone answers on the listener with its id, name, port and certificate, which the node stores.
- **Presence.** The phone checks in with the listener about once a minute, and counts as present for 5 minutes after its last check-in. Its address is taken from where the check-in came from.
- **Reading.** The node calls the phone over HTTPS, trusting only the certificate it paired with, at a stable name mapped to the phone's last known address, so a new IP from the router does not break the pin. A `404` or `410` means the file is gone, and a `401` or `403` means the phone needs pairing again.
- **The listener** is a small HTTPS server the node runs with a self-signed certificate. Its port stays the same across restarts, since phones were told it at pairing, and it does not start if it cannot get that port back. Its HTTP is written by hand, to avoid a second TLS stack, and accepts little: one request per connection, at most 64 headers and an 8 KiB body, no chunked encoding.

## On-disk files

- `.unsorted/<source dir>/<folder>/<name>` under the storage root: imported files waiting to be sorted. `ac-node` writes them, in the directory the ledger gives each source. A name another waiting file already uses gets a conflict name.
- `phone-cert.der`, `phone-key.der` (mode `0600`), `phone-name` and `phone-port` in the node's home: the phone listener's certificate, key, certificate name and port.
- Its tables live in the node's `state.sqlite`, which `ac-node` opens for it.

## Database

The database is in WAL mode with a 5 s busy timeout, and a claim runs in an `IMMEDIATE` transaction. Times are Unix seconds.
- `sources`: one row per configured source. `dir` (primary key, its directory under `.unsorted`), `name` (unique), `source` (which kind, e.g. `drive`), `config`, `added_at`, `scanned_at`, `last_error`, and `reachable`, which tells an absent phone apart from a failed one.
- `source_settings`: the settings shared by every source of one kind, keyed by `(source, key)`, with `value`.
- `import_refs`: what each source offered, keyed by `(source_dir, source_ref)`, with `folder`, `name`, `size`, the promised `algo` and `checksum`, `hash` once the file is in, and `tried_at` and `fails` for retries. A row is owed while `hash` is empty.
- `imported`: one row per content ever imported, keyed by `hash`, with `state` (`unsorted`, `sorted` or `dropped`), `name`, `size`, `at`, `group_id` (set exactly when sorted), and `source_dir`, `source_name`, `source_ref` and `folder` for where it came from.

`sources.config` holds import credentials, such as Drive's refresh token, in plain text.
