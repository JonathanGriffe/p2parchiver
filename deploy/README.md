# Deploying `ac-server`

The server never stores media. It handles enrolment, peer discovery, reachability probes,
and relaying when hole punching fails. A small VPS is ample — it is idle most of the time
and its cost is bandwidth, not CPU.

## Continuous integration

`.github/workflows/ci.yml` runs fmt, clippy (`-D warnings`) and the test suite on every
push and pull request. On a push to `main` or a `v*` tag it then builds `deploy/Dockerfile`
and publishes to Docker Hub as `<user>/ac-server`.

Two repository secrets are required:

| Secret | Value |
| --- | --- |
| `DOCKERHUB_USERNAME` | your Docker Hub account name |
| `DOCKERHUB_TOKEN` | an access token — *not* your password |

Create the token at Docker Hub → Account Settings → Personal access tokens, with
**Read & Write** scope. If you keep them in a local `.env` (git-ignored), push them with:

```bash
set -a; . ./.env; set +a
gh secret set DOCKERHUB_USERNAME --body "$DOCKERHUB_USERNAME"
gh secret set DOCKERHUB_TOKEN   --body "$DOCKERHUB_TOKEN"
```

GitHub Actions cannot read a `.env` file from the repository — and committing one would
publish the credentials — so secrets are the mechanism regardless of where you keep the
originals.

Images are tagged `latest` (main), the semver forms of any `v*` tag, and always an
immutable `sha-<commit>`. Prefer the sha tag when deploying: `latest` moves underneath a
running server, so a `docker compose pull` can change versions without you choosing to.

To run a published image, set `image:` in `compose.yaml` instead of `build:`.

## Quick start

```bash
docker compose -f deploy/compose.yaml up -d --build
docker compose -f deploy/compose.yaml logs | grep '^peer'
```

That last line prints the server's peer id. Note it: clients pin it on first contact, and
comparing it out of band is what tells a user they reached *your* server.

Then create an invite and hand it over:

```bash
docker compose -f deploy/compose.yaml exec ac-server ac-server invite new --label laptop
```

On the client:

```bash
ac join /ip4/<your-server-ip>/udp/4002/quic-v1/p2p/<peer-id> <invite-code>
ac run
```

## Ports to open

| Port | Protocol | Purpose |
| --- | --- | --- |
| 4001 | UDP + TCP | services: relay, rendezvous, AutoNAT — enrolled clients only |
| 4002 | UDP | enrolment — open to anyone, by necessity |

Both are **fixed**, and that matters: a client is told the service address once, when it
enrols, and stores it permanently. An ephemeral port would orphan every enrolled client the
first time the server restarted.

UDP is the one people forget. QUIC is the primary transport and the only one that makes
hole punching viable, so a UDP-blocking firewall silently degrades every client to TCP and
to relayed connections.

## Addresses: the thing most likely to go wrong

The server tells each client where to reach it, and clients believe it. Get this wrong and
enrolment succeeds while nothing afterwards works.

**With `network_mode: host`** (the default here) and a VPS holding its public IP directly,
there is nothing to do — the server announces what it bound, and that is correct.

**Set `external` when the bound address is not how the world reaches you**, which covers
bridge networking, cloud NAT, and load balancers. Prefer a DNS name over a literal IP:
clients store what they are given, so a hostname survives the machine changing address.

```toml
# in the data volume's config.toml
external = ["/dns4/ac.example.net/udp/4001/quic-v1"]
```

To edit it:

```bash
docker compose -f deploy/compose.yaml exec ac-server sh -c 'cat /data/config.toml'
```

## What to back up

The volume, and above all `identity.key`. It is the trust anchor: clients pin this
server's peer id, so losing it means every client must re-enrol with a fresh invite. The
key sits in its own file, separate from the database, precisely so it can be copied
somewhere safe on its own.

`state.sqlite` holds invites and enrolled clients — worth keeping, but recoverable by
re-issuing invites.

## Administration

```bash
# invites
ac-server invite new --label bobs-laptop [--ttl-hours 24]
ac-server invite list

# clients
ac-server client list
ac-server client revoke <peer-id>
ac-server client unrevoke <peer-id>
```

Each prefixed with `docker compose -f deploy/compose.yaml exec ac-server`.

Two things worth knowing about revocation. It takes effect on the peer's **next**
connection — one already open survives until it ends on its own. And it is not reversed by
issuing a fresh invite: a revoked peer cannot even reach the enrolment listener, so
`unrevoke` is the only way back.

## Relay bandwidth

This is the operating cost. A circuit is capped at 128 KiB over two minutes, with per-peer
and per-IP rate limits — sized for hole-punch coordination, not for carrying media. Two
peers that fail to hole punch get a working connection, not a fast one.

That cap is deliberate and is the reason the server is cheap to run. Raising it to carry
media would change both the bandwidth bill and the security requirements.
