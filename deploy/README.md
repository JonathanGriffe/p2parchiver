# Deploying `ac-server`

The server never stores media. It handles enrolment, peer discovery, reachability probes,
and relaying when hole punching fails. A small VPS is ample — it is idle most of the time
and its cost is bandwidth, not CPU.

## Continuous integration

`.github/workflows/ci.yml` runs fmt, clippy (`-D warnings`) and the test suite on every
push and pull request. On a push to `main` it then releases, in three steps:

1. **Version.** `scripts/tag.sh` reads the commits since the last release and bumps
   accordingly — `BREAKING CHANGE` major, `feat:` minor, anything else patch — then creates
   and pushes a bare `MAJOR.MINOR.PATCH` tag. Git tags are the only source of truth; nothing
   is written back to the repository, which is what stops CI triggering itself.
2. **Publish.** `deploy/Dockerfile` is built and pushed to Docker Hub as
   `<user>/ac-server:<version>`, plus `latest` and an immutable `sha-<commit>`.
3. **Deploy.** The `ac-server` chart in `JonathanGriffe/beatguessr-infra` has its
   `appVersion` set to the new version and the change is committed. Argo CD watches that
   path with `selfHeal`, so the commit is the deployment.

The scheme is deliberately the same as `clockdata` and `beatguessr`, which deploy into the
same infra repository — a version means the same thing in all three.

Because the version is decided from commit subjects, **the commit messages are the release
notes and the version bump**. A `feat:` on main ships a minor release.

Three repository secrets are required:

| Secret | Value |
| --- | --- |
| `DOCKERHUB_USERNAME` | your Docker Hub account name |
| `DOCKERHUB_TOKEN` | an access token — *not* your password |
| `DEPLOY_PAT` | a personal access token with write on `beatguessr-infra` |

`DEPLOY_PAT` cannot be the built-in `GITHUB_TOKEN`: that one is scoped to this repository
and the deploy step writes to another. The tag push in step 1 does use `GITHUB_TOKEN`, via
the workflow's `contents: write` permission.

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

Prefer the version tag when deploying, or the sha tag: `latest` moves underneath a running
server, so a `docker compose pull` can change versions without you choosing to.

`ac-server --version` reports the version in `Cargo.toml`, which is **not** the release —
the release is the image tag, and it is also on the image as the standard
`org.opencontainers.image.version` label:

```bash
docker inspect --format '{{ index .Config.Labels "org.opencontainers.image.version" }}' \
  <user>/ac-server:latest
```

Writing the release into `Cargo.toml` during the build was the alternative. It would make
`--version` honest at the cost of a full recompile of the dependency tree on every push,
since the edit lands in a layer above `cargo build` and invalidates the cache that step
depends on.

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
ac join /ip4/<your-server-ip>/udp/4002/quic-v1/p2p/<peer-id> <invite-code> --username alice
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
