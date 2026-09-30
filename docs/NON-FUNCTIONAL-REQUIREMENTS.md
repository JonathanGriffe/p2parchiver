# Non-functional requirements

The properties the peer-to-peer system must keep in order to work. A change that weakens one breaks the system even when every feature still appears to work, so a change that touches one must keep it, or be discussed first. Each names the crate that enforces it.

## Trust

- T1. Every connection is encrypted and authenticated.
- T2. Only enrolled peers are answered.
- T3. Identity belongs to the node.
- T4. Only the admin changes membership, and only a member speaks for itself.

## Privacy

- P1. A non-member learns nothing about a group, not even that it exists.
- P2. A former member learns only of its own removal.
- P3. The server doesn't learn about groups and files.
- P4. A peer that isn't enrolled doesn't learn anything about other peers.

## Convergence

- C1. Members converge on connection. Any two members who connect end up with the same chain, the same standings and the same catalogue for every group they share, and the same files.
- C2. Every merge is deterministic. Every node reaches the same result whatever order members meet in.
- C3. Merging is idempotent. Receiving the same data again changes nothing.
- C4. A member's own word always gets out. A member that has left, or not answered an invitation yet, still serves the group, since it holds the only copy of its own standing. (`ac-groups`)
- C5. Nothing is imported twice, and nothing dropped comes back.
- C6. Members learn about news (being added to a group, files being added) quickly when it happens while they are online (max 5min), for every group.
- C7. Members must be very likely to learn about news which happened when they were offline quickly upon coming back online.
- C8. In case a member doesn't learn about news, this must not be fatal, and they must eventually be able to learn about them.

## Liveness

- L1. Nothing waits forever. Every handshake, request, fetch, round and transfer has a deadline, after which it is abandoned and retried.
- L2. Every retry is bounded and backs off.
- L3. An idle node goes quiet.

## Resource bounds

- R1. Every message has a size cap, checked before it is parsed.
- R2. Every query has a count cap on request and answer.
- R3. Work done for one peer is capped.
- R4. Relay use is capped per user.
- R5. The disk is never filled by the app.
- R6. Bandwidth is capped.

## Durability and integrity

- D1. Every file is checked before it is kept.
- D2. An interrupted download resumes. A transfer that stops keeps its partial, and the next attempt continues from it.
- D3. The database stays consistent under concurrent use.
