# ac-peers

The application's supervisor. It decides which peers to call and when, what to reconcile with them, which files to download from whom, and when to hang up. Like the sync machines, it does no IO: it takes events and returns the actions for `ac-node` to carry out. It depends on `ac-net`, `ac-groups` and `ac-files`, since deciding who to call needs to see membership and content at once, and only `ac-node` builds on it.

Paths below are relative to `crates/ac-peers/`.

## Features

- **Supervisor**: the state machine that decides who to call, what to reconcile, what to download and when to hang up, in `src/sync.rs`.
- **Storage limits**: the free-space floor and storage budget that stop downloads in `src/sync.rs`.
- **Missing files**: pages through the files a group is missing in `src/missing.rs`.
- **Session**: the `/ac/session/1.0.0` messages two peers use to agree to hang up, in `src/wire.rs`.
- **Status**: what the supervisor is waiting on for each group and peer, which `ac-node` publishes for the status display, in `src/sync.rs`.

## Design

### Dial policy

A member is called because something changed, or because a group has been quiet for a while:
- A membership change this node made puts every reachable member of the group on the call list.
- A catalogue change this node made is shared once the catalogue has been still for 2 minutes, or after 1000 changes, so a large import is not announced file by file.
- Each group has its own 4 h heartbeat, first due on the tick the group is first seen. When a group's heartbeat comes due and none of its members is on the list already, one is put on it: the next member in rotation who is connected, or online with their dial backoff run out, or else the next member in rotation, reachable or not. Unless the member chosen was already connected, the rotation moves past them, so successive heartbeats reach different members.
- A member who has not answered a group's invitation is called when the server says they are online, ahead of everyone else.

A change only puts a member on the list if the node is connected to them or the server says they are online. The heartbeat prefers such a member, and dials blind only when there is none, since presence can be stale. Changes learned from peers are not news, so they are not told again.

The node asks the server which members of its active groups are online every 5 minutes, and at once when a membership change was made.

### Dialing

Calls are rationed to stay within what the relay allows: one new call for news per tick, at most 16 per minute, and at most 16 connections at once. Each attempt on a member doubles their backoff, from 15 s up to 30 minutes, and a member who does not pick up after 3 attempts is taken off the list. The backoff resets once a connection is verified.

### Connection workflow

```
call list ─► dial ─► connect ─► chain round ─► catalogue round ─► downloads ─► hang up
```

1. **Dial**

   ```
   limits ─► backoff ─┬─► known direct address ─┬─► connected
                      └─► relay circuit ────────┤
                                                └─► failed ─► off the list after 3 attempts
   ```

   The limits: the member is neither connected nor already being dialed, the node holds fewer than 16 connections and opened fewer than 16 in the last minute, and the member's backoff has run out. Otherwise the dial waits for a later tick. Every attempt doubles the member's backoff, from 15 s up to 30 minutes, whether or not its failure is ever reported. The address is the first direct address discovery reported for the member, or else a circuit through the server's relay. A direct address that fails moves to the back of the member's list, so the next attempt tries another.

2. **Connect**

   ```
   connected ─┬─► attestations exchanged ─┬─► both accepted ───────────┬─► Verified
              │                           └─► refused, or 15 s: closed │
              └─► relayed: hole punch ─┬─► direct ─────────────────────┤
                                       └─► 15 s: stays relayed ────────┘
   ```

   `ac-net` handles this step whoever dialed, so a peer that dials us joins here. Two things happen at once. The peers exchange attestations, each checking the other's against the server's key, and the connection is closed if either refuses or the exchange takes over 15 s. Meanwhile a relayed connection tries to become direct by hole punching, and settles once direct or after 15 s of trying. A direct connection settles at once. Only when the peer is both admitted and settled does the supervisor get `Verified`, which marks them connected and resets their dial backoff.

3. **Chain round**

   ```
   ask ─► heads ─┬─► unknown to us ─┬─► fetch ─┬─► store ─┬─► invited ─► write Unanswered ─┬─► answered
                 ├─► they are ahead ┤          │          ├─► admin ─► write Remove ───────┤
                 ├─► digests differ ┤          │          └─► neither ─────────────────────┤
                 ├─► left out ┘                └─► refused ────────────────────────────────┤
                 └─► same ─────────────────────────────────────────────────────────────────┘
   ```

   The node asks the peer for its heads: for each group both belong to that is active or pending on the peer's side, the seq of its last entry and its standings digest. The `ac-groups` sync machine compares each with its own:
   - **unknown to us**: fetch the whole chain.
   - **they are ahead**: their seq is past ours, so fetch from our head.
   - **digests differ**: some member's standing differs, so fetch from our head. When we are not behind, this brings no entries, only the peer's standings.
   - **left out**: a group of ours whose chain names the peer, but which the peer did not offer. Fetch from our head. Either the peer's chain no longer names us, and the fetch brings the entries up to our removal; or the peer has left the group, and the fetch brings its `Out` standing; or the peer does not hold the group, and the fetch is refused.
   - **same**: we are not behind and the digests match, so there is nothing to fetch. That includes being ahead, since the peer runs its own chain round on the same connection and fetches from us.

   A fetch returns the entries the peer may serve from that point, along with all its standings, or a refusal. What comes back is verified and stored: an unknown group is adopted as pending, and a known one must match the entries already held, or nothing is stored. If our head moved while the fetch was out, it is fetched again from there. Then one follow-up may apply:
   - **invited**: the group is pending here, names this node, and this node has written no standing for it yet. It writes an `Unanswered` one, so members stop re-offering the chain.
   - **admin**: this node is the group's admin, and a member's newly winning standing says `Out`. It writes a `Remove` for them.

   Once every group has reached answered, the round is answered and the catalogue round starts. Chains come first because which catalogues can be shared depends on membership.

4. **Catalogue round**

   ```
   ask ─► heads ─┬─► same digest ───────────────────────────────────┬─► settled
                 ├─► group read from another peer ──────────────────┤
                 └─► read log pages ─► merge ─► compare ─┬─► same ──┘
                                                         └─► different: reset cursor, read again once
   ```

   The node asks the peer for the heads of the catalogues shared with us, and the peer is off the call list as soon as they answer. For each group, the `ac-files` sync machine settles at once when the digests match, or when the group is already being read from another peer. Otherwise it reads the peer's log from its stored cursor, a page of up to 2048 rows at a time, merging each row, then compares the digests again. If they still differ, it resets the cursor and reads the whole log once more, and settles either way.

5. **Downloads**

   ```
   claim source ─► ask holdings ─┬─► some held ─► fetch ─┬─► done ─────────────┬─► next page
                                 │                       └─► failed: skip file ┤
                                 ├─► none held ────────────────────────────────┘
                                 ├─► refused 3 times ─┬─► peer spent ─► next member, or wait
                                 └─► backlog done ────┘
   ```

   When a group settles with this peer, the peer becomes the group's source if the group has none, is not waiting, still misses files and has room for them. The node asks the source which of the missing files it holds, 512 paths at a time, and fetches those it holds over `/ac/blob/1.0.0`, 8 transfers at once across all peers, before asking about the next page. A file the peer failed to deliver for good is not asked of them again. Once the backlog has been walked to the end, or the peer refused the question 3 times, the peer is spent for this group and the next member is tried. How the source is chosen, and how long a group waits when nobody can help, is covered under Downloads below.

6. **Hang up**

   ```
   nothing left ─► propose ─┬─► Ready ─┬─► still idle ─► disconnect
                            │          └─► work arrived: stay
                            └─► Busy, or no answer ─► stay, propose again after 30 s
   ```

   Nothing is left once no round or transfer is outstanding with the peer and no group could still download from them. `ac-node` also checks that its own links and transfers are idle before proposing over `/ac/session/1.0.0`, and counts it as `Busy` if not. The peer answers `Ready` only if it has nothing outstanding with us either, and the node disconnects if it is still idle itself. An agreed hang-up is logged as such rather than as a disconnection.

A round that fails, goes 60 s unanswered, or is deferred because a chain exchange with the peer is still outstanding, is asked again after 5 s, at most twice.

Nothing new is told to a peer while connected to them. News that arrives in the meantime keeps them on the call list, and they are called again after the hang-up. The same goes for a round still waiting to be retried when the connection drops.

### Downloads

Each active group missing files downloads from one member at a time, its source, with at most 2 groups downloading at once. The source is a connected member whose catalogue has been reconciled when there is one, and otherwise the next member in rotation is dialed. Members who have answered the group's invitation come first, since one who has not holds the group as pending and refuses.

The node asks its source which of the missing files it holds, 512 paths at a time, walking the backlog page by page rather than starting over, and fetches those it holds, 8 transfers at once across all peers. A file a peer claimed but could not deliver is not asked of them again, and a holdings query refused three times moves on to another member.

Once a member has nothing more to offer, the next one is tried. When every reachable member has been tried, the group waits before trying again, from 30 s doubling up to 30 minutes. A newly wanted file, or a member coming back online, ends the wait. When no member is reachable at all, the group waits for one without backing off.

### Storage limits

Downloads stop while free space on the storage volume is under 2 GiB, or once the held content reaches `storage_max` from the config. Nothing is deleted: downloads resume once there is room, and the reason is logged once. Each download books its size before it starts, so a file larger than the remaining room is not started. `ac-node` reports free and held space on every housekeeping tick.

## On-disk files

None.

## Database

None of its own. Its state is kept in memory, and it reads and writes the `ac-groups` and `ac-files` tables through their stores: membership, standings and missing files, the news and wanted counters it clears once acted on, and whether a file is held once its download finishes.
