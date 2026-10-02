# ac-net

The networking layer of the projects. It owns a node's identity key and on-disk config, builds the libp2p swarm (transports, NAT traversal, relay and mDNS) for each of the three process roles, and defines the wire protocols for enrolment, attestation and presence. It also runs the admission layer, which decides which peers count as trusted: every peer must present an attestation signed by the server that both sides enrolled with. For the layers above, it moves bulk bytes and caps the bandwidth they use, without knowing what the bytes are.

Paths below are relative to `crates/ac-net/`.

## Features

- **Re-export**: It re-exports a few types (`PeerId`, `Multiaddr` and `Protocol`) in `src/lib.rs` from libp2p that will be used by other layers that do not depend on libp2p.
- **Identity**: handles the identity of the node in `src/identity.rs`.
- **Config**: Owns the config in `src/config.rs`.
- **Enrollment**: It creates the protocol for enrollment in `src/proto.rs` and `src/invite.rs`.
- **Attestation**: It implements attestation and admission, ie issuing an attestation and handling it in the node in `src/attest.rs`, the protocol to ask the server for one and the protocol for admission in in `src/proto.rs`, and the admission state machine in `src/admission.rs`. It connects the admission to the swarm through the `AdmissionLink` in `src/admission_link.rs`
- **Handling connections** in `src/admitted_peers.rs`, `src/connectivity`, keeps the connection to the server alive and using server services in `src/link.rs`.
- **Authorizing connections**: implements policies for the server and node to accept or reject connections in `src/authz.rs`
- **Limits and Budget**: setting network limits in `src/limits.rs` and a budget of requests to answer in `src/budgets.rs`
- **Swarm**: building the swarm for each role (node, server and enrollment server) in `src/swarm.rs`.
- **Transfers**: a service that moves bulk bytes for a protocol mounted above it, in `src/transfer.rs`, over the frames and chunk loops in `src/stream.rs`.
- **Bandwidth**: the rate limiter the layers above share to cap the bytes they move, in `src/throttle.rs`.

## Design

### Enrollment, attestation and admission

To enter the p2p network, a peer must be enrolled with the server, who stores which users are enrolled.
Only enrolled peers can use the server's services such as the relay and presence.
Enrolled peers can also get an attestation (ie certificate of enrollment) from the server. This attestation has an expiry, so peers can be eventually revoked.

When connecting to other peers, first libp2p will ensure peers really own the peer id they claim, then they will admit each other by requesting the other's certificate and verifying it. They will only answer other protocols once the peers are admitted, else they will disconnect.
The certificates are verified using the server's public key, which is recovered from its peer id as in this system the peer ids are not hashed.

### Connections

When the server connection comes up, the client asks for a relay reservation by listening on `<server>/p2p-circuit`, so any peer that knows its peer id can reach it at `<server>/p2p-circuit/p2p/<peer>`. The server publishes no addresses and lists no peers.
Only the server connection is pinged, every 25 s, to keep the client's NAT mapping open.

A client also runs mDNS when `mdns` is on in its config, which announces it to peers on the same local network and reports theirs. Peers on the same LAN connect directly at those addresses. Others connect through the server, then try to upgrade the connection to a direct connection by attempting hole punching. If they fail, the connection stays relayed and the communication proceeds.
A connection is deemed usable once admission has completed successfully and the connection is settled, ie either upgraded to direct or attempting to upgrade has timed out.

### Swarm

The swarm mounts ac-net's protocols and has a slot so that other layers can also mount their own protocols.

### Transfers

`Transfers` is to bulk bytes what `request_response` is to messages, and it never names what the bytes are. A protocol plugs in through two traits that share its request and reply types: a `Download` for each fetch, and one `Serve` shared by every upload. `ac-files` implements both for `/ac/blob/1.0.0`, and `ac-node` mounts the service on the swarm through the `libp2p-stream` behaviour re-exported here, building it from the `Control` re-exported beside it.
- **Frames.** The opener writes a request and the other side a reply, each a 4-byte big-endian length followed by CBOR. A length over the protocol's cap is refused before the body is read, and a value over it is never written. The raw bytes then follow in 64 KiB chunks, until the sender closes the stream.
- **Caps.** A fetch past the protocol's download cap is refused at once. An inbound stream past its upload cap is answered with the protocol's busy reply and closed.
- **Spawning.** Each transfer runs in its own tokio task, which calls the protocol's code, including its blocking disk and database I/O. `Transfers::next` yields each finished download, named by the id `fetch` returned, and each inbound stream, which the caller either serves or drops to decline. A download whose code panics finishes like any failed one, with `TransferError::Panicked`, so its slot is freed and its outcome still arrives. The protocol's `on_end` does not run, though, so nothing it does on a failure, such as parking a partial, happens.
- **Bandwidth.** Every chunk waits on the service's download or upload throttle.
- **Deadlines.** The protocol sets two. The header deadline is one budget for the requester to open the stream, send its request and get the reply. On the server it bounds reading the request, writing the reply or the busy reply, and closing the stream, each on its own. The stall deadline bounds each read and write of the raw bytes, so it restarts whenever bytes move, and waiting on this node's own throttle never counts towards it. A deadline that passes fails the transfer with `TransferError::TimedOut`, which carries the deadline that passed and frees its slot on either side like any other failure. There is no deadline on a whole transfer, which may legitimately take hours.

### Bandwidth

`bandwidth_max` in the config caps downloads and uploads separately. Each limit is a `Throttle`, a token bucket with a burst of two 64 KiB chunks, that also counts every byte it lets through, limited or not. The layers above decide what shares one: in `ac-node`, downloads from peers and imports share the download limit.

### Limits

The number of connections and total memory used are capped. The connections limit per peer must be at least 2, as during hole punch a peer can hold at the same time a direct and a relayed connection to the same peer at the same time.

### Invite token

Inviting into a network is done through one single token, which holds the invite secret as well as the info necessary to connect to the network, such as the server address.

## On-disk files
- `identity.key`: a protobuf-encoded keypair. It is written through a temp file created with mode `0600`, renamed into place, and followed by an fsync of the directory, so the key is never briefly readable by others and the rename survives power loss. A world-readable key only produces a warning, because refusing to start "would lock someone out of their own node".
- `attestation.cbor`: the CBOR `Attestation`.
- `config.toml` holds the node config
- `state.sqlite` and `files/` are only named here. Other crates own them.

## Database

None. ac-net has no SQLite dependency and creates or queries no tables.