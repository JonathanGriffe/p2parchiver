#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::io::Cursor;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use libp2p::futures::{AsyncWriteExt, StreamExt};
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId, StreamProtocol, multiaddr::Protocol};
use serde::{Deserialize, Serialize};

use ac_net::authz::AcceptAnyPeer;
use ac_net::config::Config;
use ac_net::identity::Identity;
use ac_net::stream::{CHUNK, TransferError};
use ac_net::swarm::{AcBehaviour, Role, build};
use ac_net::throttle::Throttle;
use ac_net::transfer::{
    Answered, Behaviour, Control, Download, Inbound, Serve, TransferEvent, TransferId,
    TransferSpec, Transfers,
};

const TIMEOUT: Duration = Duration::from_secs(20);

const PROTOCOL: &str = "/ac/test-transfer/1.0.0";

/// A header deadline short enough for a test to wait out.
const SHORT_HEADER: Duration = Duration::from_secs(1);

type TestSwarm = libp2p::Swarm<AcBehaviour<AcceptAnyPeer, Behaviour>>;

#[derive(Debug, Serialize, Deserialize)]
enum Reply {
    Sending(u64),
    Missing,
    Busy,
}

#[derive(Debug)]
enum ToyError {
    Missing,
    Busy,
    Short,
    /// The only retryable one.
    Transfer(TransferError),
}

impl From<TransferError> for ToyError {
    fn from(e: TransferError) -> Self {
        ToyError::Transfer(e)
    }
}

/// Fetches one numbered item into a shared buffer.
struct Toy {
    item: u32,
    nothing_to_do: bool,
    panics: bool,
    into: Arc<Mutex<Vec<u8>>>,
}

struct Receiving {
    expected: u64,
    into: Arc<Mutex<Vec<u8>>>,
}

impl Download for Toy {
    type Request = u32;
    type Reply = Reply;
    type Receiving = Receiving;
    type Error = ToyError;

    fn start(&mut self) -> Result<Option<u32>, ToyError> {
        Ok((!self.nothing_to_do).then_some(self.item))
    }

    fn on_reply(self, reply: Reply) -> Result<Receiving, ToyError> {
        assert!(!self.panics, "told to panic");
        match reply {
            Reply::Sending(expected) => Ok(Receiving {
                expected,
                into: self.into,
            }),
            Reply::Missing => Err(ToyError::Missing),
            Reply::Busy => Err(ToyError::Busy),
        }
    }

    fn on_chunk(receiving: &mut Receiving, chunk: &[u8]) -> Result<(), ToyError> {
        receiving.into.lock().unwrap().extend_from_slice(chunk);
        Ok(())
    }

    fn on_end(receiving: Receiving, ended: Result<(), ToyError>) -> Result<(), ToyError> {
        ended?;
        if receiving.into.lock().unwrap().len() as u64 != receiving.expected {
            return Err(ToyError::Short);
        }
        Ok(())
    }
}

/// Serves numbered items from memory.
struct Library(HashMap<u32, Vec<u8>>);

impl Serve for Library {
    type Request = u32;
    type Reply = Reply;
    type Source = Cursor<Vec<u8>>;
    type Error = TransferError;

    fn answer(&self, _: PeerId, item: u32) -> Result<Answered<Self>, TransferError> {
        Ok(match self.0.get(&item) {
            Some(bytes) => (
                Reply::Sending(bytes.len() as u64),
                Some(Cursor::new(bytes.clone())),
            ),
            None => (Reply::Missing, None),
        })
    }

    fn busy(&self) -> Reply {
        Reply::Busy
    }
}

type Side = Transfers<Toy, Library>;

fn item() -> Vec<u8> {
    (0..200_000).map(|i| (i % 251) as u8).collect()
}

fn spec(max_downloads: usize, max_uploads: usize) -> TransferSpec {
    TransferSpec {
        protocol: PROTOCOL,
        max_header: 4096,
        max_downloads,
        max_uploads,
        header_timeout: Duration::from_secs(30),
        stall_timeout: Duration::from_secs(600),
    }
}

fn identity() -> Identity {
    let dir = tempfile::tempdir().expect("tempdir");
    Identity::load_or_generate(&dir.path().join("identity.key"))
        .expect("identity")
        .0
}

fn loopback_config() -> Config {
    Config {
        listen: vec![
            "/ip4/127.0.0.1/udp/0/quic-v1"
                .parse()
                .expect("valid multiaddr"),
        ],
        listen_enroll: Vec::new(),
        external: Vec::new(),
        mdns: false,
        server: None,
        storage_root: None,
        storage_max: None,
        bandwidth_max: None,
    }
}

fn side(swarm: &TestSwarm, spec: TransferSpec, up: Throttle) -> Side {
    Transfers::new(
        swarm.behaviour().app.new_control(),
        spec,
        Library(HashMap::from([(1, item()), (2, vec![7; 2 * CHUNK])])),
        Arc::new(Throttle::none()),
        Arc::new(up),
    )
    .unwrap()
}

/// Two connected swarms, left running in the background, with a service on each.
struct Pair {
    server: Side,
    client: Side,
    /// The server's peer id.
    peer: PeerId,
    /// Opens raw streams from the client.
    raw: Control,
}

async fn pair(server: TransferSpec, client: TransferSpec) -> Pair {
    paced_pair(server, Throttle::none(), client).await
}

/// The same, with the server's uploads held to `up`.
async fn paced_pair(server: TransferSpec, up: Throttle, client: TransferSpec) -> Pair {
    let (id_a, id_b) = (identity(), identity());
    let peer_a = id_a.peer_id();
    let mut a = build(
        &id_a,
        &loopback_config(),
        Role::Client,
        AcceptAnyPeer,
        Behaviour::new(),
    )
    .unwrap();
    let mut b = build(
        &id_b,
        &loopback_config(),
        Role::Client,
        AcceptAnyPeer,
        Behaviour::new(),
    )
    .unwrap();
    let (serving, fetching) = (side(&a, server, up), side(&b, client, Throttle::none()));
    let raw = b.behaviour().app.new_control();

    let addr: Multiaddr = tokio::time::timeout(TIMEOUT, async {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = a.select_next_some().await {
                return address;
            }
        }
    })
    .await
    .expect("a should listen");
    b.dial(addr.with(Protocol::P2p(peer_a))).unwrap();

    tokio::time::timeout(TIMEOUT, async {
        loop {
            tokio::select! {
                _ = a.select_next_some() => {}
                event = b.select_next_some() => {
                    if matches!(event, SwarmEvent::ConnectionEstablished { .. }) {
                        return;
                    }
                }
            }
        }
    })
    .await
    .expect("b should connect");

    for mut swarm in [a, b] {
        tokio::spawn(async move {
            loop {
                swarm.select_next_some().await;
            }
        });
    }
    Pair {
        server: serving,
        client: fetching,
        peer: peer_a,
        raw,
    }
}

fn toy(item: u32) -> (Toy, Arc<Mutex<Vec<u8>>>) {
    let into = Arc::new(Mutex::new(Vec::new()));
    (
        Toy {
            item,
            nothing_to_do: false,
            panics: false,
            into: into.clone(),
        },
        into,
    )
}

/// What the server does with each stream a peer opens.
#[derive(Clone, Copy)]
enum Streams {
    Serve,
    Decline,
    /// Keep it open and never answer.
    Hold,
}

/// Drive both sides until the client's next download finishes, and say whether the server
/// saw a stream.
async fn finish(
    server: &mut Side,
    client: &mut Side,
    streams: Streams,
) -> (TransferId, Result<(), ToyError>, bool) {
    let mut saw_stream = false;
    let mut held: Vec<Inbound> = Vec::new();
    tokio::time::timeout(TIMEOUT, async {
        loop {
            tokio::select! {
                event = server.next() => {
                    if let TransferEvent::Inbound(inbound) = event {
                        saw_stream = true;
                        match streams {
                            Streams::Serve => server.serve(inbound),
                            Streams::Decline => {}
                            Streams::Hold => held.push(inbound),
                        }
                    }
                }
                event = client.next() => {
                    if let TransferEvent::Finished { id, result, .. } = event {
                        return (id, result, saw_stream);
                    }
                }
            }
        }
    })
    .await
    .expect("the download should finish")
}

/// The next stream a peer opens to `server`.
async fn next_inbound(server: &mut Side) -> Inbound {
    tokio::time::timeout(TIMEOUT, async {
        loop {
            if let TransferEvent::Inbound(inbound) = server.next().await {
                return inbound;
            }
        }
    })
    .await
    .expect("the server should see the stream")
}

#[tokio::test]
async fn a_fetch_completes_and_names_its_transfer() {
    let Pair {
        mut server,
        mut client,
        peer,
        ..
    } = pair(spec(8, 64), spec(8, 64)).await;
    let (download, into) = toy(1);

    let id = client.fetch(peer, download).unwrap();
    let (finished, result, _) = finish(&mut server, &mut client, Streams::Serve).await;

    assert_eq!(finished, id);
    result.unwrap();
    assert_eq!(*into.lock().unwrap(), item(), "byte for byte");
    assert_eq!(client.moved().0, item().len() as u64);
    assert_eq!(server.moved().1, item().len() as u64);
}

#[tokio::test]
async fn a_download_with_nothing_to_fetch_opens_no_stream() {
    let Pair {
        mut server,
        mut client,
        peer,
        ..
    } = pair(spec(8, 64), spec(8, 64)).await;
    let (mut download, _) = toy(1);
    download.nothing_to_do = true;

    client.fetch(peer, download).unwrap();
    let (_, result, saw_stream) = finish(&mut server, &mut client, Streams::Serve).await;

    result.unwrap();
    assert!(!saw_stream);
}

#[tokio::test]
async fn a_fetch_past_the_download_cap_is_refused() {
    let Pair {
        mut server,
        mut client,
        peer,
        ..
    } = pair(spec(8, 64), spec(1, 64)).await;

    assert!(client.fetch(peer, toy(1).0).is_some());
    assert!(
        client.fetch(peer, toy(1).0).is_none(),
        "the one slot is taken"
    );

    finish(&mut server, &mut client, Streams::Serve)
        .await
        .1
        .unwrap();
    assert!(
        client.fetch(peer, toy(1).0).is_some(),
        "and it frees once the download ends"
    );
}

#[tokio::test]
async fn past_the_upload_cap_the_server_answers_busy() {
    let Pair {
        mut server,
        mut client,
        peer,
        ..
    } = pair(spec(8, 0), spec(8, 64)).await;

    client.fetch(peer, toy(1).0).unwrap();
    let (_, result, _) = finish(&mut server, &mut client, Streams::Serve).await;

    assert!(matches!(result, Err(ToyError::Busy)), "got {result:?}");
}

#[tokio::test]
async fn a_declined_stream_fails_the_fetch_as_retryable() {
    let Pair {
        mut server,
        mut client,
        peer,
        ..
    } = pair(spec(8, 64), spec(8, 64)).await;

    client.fetch(peer, toy(1).0).unwrap();
    let (_, result, saw_stream) = finish(&mut server, &mut client, Streams::Decline).await;

    assert!(saw_stream);
    assert!(
        matches!(result, Err(ToyError::Transfer(_))),
        "got {result:?}"
    );
}

#[tokio::test]
async fn a_download_that_panics_fails_and_frees_its_slot() {
    let Pair {
        mut server,
        mut client,
        peer,
        ..
    } = pair(spec(8, 64), spec(1, 64)).await;
    let (mut download, _) = toy(1);
    download.panics = true;

    client.fetch(peer, download).unwrap();
    let (_, result, _) = finish(&mut server, &mut client, Streams::Serve).await;

    assert!(
        matches!(result, Err(ToyError::Transfer(TransferError::Panicked))),
        "got {result:?}"
    );
    assert!(
        client.fetch(peer, toy(1).0).is_some(),
        "its one slot is free again"
    );
}

#[tokio::test]
async fn a_peer_that_never_replies_times_out_the_download() {
    let quick = TransferSpec {
        header_timeout: SHORT_HEADER,
        ..spec(8, 64)
    };
    let Pair {
        mut server,
        mut client,
        peer,
        ..
    } = pair(spec(8, 64), quick).await;

    client.fetch(peer, toy(1).0).unwrap();
    let (_, result, saw_stream) = finish(&mut server, &mut client, Streams::Hold).await;

    assert!(saw_stream, "the stream reached the server");
    assert!(
        matches!(
            result,
            Err(ToyError::Transfer(TransferError::TimedOut(after))) if after == SHORT_HEADER
        ),
        "got {result:?}"
    );
}

#[tokio::test]
async fn bytes_held_back_past_the_header_deadline_still_arrive() {
    let quick = TransferSpec {
        header_timeout: SHORT_HEADER,
        ..spec(8, 64)
    };
    // A chunk every 1.5 s, so the bytes outlast the client's header deadline.
    let paced = Throttle::new(CHUNK as u64 * 2 / 3, CHUNK as u64);
    let Pair {
        mut server,
        mut client,
        peer,
        ..
    } = paced_pair(spec(8, 64), paced, quick).await;
    let (download, into) = toy(2);

    client.fetch(peer, download).unwrap();
    let (_, result, _) = finish(&mut server, &mut client, Streams::Serve).await;

    assert!(
        result.is_ok(),
        "only the stall deadline bounds them; got {result:?}"
    );
    assert_eq!(into.lock().unwrap().len(), 2 * CHUNK);
}

#[tokio::test]
async fn a_peer_that_never_asks_holds_an_upload_slot_only_until_the_deadline() {
    let quick = TransferSpec {
        header_timeout: SHORT_HEADER,
        ..spec(8, 1)
    };
    let Pair {
        mut server,
        mut client,
        peer,
        mut raw,
    } = pair(quick, spec(8, 64)).await;

    // Half a length, so the stream reaches the server but its request never ends.
    let mut silent = raw
        .open_stream(peer, StreamProtocol::new(PROTOCOL))
        .await
        .unwrap();
    silent.write_all(&[0, 0]).await.unwrap();
    silent.flush().await.unwrap();
    let silent_inbound = next_inbound(&mut server).await;

    client.fetch(peer, toy(1).0).unwrap();
    let fetch_inbound = next_inbound(&mut server).await;
    // Served back to back, so the silent stream holds the slot however slow the runner.
    server.serve(silent_inbound);
    server.serve(fetch_inbound);
    let (_, result, _) = finish(&mut server, &mut client, Streams::Serve).await;
    assert!(
        matches!(result, Err(ToyError::Busy)),
        "the silent peer holds the one slot; got {result:?}"
    );

    tokio::time::sleep(2 * SHORT_HEADER).await;
    client.fetch(peer, toy(1).0).unwrap();
    let (_, result, _) = finish(&mut server, &mut client, Streams::Serve).await;
    assert!(
        result.is_ok(),
        "and loses it at the deadline; got {result:?}"
    );
}
