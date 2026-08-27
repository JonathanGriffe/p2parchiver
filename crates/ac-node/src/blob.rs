use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use ac_files::content::Content;
use ac_files::path::RelPath;
use ac_files::store::Files;
use ac_files::sync::may_serve;
use ac_files::wire::{BLOB_PROTOCOL, BlobReply, BlobRequest};
use ac_groups::id::GroupId;
use ac_groups::store::Groups;
use ac_peers::sync::PeerEvent;
use tokio::sync::Semaphore;

use crate::throttle::Throttle;
use futures::{AsyncReadExt, AsyncWriteExt};
use libp2p::{PeerId, StreamProtocol};
use std::io::Read as _;
use tokio::sync::mpsc;

const CHUNK: usize = 64 * 1024;

const MAX_HEADER_BYTES: usize = 4096;

/// Transfers this node will pull at once, across every peer.
const MAX_CONCURRENT: usize = 8;

/// Transfers this node will serve at once, across every peer.
pub const MAX_SERVING: usize = 64;

/// Burst for the transfer rate limits: a second of allowance, floored so a whole chunk is
/// always spendable.
pub const THROTTLE_BURST: u64 = (2 * CHUNK) as u64;

pub struct Wanted {
    pub peer: PeerId,
    pub group: GroupId,
    pub path: RelPath,
    pub hash: String,
    pub dir: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Unavailable,
    WrongContent,
    Overlong,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::Unavailable => write!(f, "the peer would not serve it"),
            Refusal::WrongContent => {
                write!(f, "the content did not match the hash it was asked for")
            }
            Refusal::Overlong => write!(f, "the peer sent more than the size it announced"),
        }
    }
}

impl std::error::Error for Refusal {}

/// Whether taking `n` more bytes would carry the transfer past what the sender announced.
fn overruns(got: u64, n: usize, expected: u64) -> bool {
    got.saturating_add(n as u64) > expected
}

fn terminal(error: &anyhow::Error) -> bool {
    error.downcast_ref::<Refusal>().is_some()
}

/// Blob transfers in flight, and the channel their outcomes come back on.
pub struct Transfers {
    outcomes: mpsc::UnboundedSender<PeerEvent>,
    inbox: mpsc::UnboundedReceiver<PeerEvent>,
    running: HashMap<PeerId, usize>,
    db: PathBuf,
    me: PeerId,
    down: Arc<Throttle>,
}

impl Transfers {
    pub fn new(db: PathBuf, me: PeerId, bandwidth_max: Option<u64>) -> Self {
        let (outcomes, inbox) = mpsc::unbounded_channel();
        Self {
            outcomes,
            inbox,
            running: HashMap::new(),
            db,
            me,
            down: Arc::new(Throttle::from_config(bandwidth_max, THROTTLE_BURST)),
        }
    }

    /// Wait for one transfer to end.
    pub async fn finished(&mut self) -> Option<PeerEvent> {
        let event = self.inbox.recv().await?;
        if let PeerEvent::BlobDone { peer, .. } | PeerEvent::BlobFailed { peer, .. } = &event {
            self.done(*peer);
        }
        Some(event)
    }

    pub fn collect(&mut self) -> Vec<PeerEvent> {
        let mut out = Vec::new();
        while let Ok(event) = self.inbox.try_recv() {
            let peer = match &event {
                PeerEvent::BlobDone { peer, .. } | PeerEvent::BlobFailed { peer, .. } => {
                    Some(*peer)
                }
                _ => None,
            };
            if let Some(peer) = peer {
                self.done(peer);
            }
            out.push(event);
        }
        out
    }

    pub fn running_with(&self, peer: &PeerId) -> usize {
        self.running.get(peer).copied().unwrap_or(0)
    }

    fn done(&mut self, peer: PeerId) {
        if let Some(n) = self.running.get_mut(&peer) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.running.remove(&peer);
            }
        }
    }

    fn total(&self) -> usize {
        self.running.values().sum()
    }

    #[must_use]
    pub fn fetch(
        &mut self,
        control: libp2p_stream::Control,
        content: Content,
        want: Wanted,
    ) -> bool {
        if self.total() >= MAX_CONCURRENT {
            return false;
        }
        *self.running.entry(want.peer).or_default() += 1;

        let outcomes = self.outcomes.clone();
        let db = self.db.clone();
        let me = self.me;
        let down = self.down.clone();
        tokio::spawn(async move {
            let peer = want.peer;
            let group = want.group;
            let path = want.path.clone();
            let event = match download(control, &content, &want, &db, me, &down).await {
                Ok(()) => PeerEvent::BlobDone { peer, group, path },
                Err(why) => PeerEvent::BlobFailed {
                    peer,
                    group,
                    path,
                    terminal: terminal(&why),
                    why: why.to_string(),
                },
            };
            let _ = outcomes.send(event);
        });
        true
    }
}

/// Ask one peer for one file and write it to disk.
async fn download(
    mut control: libp2p_stream::Control,
    content: &Content,
    want: &Wanted,
    db: &std::path::Path,
    me: PeerId,
    down: &Throttle,
) -> anyhow::Result<()> {
    let mut hash = [0u8; 32];
    hex::decode_to_slice(&want.hash, &mut hash)?;

    let resume = content.staged_len(&want.dir, &want.path);

    let mut stream = control
        .open_stream(want.peer, StreamProtocol::new(BLOB_PROTOCOL))
        .await?;

    let header = BlobRequest {
        group: want.group,
        path: want.path.to_string(),
        hash,
        offset: resume,
    };
    write_frame(&mut stream, &header).await?;

    let reply: BlobReply = read_frame(&mut stream, MAX_HEADER_BYTES).await?;
    let expected = match reply {
        BlobReply::Sending { size } => size,
        BlobReply::Unavailable => anyhow::bail!(Refusal::Unavailable),
    };

    let mut sink = content.resume(&want.dir, &want.path, resume)?;
    let mut buf = vec![0u8; CHUNK];
    let mut got = 0u64;

    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }

        if overruns(got, n, expected) {
            sink.park()?;
            anyhow::bail!(Refusal::Overlong);
        }

        down.consume(n).await;

        sink.write(&buf[..n])?;
        got += n as u64;
    }

    if got != expected {
        sink.park()?;
        anyhow::bail!("transfer ended early after {got} of {expected} bytes");
    }

    let staged = sink.finish()?;
    if staged.hash != want.hash {
        content.discard(staged).ok();
        anyhow::bail!(Refusal::WrongContent);
    }
    content.commit(staged)?;

    let mut files = Files::open(db, me)?;
    files.mark_have(want.group, &want.path, true)?;
    Ok(())
}

/// Answer an inbound blob stream.
pub fn serve(
    db: PathBuf,
    content: Content,
    me: PeerId,
    peer: PeerId,
    stream: libp2p::swarm::Stream,
    up: Arc<Throttle>,
    slots: Arc<Semaphore>,
) {
    let Ok(slot) = slots.try_acquire_owned() else {
        tracing::warn!(%peer, limit = MAX_SERVING, "already serving all we can; refusing");
        tokio::spawn(async move {
            let mut stream = stream;
            let _ = write_frame(&mut stream, &BlobReply::Unavailable).await;
            let _ = stream.close().await;
        });
        return;
    };

    tokio::spawn(async move {
        let _slot = slot;
        if let Err(e) = answer(db, content, me, peer, stream, &up).await {
            tracing::debug!(%peer, error = %e, "a blob request went unanswered");
        }
    });
}

async fn answer(
    db: PathBuf,
    content: Content,
    me: PeerId,
    peer: PeerId,
    mut stream: libp2p::swarm::Stream,
    up: &Throttle,
) -> anyhow::Result<()> {
    let request: BlobRequest = read_frame(&mut stream, MAX_HEADER_BYTES).await?;
    let path = RelPath::parse(&request.path).map_err(|e| anyhow::anyhow!("{e}"))?;

    let files = Files::open(&db, me)?;
    let groups = Groups::open(&db, me)?;

    let Some(size) = may_serve(&files, &groups, &peer, request.group, &path) else {
        write_frame(&mut stream, &BlobReply::Unavailable).await?;
        stream.close().await?;
        return Ok(());
    };

    let row = files.get(request.group, &path)?;
    if row.is_none_or(|r| r.hash != hex::encode(request.hash)) {
        write_frame(&mut stream, &BlobReply::Unavailable).await?;
        stream.close().await?;
        return Ok(());
    }

    let Some(dir) = files.dir_of(request.group)? else {
        write_frame(&mut stream, &BlobReply::Unavailable).await?;
        stream.close().await?;
        return Ok(());
    };

    let file = match content.open_at(&dir, &path, request.offset) {
        Ok(file) => file,
        Err(e) => {
            tracing::warn!(%path, error = %e, "indexed as held, but not on disk; correcting");
            let mut files = files;
            let _ = files.mark_have(request.group, &path, false);

            write_frame(&mut stream, &BlobReply::Unavailable).await?;
            stream.close().await?;
            return Ok(());
        }
    };

    let remaining = size.saturating_sub(request.offset);
    write_frame(&mut stream, &BlobReply::Sending { size: remaining }).await?;

    let mut file = file;
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        up.consume(n).await;
        stream.write_all(&buf[..n]).await?;
    }
    stream.close().await?;
    Ok(())
}

/// Write a length-prefixed CBOR value.
async fn write_frame<T: serde::Serialize>(
    stream: &mut libp2p::swarm::Stream,
    value: &T,
) -> anyhow::Result<()> {
    let mut body = Vec::new();
    ciborium::into_writer(value, &mut body)?;
    anyhow::ensure!(body.len() <= MAX_HEADER_BYTES, "header too large");

    stream.write_all(&(body.len() as u32).to_be_bytes()).await?;
    stream.write_all(&body).await?;
    Ok(())
}

async fn read_frame<T: serde::de::DeserializeOwned>(
    stream: &mut libp2p::swarm::Stream,
    limit: usize,
) -> anyhow::Result<T> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await?;

    let len = u32::from_be_bytes(len) as usize;
    anyhow::ensure!(
        len <= limit,
        "a {len} byte header exceeds the {limit} limit"
    );

    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    Ok(ciborium::from_reader(&body[..])?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_transfer_may_take_exactly_what_was_announced_and_not_a_byte_more() {
        // Exactly the announced size is the ordinary end of every honest transfer.
        assert!(!overruns(0, 1000, 1000));
        assert!(!overruns(936, 64, 1000));

        // One byte past it is not, however small the overrun.
        assert!(overruns(936, 65, 1000));
        assert!(overruns(1000, 1, 1000));

        // A sender that keeps going cannot wrap the counter into looking acceptable.
        assert!(overruns(u64::MAX - 1, usize::MAX, 1000));
    }

    #[test]
    fn nothing_is_announced_means_nothing_may_arrive() {
        assert!(!overruns(0, 0, 0));
        assert!(overruns(0, 1, 0));
    }

    #[test]
    fn a_severed_transfer_is_retryable_and_a_refusal_is_not() {
        let severed = anyhow::anyhow!("transfer ended early after 12 of 4096 bytes");
        assert!(!terminal(&severed), "a cut circuit is the ordinary case");

        for refusal in [
            Refusal::Unavailable,
            Refusal::WrongContent,
            Refusal::Overlong,
        ] {
            assert!(
                terminal(&anyhow::Error::new(refusal)),
                "{refusal:?} cannot be fixed by asking again"
            );
        }
    }

    #[test]
    fn a_refusal_survives_the_context_a_caller_adds() {
        let wrapped =
            anyhow::Error::new(Refusal::WrongContent).context("fetching photos/beach.jpg");
        assert!(terminal(&wrapped));
    }
}
