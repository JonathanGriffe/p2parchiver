use std::collections::HashMap;
use std::path::PathBuf;

use ac_files::content::Content;
use ac_files::path::RelPath;
use ac_files::store::Files;
use ac_files::sync::may_serve;
use ac_files::wire::{BLOB_PROTOCOL, BlobReply, BlobRequest};
use ac_groups::id::GroupId;
use ac_groups::store::Groups;
use ac_peers::sync::PeerEvent;
use futures::{AsyncReadExt, AsyncWriteExt};
use libp2p::{PeerId, StreamProtocol};
use std::io::Read as _;
use tokio::sync::mpsc;

const CHUNK: usize = 64 * 1024;

const MAX_HEADER_BYTES: usize = 4096;

const MAX_CONCURRENT: usize = 8;

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
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::Unavailable => write!(f, "the peer would not serve it"),
            Refusal::WrongContent => {
                write!(f, "the content did not match the hash it was asked for")
            }
        }
    }
}

impl std::error::Error for Refusal {}

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
}

impl Transfers {
    pub fn new(db: PathBuf, me: PeerId) -> Self {
        let (outcomes, inbox) = mpsc::unbounded_channel();
        Self {
            outcomes,
            inbox,
            running: HashMap::new(),
            db,
            me,
        }
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

    /// How many transfers are running with this peer.
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

    /// Start a download, and say whether it started.
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
        tokio::spawn(async move {
            let peer = want.peer;
            let group = want.group;
            let path = want.path.clone();
            let event = match download(control, &content, &want, &db, me).await {
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

    // Bytes first, row second — `Content` enforces the ordering, this just feeds it.
    let mut sink = content.resume(&want.dir, &want.path, resume)?;
    let mut buf = vec![0u8; CHUNK];
    let mut got = 0u64;

    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
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
) {
    tokio::spawn(async move {
        if let Err(e) = answer(db, content, me, peer, stream).await {
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

    // Checked before allocating: the length comes from the other end.
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
    fn a_severed_transfer_is_retryable_and_a_refusal_is_not() {
        // The supervisor denies a peer a file on a terminal failure and resumes on a
        // retryable one, so getting this backwards is either an unbounded retry loop or a
        // large file that gives up the first time a relay circuit fills. Neither shows up as
        // an error — one looks like a busy node, the other like a slow one.
        let severed = anyhow::anyhow!("transfer ended early after 12 of 4096 bytes");
        assert!(!terminal(&severed), "a cut circuit is the ordinary case");

        for refusal in [Refusal::Unavailable, Refusal::WrongContent] {
            assert!(
                terminal(&anyhow::Error::new(refusal)),
                "{refusal:?} cannot be fixed by asking again"
            );
        }
    }

    #[test]
    fn a_refusal_survives_the_context_a_caller_adds() {
        // `anyhow`'s `context` wraps rather than replaces, and `downcast_ref` walks the chain.
        // Asserted because the alternative — matching on the rendered message — is what this
        // type exists to avoid, and a wrapped error is exactly where that would break.
        let wrapped =
            anyhow::Error::new(Refusal::WrongContent).context("fetching photos/beach.jpg");
        assert!(terminal(&wrapped));
    }
}
