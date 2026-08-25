//! Moving file bytes, over a stream rather than a message.
//!
//! The **only** module in the workspace that names `libp2p-stream`, and the only place file
//! content crosses a socket.
//!
//! # Why a stream, and why a task
//!
//! `request_response` buffers a whole message in memory, so a file cannot be one. Chunking it
//! into messages would mean reassembling out-of-order pieces, hashing in a second pass rather
//! than while copying, and reading from disk inside the event loop. A stream avoids all three:
//! one transfer is one duplex byte stream, fed straight into `Content::stage`, hashed as it is
//! written — the same loop `ac file add` already uses.
//!
//! Each transfer therefore runs in its own task, off the event loop, and **opens its own
//! database handle**. Nothing in this workspace is shared behind a lock; `ac-server` opens
//! three connections for exactly this reason. Outcomes come back on a channel and are drained
//! on the housekeeping tick.
//!
//! # Resuming is ordinary, not exceptional
//!
//! A relayed transfer is cut every `MAX_CIRCUIT_BYTES`, so a large file over a relay *will*
//! span several attempts. A partial download stays in staging; the next attempt re-reads it to
//! rebuild the hash state and asks for the rest. That local read is far cheaper than starting
//! a multi-gigabyte transfer again.

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

/// Copy buffer. Matches `ac_files::content`'s, so a transfer and a local add move bytes in the
/// same sized bites.
const CHUNK: usize = 64 * 1024;

/// Ceiling on a header, which is a handful of fixed fields plus a path.
const MAX_HEADER_BYTES: usize = 4096;

/// Transfers that may run at once.
///
/// Bounded because each holds a database handle, a staging file and a socket. Eight matches
/// `ac_files::sync`'s outbound cap, so neither half of the file layer can starve the other.
const MAX_CONCURRENT: usize = 8;

/// What one download needs to know.
pub struct Wanted {
    pub peer: PeerId,
    pub group: GroupId,
    pub path: RelPath,
    pub hash: String,
    pub dir: String,
}

/// The two failures a peer cannot fix by being asked the same thing again.
///
/// This distinction is the supervisor's whole basis for giving up on a peer, and only this
/// module can draw it — "they refused" and "the wire broke" look identical from above. A typed
/// error rather than a string, because a message that gets reworded would silently turn a
/// terminal failure back into an infinite retry, which is precisely the bug §0 of this
/// milestone fixed on the serving side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// They answered `Unavailable` — after a holdings query said they held it, that is their
    /// index disagreeing with their disk.
    Unavailable,
    /// A *complete* transfer whose content did not hash to what was asked for. Misbehaviour,
    /// not misfortune.
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

/// Whether a failed transfer is worth retrying with the same peer.
///
/// Everything that is not a [`Refusal`] is retryable, and a short read in particular: a relayed
/// transfer is cut every `MAX_CIRCUIT_BYTES` by design, so a severed stream is the *ordinary*
/// case for a large file and the partial resumes from where it stopped.
fn terminal(error: &anyhow::Error) -> bool {
    error.downcast_ref::<Refusal>().is_some()
}

/// Blob transfers in flight, and the channel their outcomes come back on.
///
/// Keyed by peer, because the close decision depends on "is a transfer running with P" — a
/// bare count cannot answer that, and proposing to close a peer we are mid-download from is
/// the one mistake this protocol exists to avoid.
pub struct Transfers {
    outcomes: mpsc::UnboundedSender<PeerEvent>,
    inbox: mpsc::UnboundedReceiver<PeerEvent>,
    running: HashMap<PeerId, usize>,
    /// Where a spawned task opens its own handles. Passed rather than shared, because nothing
    /// in this workspace shares a connection behind a lock.
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

    /// Everything that finished since the last tick.
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
    ///
    /// **Answering is the point.** Declining silently was safe while `ac-files` drove fetching
    /// off a timer and simply asked again; it stopped being safe the moment the supervisor began
    /// counting what it had issued, because a refusal it never heard about was a transfer it
    /// waited on for ever. The supervisor now paces itself to `MAX_TRANSFERS` and should never
    /// reach this, so a `false` here means the two have drifted — and the caller turns it into a
    /// retryable failure rather than a file that quietly never arrives.
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

    // Whatever a previous attempt managed. Its hash state is rebuilt by re-reading it, which
    // is a local read against re-fetching everything.
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
        // Kept, not discarded: a short read is what a severed relay circuit looks like, and
        // the next attempt continues from here.
        sink.park()?;
        anyhow::bail!("transfer ended early after {got} of {expected} bytes");
    }

    let staged = sink.finish()?;
    if staged.hash != want.hash {
        // Discarded, unlike a short read: these bytes are not a head start, they are poison.
        // Left in place, the next attempt reads their length as its resume offset and fails
        // the same way for ever, blaming a different peer each time.
        content.discard(staged).ok();
        anyhow::bail!(Refusal::WrongContent);
    }
    content.commit(staged)?;

    let mut files = Files::open(db, me)?;
    files.mark_have(want.group, &want.path, true)?;
    Ok(())
}

/// Answer an inbound blob stream.
///
/// Spawned with its own database handles: the authorization has to be re-checked here rather
/// than trusted from whoever accepted the stream, and the event loop must not block on a disk
/// read the size of a film.
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

    // The free function, not `FileSync::may_serve`: this runs in its own task with its own
    // handles and never sees the roster. That is not a gap. A stream cannot exist without an
    // admitted connection — `Admission` disconnects anyone who fails — so the only question
    // left is whether the *stores* entitle this peer to these bytes, which is exactly what
    // this answers.
    let Some(size) = may_serve(&files, &groups, &peer, request.group, &path) else {
        write_frame(&mut stream, &BlobReply::Unavailable).await?;
        stream.close().await?;
        return Ok(());
    };

    // The hash is what was asked for, not what the path happens to hold now. Refusing a
    // mismatch means a catalogue that moved underneath the request produces a clean retry
    // rather than the wrong bytes.
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

    // Opened *before* the reply, never after.
    //
    // Promising bytes and then failing to find them is indistinguishable, from the other end,
    // from a relay circuit being cut mid-transfer — which is routine and therefore retried.
    // So a row whose `have` is stale used to produce an unbounded retry loop: the requester
    // asked, was promised, received nothing, resumed, and asked again for ever. Worse than
    // wasted work, it meant a single stale row anywhere left a peer with permanent
    // outstanding work, so it could never go idle.
    let file = match content.open_at(&dir, &path, request.offset) {
        Ok(file) => file,
        Err(e) => {
            // Our index was wrong. Correct it here rather than only refusing this request:
            // otherwise the same claim is made to every other member in turn, and nothing
            // surfaces it to whoever could put the file back.
            //
            // `have = 0`, **not** a tombstone. `removed_at` means the file was deleted from
            // the group; this only means the bytes are not on *this* disk, and other members
            // may hold it perfectly well.
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
///
/// Length-prefixed because a stream has no message boundaries: without one the reader cannot
/// tell where a header stops and the file begins.
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
