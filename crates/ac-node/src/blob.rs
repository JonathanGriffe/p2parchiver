use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use ac_files::blob::{Fetch, FetchError, Local, Server};
use ac_files::content::Content;
use ac_files::path::RelPath;
use ac_files::wire::{BLOB_PROTOCOL, BlobRequest, MAX_BLOB_HEADER_BYTES, MAX_DOWNLOADS};
use ac_groups::id::GroupId;
use ac_peers::sync::PeerEvent;
use tokio::sync::Semaphore;

use ac_net::stream::{StreamError, read_frame, receive, send, write_frame};
use ac_net::throttle::Throttle;
use ac_net::transfer::{Download, Serve};
use futures::AsyncWriteExt;
use libp2p::{PeerId, StreamProtocol};
use tokio::sync::mpsc;

pub struct Wanted {
    pub peer: PeerId,
    pub group: GroupId,
    pub path: RelPath,
    pub hash: String,
    pub dir: String,
}

/// Imported files not yet sorted, where a download looks before asking a peer.
pub struct Unsorted {
    pub db: PathBuf,
    pub content: Content,
}

impl Local for Unsorted {
    fn take(&self, group: GroupId, dir: &str, path: &RelPath, hash: &str) -> bool {
        crate::ops::import::adopt_unsorted(
            &self.db,
            &self.content,
            &group.to_string(),
            dir,
            path,
            hash,
        )
        .unwrap_or_else(|e| {
            // Never fatal: a peer has the bytes, and fetching them is what would have happened
            // anyway. Worth a line, because it means the import ledger is unhappy about something.
            tracing::warn!(%hash, error = %format!("{e:#}"), "could not take the unsorted copy");
            false
        })
    }
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
    pub fn new(db: PathBuf, me: PeerId, down: Arc<Throttle>) -> Self {
        let (outcomes, inbox) = mpsc::unbounded_channel();
        Self {
            outcomes,
            inbox,
            running: HashMap::new(),
            db,
            me,
            down,
        }
    }

    /// Bytes of content fetched since this node started.
    pub fn moved_down(&self) -> u64 {
        self.down.moved()
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
        if self.total() >= MAX_DOWNLOADS {
            return false;
        }
        *self.running.entry(want.peer).or_default() += 1;

        let unsorted = Arc::new(Unsorted {
            db: self.db.clone(),
            content: content.clone(),
        });
        let fetch = Fetch::new(
            self.db.clone(),
            self.me,
            content,
            want.group,
            want.dir,
            want.path.clone(),
            want.hash,
        )
        .with_local(unsorted);

        let outcomes = self.outcomes.clone();
        let down = self.down.clone();
        let (peer, group, path) = (want.peer, want.group, want.path);
        tokio::spawn(async move {
            let event = match download(control, peer, fetch, &down).await {
                Ok(()) => PeerEvent::BlobDone { peer, group, path },
                Err(why) => PeerEvent::BlobFailed {
                    peer,
                    group,
                    path,
                    terminal: why.is_terminal(),
                    why: why.to_string(),
                },
            };
            let _ = outcomes.send(event);
        });
        true
    }
}

/// Ask one peer for one file, unless it turns out to be here already.
async fn download(
    mut control: libp2p_stream::Control,
    peer: PeerId,
    mut fetch: Fetch,
    down: &Throttle,
) -> Result<(), FetchError> {
    let Some(request) = fetch.start()? else {
        return Ok(());
    };

    let mut stream = control
        .open_stream(peer, StreamProtocol::new(BLOB_PROTOCOL))
        .await
        .map_err(|e| StreamError::Io(std::io::Error::other(e)))?;
    write_frame(&mut stream, &request, MAX_BLOB_HEADER_BYTES).await?;

    let reply = read_frame(&mut stream, MAX_BLOB_HEADER_BYTES).await?;
    let mut receiving = fetch.on_reply(reply)?;
    let ended = receive(&mut stream, down, |chunk| {
        Fetch::on_chunk(&mut receiving, chunk)
    })
    .await;
    Fetch::on_end(receiving, ended)
}

/// Answer an inbound blob stream.
pub fn serve(
    server: Arc<Server>,
    peer: PeerId,
    stream: libp2p::swarm::Stream,
    up: Arc<Throttle>,
    slots: Arc<Semaphore>,
) {
    let Ok(slot) = slots.try_acquire_owned() else {
        tracing::warn!(%peer, "already serving all we can; refusing");
        tokio::spawn(async move {
            let mut stream = stream;
            let _ = write_frame(&mut stream, &server.busy(), MAX_BLOB_HEADER_BYTES).await;
            let _ = stream.close().await;
        });
        return;
    };

    tokio::spawn(async move {
        let _slot = slot;
        if let Err(e) = answer(&server, peer, stream, &up).await {
            tracing::debug!(%peer, error = %e, "a blob request went unanswered");
        }
    });
}

async fn answer(
    server: &Server,
    peer: PeerId,
    mut stream: libp2p::swarm::Stream,
    up: &Throttle,
) -> anyhow::Result<()> {
    let request: BlobRequest = read_frame(&mut stream, MAX_BLOB_HEADER_BYTES).await?;
    let (reply, source) = server.answer(peer, request)?;

    write_frame(&mut stream, &reply, MAX_BLOB_HEADER_BYTES).await?;
    if let Some(file) = source {
        send(&mut stream, file, up).await?;
    }
    stream.close().await?;
    Ok(())
}
