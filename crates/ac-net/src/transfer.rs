//! Bulk byte transfers: a request frame, a reply frame, then raw bytes in chunks.
//!
//! The protocol plugs in through [`Download`] and [`Serve`], the way `request_response` is
//! generic over its request and response. Nothing here knows what the bytes are.

use std::fmt::{self, Display};
use std::future::poll_fn;
use std::io::{self, Read};
use std::sync::Arc;
use std::task::Poll;

use libp2p::futures::{AsyncWriteExt, StreamExt};
use libp2p::{PeerId, Stream, StreamProtocol};
use libp2p_stream::{AlreadyRegistered, Control, IncomingStreams};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::{Semaphore, mpsc};

use crate::stream::{StreamError, read_frame, receive, send, write_frame};
use crate::throttle::Throttle;

/// The behaviour to mount on the swarm for [`Transfers`].
pub use libp2p_stream::Behaviour;

/// One download, driven by the service from its own task.
pub trait Download: Send + 'static {
    type Request: Serialize + Send + Sync;
    type Reply: DeserializeOwned + Send;
    type Receiving: Send;
    type Error: From<StreamError> + Send;

    /// The request to send, or `None` if there turned out to be nothing to fetch.
    fn start(&mut self) -> Result<Option<Self::Request>, Self::Error>;
    /// The peer's reply, before any bytes.
    fn on_reply(self, reply: Self::Reply) -> Result<Self::Receiving, Self::Error>;
    /// One chunk of bytes. An error stops the transfer.
    fn on_chunk(receiving: &mut Self::Receiving, chunk: &[u8]) -> Result<(), Self::Error>;
    /// The stream ended, cleanly or not.
    fn on_end(
        receiving: Self::Receiving,
        ended: Result<(), Self::Error>,
    ) -> Result<(), Self::Error>;
}

/// A reply, and the bytes to send after it, if any.
pub type Answered<S> = (<S as Serve>::Reply, Option<<S as Serve>::Source>);

/// What this node answers, shared by every upload.
pub trait Serve: Send + Sync + 'static {
    type Request: DeserializeOwned + Send;
    type Reply: Serialize + Send + Sync;
    type Source: Read + Send;
    type Error: Display + Send;

    /// The reply to `peer`, and the bytes to send after it, if any.
    fn answer(&self, peer: PeerId, request: Self::Request) -> Result<Answered<Self>, Self::Error>;
    /// The reply when every upload slot is taken.
    fn busy(&self) -> Self::Reply;
}

/// The protocol a [`Transfers`] carries, and its limits.
#[derive(Debug, Clone, Copy)]
pub struct TransferSpec {
    pub protocol: &'static str,
    /// The cap on the request and reply frames.
    pub max_header: usize,
    pub max_downloads: usize,
    pub max_uploads: usize,
}

/// Names one download, the way `OutboundRequestId` names a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransferId(u64);

/// A stream a peer opened. Pass it to [`Transfers::serve`], or drop it to decline.
pub struct Inbound {
    peer: PeerId,
    stream: Box<Stream>,
}

impl Inbound {
    pub fn peer(&self) -> PeerId {
        self.peer
    }
}

pub enum TransferEvent<E> {
    Finished {
        id: TransferId,
        peer: PeerId,
        result: Result<(), E>,
    },
    Inbound(Inbound),
}

type Outcome<E> = (TransferId, PeerId, Result<(), E>);

/// Downloads and uploads in flight, each in its own task.
pub struct Transfers<D: Download, S: Serve> {
    control: Control,
    incoming: Option<IncomingStreams>,
    protocol: StreamProtocol,
    spec: TransferSpec,
    server: Arc<S>,
    down: Arc<Throttle>,
    up: Arc<Throttle>,
    uploads: Arc<Semaphore>,
    running: usize,
    next_id: u64,
    outcomes: mpsc::UnboundedSender<Outcome<D::Error>>,
    finished: mpsc::UnboundedReceiver<Outcome<D::Error>>,
}

impl<D: Download, S: Serve> Transfers<D, S> {
    /// Start accepting `spec.protocol` on `control`.
    pub fn new(
        mut control: Control,
        spec: TransferSpec,
        server: S,
        down: Arc<Throttle>,
        up: Arc<Throttle>,
    ) -> Result<Self, AlreadyRegistered> {
        let protocol = StreamProtocol::new(spec.protocol);
        let incoming = control.accept(protocol.clone())?;
        let (outcomes, finished) = mpsc::unbounded_channel();
        Ok(Self {
            control,
            incoming: Some(incoming),
            protocol,
            spec,
            server: Arc::new(server),
            down,
            up,
            uploads: Arc::new(Semaphore::new(spec.max_uploads)),
            running: 0,
            next_id: 0,
            outcomes,
            finished,
        })
    }

    /// Bytes downloaded and uploaded since this node started.
    pub fn moved(&self) -> (u64, u64) {
        (self.down.moved(), self.up.moved())
    }

    /// Start a download from `peer`, or `None` if every download slot is taken.
    pub fn fetch(&mut self, peer: PeerId, download: D) -> Option<TransferId> {
        if self.running >= self.spec.max_downloads {
            return None;
        }
        self.running += 1;
        let id = TransferId(self.next_id);
        self.next_id += 1;

        let control = self.control.clone();
        let protocol = self.protocol.clone();
        let limit = self.spec.max_header;
        let down = self.down.clone();
        let outcomes = self.outcomes.clone();
        tokio::spawn(async move {
            let result = download_from(control, protocol, limit, peer, download, &down).await;
            let _ = outcomes.send((id, peer, result));
        });
        Some(id)
    }

    /// Wait for a download to finish or a peer to open a stream.
    pub async fn next(&mut self) -> TransferEvent<D::Error> {
        poll_fn(|cx| {
            if let Poll::Ready(Some((id, peer, result))) = self.finished.poll_recv(cx) {
                self.running = self.running.saturating_sub(1);
                return Poll::Ready(TransferEvent::Finished { id, peer, result });
            }
            if let Some(incoming) = &mut self.incoming {
                match incoming.poll_next_unpin(cx) {
                    Poll::Ready(Some((peer, stream))) => {
                        return Poll::Ready(TransferEvent::Inbound(Inbound {
                            peer,
                            stream: Box::new(stream),
                        }));
                    }
                    Poll::Ready(None) => self.incoming = None,
                    Poll::Pending => {}
                }
            }
            Poll::Pending
        })
        .await
    }

    /// Answer an inbound stream, or reply [`Serve::busy`] if every upload slot is taken.
    pub fn serve(&self, inbound: Inbound) {
        let Inbound { peer, mut stream } = inbound;
        let limit = self.spec.max_header;

        let Ok(slot) = self.uploads.clone().try_acquire_owned() else {
            tracing::warn!(%peer, limit = self.spec.max_uploads, "already serving all we can; refusing");
            let busy = self.server.busy();
            tokio::spawn(async move {
                let _ = write_frame(&mut stream, &busy, limit).await;
                let _ = stream.close().await;
            });
            return;
        };

        let server = self.server.clone();
        let up = self.up.clone();
        tokio::spawn(async move {
            let _slot = slot;
            if let Err(e) = upload_to(&*server, peer, &mut stream, limit, &up).await {
                tracing::debug!(%peer, error = %e, "a transfer request went unanswered");
            }
        });
    }
}

async fn download_from<D: Download>(
    mut control: Control,
    protocol: StreamProtocol,
    limit: usize,
    peer: PeerId,
    mut download: D,
    down: &Throttle,
) -> Result<(), D::Error> {
    let Some(request) = download.start()? else {
        return Ok(());
    };

    let mut stream = control
        .open_stream(peer, protocol)
        .await
        .map_err(|e| StreamError::Io(io::Error::other(e)))?;
    write_frame(&mut stream, &request, limit).await?;

    let reply = read_frame(&mut stream, limit).await?;
    let mut receiving = download.on_reply(reply)?;
    let ended = receive(&mut stream, down, |chunk| {
        D::on_chunk(&mut receiving, chunk)
    })
    .await;
    D::on_end(receiving, ended)
}

/// Why an inbound stream got no answer.
enum Unanswered<E> {
    Stream(StreamError),
    Refused(E),
}

impl<E> From<StreamError> for Unanswered<E> {
    fn from(e: StreamError) -> Self {
        Unanswered::Stream(e)
    }
}

impl<E: Display> Display for Unanswered<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unanswered::Stream(e) => e.fmt(f),
            Unanswered::Refused(e) => e.fmt(f),
        }
    }
}

async fn upload_to<S: Serve>(
    server: &S,
    peer: PeerId,
    stream: &mut Stream,
    limit: usize,
    up: &Throttle,
) -> Result<(), Unanswered<S::Error>> {
    let request = read_frame(stream, limit).await?;
    let (reply, source) = server.answer(peer, request).map_err(Unanswered::Refused)?;

    write_frame(stream, &reply, limit).await?;
    if let Some(source) = source {
        send(stream, source, up).await?;
    }
    stream
        .close()
        .await
        .map_err(|e| Unanswered::Stream(StreamError::Io(e)))
}
