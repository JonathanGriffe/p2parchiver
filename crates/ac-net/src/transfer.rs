//! Bulk byte transfers: a request frame, a reply frame, then raw bytes in chunks.
//!
//! The protocol plugs in through [`Download`] and [`Serve`], the way `request_response` is
//! generic over its request and response. Nothing here knows what the bytes are.

use std::fmt::Display;
use std::future::poll_fn;
use std::io::Read;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use libp2p::futures::{AsyncWriteExt, FutureExt, StreamExt};
use libp2p::{PeerId, Stream, StreamProtocol};
use libp2p_stream::{AlreadyRegistered, IncomingStreams};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::{Semaphore, mpsc};

use crate::stream::{TransferError, read_frame, receive, send, within, write_frame};
use crate::throttle::Throttle;

/// The behaviour to mount on the swarm for [`Transfers`], and the handle to it a service is
/// built from.
pub use libp2p_stream::{Behaviour, Control};

/// One download, driven by the service from its own task.
pub trait Download: Send + 'static {
    type Request: Serialize + Send + Sync;
    type Reply: DeserializeOwned + Send;
    type Receiving: Send;
    type Error: From<TransferError> + Send;

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
    type Error: From<TransferError> + Display + Send;

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
    /// How long the requester may take to open a stream and get its reply, and the server to
    /// read the request, write its reply, or close the stream.
    pub header_timeout: Duration,
    /// How long the bytes may go without moving, throttle waits aside.
    pub stall_timeout: Duration,
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
    spec: TransferSpec,
    server: Arc<S>,
    down: Arc<Throttle>,
    up: Arc<Throttle>,
    downloads: Arc<Semaphore>,
    uploads: Arc<Semaphore>,
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
        let incoming = control.accept(StreamProtocol::new(spec.protocol))?;
        let (outcomes, finished) = mpsc::unbounded_channel();
        Ok(Self {
            control,
            incoming: Some(incoming),
            spec,
            server: Arc::new(server),
            down,
            up,
            downloads: Arc::new(Semaphore::new(spec.max_downloads)),
            uploads: Arc::new(Semaphore::new(spec.max_uploads)),
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
        let slot = self.downloads.clone().try_acquire_owned().ok()?;
        let id = TransferId(self.next_id);
        self.next_id += 1;

        let control = self.control.clone();
        let spec = self.spec;
        let down = self.down.clone();
        let outcomes = self.outcomes.clone();
        tokio::spawn(async move {
            let download = download_from(control, spec, peer, download, &down);
            let result = AssertUnwindSafe(download)
                .catch_unwind()
                .await
                .unwrap_or_else(|_| {
                    tracing::error!(%peer, "a download panicked");
                    Err(TransferError::Panicked.into())
                });
            // Freed before the outcome goes out, so the next fetch can start on it.
            drop(slot);
            let _ = outcomes.send((id, peer, result));
        });
        Some(id)
    }

    /// Wait for a download to finish or a peer to open a stream.
    pub async fn next(&mut self) -> TransferEvent<D::Error> {
        poll_fn(|cx| {
            if let Poll::Ready(Some((id, peer, result))) = self.finished.poll_recv(cx) {
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
        let spec = self.spec;

        let Ok(slot) = self.uploads.clone().try_acquire_owned() else {
            tracing::warn!(%peer, limit = spec.max_uploads, "already serving all we can; refusing");
            let busy = self.server.busy();
            tokio::spawn(async move {
                let header = spec.header_timeout;
                let _ = within(header, write_frame(&mut stream, &busy, spec.max_header)).await;
                let _ = within(header, stream.close()).await;
            });
            return;
        };

        let server = self.server.clone();
        let up = self.up.clone();
        tokio::spawn(async move {
            let _slot = slot;
            if let Err(e) = upload_to(&*server, peer, &mut stream, spec, &up).await {
                tracing::debug!(%peer, error = %e, "a transfer request went unanswered");
            }
        });
    }
}

async fn download_from<D: Download>(
    mut control: Control,
    spec: TransferSpec,
    peer: PeerId,
    mut download: D,
    down: &Throttle,
) -> Result<(), D::Error> {
    let Some(request) = download.start()? else {
        return Ok(());
    };

    let (mut stream, reply) = within(spec.header_timeout, async {
        let protocol = StreamProtocol::new(spec.protocol);
        let mut stream = control.open_stream(peer, protocol).await?;
        write_frame(&mut stream, &request, spec.max_header).await?;
        let reply = read_frame(&mut stream, spec.max_header).await?;
        Ok::<_, TransferError>((stream, reply))
    })
    .await?;
    let mut receiving = download.on_reply(reply)?;
    let ended = receive(&mut stream, down, spec.stall_timeout, |chunk| {
        D::on_chunk(&mut receiving, chunk)
    })
    .await;
    D::on_end(receiving, ended)
}

async fn upload_to<S: Serve>(
    server: &S,
    peer: PeerId,
    stream: &mut Stream,
    spec: TransferSpec,
    up: &Throttle,
) -> Result<(), S::Error> {
    let header = spec.header_timeout;
    let request = within(header, read_frame(stream, spec.max_header)).await?;
    let (reply, source) = server.answer(peer, request)?;

    within(header, write_frame(stream, &reply, spec.max_header)).await?;
    if let Some(source) = source {
        send(stream, source, up, spec.stall_timeout).await?;
    }
    within(header, stream.close()).await?;
    Ok(())
}
