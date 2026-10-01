//! Byte-level I/O over one stream: length-prefixed CBOR frames, and raw bytes in chunks.

use std::io::{self, Read};
use std::time::Duration;

use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p_stream::OpenStreamError;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::throttle::Throttle;

/// Bytes moved per read or write once the frames are exchanged.
pub const CHUNK: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum TransferError {
    #[error("could not open the stream: {0}")]
    Open(OpenStreamError),
    #[error("a {len} byte frame exceeds the {limit} byte limit")]
    TooLarge { len: usize, limit: usize },
    #[error("could not encode a frame: {0}")]
    Encode(String),
    #[error("could not decode a frame: {0}")]
    Decode(String),
    #[error("could not read the bytes to send: {0}")]
    Source(io::Error),
    #[error(transparent)]
    Io(io::Error),
    #[error("the transfer panicked")]
    Panicked,
    #[error("the peer went quiet past the deadline")]
    TimedOut,
}

/// Run `io`, failing with [`TransferError::TimedOut`] if it has not finished within `limit`.
pub(crate) async fn within<T>(
    limit: Duration,
    io: impl Future<Output = Result<T, TransferError>>,
) -> Result<T, TransferError> {
    tokio::time::timeout(limit, io)
        .await
        .map_err(|_| TransferError::TimedOut)?
}

/// Write `value` as a 4-byte big-endian length followed by its CBOR encoding, within
/// `timeout`.
pub async fn write_frame<W, T>(
    stream: &mut W,
    value: &T,
    limit: usize,
    timeout: Duration,
) -> Result<(), TransferError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let mut body = Vec::new();
    ciborium::into_writer(value, &mut body).map_err(|e| TransferError::Encode(e.to_string()))?;
    if body.len() > limit {
        return Err(TransferError::TooLarge {
            len: body.len(),
            limit,
        });
    }

    let len = u32::try_from(body.len()).map_err(|_| TransferError::TooLarge {
        len: body.len(),
        limit,
    })?;
    within(timeout, async {
        stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(TransferError::Io)?;
        stream.write_all(&body).await.map_err(TransferError::Io)
    })
    .await
}

/// Read one frame within `timeout`, refusing a length over `limit` before reading the body.
pub async fn read_frame<R, T>(
    stream: &mut R,
    limit: usize,
    timeout: Duration,
) -> Result<T, TransferError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let body = within(timeout, async {
        let mut len = [0u8; 4];
        stream
            .read_exact(&mut len)
            .await
            .map_err(TransferError::Io)?;

        let len = u32::from_be_bytes(len) as usize;
        if len > limit {
            return Err(TransferError::TooLarge { len, limit });
        }

        let mut body = vec![0u8; len];
        stream
            .read_exact(&mut body)
            .await
            .map_err(TransferError::Io)?;
        Ok(body)
    })
    .await?;
    ciborium::from_reader(&body[..]).map_err(|e| TransferError::Decode(e.to_string()))
}

/// Copy `source` to the stream a chunk at a time, waiting on the throttle before each chunk.
/// Each write must finish within `stall`; the throttle's waits do not count.
pub async fn send<W: AsyncWrite + Unpin>(
    stream: &mut W,
    mut source: impl Read,
    throttle: &Throttle,
    stall: Duration,
) -> Result<(), TransferError> {
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = source.read(&mut buf).map_err(TransferError::Source)?;
        if n == 0 {
            return Ok(());
        }
        throttle.consume(n).await;
        let mut left = &buf[..n];
        while !left.is_empty() {
            let written = within(stall, async {
                stream.write(left).await.map_err(TransferError::Io)
            })
            .await?;
            if written == 0 {
                return Err(TransferError::Io(io::ErrorKind::WriteZero.into()));
            }
            left = &left[written..];
        }
    }
}

/// Read to the end of the stream, handing each chunk to `each` and then waiting on the
/// throttle. Stops at the first error `each` returns. Each read must finish within `stall`;
/// the throttle's waits do not count.
pub async fn receive<R, E>(
    stream: &mut R,
    throttle: &Throttle,
    stall: Duration,
    mut each: impl FnMut(&[u8]) -> Result<(), E>,
) -> Result<(), E>
where
    R: AsyncRead + Unpin,
    E: From<TransferError>,
{
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = within(stall, async {
            stream.read(&mut buf).await.map_err(TransferError::Io)
        })
        .await?;
        if n == 0 {
            return Ok(());
        }
        each(&buf[..n])?;
        throttle.consume(n).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll, ready};

    use libp2p::futures::io::Cursor;
    use tokio::time::{Instant, Sleep};

    const DEADLINE: Duration = Duration::from_secs(10);

    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Header {
        name: String,
        offset: u64,
    }

    fn header() -> Header {
        Header {
            name: "photos/beach.jpg".to_owned(),
            offset: 4096,
        }
    }

    #[tokio::test]
    async fn a_frame_round_trips() {
        let mut wire = Cursor::new(Vec::new());
        write_frame(&mut wire, &header(), 4096, DEADLINE)
            .await
            .unwrap();

        wire.set_position(0);
        let back: Header = read_frame(&mut wire, 4096, DEADLINE).await.unwrap();
        assert_eq!(back, header());
    }

    #[tokio::test]
    async fn an_over_limit_length_is_refused_before_the_body_is_read() {
        // A length that claims far more than the limit, and no body at all: reading one would
        // fail on the missing bytes rather than on the length.
        let mut wire = Cursor::new(u32::MAX.to_be_bytes().to_vec());
        let refused = read_frame::<_, Header>(&mut wire, 4096, DEADLINE).await;

        assert!(matches!(
            refused,
            Err(TransferError::TooLarge { limit: 4096, .. })
        ));
        assert_eq!(wire.position(), 4, "only the length was read");
    }

    #[tokio::test]
    async fn an_over_limit_value_is_not_written() {
        let mut wire = Cursor::new(Vec::new());
        let refused = write_frame(&mut wire, &header(), 8, DEADLINE).await;

        assert!(matches!(
            refused,
            Err(TransferError::TooLarge { limit: 8, .. })
        ));
        assert!(wire.get_ref().is_empty(), "nothing went out");
    }

    #[tokio::test]
    async fn sent_bytes_are_received_whole_through_the_throttle() {
        let bytes: Vec<u8> = (0..3 * CHUNK + 17).map(|i| (i % 251) as u8).collect();
        let (up, down) = (Throttle::none(), Throttle::none());

        let mut wire = Cursor::new(Vec::new());
        send(&mut wire, &bytes[..], &up, DEADLINE).await.unwrap();

        wire.set_position(0);
        let mut got = Vec::new();
        receive::<_, TransferError>(&mut wire, &down, DEADLINE, |chunk| {
            got.extend_from_slice(chunk);
            Ok(())
        })
        .await
        .unwrap();

        assert_eq!(got, bytes);
        assert_eq!(up.moved(), bytes.len() as u64);
        assert_eq!(down.moved(), bytes.len() as u64);
    }

    #[tokio::test]
    async fn receiving_stops_at_the_first_refused_chunk() {
        #[derive(Debug, PartialEq)]
        enum Refused {
            Enough,
            Stream,
        }
        impl From<TransferError> for Refused {
            fn from(_: TransferError) -> Self {
                Refused::Stream
            }
        }

        let bytes = vec![7u8; 3 * CHUNK];
        let mut wire = Cursor::new(bytes);
        let throttle = Throttle::none();

        let mut chunks = 0;
        let ended = receive(&mut wire, &throttle, DEADLINE, |_| {
            chunks += 1;
            Err(Refused::Enough)
        })
        .await;

        assert_eq!(ended, Err(Refused::Enough));
        assert_eq!(chunks, 1, "nothing is handed over after the refusal");
        assert_eq!(throttle.moved(), 0, "and the refused chunk is not counted");
    }

    /// An in-memory peer. It hands over `readable` then either ends or goes silent, and accepts
    /// `writable` bytes then stops taking more. With a `pace`, each read and write waits that
    /// long first.
    struct Peer {
        readable: Vec<u8>,
        read: usize,
        ends: bool,
        writable: usize,
        written: usize,
        per_op: usize,
        pace: Option<Duration>,
        sleep: Option<Pin<Box<Sleep>>>,
    }

    impl Peer {
        fn new(readable: Vec<u8>, ends: bool, writable: usize) -> Self {
            Self {
                readable,
                read: 0,
                ends,
                writable,
                written: 0,
                per_op: CHUNK,
                pace: None,
                sleep: None,
            }
        }

        fn silent() -> Self {
            Self::new(Vec::new(), false, 0)
        }

        fn paced(mut self, per_op: usize, pace: Duration) -> Self {
            self.per_op = per_op;
            self.pace = Some(pace);
            self
        }

        fn wait(&mut self, cx: &mut Context<'_>) -> Poll<()> {
            let Some(pace) = self.pace else {
                return Poll::Ready(());
            };
            self.sleep
                .get_or_insert_with(|| Box::pin(tokio::time::sleep(pace)))
                .as_mut()
                .poll(cx)
        }
    }

    impl AsyncRead for Peer {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            ready!(this.wait(cx));
            let left = this.readable.len() - this.read;
            if left == 0 {
                return if this.ends {
                    Poll::Ready(Ok(0))
                } else {
                    // Never woken: only the caller's deadline ends the wait.
                    Poll::Pending
                };
            }
            let n = buf.len().min(left).min(this.per_op);
            buf[..n].copy_from_slice(&this.readable[this.read..this.read + n]);
            this.read += n;
            this.sleep = None;
            Poll::Ready(Ok(n))
        }
    }

    impl AsyncWrite for Peer {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            ready!(this.wait(cx));
            let n = buf.len().min(this.writable - this.written).min(this.per_op);
            if n == 0 {
                return Poll::Pending;
            }
            this.written += n;
            this.sleep = None;
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Receive from `peer` into a buffer, whatever the outcome.
    async fn receive_all(
        peer: &mut Peer,
        throttle: &Throttle,
    ) -> (Result<(), TransferError>, Vec<u8>) {
        let mut got = Vec::new();
        let ended = receive(peer, throttle, DEADLINE, |chunk| {
            got.extend_from_slice(chunk);
            Ok(())
        })
        .await;
        (ended, got)
    }

    /// A rate at which every chunk waits twice the deadline on the throttle.
    fn slower_than_the_deadline() -> Throttle {
        let rate = CHUNK as u64 / (2 * DEADLINE.as_secs());
        Throttle::new(rate, CHUNK as u64)
    }

    #[tokio::test(start_paused = true)]
    async fn reading_a_frame_times_out_on_a_peer_that_never_sends() {
        let start = Instant::now();
        let read = read_frame::<_, Header>(&mut Peer::silent(), 4096, DEADLINE).await;

        assert!(matches!(read, Err(TransferError::TimedOut)), "got {read:?}");
        assert_eq!(start.elapsed(), DEADLINE);
    }

    #[tokio::test(start_paused = true)]
    async fn writing_a_frame_times_out_on_a_peer_that_never_reads() {
        let written = write_frame(&mut Peer::silent(), &header(), 4096, DEADLINE).await;

        assert!(matches!(written, Err(TransferError::TimedOut)));
    }

    #[tokio::test(start_paused = true)]
    async fn receiving_times_out_on_a_peer_that_stops_sending_partway() {
        let mut peer = Peer::new(vec![7u8; 100_000], false, 0);
        let (ended, got) = receive_all(&mut peer, &Throttle::none()).await;

        assert!(
            matches!(ended, Err(TransferError::TimedOut)),
            "got {ended:?}"
        );
        assert_eq!(got.len(), 100_000, "what came before the stall was kept");
    }

    #[tokio::test(start_paused = true)]
    async fn sending_times_out_on_a_peer_that_stops_reading_partway() {
        let mut peer = Peer::new(Vec::new(), false, 100_000);
        let bytes = vec![7u8; 3 * CHUNK];
        let sent = send(&mut peer, &bytes[..], &Throttle::none(), DEADLINE).await;

        assert!(matches!(sent, Err(TransferError::TimedOut)), "got {sent:?}");
        assert_eq!(peer.written, 100_000);
    }

    #[tokio::test(start_paused = true)]
    async fn waiting_on_the_throttle_does_not_count_as_a_stall() {
        let bytes = vec![7u8; 3 * CHUNK];
        let start = Instant::now();

        let mut from = Peer::new(bytes.clone(), true, 0);
        let (ended, got) = receive_all(&mut from, &slower_than_the_deadline()).await;
        ended.unwrap();
        assert_eq!(got, bytes);

        let mut to = Peer::new(Vec::new(), false, bytes.len());
        send(&mut to, &bytes[..], &slower_than_the_deadline(), DEADLINE)
            .await
            .unwrap();
        assert_eq!(to.written, bytes.len());

        assert!(start.elapsed() > 4 * DEADLINE, "each chunk was held back");
    }

    #[tokio::test(start_paused = true)]
    async fn progress_restarts_the_stall_deadline() {
        let bytes: Vec<u8> = (0..10_000).map(|i| (i % 251) as u8).collect();
        let start = Instant::now();

        let mut from = Peer::new(bytes.clone(), true, 0).paced(1000, DEADLINE / 2);
        let (ended, got) = receive_all(&mut from, &Throttle::none()).await;
        ended.unwrap();
        assert_eq!(got, bytes);

        let mut to = Peer::new(Vec::new(), false, bytes.len()).paced(1000, DEADLINE / 2);
        send(&mut to, &bytes[..], &Throttle::none(), DEADLINE)
            .await
            .unwrap();
        assert_eq!(to.written, bytes.len());

        assert!(
            start.elapsed() > 4 * DEADLINE,
            "slower than the deadline overall"
        );
    }
}
