//! Byte-level I/O over one stream: length-prefixed CBOR frames, and raw bytes in chunks.

use std::io::{self, Read};

use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p_stream::OpenStreamError;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::throttle::Throttle;

/// Bytes moved per read or write once the frames are exchanged.
pub const CHUNK: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum StreamError {
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
}

/// Write `value` as a 4-byte big-endian length followed by its CBOR encoding.
pub async fn write_frame<W, T>(stream: &mut W, value: &T, limit: usize) -> Result<(), StreamError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let mut body = Vec::new();
    ciborium::into_writer(value, &mut body).map_err(|e| StreamError::Encode(e.to_string()))?;
    if body.len() > limit {
        return Err(StreamError::TooLarge {
            len: body.len(),
            limit,
        });
    }

    let len = u32::try_from(body.len()).map_err(|_| StreamError::TooLarge {
        len: body.len(),
        limit,
    })?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(StreamError::Io)?;
    stream.write_all(&body).await.map_err(StreamError::Io)
}

/// Read one frame, refusing a length over `limit` before reading the body.
pub async fn read_frame<R, T>(stream: &mut R, limit: usize) -> Result<T, StreamError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await.map_err(StreamError::Io)?;

    let len = u32::from_be_bytes(len) as usize;
    if len > limit {
        return Err(StreamError::TooLarge { len, limit });
    }

    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .await
        .map_err(StreamError::Io)?;
    ciborium::from_reader(&body[..]).map_err(|e| StreamError::Decode(e.to_string()))
}

/// Copy `source` to the stream a chunk at a time, waiting on the throttle before each chunk.
pub async fn send<W: AsyncWrite + Unpin>(
    stream: &mut W,
    mut source: impl Read,
    throttle: &Throttle,
) -> Result<(), StreamError> {
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = source.read(&mut buf).map_err(StreamError::Source)?;
        if n == 0 {
            return Ok(());
        }
        throttle.consume(n).await;
        stream.write_all(&buf[..n]).await.map_err(StreamError::Io)?;
    }
}

/// Read to the end of the stream, handing each chunk to `each` and then waiting on the
/// throttle. Stops at the first error `each` returns.
pub async fn receive<R, E>(
    stream: &mut R,
    throttle: &Throttle,
    mut each: impl FnMut(&[u8]) -> Result<(), E>,
) -> Result<(), E>
where
    R: AsyncRead + Unpin,
    E: From<StreamError>,
{
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = stream
            .read(&mut buf)
            .await
            .map_err(|e| E::from(StreamError::Io(e)))?;
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
    use libp2p::futures::io::Cursor;

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
        write_frame(&mut wire, &header(), 4096).await.unwrap();

        wire.set_position(0);
        let back: Header = read_frame(&mut wire, 4096).await.unwrap();
        assert_eq!(back, header());
    }

    #[tokio::test]
    async fn an_over_limit_length_is_refused_before_the_body_is_read() {
        // A length that claims far more than the limit, and no body at all: reading one would
        // fail on the missing bytes rather than on the length.
        let mut wire = Cursor::new(u32::MAX.to_be_bytes().to_vec());
        let refused = read_frame::<_, Header>(&mut wire, 4096).await;

        assert!(matches!(
            refused,
            Err(StreamError::TooLarge { limit: 4096, .. })
        ));
        assert_eq!(wire.position(), 4, "only the length was read");
    }

    #[tokio::test]
    async fn an_over_limit_value_is_not_written() {
        let mut wire = Cursor::new(Vec::new());
        let refused = write_frame(&mut wire, &header(), 8).await;

        assert!(matches!(
            refused,
            Err(StreamError::TooLarge { limit: 8, .. })
        ));
        assert!(wire.get_ref().is_empty(), "nothing went out");
    }

    #[tokio::test]
    async fn sent_bytes_are_received_whole_through_the_throttle() {
        let bytes: Vec<u8> = (0..3 * CHUNK + 17).map(|i| (i % 251) as u8).collect();
        let (up, down) = (Throttle::none(), Throttle::none());

        let mut wire = Cursor::new(Vec::new());
        send(&mut wire, &bytes[..], &up).await.unwrap();

        wire.set_position(0);
        let mut got = Vec::new();
        receive::<_, StreamError>(&mut wire, &down, |chunk| {
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
        impl From<StreamError> for Refused {
            fn from(_: StreamError) -> Self {
                Refused::Stream
            }
        }

        let bytes = vec![7u8; 3 * CHUNK];
        let mut wire = Cursor::new(bytes);
        let throttle = Throttle::none();

        let mut chunks = 0;
        let ended = receive(&mut wire, &throttle, |_| {
            chunks += 1;
            Err(Refused::Enough)
        })
        .await;

        assert_eq!(ended, Err(Refused::Enough));
        assert_eq!(chunks, 1, "nothing is handed over after the refusal");
        assert_eq!(throttle.moved(), 0, "and the refused chunk is not counted");
    }
}
