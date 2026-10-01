//! Bulk byte transfers: a request frame, a reply frame, then raw bytes in chunks.
//!
//! The protocol plugs in through [`Download`] and [`Serve`], the way `request_response` is
//! generic over its request and response. Nothing here knows what the bytes are.

use std::fmt::Display;
use std::io::Read;

use libp2p::PeerId;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::stream::StreamError;

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
