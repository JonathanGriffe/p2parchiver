//! The `/ac/session/1.0.0` protocol.
//!
//! The **only** module in this crate permitted to name `libp2p::request_response`. Everything
//! that decides anything — who to dial, what to ask for, when to hang up — is free of
//! networking types, which is what lets the whole supervisor be driven from a test with no
//! socket. `tests/layering.rs` enforces it.
//!
//! # What it is for
//!
//! Two peers that have finished with each other should stop holding a connection open, and
//! neither of them can tell on its own: a peer sitting silent may be about to ask for a
//! four-gigabyte file. So closing is **proposed**, not announced. We propose when we are
//! drained — no round in flight with them, no transfer in flight with them, and they are not
//! the member we are currently pulling a group's files through — and they answer under the
//! same test on their side.
//!
//! Only the **proposer** disconnects when both sides say `Ready`. One side hanging up is
//! enough, and two would race.
//!
//! # It is politeness, not correctness
//!
//! Nothing here is load-bearing for data integrity. A connection cut mid-transfer parks the
//! partial and resumes later, which `ac-node`'s blob reader already does because a relayed
//! transfer is severed every `MAX_CIRCUIT_BYTES` regardless of what anyone intended. This
//! protocol exists so that the common case — both sides genuinely done — costs one round trip
//! instead of an idle-timeout, and so a peer is never cut off mid-sentence when it could have
//! said "not yet".
//!
//! Two peers that never speak this protocol still work. Their connections are reaped by
//! `IDLE_CONNECTION_TIMEOUT` instead, which is exactly what happens with a peer running an
//! older build.

use libp2p::StreamProtocol;
use libp2p::request_response::{self, ProtocolSupport};
use serde::{Deserialize, Serialize};

/// Bumped on any incompatible change to the types below. The version lives in the name because
/// multistream-select negotiates on it, so an incompatible peer fails cleanly at negotiation
/// rather than misreading a message — the same convention as `ac_net::proto`.
pub const SESSION_PROTOCOL: &str = "/ac/session/1.0.0";

/// Largest session message either side will decode.
///
/// A kilobyte for what encodes to a handful of bytes. Set explicitly rather than left at the
/// codec's 1 MiB request and 10 MiB response, because those are a memory budget this protocol
/// has no use for: anything larger than this is not a session message and refusing to buffer
/// it costs nothing.
const MAX_SESSION_BYTES: u64 = 1024;

/// "I have nothing further for you. Do you have anything further for me?"
///
/// Carries no reason and no group. Whether *we* are done is a fact about the whole peer, and
/// whether *they* are is exactly what the answer says — so there is nothing to qualify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionRequest {
    Closing,
}

/// The answer, which is only ever about the responder's own outstanding work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionResponse {
    /// Drained on this side too. The **proposer** may now disconnect.
    Ready,
    /// Still has something to ask for or to send. The proposal is dropped and the connection
    /// left alone; whoever is still busy will go quiet eventually and the question is asked
    /// again then.
    Busy,
}

pub type Behaviour = request_response::cbor::Behaviour<SessionRequest, SessionResponse>;

/// Build the behaviour `ac-node` mounts in `AcBehaviour`'s app slot.
///
/// [`ProtocolSupport::Full`] because the exchange is symmetric: either peer may propose and
/// either may be asked, and which of them dialled is not a useful distinction — a relayed
/// connection that gets upgraded makes "who dialled" a slippery question anyway, the same
/// reason `/ac/peer-attest/1.0.0` is symmetric.
///
/// Note the app slot's first rule, which this obeys by construction: it may *ask* to close,
/// never refuse a connection. Admission belongs to `ac_net::authz`.
pub fn behaviour() -> Behaviour {
    let codec = request_response::cbor::codec::Codec::default()
        .set_request_size_maximum(MAX_SESSION_BYTES)
        .set_response_size_maximum(MAX_SESSION_BYTES);

    Behaviour::with_codec(
        codec,
        [(StreamProtocol::new(SESSION_PROTOCOL), ProtocolSupport::Full)],
        request_response::Config::default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip<T: Serialize + serde::de::DeserializeOwned>(value: &T) -> T {
        let mut buf = Vec::new();
        ciborium::into_writer(value, &mut buf).unwrap();
        ciborium::from_reader(buf.as_slice()).unwrap()
    }

    fn encoded<T: Serialize>(value: &T) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(value, &mut buf).unwrap();
        buf
    }

    #[test]
    fn every_message_survives_cbor() {
        assert_eq!(
            round_trip(&SessionRequest::Closing),
            SessionRequest::Closing
        );

        for response in [SessionResponse::Ready, SessionResponse::Busy] {
            assert_eq!(round_trip(&response), response);
        }
    }

    #[test]
    fn ready_and_busy_are_not_the_same_bytes() {
        // A unit-only enum that encoded both variants identically would make every proposal
        // succeed, which is the one failure this protocol could have that still looks like
        // it works: connections would close mid-transfer and the partials would silently
        // resume, so the symptom would be slowness rather than an error.
        assert_ne!(
            encoded(&SessionResponse::Ready),
            encoded(&SessionResponse::Busy)
        );
    }

    #[test]
    fn a_session_message_fits_far_inside_its_ceiling() {
        // The ceiling is deliberately far above what these encode to, so the check is that
        // nothing has quietly grown a field rather than that the number is tight.
        for size in [
            encoded(&SessionRequest::Closing).len(),
            encoded(&SessionResponse::Ready).len(),
            encoded(&SessionResponse::Busy).len(),
        ] {
            assert!(
                (size as u64) < MAX_SESSION_BYTES,
                "a session message encodes to {size} bytes, over the {MAX_SESSION_BYTES} the \
                 codec will decode"
            );
        }
    }
}
