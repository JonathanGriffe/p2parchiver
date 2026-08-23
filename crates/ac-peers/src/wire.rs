//! The `/ac/session/1.0.0` protocol: what is said, not how it is carried.
//!
//! The name, the two message types and the size ceiling are here; the `request_response`
//! behaviour that carries them is built by `ac-node`, the only crate that mounts anything. That
//! split is what keeps **this whole crate free of libp2p** — not as a convention a grep
//! polices, but because libp2p is not a dependency and its types cannot be named. So everything
//! that decides anything — who to dial, what to ask for, when to hang up — is free of
//! networking types by construction, which is what lets the whole supervisor be driven from a
//! test with no socket.
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
///
/// Public because `ac-node` builds the codec from it. Deliberately not shared with the group,
/// manifest or presence ceilings: each is checked against its own protocol's largest legal
/// message by a test in its own crate, and one number cannot answer to four of those.
pub const MAX_SESSION_BYTES: u64 = 1024;

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
