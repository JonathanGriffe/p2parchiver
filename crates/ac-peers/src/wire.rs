use serde::{Deserialize, Serialize};
pub const SESSION_PROTOCOL: &str = "/ac/session/1.0.0";

/// Largest session message either side will decode.
pub const MAX_SESSION_BYTES: u64 = 1024;

/// "I have nothing further for you. Do you have anything further for me?"
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionRequest {
    Closing,
}

/// The answer, which is only ever about the responder's own outstanding work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionResponse {
    Ready,
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
