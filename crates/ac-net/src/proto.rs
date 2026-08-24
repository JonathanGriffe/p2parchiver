use serde::{Deserialize, Serialize};

use crate::attest::Attestation;

pub const ENROLL_PROTOCOL: &str = "/ac/enroll/2.0.0";
pub const ATTEST_PROTOCOL: &str = "/ac/attest/1.0.0";
pub const PRESENCE_PROTOCOL: &str = "/ac/presence/1.0.0";
pub const PEER_ATTEST_PROTOCOL: &str = "/ac/peer-attest/1.0.0";
pub const RENDEZVOUS_NAMESPACE: &str = "ac";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub code: String,
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EnrollResponse {
    Enrolled {
        username: String,
        service: Vec<libp2p::Multiaddr>,
        attestation: Attestation,
    },
    Refused(Refusal),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Refusal {
    UnknownCode,
    AlreadyRedeemed,
    Expired,
    Malformed,
    UsernameTaken,
    InvalidUsername,
    ServerError,
}

impl Refusal {
    /// Wording for a person reading a failed `ac join`.
    pub fn explain(self) -> &'static str {
        match self {
            Refusal::UnknownCode => "the server does not recognise this code",
            Refusal::AlreadyRedeemed => "this code has already been used",
            Refusal::Expired => "this code has expired",
            Refusal::Malformed => "this does not look like an invite code",
            Refusal::UsernameTaken => "that username is already taken on this server",
            Refusal::InvalidUsername => {
                "that username is not allowed; use 3-32 characters of letters, digits, \
                 '-' or '_', starting with a letter or digit"
            }
            Refusal::ServerError => "the server hit an internal error; try again shortly",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestRequest;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AttestResponse {
    Issued(Attestation),
    Refused(AttestRefusal),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AttestRefusal {
    NoUsername,
    ServerError,
}

impl AttestRefusal {
    pub fn explain(self) -> &'static str {
        match self {
            AttestRefusal::NoUsername => {
                "the server has no username on file for this node; run `ac join` again \
                 with a fresh invite"
            }
            AttestRefusal::ServerError => "the server could not issue an attestation",
        }
    }
}

pub const MAX_PRESENCE_QUERY: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PresenceRequest {
    Who(Vec<libp2p::PeerId>),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PresenceResponse {
    Online(Vec<libp2p::PeerId>),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerAttestRequest {
    pub attestation: Attestation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PeerAttestResponse {
    Accepted,
    Rejected(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::{self, Attestation};

    const EVERY_REFUSAL: [Refusal; 7] = [
        Refusal::UnknownCode,
        Refusal::AlreadyRedeemed,
        Refusal::Expired,
        Refusal::Malformed,
        Refusal::UsernameTaken,
        Refusal::InvalidUsername,
        Refusal::ServerError,
    ];

    fn round_trip<T: serde::Serialize + serde::de::DeserializeOwned>(value: &T) -> T {
        let mut buf = Vec::new();
        ciborium::into_writer(value, &mut buf).unwrap();
        ciborium::from_reader(buf.as_slice()).unwrap()
    }

    fn attestation() -> Attestation {
        let server = libp2p::identity::Keypair::generate_ed25519();
        let peer = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        Attestation::issue(&server, &peer, "alice", 1_000_000, attest::LIFETIME).unwrap()
    }

    #[test]
    fn enrol_responses_survive_cbor() {
        let enrolled = EnrollResponse::Enrolled {
            username: "bobs-laptop".to_owned(),
            service: vec!["/ip4/203.0.113.7/udp/4001/quic-v1".parse().unwrap()],
            attestation: attestation(),
        };
        assert_eq!(round_trip(&enrolled), enrolled);

        for refusal in EVERY_REFUSAL {
            let value = EnrollResponse::Refused(refusal);
            assert_eq!(round_trip(&value), value);
        }
    }

    #[test]
    fn attestation_messages_survive_cbor() {
        // The renewal and peer-exchange types carry the credential itself, so a serde
        // mistake here would break admission rather than merely logging oddly.
        assert_eq!(round_trip(&AttestRequest), AttestRequest);

        let issued = AttestResponse::Issued(attestation());
        assert_eq!(round_trip(&issued), issued);

        for refusal in [AttestRefusal::NoUsername, AttestRefusal::ServerError] {
            let value = AttestResponse::Refused(refusal);
            assert_eq!(round_trip(&value), value);
        }

        let request = PeerAttestRequest {
            attestation: attestation(),
        };
        assert_eq!(round_trip(&request), request);

        for response in [
            PeerAttestResponse::Accepted,
            PeerAttestResponse::Rejected("expired".to_owned()),
        ] {
            assert_eq!(round_trip(&response), response);
        }
    }

    #[test]
    fn presence_messages_survive_cbor() {
        let peers: Vec<libp2p::PeerId> = (0..3)
            .map(|_| {
                libp2p::identity::Keypair::generate_ed25519()
                    .public()
                    .to_peer_id()
            })
            .collect();

        let request = PresenceRequest::Who(peers.clone());
        assert_eq!(round_trip(&request), request);

        let response = PresenceResponse::Online(peers[..1].to_vec());
        assert_eq!(round_trip(&response), response);

        let empty = PresenceResponse::Online(Vec::new());
        assert_eq!(round_trip(&empty), empty);
    }

    #[test]
    fn a_full_presence_query_fits_the_request_ceiling() {
        // `MAX_PRESENCE_QUERY` and the codec's byte maximum have to agree, and neither is
        // derivable from the other: a count cap is not a size cap. Measured rather than
        // assumed, because a peer id encoded as a sequence of integers rather than a byte
        // string would be nearly twice this and the count cap would not notice.
        let peers: Vec<libp2p::PeerId> = (0..MAX_PRESENCE_QUERY)
            .map(|_| {
                libp2p::identity::Keypair::generate_ed25519()
                    .public()
                    .to_peer_id()
            })
            .collect();

        let mut buf = Vec::new();
        ciborium::into_writer(&PresenceRequest::Who(peers), &mut buf).unwrap();

        assert!(
            (buf.len() as u64) < crate::swarm::MAX_PRESENCE_BYTES,
            "a full query encodes to {} bytes, over the {} the codec will decode",
            buf.len(),
            crate::swarm::MAX_PRESENCE_BYTES
        );
    }

    #[test]
    fn an_attestation_still_verifies_after_a_round_trip() {
        // The bytes that were signed have to survive encoding unchanged, or verification
        // would pass locally and fail across the wire.
        let server_key = libp2p::identity::Keypair::generate_ed25519();
        let server = server_key.public().to_peer_id();
        let peer = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        let original =
            Attestation::issue(&server_key, &peer, "alice", 1_000_000, attest::LIFETIME).unwrap();

        let delivered = round_trip(&PeerAttestRequest {
            attestation: original,
        });

        assert!(
            delivered
                .attestation
                .verify(&peer, &server, 1_000_000)
                .is_ok()
        );
    }

    #[test]
    fn every_refusal_explains_itself() {
        for refusal in EVERY_REFUSAL {
            assert!(!refusal.explain().is_empty());
        }
        for refusal in [AttestRefusal::NoUsername, AttestRefusal::ServerError] {
            assert!(!refusal.explain().is_empty());
        }
    }
}
