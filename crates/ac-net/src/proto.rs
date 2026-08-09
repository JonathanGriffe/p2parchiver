//! Wire types shared by `ac` and `ac-server`.
//!
//! Changing anything here changes the protocol. The version lives in the protocol name
//! rather than in a field, because multistream-select negotiates on that name — so an
//! incompatible peer fails cleanly at negotiation instead of misreading a message.

use serde::{Deserialize, Serialize};

use crate::attest::Attestation;

/// Bumped on any incompatible change to [`EnrollRequest`] or [`EnrollResponse`].
///
/// At 2.0.0 because enrolment now carries a username and answers with an attestation. A
/// 1.0.0 client fails cleanly at negotiation rather than enrolling without a name.
pub const ENROLL_PROTOCOL: &str = "/ac/enroll/2.0.0";

/// Renewal: a client asks its server for a fresh attestation.
///
/// Mounted on the **service** listener, not on enrolment. That listener already admits
/// only enrolled peers, so the request needs no credential of its own — the connection is
/// the credential — and a revoked client cannot reach it at all. Revocation therefore stops
/// renewal without a line of code to enforce it, and the peer's existing attestation simply
/// runs out.
pub const ATTEST_PROTOCOL: &str = "/ac/attest/1.0.0";

/// Mutual attestation between two clients.
///
/// Symmetric on purpose: both sides send their own attestation as a *request* and answer
/// the other's with a verdict, rather than one side interrogating the other. A dialer and a
/// listener would otherwise need different code paths, and the relayed-then-upgraded case
/// makes "who dialled" a surprisingly slippery question.
pub const PEER_ATTEST_PROTOCOL: &str = "/ac/peer-attest/1.0.0";

/// The rendezvous namespace every node registers under — one, for the whole network.
///
/// # Keep it that way when groups arrive
///
/// Per-group namespaces look like the private option and are the opposite. A namespace is
/// a *filter*, not a capability: `discover(None, ..)` returns every registration in every
/// namespace, so anyone who can query the server can enumerate the lot. Hashing a group's
/// name from a shared secret hides only the label — the table still reads
///
/// ```text
/// ns=8f3a…  A      ← A and B are grouped
/// ns=8f3a…  B
/// ns=c72d…  C      ← C is elsewhere
/// ```
///
/// and that partition *is* the social graph. A single namespace has no partition to leak:
/// the server learns who is online and at what address, which it already knows from
/// enrolment, and nothing about who associates with whom.
///
/// So group-scoped discovery belongs on the client, filtering results locally, exactly as
/// [`crate::swarm`]'s consumers do against the contact list today. The cost is that
/// discovery returns every peer on the server, which is nothing at friend-and-family
/// scale and cheap to poll once the discovery cookie is used.
pub const RENDEZVOUS_NAMESPACE: &str = "ac";

/// Redeem an invite code and claim a username.
///
/// Deliberately carries no peer id. libp2p has already proven who is asking as part of
/// establishing the connection, so a peer id in the message would be an unverified claim
/// sitting next to a verified fact — at best redundant, at worst something a later reader
/// trusts by mistake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub code: String,
    /// The name this user picked. Normalised and validated by the server as well as by the
    /// client — the client's check is a courtesy that fails fast, not a control.
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EnrollResponse {
    /// Enrolled, under the username the client asked for.
    Enrolled {
        /// As stored — normalised, so a client learns the canonical form of its own name.
        username: String,
        /// Where to reach the server's *services* from now on.
        ///
        /// Enrolment answers on its own listener, which speaks nothing else. This is how
        /// a client learns the address that carries relay, rendezvous and AutoNAT — so it
        /// stores this and never needs the enrolment address again.
        service: Vec<libp2p::Multiaddr>,
        /// The credential this client shows other peers. Renewed thereafter over
        /// [`ATTEST_PROTOCOL`]; this is only the first one.
        attestation: Attestation,
    },
    Refused(Refusal),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Refusal {
    /// No such invite. Also what a correctly-formed guess gets.
    UnknownCode,
    AlreadyRedeemed,
    Expired,
    /// Not a well-formed code at all.
    Malformed,
    /// Someone else already has that username.
    UsernameTaken,
    /// The username does not meet [`crate::attest::normalise_username`]'s rules.
    InvalidUsername,
    /// The invite was good; something on the server was not. Kept distinct from
    /// `UnknownCode` so a user is never told to check what they typed over a fault that
    /// had nothing to do with it.
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

/// Ask the server for a fresh attestation.
///
/// Empty for the same reason [`EnrollRequest`] carries no peer id: the connection has
/// already proven who is asking, and the service listener has already proven they are
/// enrolled. There is nothing left to say.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestRequest;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AttestResponse {
    Issued(Attestation),
    Refused(AttestRefusal),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AttestRefusal {
    /// Connected, but with no client row — a peer enrolled before usernames existed, or
    /// one whose row was removed out from under it.
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

/// One half of the mutual check: "here is mine".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerAttestRequest {
    pub attestation: Attestation,
}

/// The other half: what the recipient made of it.
///
/// A rejection carries a reason so the refused peer can log something better than "closed".
/// It is a courtesy to an operator reading two sides of a failure, not information the
/// receiver acts on — a peer that rejects us has already decided.
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
