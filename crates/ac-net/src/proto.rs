//! Wire types shared by `ac` and `ac-server`.
//!
//! Changing anything here changes the protocol. The version lives in the protocol name
//! rather than in a field, because multistream-select negotiates on that name — so an
//! incompatible peer fails cleanly at negotiation instead of misreading a message.

use serde::{Deserialize, Serialize};

/// Bumped on any incompatible change to [`EnrollRequest`] or [`EnrollResponse`].
pub const ENROLL_PROTOCOL: &str = "/ac/enroll/1.0.0";

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

/// Redeem an invite code.
///
/// Deliberately carries no peer id. libp2p has already proven who is asking as part of
/// establishing the connection, so a peer id in the message would be an unverified claim
/// sitting next to a verified fact — at best redundant, at worst something a later reader
/// trusts by mistake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EnrollResponse {
    /// Enrolled, under the label the invite was created with.
    Enrolled {
        label: String,
        /// Where to reach the server's *services* from now on.
        ///
        /// Enrolment answers on its own listener, which speaks nothing else. This is how
        /// a client learns the address that carries relay, rendezvous and AutoNAT — so it
        /// stores this and never needs the enrolment address again.
        service: Vec<libp2p::Multiaddr>,
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
}

impl Refusal {
    /// Wording for a person reading a failed `ac join`.
    pub fn explain(self) -> &'static str {
        match self {
            Refusal::UnknownCode => "the server does not recognise this code",
            Refusal::AlreadyRedeemed => "this code has already been used",
            Refusal::Expired => "this code has expired",
            Refusal::Malformed => "this does not look like an invite code",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(value: &EnrollResponse) -> EnrollResponse {
        let mut buf = Vec::new();
        ciborium::into_writer(value, &mut buf).unwrap();
        ciborium::from_reader(buf.as_slice()).unwrap()
    }

    #[test]
    fn responses_survive_cbor() {
        let enrolled = EnrollResponse::Enrolled {
            label: "bobs-laptop".to_owned(),
            service: vec!["/ip4/203.0.113.7/udp/4001/quic-v1".parse().unwrap()],
        };
        assert_eq!(round_trip(&enrolled), enrolled);

        for refusal in [
            Refusal::UnknownCode,
            Refusal::AlreadyRedeemed,
            Refusal::Expired,
            Refusal::Malformed,
        ] {
            let value = EnrollResponse::Refused(refusal);
            assert_eq!(round_trip(&value), value);
        }
    }

    #[test]
    fn every_refusal_explains_itself() {
        for refusal in [
            Refusal::UnknownCode,
            Refusal::AlreadyRedeemed,
            Refusal::Expired,
            Refusal::Malformed,
        ] {
            assert!(!refusal.explain().is_empty());
        }
    }
}
