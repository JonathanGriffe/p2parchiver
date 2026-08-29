//! One token that carries everything enrolling needs.
//!
//! An invite code has always had to travel out of band, by whatever channel the operator and
//! the newcomer already trust. The server's address and its peer id have to travel with it —
//! the peer id in particular, because it is what pins the server: without it a node would
//! trust whichever machine answered that address, and could be enrolled into a bubble by
//! anyone able to intercept the first connection.
//!
//! Packing all three into one string is what lets that pinning cost the newcomer nothing.
//! They paste one thing instead of transcribing a multiaddr with a base58 key on the end.

use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};

/// Marks the token as ours and says which shape it is, so a later format can be told apart
/// from this one rather than failing as corruption.
const PREFIX: &str = "ac1";

/// Refuses a token far larger than anything this format produces before decoding it.
const MAX_TOKEN_BYTES: usize = 4096;

/// What an operator hands a newcomer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    /// The enrolment address, ending in `/p2p/<peer-id>`.
    pub server: Multiaddr,
    pub code: String,
}

/// The encoded form. A struct rather than a tuple so a field can be added without every old
/// token becoming unreadable.
#[derive(Serialize, Deserialize)]
struct Wire {
    server: String,
    code: String,
}

impl Invite {
    /// Refuses an address with no peer id: a token without one would silently give up the
    /// pinning this whole format exists to carry.
    pub fn new(server: Multiaddr, code: impl Into<String>) -> Result<Self, InviteError> {
        let invite = Self {
            server,
            code: code.into(),
        };
        invite.server_peer().ok_or(InviteError::NoPeerId)?;
        Ok(invite)
    }

    /// The server this token pins.
    pub fn server_peer(&self) -> Option<PeerId> {
        self.server.iter().find_map(|part| match part {
            Protocol::P2p(peer) => Some(peer),
            _ => None,
        })
    }

    pub fn encode(&self) -> Result<String, InviteError> {
        let wire = Wire {
            server: self.server.to_string(),
            code: self.code.clone(),
        };
        let mut body = Vec::new();
        ciborium::into_writer(&wire, &mut body).map_err(|_| InviteError::Encode)?;

        // Base58 with a checksum: the same alphabet peer ids already use, and a token that
        // lost a character on its way through a chat window fails here rather than resolving
        // to a subtly different address.
        Ok(format!(
            "{PREFIX}{}",
            bs58::encode(body).with_check().into_string()
        ))
    }

    pub fn decode(text: &str) -> Result<Self, InviteError> {
        let text = text.trim();
        if text.len() > MAX_TOKEN_BYTES {
            return Err(InviteError::TooLong);
        }
        let body = text.strip_prefix(PREFIX).ok_or(InviteError::NotTheFormat)?;

        let bytes = bs58::decode(body)
            .with_check(None)
            .into_vec()
            .map_err(|_| InviteError::Damaged)?;
        let wire: Wire =
            ciborium::from_reader(bytes.as_slice()).map_err(|_| InviteError::Damaged)?;

        let server: Multiaddr = wire.server.parse().map_err(|_| InviteError::Damaged)?;
        Self::new(server, wire.code)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InviteError {
    #[error(
        "the server address must end with /p2p/<peer-id>: it is what pins the server, so a \
         token without it would trust whichever machine answered"
    )]
    NoPeerId,
    #[error("the invite could not be encoded")]
    Encode,
    #[error("that does not look like an invite token; they begin with \"{PREFIX}\"")]
    NotTheFormat,
    #[error("that invite token is damaged; ask for it again, and copy all of it")]
    Damaged,
    #[error("that is too long to be an invite token")]
    TooLong,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const PEER: &str = "12D3KooWDmPLKCjUV7snQBQVod5bNQnDmZ5X4MYNnPx8NM95zxke";

    fn invite() -> Invite {
        Invite::new(
            format!("/dns4/ac.example.net/udp/4002/quic-v1/p2p/{PEER}")
                .parse()
                .unwrap(),
            "ABCD-EFGH-JKMN",
        )
        .unwrap()
    }

    #[test]
    fn a_token_survives_the_round_trip_exactly() {
        let there = invite();
        let back = Invite::decode(&there.encode().unwrap()).unwrap();

        assert_eq!(back, there);
        assert_eq!(back.server_peer().unwrap().to_string(), PEER);
    }

    #[test]
    fn a_token_is_one_word_a_person_can_paste() {
        let token = invite().encode().unwrap();

        assert!(token.starts_with(PREFIX), "got {token}");
        assert!(
            !token.contains(char::is_whitespace),
            "it has to survive a chat window: {token}"
        );
    }

    /// The whole point of the checksum. A token that lost or gained a character has to be
    /// refused, not resolved to some other address that happens to decode.
    #[test]
    fn a_token_that_did_not_arrive_intact_is_refused() {
        let token = invite().encode().unwrap();

        assert_eq!(
            Invite::decode(&token[..token.len() - 1]),
            Err(InviteError::Damaged)
        );
        assert_eq!(
            Invite::decode(&format!("{token}x")),
            Err(InviteError::Damaged)
        );

        let mut swapped: Vec<char> = token.chars().collect();
        swapped.swap(PREFIX.len() + 3, PREFIX.len() + 4);
        let swapped: String = swapped.into_iter().collect();
        if swapped != token {
            assert_eq!(Invite::decode(&swapped), Err(InviteError::Damaged));
        }
    }

    #[test]
    fn something_that_is_not_a_token_says_so_rather_than_looking_damaged() {
        for text in [
            "",
            "hello",
            "/dns4/ac.example.net/udp/4002/quic-v1",
            "ABCD-EFGH-JKMN",
        ] {
            assert_eq!(
                Invite::decode(text),
                Err(InviteError::NotTheFormat),
                "{text:?}"
            );
        }
    }

    #[test]
    fn surrounding_whitespace_is_forgiven() {
        let token = invite().encode().unwrap();

        assert_eq!(Invite::decode(&format!("  {token}\n")).unwrap(), invite());
    }

    #[test]
    fn an_address_with_no_peer_id_is_refused_at_the_source() {
        let bare: Multiaddr = "/dns4/ac.example.net/udp/4002/quic-v1".parse().unwrap();

        assert_eq!(Invite::new(bare, "code"), Err(InviteError::NoPeerId));
    }
}
