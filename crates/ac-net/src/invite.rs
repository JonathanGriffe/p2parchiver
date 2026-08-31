use std::borrow::Cow;
use std::net::{Ipv4Addr, Ipv6Addr};

use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId, identity};

use crate::identity::public_key_of;

const PREFIX: &str = "ac1";

/// The invite secret
pub const CODE_BYTES: usize = 16;

/// An ed25519 public key, which is all a peer id is once the multihash wrapping is dropped.
const KEY_BYTES: usize = 32;

/// Refuses a token far larger than anything this format produces before decoding it.
const MAX_TOKEN_CHARS: usize = 512;

const TAG_IP4: u8 = 0;
const TAG_IP6: u8 = 1;
const TAG_DNS: u8 = 2;
const TAG_DNS4: u8 = 3;
const TAG_DNS6: u8 = 4;

/// What an operator hands a newcomer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    /// The enrolment address, `/<host>/udp/<port>/quic-v1/p2p/<peer-id>`.
    pub server: Multiaddr,
    pub code: [u8; CODE_BYTES],
}

impl Invite {
    pub fn new(server: Multiaddr, code: [u8; CODE_BYTES]) -> Result<Self, InviteError> {
        let parts = Parts::of(&server).ok_or(InviteError::NotAnEnrolmentAddress)?;
        key_of(&parts.peer)?;
        Ok(Self { server, code })
    }

    /// The server this token pins.
    pub fn server_peer(&self) -> Option<PeerId> {
        self.server.iter().find_map(|part| match part {
            Protocol::P2p(peer) => Some(peer),
            _ => None,
        })
    }

    pub fn encode(&self) -> Result<String, InviteError> {
        let parts = Parts::of(&self.server).ok_or(InviteError::NotAnEnrolmentAddress)?;

        let mut body = Vec::with_capacity(64);
        parts.host.write(&mut body)?;
        body.extend_from_slice(&parts.port.to_be_bytes());
        body.extend_from_slice(&key_of(&parts.peer)?);
        body.extend_from_slice(&self.code);
        Ok(format!(
            "{PREFIX}{}",
            bs58::encode(body).with_check().into_string()
        ))
    }

    pub fn decode(text: &str) -> Result<Self, InviteError> {
        let text = text.trim();
        if text.len() > MAX_TOKEN_CHARS {
            return Err(InviteError::TooLong);
        }
        let body = text.strip_prefix(PREFIX).ok_or(InviteError::NotTheFormat)?;

        let bytes = bs58::decode(body)
            .with_check(None)
            .into_vec()
            .map_err(|_| InviteError::Damaged)?;

        let mut rest = bytes.as_slice();
        let host = Host::read(&mut rest)?;
        let port = u16::from_be_bytes(
            take(&mut rest, 2)?
                .try_into()
                .map_err(|_| InviteError::Damaged)?,
        );
        let peer = peer_of(take(&mut rest, KEY_BYTES)?)?;
        let code: [u8; CODE_BYTES] = take(&mut rest, CODE_BYTES)?
            .try_into()
            .map_err(|_| InviteError::Damaged)?;
        if !rest.is_empty() {
            return Err(InviteError::Damaged);
        }

        let mut server = Multiaddr::empty();
        server.push(host.into_protocol());
        server.push(Protocol::Udp(port));
        server.push(Protocol::QuicV1);
        server.push(Protocol::P2p(peer));

        Ok(Self { server, code })
    }
}

/// The parts of an enrolment address that vary, which is all the token carries.
struct Parts {
    host: Host,
    port: u16,
    peer: PeerId,
}

impl Parts {
    /// `None` for anything that is not `/<host>/udp/<port>/quic-v1/p2p/<peer-id>`.
    fn of(addr: &Multiaddr) -> Option<Self> {
        let mut parts = addr.iter();
        let host = Host::of(&parts.next()?)?;
        let Protocol::Udp(port) = parts.next()? else {
            return None;
        };
        if !matches!(parts.next()?, Protocol::QuicV1) {
            return None;
        }
        let Protocol::P2p(peer) = parts.next()? else {
            return None;
        };
        if parts.next().is_some() {
            return None;
        }
        Some(Self { host, port, peer })
    }
}

/// Owned so it outlives the address it was read from.
enum Host {
    Ip4(Ipv4Addr),
    Ip6(Ipv6Addr),
    Name(u8, String),
}

impl Host {
    fn of(part: &Protocol<'_>) -> Option<Self> {
        Some(match part {
            Protocol::Ip4(ip) => Self::Ip4(*ip),
            Protocol::Ip6(ip) => Self::Ip6(*ip),
            Protocol::Dns(name) => Self::Name(TAG_DNS, name.to_string()),
            Protocol::Dns4(name) => Self::Name(TAG_DNS4, name.to_string()),
            Protocol::Dns6(name) => Self::Name(TAG_DNS6, name.to_string()),
            _ => return None,
        })
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), InviteError> {
        match self {
            Self::Ip4(ip) => {
                out.push(TAG_IP4);
                out.extend_from_slice(&ip.octets());
            }
            Self::Ip6(ip) => {
                out.push(TAG_IP6);
                out.extend_from_slice(&ip.octets());
            }
            Self::Name(tag, name) => {
                let len = u8::try_from(name.len()).map_err(|_| InviteError::HostTooLong)?;
                out.push(*tag);
                out.push(len);
                out.extend_from_slice(name.as_bytes());
            }
        }
        Ok(())
    }

    fn read(rest: &mut &[u8]) -> Result<Self, InviteError> {
        let tag = take(rest, 1)?[0];
        Ok(match tag {
            TAG_IP4 => {
                let octets: [u8; 4] = take(rest, 4)?
                    .try_into()
                    .map_err(|_| InviteError::Damaged)?;
                Self::Ip4(octets.into())
            }
            TAG_IP6 => {
                let octets: [u8; 16] = take(rest, 16)?
                    .try_into()
                    .map_err(|_| InviteError::Damaged)?;
                Self::Ip6(octets.into())
            }
            TAG_DNS | TAG_DNS4 | TAG_DNS6 => {
                let len = usize::from(take(rest, 1)?[0]);
                let name = take(rest, len)?;
                let name = std::str::from_utf8(name).map_err(|_| InviteError::Damaged)?;
                Self::Name(tag, name.to_owned())
            }
            _ => return Err(InviteError::Damaged),
        })
    }

    fn into_protocol(self) -> Protocol<'static> {
        match self {
            Self::Ip4(ip) => Protocol::Ip4(ip),
            Self::Ip6(ip) => Protocol::Ip6(ip),
            Self::Name(TAG_DNS4, name) => Protocol::Dns4(Cow::Owned(name)),
            Self::Name(TAG_DNS6, name) => Protocol::Dns6(Cow::Owned(name)),
            Self::Name(_, name) => Protocol::Dns(Cow::Owned(name)),
        }
    }
}

/// The 32 bytes inside a peer id. Everything else in a peer id is multihash and protobuf
/// framing this format can rebuild.
fn key_of(peer: &PeerId) -> Result<[u8; KEY_BYTES], InviteError> {
    public_key_of(peer)
        .map_err(|_| InviteError::UnsupportedKey)?
        .try_into_ed25519()
        .map(|key| key.to_bytes())
        .map_err(|_| InviteError::UnsupportedKey)
}

fn peer_of(key: &[u8]) -> Result<PeerId, InviteError> {
    let key =
        identity::ed25519::PublicKey::try_from_bytes(key).map_err(|_| InviteError::Damaged)?;
    Ok(PeerId::from_public_key(&identity::PublicKey::from(key)))
}

fn take<'a>(rest: &mut &'a [u8], n: usize) -> Result<&'a [u8], InviteError> {
    if rest.len() < n {
        return Err(InviteError::Damaged);
    }
    let (head, tail) = rest.split_at(n);
    *rest = tail;
    Ok(head)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InviteError {
    #[error(
        "an invite address must be /<ip-or-name>/udp/<port>/quic-v1/p2p/<peer-id>: the peer \
         id is what pins the server, so a token without it would trust whichever machine \
         answered"
    )]
    NotAnEnrolmentAddress,
    #[error("a token can only pin a server with an ed25519 key")]
    UnsupportedKey,
    #[error("that host name is too long to put in a token")]
    HostTooLong,
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
    const CODE: [u8; CODE_BYTES] = [
        0x9f, 0x1c, 0x00, 0xff, 0x42, 0x7a, 0x13, 0x88, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03,
        0x04,
    ];

    fn invite_to(address: &str) -> Invite {
        Invite::new(format!("{address}/p2p/{PEER}").parse().unwrap(), CODE).unwrap()
    }

    fn invite() -> Invite {
        invite_to("/dns4/ac.example.net/udp/4002/quic-v1")
    }

    #[test]
    fn a_token_survives_the_round_trip_exactly() {
        let there = invite();
        let back = Invite::decode(&there.encode().unwrap()).unwrap();

        assert_eq!(back, there);
        assert_eq!(back.server_peer().unwrap().to_string(), PEER);
    }

    #[test]
    fn every_kind_of_host_survives_the_round_trip() {
        for address in [
            "/ip4/203.0.113.7/udp/4002/quic-v1",
            "/ip6/2001:db8::1/udp/4002/quic-v1",
            "/dns/ac.example.net/udp/4002/quic-v1",
            "/dns4/ac.example.net/udp/4002/quic-v1",
            "/dns6/ac.example.net/udp/65535/quic-v1",
        ] {
            let there = invite_to(address);
            assert_eq!(Invite::decode(&there.encode().unwrap()).unwrap(), there);
        }
    }

    #[test]
    fn a_token_stays_short() {
        let token = invite().encode().unwrap();

        assert!(token.len() < 110, "{} chars: {token}", token.len());
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

    /// The transport is not in the token, so an address that is not the one shape it can
    /// carry has to be refused where the operator will see it.
    #[test]
    fn an_address_the_token_cannot_carry_is_refused_at_the_source() {
        for address in [
            "/dns4/ac.example.net/udp/4002/quic-v1".to_owned(),
            "/ip4/203.0.113.7/tcp/4002".to_owned(),
            format!("/ip4/203.0.113.7/tcp/4002/p2p/{PEER}"),
            format!("/p2p/{PEER}"),
            format!("/dns4/ac.example.net/udp/4002/quic-v1/p2p/{PEER}/p2p-circuit"),
        ] {
            assert_eq!(
                Invite::new(address.parse().unwrap(), CODE),
                Err(InviteError::NotAnEnrolmentAddress),
                "{address}"
            );
        }
    }
}
