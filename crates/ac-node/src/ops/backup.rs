//! Backing this node's identity up to the companion app, and restoring it from there.

use ac_net::config::{Config, Paths};
use ac_net::identity::Identity;
use ac_net::{Multiaddr, PeerId, Protocol};
use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

/// The payload's version. A later desktop must still read every version a phone may hold.
pub const VERSION: u64 = 1;

/// What the phone keeps, exactly as it received it.
#[derive(Serialize, Deserialize)]
struct Payload {
    v: u64,
    peer: String,
    /// The protobuf-encoded keypair, the bytes of `identity.key`, in base64. A secret.
    key: String,
    server: String,
    username: String,
}

/// A backup taken back from a phone: enough to enrol as the same node again.
pub struct Recovered {
    pub identity: Identity,
    /// The service address the node enrolled with, ending in `/p2p/<server peer id>`.
    pub server: Multiaddr,
    pub username: String,
}

/// By hand, so the key never reaches a log.
impl std::fmt::Debug for Recovered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recovered")
            .field("peer", &self.identity.peer_id())
            .field("server", &self.server)
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

impl Recovered {
    pub fn peer(&self) -> PeerId {
        self.identity.peer_id()
    }
}

/// The payload for this identity, its server and its username, as JSON.
pub fn encode(identity: &Identity, server: &Multiaddr, username: &str) -> Result<String> {
    let key = identity
        .to_protobuf()
        .map_err(|_| anyhow!("this node's key could not be encoded"))?;
    let payload = Payload {
        v: VERSION,
        peer: identity.peer_id().to_base58(),
        key: STANDARD.encode(key),
        server: server.to_string(),
        username: username.to_owned(),
    };
    serde_json::to_string(&payload).context("encoding the backup")
}

/// Read a payload and check it. No error names the key's bytes.
pub fn decode(raw: &str) -> Result<Recovered> {
    let payload: Payload =
        serde_json::from_str(raw).map_err(|_| anyhow!("the backup is not one this app reads"))?;
    if payload.v != VERSION {
        bail!(
            "the backup is version {}, which this app does not read; update the app",
            payload.v
        );
    }

    let key = STANDARD
        .decode(payload.key.as_bytes())
        .map_err(|_| anyhow!("the backup's key is unreadable"))?;
    let identity =
        Identity::from_protobuf(&key).map_err(|_| anyhow!("the backup's key is unreadable"))?;
    if identity.peer_id().to_base58() != payload.peer {
        bail!("the backup's key does not match the node it names");
    }

    let server: Multiaddr = payload
        .server
        .parse()
        .map_err(|_| anyhow!("the backup's server address is unreadable"))?;
    if !server.iter().any(|p| matches!(p, Protocol::P2p(_))) {
        bail!("the backup's server address does not say which server it is");
    }

    Ok(Recovered {
        identity,
        server,
        username: payload.username,
    })
}

/// Whether the home has enrolled, which is what `server` in the config records.
fn enrolled_with(paths: &Paths) -> Result<Option<Multiaddr>> {
    let path = paths.config_file();
    let config =
        Config::load(&path).with_context(|| format!("loading config from {}", path.display()))?;
    Ok(config.server)
}

/// Show a backup code, and hand this node's identity to the phone that scans it. Only once
/// the home has enrolled, since a key that never enrolled has nothing to come back to.
pub fn backup(paths: &Paths) -> Result<()> {
    let Some(server) = enrolled_with(paths)? else {
        bail!("this node has not enrolled yet, so there is nothing to back up");
    };
    let Some(statement) = super::enrolment(paths)? else {
        bail!("this node has no attestation yet, so there is nothing to back up");
    };
    let payload = encode(&super::identity(paths)?, &server, &statement.username)?;
    ac_import::registry::companion::back_up(payload).map_err(|e| anyhow!("{e}"))
}

/// Show a restore code, and take back the identity the phone that scans it sends. Refused
/// once the home has enrolled, since it already has an identity in use. Writes nothing:
/// enrolling with what it returns is what keeps it.
pub fn restore(paths: &Paths) -> Result<Recovered> {
    if enrolled_with(paths)?.is_some() {
        bail!("this node has already enrolled, so it keeps the identity it has");
    }
    let backup = ac_import::registry::companion::restore(|backup| decode(backup).is_ok())
        .map_err(|e| anyhow!("{e}"))?;
    decode(&backup)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ac_net::identity::Keypair;

    const SERVER: &str = "/ip4/203.0.113.7/udp/4001/quic-v1/p2p/12D3KooWDmPLKCjUV7snQBQVod5bNQnDmZ5X4MYNnPx8NM95zxke";

    fn identity() -> Identity {
        Identity::from_protobuf(&Keypair::generate_ed25519().to_protobuf_encoding().unwrap())
            .unwrap()
    }

    fn payload(identity: &Identity) -> serde_json::Value {
        let raw = encode(identity, &SERVER.parse().unwrap(), "alice").unwrap();
        serde_json::from_str(&raw).unwrap()
    }

    #[test]
    fn a_backup_survives_the_round_trip() {
        let mine = identity();
        let raw = encode(&mine, &SERVER.parse().unwrap(), "alice").unwrap();
        let back = decode(&raw).unwrap();

        assert_eq!(back.peer(), mine.peer_id());
        assert_eq!(back.server.to_string(), SERVER);
        assert_eq!(back.username, "alice");
        assert_eq!(
            back.identity.to_protobuf().unwrap(),
            mine.to_protobuf().unwrap(),
            "the very same key"
        );

        let fields = payload(&mine);
        assert_eq!(fields["v"], 1);
        assert_eq!(fields["peer"], mine.peer_id().to_base58());
    }

    #[test]
    fn a_backup_whose_key_is_not_the_peer_it_names_is_refused() {
        let mut fields = payload(&identity());
        fields["peer"] = identity().peer_id().to_base58().into();
        let err = decode(&fields.to_string()).unwrap_err().to_string();
        assert!(err.contains("does not match"), "{err}");
    }

    #[test]
    fn a_backup_of_an_unknown_version_is_refused() {
        let mut fields = payload(&identity());
        fields["v"] = 2.into();
        let err = decode(&fields.to_string()).unwrap_err().to_string();
        assert!(err.contains("version 2"), "{err}");
    }

    #[test]
    fn a_backup_whose_server_is_not_pinned_is_refused() {
        let mut fields = payload(&identity());
        fields["server"] = "/ip4/203.0.113.7/udp/4001/quic-v1".into();
        let err = decode(&fields.to_string()).unwrap_err().to_string();
        assert!(err.contains("which server"), "{err}");
    }

    #[test]
    fn a_broken_key_is_refused_without_being_repeated() {
        for key in ["not base64 at all!", "aGVsbG8="] {
            let mut fields = payload(&identity());
            fields["key"] = key.into();
            let err = format!("{:#}", decode(&fields.to_string()).unwrap_err());
            assert!(err.contains("key is unreadable"), "{err}");
            assert!(!err.contains(key), "{err}");
        }
        assert!(decode("not json").is_err());
    }

    #[test]
    fn printing_a_restored_backup_does_not_print_its_key() {
        let mine = identity();
        let raw = encode(&mine, &SERVER.parse().unwrap(), "alice").unwrap();
        let key = payload(&mine)["key"].as_str().unwrap().to_owned();
        let shown = format!("{:?}", decode(&raw).unwrap());
        assert!(!shown.contains(&key), "{shown}");
        assert!(shown.contains("alice"), "{shown}");
    }

    #[test]
    fn backup_needs_an_enrolled_home_and_restore_a_fresh_one() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::rooted_at(dir.path());
        let err = backup(&paths).unwrap_err().to_string();
        assert!(err.contains("not enrolled"), "{err}");

        let config = Config {
            server: Some(SERVER.parse().unwrap()),
            ..Config::default()
        };
        config.save(&paths.config_file()).unwrap();
        let err = restore(&paths).unwrap_err().to_string();
        assert!(err.contains("already enrolled"), "{err}");
    }
}
