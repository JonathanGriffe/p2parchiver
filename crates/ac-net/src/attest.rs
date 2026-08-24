use std::path::Path;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use libp2p::PeerId;
use libp2p::identity::Keypair;
use serde::{Deserialize, Serialize};

/// How long a freshly issued attestation is valid.
pub const LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

/// Renew once less than this remains.
pub const RENEW_WHEN_REMAINING: Duration = Duration::from_secs(6 * 60 * 60);

/// Tolerance for clock skew between the issuing server and a verifying peer.
/// Applied to `issued_at` only. Expiry is deliberately *not* given the same grace.
const CLOCK_SKEW: i64 = 300;

/// Unix seconds. Mirrors the server's own clock helper so both sides agree on the unit.
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Filename inside the node's directory.
pub const ATTESTATION_FILENAME: &str = "attestation.cbor";

pub const USERNAME_MIN_LEN: usize = 3;
pub const USERNAME_MAX_LEN: usize = 32;

/// Normalise a username, or explain why it is not one.
pub fn normalise_username(raw: &str) -> Result<String, UsernameError> {
    let name = raw.trim().to_lowercase();

    if name.len() < USERNAME_MIN_LEN {
        return Err(UsernameError::TooShort);
    }
    if name.len() > USERNAME_MAX_LEN {
        return Err(UsernameError::TooLong);
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(UsernameError::BadCharacter);
    }
    if !name.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return Err(UsernameError::BadStart);
    }

    Ok(name)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UsernameError {
    #[error("a username must be at least {USERNAME_MIN_LEN} characters")]
    TooShort,
    #[error("a username may be at most {USERNAME_MAX_LEN} characters")]
    TooLong,
    #[error("a username may contain only letters, digits, '-' and '_'")]
    BadCharacter,
    #[error("a username must start with a letter or a digit")]
    BadStart,
}

/// What the server asserts about a client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    pub peer: String,
    pub username: String,
    pub server: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

impl Statement {
    pub fn peer_id(&self) -> Option<PeerId> {
        self.peer.parse().ok()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    pub statement: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum AttestError {
    #[error("the attestation is not valid CBOR")]
    Malformed,
    #[error("the attestation could not be encoded")]
    Encode,
    #[error("the attestation could not be signed")]
    Signing,
    #[error("the server's public key could not be recovered from its peer id")]
    ServerKey,
    #[error("the signature does not match the server's key")]
    BadSignature,
    #[error("the attestation was issued by {issuer}, not by this node's server")]
    WrongServer { issuer: String },
    #[error("the attestation is for {subject}, not for the peer presenting it")]
    WrongPeer { subject: String },
    #[error("the attestation expired {} seconds ago", .by)]
    Expired { by: i64 },
    #[error("the attestation is not valid yet; check the clock on this machine")]
    NotYetValid,
    #[error("the attestation names an unparseable peer id")]
    UnparseablePeer,
}

impl Attestation {
    /// Sign a statement about `peer`. Server side.
    pub fn issue(
        server_key: &Keypair,
        peer: &PeerId,
        username: &str,
        issued_at: i64,
        lifetime: Duration,
    ) -> Result<Self, AttestError> {
        let statement = Statement {
            peer: peer.to_base58(),
            username: username.to_owned(),
            server: server_key.public().to_peer_id().to_base58(),
            issued_at,
            expires_at: issued_at + lifetime.as_secs() as i64,
        };

        let mut bytes = Vec::new();
        ciborium::into_writer(&statement, &mut bytes).map_err(|_| AttestError::Encode)?;
        let signature = server_key.sign(&bytes).map_err(|_| AttestError::Signing)?;

        Ok(Self {
            statement: bytes,
            signature,
        })
    }

    /// Decode the statement without verification..
    pub fn statement(&self) -> Result<Statement, AttestError> {
        ciborium::from_reader(self.statement.as_slice()).map_err(|_| AttestError::Malformed)
    }

    /// Check everything, and return what was asserted.
    pub fn verify(
        &self,
        subject: &PeerId,
        server: &PeerId,
        now: i64,
    ) -> Result<Statement, AttestError> {
        let statement = self.statement()?;

        if statement.server != server.to_base58() {
            return Err(AttestError::WrongServer {
                issuer: statement.server,
            });
        }

        let key = crate::identity::public_key_of(server).map_err(|_| AttestError::ServerKey)?;
        if !key.verify(&self.statement, &self.signature) {
            return Err(AttestError::BadSignature);
        }

        if statement.peer != subject.to_base58() {
            return Err(AttestError::WrongPeer {
                subject: statement.peer,
            });
        }
        if statement.peer_id().is_none() {
            return Err(AttestError::UnparseablePeer);
        }
        if now >= statement.expires_at {
            return Err(AttestError::Expired {
                by: now - statement.expires_at,
            });
        }
        if now + CLOCK_SKEW < statement.issued_at {
            return Err(AttestError::NotYetValid);
        }

        Ok(statement)
    }

    /// When this attestation stops being valid, or `None` if it will not decode.
    pub fn expires_at(&self) -> Option<i64> {
        self.statement().ok().map(|s| s.expires_at)
    }

    /// Whether it is time to ask the server for a fresh one.
    ///
    /// True for an attestation that will not decode, so a corrupt file is replaced rather
    /// than leaving the node permanently unable to talk to anyone.
    pub fn needs_renewal(&self, now: i64) -> bool {
        match self.expires_at() {
            Some(expires_at) => expires_at - now <= RENEW_WHEN_REMAINING.as_secs() as i64,
            None => true,
        }
    }
}

/// Read the attestation stored at `path`.
pub fn load(path: &Path) -> std::io::Result<Option<Attestation>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };

    match ciborium::from_reader(bytes.as_slice()) {
        Ok(attestation) => Ok(Some(attestation)),
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "discarding an unreadable attestation");
            Ok(None)
        }
    }
}

/// Write an attestation, creating parent directories as needed.
pub fn save(path: &Path, attestation: &Attestation) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut bytes = Vec::new();
    ciborium::into_writer(attestation, &mut bytes)
        .map_err(|e| std::io::Error::other(format!("encoding the attestation: {e}")))?;
    std::fs::write(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: i64 = 3600;

    fn keypair() -> Keypair {
        Keypair::generate_ed25519()
    }

    fn peer() -> PeerId {
        keypair().public().to_peer_id()
    }

    /// A server, a client, and a valid attestation binding them.
    fn issued() -> (Keypair, PeerId, PeerId, Attestation) {
        let server_key = keypair();
        let server = server_key.public().to_peer_id();
        let client = peer();
        let attestation =
            Attestation::issue(&server_key, &client, "alice", 1_000_000, LIFETIME).unwrap();
        (server_key, server, client, attestation)
    }

    #[test]
    fn a_freshly_issued_attestation_verifies() {
        let (_, server, client, attestation) = issued();

        let statement = attestation
            .verify(&client, &server, 1_000_000 + HOUR)
            .unwrap();
        assert_eq!(statement.username, "alice");
        assert_eq!(statement.peer, client.to_base58());
    }

    #[test]
    fn an_attestation_cannot_be_worn_by_another_peer() {
        // The binding that removes the bearer property: presenting someone else's
        // attestation means also holding their key, and then you are them.
        let (_, server, _, attestation) = issued();

        assert!(matches!(
            attestation.verify(&peer(), &server, 1_000_000),
            Err(AttestError::WrongPeer { .. })
        ));
    }

    #[test]
    fn an_attestation_from_another_server_is_refused() {
        let (_, _, client, attestation) = issued();
        let other_server = peer();

        assert!(matches!(
            attestation.verify(&client, &other_server, 1_000_000),
            Err(AttestError::WrongServer { .. })
        ));
    }

    #[test]
    fn a_forged_signature_is_refused() {
        // Same statement, signed by someone else, presented as though it came from the
        // server whose peer id the client pinned.
        let (_, server, client, mut attestation) = issued();
        let impostor = keypair();
        attestation.signature = impostor.sign(&attestation.statement).unwrap();

        assert!(matches!(
            attestation.verify(&client, &server, 1_000_000),
            Err(AttestError::BadSignature)
        ));
    }

    #[test]
    fn tampering_with_the_statement_is_refused() {
        // The reason the signed bytes are carried verbatim: editing the username has to
        // break the signature, and it can only do that if the bytes are what was signed.
        let (server_key, server, client, _) = issued();
        let honest =
            Attestation::issue(&server_key, &client, "alice", 1_000_000, LIFETIME).unwrap();

        let mut forged_statement: Statement = honest.statement().unwrap();
        forged_statement.username = "admin".to_owned();
        let mut bytes = Vec::new();
        ciborium::into_writer(&forged_statement, &mut bytes).unwrap();

        let forged = Attestation {
            statement: bytes,
            signature: honest.signature.clone(),
        };

        assert!(matches!(
            forged.verify(&client, &server, 1_000_000),
            Err(AttestError::BadSignature)
        ));
    }

    #[test]
    fn an_expired_attestation_is_refused() {
        let (_, server, client, attestation) = issued();
        let past_expiry = 1_000_000 + LIFETIME.as_secs() as i64 + 1;

        assert!(matches!(
            attestation.verify(&client, &server, past_expiry),
            Err(AttestError::Expired { .. })
        ));
    }

    #[test]
    fn expiry_is_not_given_skew_grace() {
        // Clock skew is tolerated at the start of the window and not at the end, because
        // the end is the interval revocation depends on.
        let (_, server, client, attestation) = issued();
        let one_second_over = 1_000_000 + LIFETIME.as_secs() as i64;

        assert!(
            attestation
                .verify(&client, &server, one_second_over)
                .is_err()
        );
    }

    #[test]
    fn a_clock_slightly_behind_the_server_still_verifies() {
        let (_, server, client, attestation) = issued();
        assert!(attestation.verify(&client, &server, 1_000_000 - 60).is_ok());
    }

    #[test]
    fn a_clock_far_behind_the_server_is_refused() {
        let (_, server, client, attestation) = issued();
        assert!(matches!(
            attestation.verify(&client, &server, 1_000_000 - CLOCK_SKEW - 60),
            Err(AttestError::NotYetValid)
        ));
    }

    #[test]
    fn renewal_is_due_only_inside_the_window() {
        let (_, _, _, attestation) = issued();
        let expires_at = 1_000_000 + LIFETIME.as_secs() as i64;

        assert!(!attestation.needs_renewal(1_000_000), "just issued");
        assert!(
            !attestation.needs_renewal(expires_at - RENEW_WHEN_REMAINING.as_secs() as i64 - 1),
            "one second before the window opens"
        );
        assert!(
            attestation.needs_renewal(expires_at - RENEW_WHEN_REMAINING.as_secs() as i64),
            "the moment the window opens"
        );
        assert!(attestation.needs_renewal(expires_at + 1), "already expired");
    }

    #[test]
    fn an_undecodable_attestation_always_wants_renewing() {
        // Otherwise a corrupt file leaves the node unable to talk to anyone, permanently.
        let broken = Attestation {
            statement: b"not cbor".to_vec(),
            signature: Vec::new(),
        };
        assert!(broken.needs_renewal(0));
        assert!(broken.expires_at().is_none());
    }

    #[test]
    fn usernames_are_normalised() {
        assert_eq!(normalise_username("  Alice  ").unwrap(), "alice");
        assert_eq!(normalise_username("bobs-laptop").unwrap(), "bobs-laptop");
        assert_eq!(normalise_username("node_2").unwrap(), "node_2");
    }

    #[test]
    fn bad_usernames_are_rejected() {
        for (raw, want) in [
            ("ab", UsernameError::TooShort),
            (
                "a".repeat(USERNAME_MAX_LEN + 1).as_str(),
                UsernameError::TooLong,
            ),
            ("alice smith", UsernameError::BadCharacter),
            ("ali.ce", UsernameError::BadCharacter),
            ("alicé", UsernameError::BadCharacter),
            ("-alice", UsernameError::BadStart),
            ("_alice", UsernameError::BadStart),
        ] {
            assert_eq!(normalise_username(raw), Err(want), "{raw:?}");
        }
    }

    #[test]
    fn an_attestation_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(ATTESTATION_FILENAME);
        let (_, _, _, attestation) = issued();

        assert!(load(&path).unwrap().is_none(), "nothing stored yet");
        save(&path, &attestation).unwrap();
        assert_eq!(load(&path).unwrap().unwrap(), attestation);
    }

    #[test]
    fn a_corrupt_file_reads_as_absent_rather_than_failing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(ATTESTATION_FILENAME);
        std::fs::write(&path, b"garbage").unwrap();

        assert!(load(&path).unwrap().is_none());
    }
}
