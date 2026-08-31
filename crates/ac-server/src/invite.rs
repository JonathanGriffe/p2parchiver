use ac_net::invite::CODE_BYTES;
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum InviteError {
    #[error("an invite code is {CODE_BYTES} bytes, got {got}")]
    Length { got: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteCode([u8; CODE_BYTES]);

impl InviteCode {
    /// Mint a fresh code from the operating system's randomness.
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut bytes = [0u8; CODE_BYTES];
        getrandom::fill(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// Take a code off the wire, where its length is whatever the client sent.
    pub fn parse(bytes: &[u8]) -> Result<Self, InviteError> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| InviteError::Length { got: bytes.len() })
    }

    pub fn as_bytes(&self) -> &[u8; CODE_BYTES] {
        &self.0
    }

    pub fn hash(&self) -> String {
        hex::encode(Sha256::digest(self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_codes_differ() {
        let a = InviteCode::generate().unwrap();
        let b = InviteCode::generate().unwrap();
        assert_ne!(a, b, "two codes in a row must not collide");
    }

    #[test]
    fn a_generated_code_parses_back_from_its_bytes() {
        let code = InviteCode::generate().unwrap();
        assert_eq!(InviteCode::parse(code.as_bytes()).unwrap(), code);
    }

    #[test]
    fn a_code_of_the_wrong_length_is_rejected() {
        assert!(matches!(
            InviteCode::parse(&[0u8; 4]),
            Err(InviteError::Length { got: 4 })
        ));
        assert!(matches!(
            InviteCode::parse(&[]),
            Err(InviteError::Length { got: 0 })
        ));
    }

    #[test]
    fn the_hash_is_stable_and_is_not_the_code() {
        let code = InviteCode::parse(&[7u8; CODE_BYTES]).unwrap();
        let hash = code.hash();

        assert_eq!(hash, code.hash(), "hashing must be deterministic");
        assert_eq!(hash.len(), 64, "hex sha-256");
        assert!(
            !hash.contains(&hex::encode(code.as_bytes())),
            "the code must not be recoverable from what we store"
        );
    }

    #[test]
    fn different_codes_hash_differently() {
        let mut other = [7u8; CODE_BYTES];
        other[0] = 8;

        assert_ne!(
            InviteCode::parse(&[7u8; CODE_BYTES]).unwrap().hash(),
            InviteCode::parse(&other).unwrap().hash()
        );
    }
}
