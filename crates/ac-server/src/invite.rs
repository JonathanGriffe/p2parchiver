//! Invite codes — the credential that lets a client enroll with this server.
//!
//! A code is a bearer secret: whoever holds it can enroll. That drives every choice
//! here — enough entropy that guessing is hopeless, a hash rather than the code itself
//! in the database, and single-use redemption enforced in [`crate::store`].
//!
//! The alphabet is Crockford base32, which omits `I`, `L`, `O`, and `U` so that a code
//! read aloud or copied by hand does not turn into a different code.

use std::fmt;

use sha2::{Digest, Sha256};

/// Crockford base32: no `I`, `L`, `O`, or `U`.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

const GROUPS: usize = 4;
const GROUP_LEN: usize = 4;

/// 16 characters over a 32-symbol alphabet: 80 bits.
///
/// Well beyond brute force even against a stolen database — at 10^10 hashes a second,
/// 2^80 takes millions of years — and single-use redemption plus a TTL bound it further.
/// That headroom is why a plain SHA-256 is appropriate here rather than a slow password
/// KDF: those exist for low-entropy secrets, which this is not.
const CODE_LEN: usize = GROUPS * GROUP_LEN;

#[derive(Debug, thiserror::Error)]
pub enum InviteError {
    #[error("an invite code is {CODE_LEN} characters, got {got}")]
    Length { got: usize },
    #[error("'{ch}' is not valid in an invite code")]
    Character { ch: char },
}

/// A normalized invite code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteCode(String);

impl InviteCode {
    /// Mint a fresh code from the operating system's randomness.
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut bytes = [0u8; CODE_LEN];
        getrandom::fill(&mut bytes)?;

        // 256 is a multiple of 32, so the modulo introduces no bias.
        let code = bytes
            .iter()
            .map(|b| ALPHABET[(*b % 32) as usize] as char)
            .collect();

        Ok(Self(code))
    }

    /// Accept a code as a person is likely to have typed it.
    ///
    /// Case, dashes and spaces are all forgiven, as are the Crockford substitutions a
    /// reader naturally makes: `I` and `L` for `1`, `O` for `0`.
    pub fn parse(input: &str) -> Result<Self, InviteError> {
        let mut code = String::with_capacity(CODE_LEN);

        for ch in input.chars() {
            if ch == '-' || ch.is_whitespace() {
                continue;
            }
            let upper = ch.to_ascii_uppercase();
            let mapped = match upper {
                'I' | 'L' => '1',
                'O' => '0',
                other => other,
            };
            if !ALPHABET.contains(&(mapped as u8)) {
                return Err(InviteError::Character { ch });
            }
            code.push(mapped);
        }

        if code.len() != CODE_LEN {
            return Err(InviteError::Length { got: code.len() });
        }
        Ok(Self(code))
    }

    /// What the database stores. The code itself is never written to disk, so a leaked
    /// backup does not hand over live invites.
    pub fn hash(&self) -> String {
        hex::encode(Sha256::digest(self.0.as_bytes()))
    }
}

/// Grouped for legibility: `K7X2-9QM4-PL3V-8NRT`.
impl fmt::Display for InviteCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, chunk) in self.0.as_bytes().chunks(GROUP_LEN).enumerate() {
            if i > 0 {
                f.write_str("-")?;
            }
            f.write_str(&String::from_utf8_lossy(chunk))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_codes_are_the_right_shape() {
        let code = InviteCode::generate().unwrap();
        assert_eq!(code.0.len(), CODE_LEN);
        assert!(code.0.bytes().all(|b| ALPHABET.contains(&b)));
    }

    #[test]
    fn generated_codes_differ() {
        let a = InviteCode::generate().unwrap();
        let b = InviteCode::generate().unwrap();
        assert_ne!(a, b, "two codes in a row must not collide");
    }

    #[test]
    fn display_groups_with_dashes() {
        let code = InviteCode("K7X29QM4PL3V8NRT".to_owned());
        assert_eq!(code.to_string(), "K7X2-9QM4-PL3V-8NRT");
    }

    #[test]
    fn a_displayed_code_parses_back() {
        let code = InviteCode::generate().unwrap();
        assert_eq!(InviteCode::parse(&code.to_string()).unwrap(), code);
    }

    #[test]
    fn parsing_forgives_case_dashes_and_spaces() {
        let canonical = InviteCode::parse("K7X29QM4PL3V8NRT").unwrap();
        for variant in [
            "k7x2-9qm4-pl3v-8nrt",
            "K7X2 9QM4 PL3V 8NRT",
            "  K7X2-9qm4-PL3V-8nrt  ",
        ] {
            assert_eq!(InviteCode::parse(variant).unwrap(), canonical, "{variant}");
        }
    }

    #[test]
    fn crockford_substitutions_are_accepted() {
        // Someone reading a code aloud will say "oh" for zero and "eye" for one.
        let canonical = InviteCode::parse("0123456789ABCDEF").unwrap();
        assert_eq!(InviteCode::parse("O123456789ABCDEF").unwrap(), canonical);
        assert_eq!(InviteCode::parse("0I23456789ABCDEF").unwrap(), canonical);
        assert_eq!(InviteCode::parse("0L23456789ABCDEF").unwrap(), canonical);
    }

    #[test]
    fn wrong_length_is_rejected() {
        assert!(matches!(
            InviteCode::parse("K7X2-9QM4"),
            Err(InviteError::Length { got: 8 })
        ));
    }

    #[test]
    fn characters_outside_the_alphabet_are_rejected() {
        assert!(matches!(
            InviteCode::parse("K7X2-9QM4-PL3V-8NR!"),
            Err(InviteError::Character { ch: '!' })
        ));
    }

    #[test]
    fn the_hash_is_stable_and_is_not_the_code() {
        let code = InviteCode::parse("K7X29QM4PL3V8NRT").unwrap();
        let hash = code.hash();

        assert_eq!(hash, code.hash(), "hashing must be deterministic");
        assert_eq!(hash.len(), 64, "hex sha-256");
        assert!(
            !hash.contains("K7X2"),
            "the code must not be recoverable from what we store"
        );
    }

    #[test]
    fn different_codes_hash_differently() {
        let a = InviteCode::parse("K7X29QM4PL3V8NRT").unwrap();
        let b = InviteCode::parse("K7X29QM4PL3V8NRV").unwrap();
        assert_ne!(a.hash(), b.hash());
    }
}
