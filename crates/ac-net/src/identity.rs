//! The node's long-lived cryptographic identity.
//!
//! A node is named by its [`PeerId`], which is derived from an Ed25519 public key. That
//! name is durable: it survives restarts, it is what peers add to their trust lists, and
//! it is what the server records at enrollment. Losing the key means becoming a different
//! node to everyone else, so the key is written once and then only ever read.
//!
//! Writes go through a temporary file in the same directory followed by a rename, so a
//! crash mid-write can never leave a truncated key where a valid one used to be.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use libp2p::PeerId;
use libp2p::identity::Keypair;

/// Name of the key file inside the node's data directory.
pub const KEY_FILENAME: &str = "identity.key";

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("could not read identity at {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("could not write identity to {path}")]
    Write {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("identity at {path} is not a valid key")]
    Decode {
        path: PathBuf,
        #[source]
        source: libp2p::identity::DecodingError,
    },
}

/// Whether [`Identity::load_or_generate`] found an existing key or minted a new one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Loaded,
    Generated,
}

/// A node's keypair, loaded from disk.
#[derive(Debug, Clone)]
pub struct Identity {
    keypair: Keypair,
}

impl Identity {
    /// Load the key at `path`, generating and persisting one if it is not there yet.
    pub fn load_or_generate(path: &Path) -> Result<(Self, Origin), IdentityError> {
        match Self::load(path) {
            Ok(identity) => Ok((identity, Origin::Loaded)),
            Err(IdentityError::Read { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                let identity = Self {
                    keypair: Keypair::generate_ed25519(),
                };
                identity.save(path)?;
                Ok((identity, Origin::Generated))
            }
            Err(other) => Err(other),
        }
    }

    /// Load an existing key. Fails if `path` does not exist.
    pub fn load(path: &Path) -> Result<Self, IdentityError> {
        let bytes = fs::read(path).map_err(|source| IdentityError::Read {
            path: path.to_path_buf(),
            source,
        })?;

        warn_if_world_readable(path);

        let keypair =
            Keypair::from_protobuf_encoding(&bytes).map_err(|source| IdentityError::Decode {
                path: path.to_path_buf(),
                source,
            })?;

        Ok(Self { keypair })
    }

    /// Persist the key, replacing whatever is at `path`.
    pub fn save(&self, path: &Path) -> Result<(), IdentityError> {
        let encoded =
            self.keypair
                .to_protobuf_encoding()
                .map_err(|source| IdentityError::Decode {
                    path: path.to_path_buf(),
                    source,
                })?;

        write_private_atomic(path, &encoded).map_err(|source| IdentityError::Write {
            path: path.to_path_buf(),
            source,
        })
    }

    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }

    pub fn peer_id(&self) -> PeerId {
        self.keypair.public().to_peer_id()
    }
}

/// Write `bytes` to `path` atomically, owner-readable only.
///
/// The mode is applied at creation rather than afterwards, so the key material is never
/// briefly visible to other users. A stale temporary file from an earlier crash is
/// removed first, since `OpenOptions::mode` is ignored when the file already exists.
fn write_private_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::other("identity path has no parent directory"))?;
    fs::create_dir_all(dir)?;

    let tmp = path.with_extension("tmp");
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let mut file = opts.open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);

    fs::rename(&tmp, path)?;

    // Without fsyncing the directory the rename itself can be lost on power failure,
    // leaving neither the temporary file nor the new key.
    #[cfg(unix)]
    if let Ok(handle) = fs::File::open(dir) {
        let _ = handle.sync_all();
    }

    Ok(())
}

/// Log a warning if others can read the key. Deliberately not an error: refusing to start
/// would lock someone out of their own node over a restored backup or a filesystem that
/// cannot represent Unix modes.
fn warn_if_world_readable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let Ok(meta) = fs::metadata(path) else {
            return;
        };
        let mode = meta.permissions().mode() & 0o077;
        if mode != 0 {
            tracing::warn!(
                path = %path.display(),
                mode = format!("{:o}", meta.permissions().mode() & 0o777),
                "identity key is readable by other users; consider chmod 600"
            );
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_then_reloads_the_same_peer_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(KEY_FILENAME);

        let (first, origin) = Identity::load_or_generate(&path).unwrap();
        assert_eq!(origin, Origin::Generated);

        let (second, origin) = Identity::load_or_generate(&path).unwrap();
        assert_eq!(origin, Origin::Loaded);
        assert_eq!(first.peer_id(), second.peer_id());
    }

    #[test]
    fn creates_missing_parent_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("deeper").join(KEY_FILENAME);

        let (identity, _) = Identity::load_or_generate(&path).unwrap();
        assert_eq!(Identity::load(&path).unwrap().peer_id(), identity.peer_id());
    }

    #[cfg(unix)]
    #[test]
    fn key_is_owner_readable_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(KEY_FILENAME);
        Identity::load_or_generate(&path).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600, got {mode:o}");
    }

    #[test]
    fn save_replaces_an_existing_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(KEY_FILENAME);

        let (first, _) = Identity::load_or_generate(&path).unwrap();
        let replacement = Identity {
            keypair: Keypair::generate_ed25519(),
        };
        replacement.save(&path).unwrap();

        let reloaded = Identity::load(&path).unwrap();
        assert_ne!(reloaded.peer_id(), first.peer_id());
        assert_eq!(reloaded.peer_id(), replacement.peer_id());
    }

    #[test]
    fn save_recovers_from_a_stale_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(KEY_FILENAME);
        fs::write(path.with_extension("tmp"), b"leftover from a crash").unwrap();

        let (identity, origin) = Identity::load_or_generate(&path).unwrap();
        assert_eq!(origin, Origin::Generated);
        assert_eq!(Identity::load(&path).unwrap().peer_id(), identity.peer_id());
    }

    #[test]
    fn corrupt_key_reports_a_decode_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(KEY_FILENAME);
        fs::write(&path, b"not a protobuf keypair").unwrap();

        assert!(matches!(
            Identity::load(&path),
            Err(IdentityError::Decode { .. })
        ));
    }
}
