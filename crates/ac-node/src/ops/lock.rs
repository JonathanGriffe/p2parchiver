use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use ac_net::config::Paths;
use fs4::{FileExt, TryLockError};

pub const LOCK_FILENAME: &str = "node.lock";

#[derive(Debug, thiserror::Error)]
pub enum LockError {
    #[error(
        "another node is already using {path}. Stop it before starting a second one: two \
         daemons on one home share an identity and a database, and neither would know."
    )]
    Held { path: PathBuf },

    #[error("could not take the lock at {path}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// Proof that this process is the only daemon on a home
#[derive(Debug)]
pub struct NodeLock {
    _file: File,
}

impl NodeLock {
    pub fn take(paths: &Paths) -> Result<Self, LockError> {
        Self::at(&paths.root.join(LOCK_FILENAME))
    }

    pub fn at(path: &Path) -> Result<Self, LockError> {
        let io = |source| LockError::Io {
            path: path.to_path_buf(),
            source,
        };

        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(io)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .truncate(false)
            .write(true)
            .open(path)
            .map_err(io)?;

        match FileExt::try_lock(&file) {
            Ok(()) => Ok(Self { _file: file }),
            Err(TryLockError::WouldBlock) => Err(LockError::Held {
                path: path.to_path_buf(),
            }),
            Err(TryLockError::Error(source)) => Err(io(source)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_node_on_one_home_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(LOCK_FILENAME);

        let first = NodeLock::at(&path).unwrap();
        assert!(
            matches!(NodeLock::at(&path), Err(LockError::Held { .. })),
            "the second daemon must be told, not left to corrupt the first one's database"
        );
        drop(first);
    }

    #[test]
    fn the_lock_is_released_when_the_node_stops() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(LOCK_FILENAME);

        drop(NodeLock::at(&path).unwrap());
        assert!(NodeLock::at(&path).is_ok());
    }

    #[test]
    fn separate_homes_do_not_contend() {
        let dir = tempfile::tempdir().unwrap();
        let a = NodeLock::at(&dir.path().join("a").join(LOCK_FILENAME)).unwrap();
        let b = NodeLock::at(&dir.path().join("b").join(LOCK_FILENAME));

        assert!(b.is_ok(), "one lock per home, not one per host");
        drop(a);
    }

    #[test]
    fn the_lock_file_is_made_if_the_home_is_new() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fresh").join(LOCK_FILENAME);

        let _lock = NodeLock::at(&path).unwrap();
        assert!(path.exists());
    }
}
