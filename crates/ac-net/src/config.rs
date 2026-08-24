use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use libp2p::Multiaddr;
use serde::{Deserialize, Serialize};

pub const CONFIG_FILENAME: &str = "config.toml";
pub const DB_FILENAME: &str = "state.sqlite";
pub const STORAGE_DIRNAME: &str = "files";

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("could not determine a home directory for this user")]
    NoHomeDir,
    #[error("could not read config at {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("could not write config to {path}")]
    Write {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid config at {path}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("could not serialize config")]
    Serialize(#[source] toml::ser::Error),
    #[error(
        "storage_root in {path} must be an absolute path, but is {storage_root}. \
         Write it in full, like \"/mnt/archive\""
    )]
    RelativeStorageRoot {
        path: PathBuf,
        storage_root: PathBuf,
    },
}

#[derive(Debug, Clone)]
pub struct Paths {
    pub root: PathBuf,
}

impl Paths {
    /// Locate a node's directory, per-OS.
    pub fn discover(app_name: &str, env_override: &str) -> Result<Self, ConfigError> {
        if let Some(root) = std::env::var_os(env_override) {
            return Ok(Self::rooted_at(PathBuf::from(root)));
        }

        let dirs = ProjectDirs::from("", "", app_name).ok_or(ConfigError::NoHomeDir)?;
        Ok(Self::rooted_at(dirs.data_dir()))
    }

    pub fn rooted_at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn config_file(&self) -> PathBuf {
        self.root.join(CONFIG_FILENAME)
    }

    pub fn identity_file(&self) -> PathBuf {
        self.root.join(super::identity::KEY_FILENAME)
    }

    pub fn db_file(&self) -> PathBuf {
        self.root.join(DB_FILENAME)
    }
    pub fn attestation_file(&self) -> PathBuf {
        self.root.join(super::attest::ATTESTATION_FILENAME)
    }

    pub fn default_storage_root(&self) -> PathBuf {
        self.root.join(STORAGE_DIRNAME)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Addresses to listen on. Port 0 asks the OS for an ephemeral port
    pub listen: Vec<Multiaddr>,

    /// Server only. Where the enrolment listener binds.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub listen_enroll: Vec<Multiaddr>,

    /// Addresses this node announces as its own, beyond what it discovers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub external: Vec<Multiaddr>,

    /// mDNS toggle
    pub mdns: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<Multiaddr>,

    /// Where this node keeps the files it holds, overriding `<root>/files`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_root: Option<PathBuf>,

    /// Stop mirroring once this node holds this many bytes. Absent means no ceiling beyond
    /// the free-space floor the node keeps regardless.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_max: Option<u64>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: default_listen_addrs(),
            listen_enroll: Vec::new(),
            external: Vec::new(),
            mdns: true,
            server: None,
            storage_root: None,
            storage_max: None,
        }
    }
}

impl Config {
    /// Read the config file, falling back to defaults when it does not exist.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(source) => {
                return Err(ConfigError::Read {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };

        let config: Self = toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;

        if let Some(root) = &config.storage_root
            && !root.is_absolute()
        {
            return Err(ConfigError::RelativeStorageRoot {
                path: path.to_path_buf(),
                storage_root: root.clone(),
            });
        }

        Ok(config)
    }

    /// Where this node's files live. Absolute, enforced by [`Self::load`].
    pub fn storage_root(&self, paths: &Paths) -> PathBuf {
        self.storage_root
            .clone()
            .unwrap_or_else(|| paths.default_storage_root())
    }

    /// Write the config file, creating parent directories as needed.
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        let text = toml::to_string_pretty(self).map_err(ConfigError::Serialize)?;

        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(|source| ConfigError::Write {
                path: path.to_path_buf(),
                source,
            })?;
        }

        fs::write(path, text).map_err(|source| ConfigError::Write {
            path: path.to_path_buf(),
            source,
        })
    }
}

/// QUIC and TCP, IPv4 and IPv6, all on ephemeral ports.
fn default_listen_addrs() -> Vec<Multiaddr> {
    [
        "/ip4/0.0.0.0/udp/0/quic-v1",
        "/ip4/0.0.0.0/tcp/0",
        "/ip6/::/udp/0/quic-v1",
        "/ip6/::/tcp/0",
    ]
    .iter()
    .filter_map(|a| a.parse().ok())
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_yields_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::load(&dir.path().join(CONFIG_FILENAME)).unwrap();
        assert_eq!(config.listen, default_listen_addrs());
        assert_eq!(
            config.server, None,
            "a fresh node has not enrolled anywhere"
        );
    }

    #[test]
    fn round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CONFIG_FILENAME);

        let config = Config {
            listen: vec!["/ip4/127.0.0.1/udp/4242/quic-v1".parse().unwrap()],
            listen_enroll: Vec::new(),
            external: vec!["/ip4/203.0.113.7/udp/4001/quic-v1".parse().unwrap()],
            mdns: false,
            server: Some(
                "/ip4/203.0.113.7/udp/4001/quic-v1/p2p/12D3KooWDmPLKCjUV7snQBQVod5bNQnDmZ5X4MYNnPx8NM95zxke"
                    .parse()
                    .unwrap(),
            ),
            storage_root: Some(PathBuf::from("/mnt/archive")),
            storage_max: Some(200 * 1024 * 1024 * 1024),
        };
        config.save(&path).unwrap();

        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded.listen, config.listen);
        assert_eq!(loaded.external, config.external);
        assert_eq!(loaded.server, config.server);
        assert_eq!(loaded.storage_max, config.storage_max);
        assert_eq!(loaded.storage_root, config.storage_root);
    }

    #[test]
    fn storage_root_defaults_under_the_root() {
        let paths = Paths::rooted_at("/tmp/ac-test-root");

        assert_eq!(
            Config::default().storage_root(&paths),
            PathBuf::from("/tmp/ac-test-root/files")
        );
    }

    #[test]
    fn an_absolute_storage_root_is_taken_as_given() {
        let paths = Paths::rooted_at("/tmp/ac-test-root");
        let config = Config {
            storage_root: Some(PathBuf::from("/mnt/archive")),
            ..Config::default()
        };

        assert_eq!(config.storage_root(&paths), PathBuf::from("/mnt/archive"));
    }

    #[test]
    fn a_relative_storage_root_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CONFIG_FILENAME);
        fs::write(&path, "storage_root = \"bulk\"\n").unwrap();

        assert!(matches!(
            Config::load(&path),
            Err(ConfigError::RelativeStorageRoot { .. })
        ));
    }

    #[test]
    fn an_absolute_storage_root_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CONFIG_FILENAME);
        fs::write(&path, "storage_root = \"/mnt/archive\"\n").unwrap();

        assert_eq!(
            Config::load(&path).unwrap().storage_root,
            Some(PathBuf::from("/mnt/archive"))
        );
    }

    #[test]
    fn a_config_without_a_storage_root_still_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CONFIG_FILENAME);
        fs::write(&path, "mdns = false\n").unwrap();

        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded.storage_root, None);
    }

    #[test]
    fn defaults_cover_every_listed_address() {
        // on less than intended.
        assert_eq!(default_listen_addrs().len(), 4);
    }

    #[test]
    fn unknown_key_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CONFIG_FILENAME);
        fs::write(&path, "lisen = []\n").unwrap();

        assert!(matches!(
            Config::load(&path),
            Err(ConfigError::Parse { .. })
        ));
    }
    const UNSET_ENV: &str = "AC_TEST_HOME_OVERRIDE_THAT_IS_NEVER_SET";

    #[test]
    fn without_an_override_the_os_directory_is_used() {
        assert!(
            std::env::var_os(UNSET_ENV).is_none(),
            "{UNSET_ENV} is set in this environment, so this checks the wrong branch"
        );

        let paths = Paths::discover("archiverclient-test", UNSET_ENV).unwrap();

        assert!(paths.root.ends_with("archiverclient-test"));
        assert_eq!(paths.identity_file(), paths.root.join("identity.key"));
    }

    #[test]
    fn everything_a_node_owns_shares_one_directory() {
        let paths = Paths::rooted_at("/tmp/ac-test-root");
        let root = Path::new("/tmp/ac-test-root");

        for file in [
            paths.config_file(),
            paths.identity_file(),
            paths.db_file(),
            paths.attestation_file(),
            paths.default_storage_root(),
        ] {
            assert_eq!(
                file.parent(),
                Some(root),
                "{} escaped the root",
                file.display()
            );
        }
    }

    #[test]
    fn a_config_without_a_ceiling_says_so() {
        assert_eq!(Config::default().storage_max, None);
    }

    #[test]
    fn a_ceiling_survives_the_round_trip_as_a_number() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CONFIG_FILENAME);

        let config = Config {
            storage_max: Some(20_000_000_000),
            ..Config::default()
        };
        config.save(&path).unwrap();

        assert_eq!(Config::load(&path).unwrap().storage_max, config.storage_max);
    }
}
