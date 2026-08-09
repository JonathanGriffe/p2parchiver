//! Where a node keeps its files, and what it reads out of them.
//!
//! Both binaries have the same shape here: a config directory holding `config.toml`, and
//! a data directory holding the identity key and the SQLite database. A missing config
//! file is not an error — the defaults are a working configuration, so a fresh node runs
//! with nothing on disk but its key.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use libp2p::Multiaddr;
use serde::{Deserialize, Serialize};

pub const CONFIG_FILENAME: &str = "config.toml";
pub const DB_FILENAME: &str = "state.sqlite";

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
}

/// The directories a node reads and writes.
#[derive(Debug, Clone)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
}

impl Paths {
    /// Locate a node's directories, per-OS.
    ///
    /// `env_override` names an environment variable that, when set, replaces both
    /// directories with a single root. Running several nodes on one machine depends on
    /// it — both the two-process dial test and the netns lab set it per node.
    pub fn discover(app: &str, env_override: &str) -> Result<Self, ConfigError> {
        Self::resolve(std::env::var_os(env_override), app)
    }

    /// The body of [`Self::discover`], with the environment read out as a parameter so
    /// tests can exercise both branches without mutating the process environment.
    fn resolve(override_root: Option<std::ffi::OsString>, app: &str) -> Result<Self, ConfigError> {
        if let Some(root) = override_root {
            return Ok(Self::rooted_at(PathBuf::from(root)));
        }

        let dirs = ProjectDirs::from("", "", app).ok_or(ConfigError::NoHomeDir)?;
        Ok(Self {
            config_dir: dirs.config_dir().to_path_buf(),
            data_dir: dirs.data_dir().to_path_buf(),
        })
    }

    /// Use an explicit root for both directories.
    pub fn rooted_at(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            config_dir: root.clone(),
            data_dir: root,
        }
    }

    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join(CONFIG_FILENAME)
    }

    pub fn identity_file(&self) -> PathBuf {
        self.data_dir.join(super::identity::KEY_FILENAME)
    }

    pub fn db_file(&self) -> PathBuf {
        self.data_dir.join(DB_FILENAME)
    }

    /// The server-signed attestation this node presents to peers.
    ///
    /// Lives beside the identity key because the two are useless apart: the attestation
    /// names the peer id the key produces, so it is worthless to anyone who copies it
    /// without the key.
    pub fn attestation_file(&self) -> PathBuf {
        self.data_dir.join(super::attest::ATTESTATION_FILENAME)
    }
}

/// A node's on-disk settings.
///
/// `deny_unknown_fields` turns a mistyped key into a startup error rather than a setting
/// that silently does nothing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Addresses to listen on. Port 0 asks the OS for an ephemeral port; UPnP and the
    /// relay reservation both cope with that, and it avoids colliding with anything else
    /// on the host.
    pub listen: Vec<Multiaddr>,

    /// **Server only.** Where the enrolment listener binds.
    ///
    /// A second listener exists because one cannot hold two contradictory policies:
    /// strangers must reach enrolment, and only members may reach the services. Keeping
    /// them on separate ports lets the service listener refuse an unenrolled peer during
    /// connection establishment, before any protocol is negotiated.
    ///
    /// Clients ignore this and leave it empty; `ac-server init` writes the server's.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub listen_enroll: Vec<Multiaddr>,

    /// Addresses this node announces as its own, beyond what it discovers.
    ///
    /// A **server must have these**, because a relay builds each client's circuit address
    /// out of the relay's own external addresses. With none, a reservation is accepted and
    /// then fails with `NoAddressesInReservation` — the client is told "you are reserved,
    /// at nowhere". A server left empty falls back to announcing what it bound, which is
    /// right for a host that is directly reachable and wrong behind a cloud NAT or load
    /// balancer, where the public address differs from the bound one.
    ///
    /// Clients normally leave this empty and let AutoNAT confirm addresses instead.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub external: Vec<Multiaddr>,

    /// Find peers on the local network without involving the server.
    ///
    /// Worth having because rendezvous publishes only *external* addresses, so two peers
    /// behind the same home NAT learn each other's public address and have to rely on NAT
    /// hairpinning — inconsistent on cheap routers, usually absent under CGNAT. When it
    /// fails, two devices in the same room relay through a server on the other side of the
    /// internet.
    ///
    /// Set false on a network you do not control: mDNS announces this node's presence to
    /// everyone on the segment. Fine at home, less so on café wifi.
    pub mdns: bool,

    /// The server this node enrolled with, written by `ac join`.
    ///
    /// Includes the server's `/p2p/<peer-id>`, which is what pins it: reaching that
    /// address later only succeeds if the peer answering still holds the same key. A
    /// server that changed identity fails the dial rather than being trusted silently.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<Multiaddr>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: default_listen_addrs(),
            listen_enroll: Vec::new(),
            external: Vec::new(),
            mdns: true,
            server: None,
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

        toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })
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
///
/// IPv6 is listed because a node with a routable v6 address skips NAT traversal
/// entirely, which is the cheapest possible path. Binding it fails harmlessly on hosts
/// without IPv6 — the swarm reports the failure per-address and keeps the rest.
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
        };
        config.save(&path).unwrap();

        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded.listen, config.listen);
        assert_eq!(loaded.external, config.external);
        assert_eq!(loaded.server, config.server);
    }

    #[test]
    fn defaults_cover_every_listed_address() {
        // filter_map would silently drop a typo'd default, leaving a node that listens
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

    #[test]
    fn override_replaces_both_directories() {
        let paths = Paths::resolve(Some("/tmp/ac-test-root".into()), "archiverclient").unwrap();

        assert_eq!(paths.config_dir, PathBuf::from("/tmp/ac-test-root"));
        assert_eq!(paths.data_dir, PathBuf::from("/tmp/ac-test-root"));
        assert_eq!(
            paths.identity_file(),
            PathBuf::from("/tmp/ac-test-root/identity.key")
        );
        assert_eq!(
            paths.config_file(),
            PathBuf::from("/tmp/ac-test-root/config.toml")
        );
    }

    #[test]
    fn without_an_override_the_os_directories_are_used() {
        let paths = Paths::resolve(None, "archiverclient-test").unwrap();

        // The exact location is the OS's business; what matters is that it is not the
        // override branch, and that the filenames hang off it correctly.
        assert!(paths.data_dir.ends_with("archiverclient-test"));
        assert_eq!(paths.identity_file(), paths.data_dir.join("identity.key"));
    }
}
