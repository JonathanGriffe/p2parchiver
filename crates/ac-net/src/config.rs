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
    #[error("{text:?} is not a size. Write it like \"200 GiB\", \"1.5 TB\" or a plain byte count")]
    Size { text: String },
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

    /// Where a node keeps the files it holds, absent a `storage_root` in the config.
    ///
    /// Under the data directory by default, so a fresh node needs no configuration and a
    /// node rooted by `AC_HOME` keeps everything it owns beneath that one root. The default
    /// is separate from the config because content is the one thing here likely to outgrow
    /// its disk: [`Config::storage_root`] is what points it at a bigger one.
    pub fn default_storage_root(&self) -> PathBuf {
        self.data_dir.join(STORAGE_DIRNAME)
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

    /// Where this node keeps the files it holds, overriding `<data_dir>/files`.
    ///
    /// Content is the one thing a node stores that can outgrow its disk, so it is the one
    /// path worth pointing somewhere else — an external drive, a NAS mount, a larger volume.
    ///
    /// A relative path resolves against the **data directory**, never the working directory.
    /// The CLI and the daemon are separate processes started from wherever the user happened
    /// to be, and a root that moved with `cwd` would have them disagree about where a group's
    /// files live.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_root: Option<PathBuf>,

    /// Stop mirroring once this node holds this much content.
    ///
    /// Written the way a person would say it — `"200 GiB"`, `"1.5 TB"`, `"500M"` — because a
    /// raw byte count is a number nobody can check at a glance. Absent means no ceiling beyond
    /// the free-space floor the node keeps regardless.
    ///
    /// Reaching it stops *fetching* and deletes nothing. Files stay listed as remote and
    /// arrive if the limit is raised or something is removed, so hitting it is legible in
    /// `ac file list` rather than surfacing as an I/O error inside a transfer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_max: Option<String>,
}

/// Parse a human-written size into bytes.
///
/// Accepts a bare number, or a number with a unit. Both conventions are honoured and they
/// differ: `KiB`/`MiB`/`GiB`/`TiB` are powers of 1024, `KB`/`MB`/`GB`/`TB` powers of 1000, and
/// a bare `K`/`M`/`G`/`T` is read as the binary form because that is what a person setting a
/// disk budget almost always means. Case-insensitive, and whitespace before the unit is fine.
///
/// Deliberately strict about everything else: a `storage_max` that silently parsed to zero
/// would stop the node fetching anything and look like a network fault.
pub fn parse_size(text: &str) -> Result<u64, ConfigError> {
    let text = text.trim();
    let split = text
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(split);

    let number: f64 = number
        .parse()
        .map_err(|_| ConfigError::Size { text: text.into() })?;
    if !number.is_finite() || number < 0.0 {
        return Err(ConfigError::Size { text: text.into() });
    }

    let multiplier: u64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kib" => 1024,
        "m" | "mib" => 1024 * 1024,
        "g" | "gib" => 1024 * 1024 * 1024,
        "t" | "tib" => 1024u64.pow(4),
        "kb" => 1_000,
        "mb" => 1_000_000,
        "gb" => 1_000_000_000,
        "tb" => 1_000_000_000_000,
        _ => return Err(ConfigError::Size { text: text.into() }),
    };

    let bytes = number * multiplier as f64;
    if bytes > u64::MAX as f64 {
        return Err(ConfigError::Size { text: text.into() });
    }
    Ok(bytes as u64)
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

        toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }

    /// The configured storage ceiling in bytes, if there is one.
    ///
    /// Parsed on every call rather than at load: this is read once per housekeeping tick, and
    /// a bad value should be a warning a person can fix by editing the file rather than a node
    /// that refuses to start. The caller decides what to do with the error.
    pub fn storage_max_bytes(&self) -> Result<Option<u64>, ConfigError> {
        self.storage_max.as_deref().map(parse_size).transpose()
    }

    /// Where this node's files live, resolved against `paths`.
    ///
    /// The single answer to that question: every caller goes through here rather than reading
    /// [`Self::storage_root`] directly, so the relative-path rule is applied once.
    pub fn storage_root(&self, paths: &Paths) -> PathBuf {
        match &self.storage_root {
            // `join` with an absolute path discards the base, which is exactly the rule:
            // absolute is taken as given, relative hangs off the data directory.
            Some(root) => paths.data_dir.join(root),
            None => paths.default_storage_root(),
        }
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
            storage_root: Some(PathBuf::from("/mnt/archive")),
            storage_max: Some("200 GiB".into()),
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
    fn storage_root_defaults_under_the_data_directory() {
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
    fn a_relative_storage_root_hangs_off_the_data_directory() {
        // Never off the working directory: the CLI and the daemon are started from wherever
        // the user happened to be, and must agree on where a group's files live.
        let paths = Paths::rooted_at("/tmp/ac-test-root");
        let config = Config {
            storage_root: Some(PathBuf::from("bulk")),
            ..Config::default()
        };

        assert_eq!(
            config.storage_root(&paths),
            PathBuf::from("/tmp/ac-test-root/bulk")
        );
    }

    #[test]
    fn a_config_without_a_storage_root_still_loads() {
        // Every config written before this field existed.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CONFIG_FILENAME);
        fs::write(&path, "mdns = false\n").unwrap();

        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded.storage_root, None);
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

    #[test]
    fn a_size_is_read_the_way_a_person_wrote_it() {
        // Both conventions are in the wild and they differ by 7% at GB scale, so guessing one
        // would quietly hand a user a budget several gigabytes from what they asked for.
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size("1 KiB").unwrap(), 1024);
        assert_eq!(parse_size("1KB").unwrap(), 1000);
        assert_eq!(parse_size("200 GiB").unwrap(), 200 * 1024 * 1024 * 1024);
        assert_eq!(parse_size("1.5 TB").unwrap(), 1_500_000_000_000);

        // A bare suffix is binary, because that is what someone sizing a disk means.
        assert_eq!(parse_size("500M").unwrap(), 500 * 1024 * 1024);
        assert_eq!(parse_size("  2 g  ").unwrap(), 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn a_size_that_makes_no_sense_is_refused_rather_than_guessed() {
        // The failure that matters: a value silently read as zero stops the node fetching
        // anything at all, which presents as a network fault and not as a typo.
        for text in ["", "lots", "10 furlongs", "-5", "1.2.3", "GiB"] {
            assert!(
                parse_size(text).is_err(),
                "{text:?} should not parse to a size"
            );
        }
    }

    #[test]
    fn a_config_without_a_ceiling_says_so() {
        let config = Config::default();
        assert_eq!(config.storage_max_bytes().unwrap(), None);

        let config = Config {
            storage_max: Some("200 GiB".into()),
            ..Config::default()
        };
        assert_eq!(
            config.storage_max_bytes().unwrap(),
            Some(200 * 1024 * 1024 * 1024)
        );
    }
}
