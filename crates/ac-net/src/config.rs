use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use libp2p::Multiaddr;
use serde::{Deserialize, Serialize};

/// The slowest `bandwidth_max` worth honouring, in bytes per second.
pub const MIN_BANDWIDTH: u64 = 8 * 1024;

/// How much a node holds before it stops mirroring, unless its config says otherwise. Enough
/// to be a useful mirror, little enough that installing this does not quietly fill a laptop.
pub const DEFAULT_STORAGE_MAX: u64 = 500_000_000_000;

/// How fast it moves that content, unless its config says otherwise. A background sync that
/// takes the whole line is one people uninstall.
pub const DEFAULT_BANDWIDTH_MAX: u64 = 10_000_000;

/// What a limit of zero means on disk. A missing key takes the default, so a config that
/// wants no limit at all needs a way to say so.
const NO_LIMIT: u64 = 0;

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
        "bandwidth_max in {path} is {bandwidth_max} bytes per second, below the {floor} \
         this node will honour. A limit that slow stalls a transfer long enough to look \
         like a dead connection. Raise it, or remove it for no limit."
    )]
    BandwidthTooLow {
        path: PathBuf,
        bandwidth_max: u64,
        floor: u64,
    },

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

    /// Stop mirroring once this node holds this many bytes. Absent takes
    /// [`DEFAULT_STORAGE_MAX`]; `0` asks for no ceiling beyond the free-space floor the node
    /// keeps regardless. Both attributes are deliberately missing: the container's `default`
    /// is what makes an absent key mean the default rather than `None`, and writing the key
    /// out every time is what lets `0` survive a round trip.
    pub storage_max: Option<u64>,

    /// Bytes a second. Absent takes [`DEFAULT_BANDWIDTH_MAX`]; `0` asks for no limit.
    pub bandwidth_max: Option<u64>,
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
            storage_max: Some(DEFAULT_STORAGE_MAX),
            bandwidth_max: Some(DEFAULT_BANDWIDTH_MAX),
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

        let mut config: Self = toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;

        // Past here a limit is either a number to honour or nothing at all, so the file's way
        // of asking for no limit is turned into one before anything else looks at it — the
        // bandwidth floor below included, which a literal zero would otherwise fail.
        config.storage_max = config.storage_max.filter(|n| *n != NO_LIMIT);
        config.bandwidth_max = config.bandwidth_max.filter(|n| *n != NO_LIMIT);

        if let Some(root) = &config.storage_root
            && !root.is_absolute()
        {
            return Err(ConfigError::RelativeStorageRoot {
                path: path.to_path_buf(),
                storage_root: root.clone(),
            });
        }

        if let Some(rate) = config.bandwidth_max
            && rate < MIN_BANDWIDTH
        {
            return Err(ConfigError::BandwidthTooLow {
                path: path.to_path_buf(),
                bandwidth_max: rate,
                floor: MIN_BANDWIDTH,
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
        // Written as a number either way. Leaving the key out for "no limit" would read back
        // as the default, which is the one thing the person setting it did not ask for.
        let written = Self {
            storage_max: Some(self.storage_max.unwrap_or(NO_LIMIT)),
            bandwidth_max: Some(self.bandwidth_max.unwrap_or(NO_LIMIT)),
            ..self.clone()
        };
        let text = toml::to_string_pretty(&written).map_err(ConfigError::Serialize)?;

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

    /// An absolute path in the platform's own terms. Windows reads `/mnt/archive` as the
    /// root of whichever drive happens to be current, which is exactly the ambiguity
    /// `storage_root` refuses, so there it has to name a drive.
    #[cfg(windows)]
    const ABSOLUTE_ROOT: &str = "C:/mnt/archive";
    #[cfg(not(windows))]
    const ABSOLUTE_ROOT: &str = "/mnt/archive";

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
    fn a_bandwidth_limit_too_low_to_honour_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CONFIG_FILENAME);

        let config = Config {
            bandwidth_max: Some(MIN_BANDWIDTH - 1),
            ..Config::default()
        };
        config.save(&path).unwrap();

        assert!(
            matches!(
                Config::load(&path),
                Err(ConfigError::BandwidthTooLow { .. })
            ),
            "a rate that would stall a chunk past the idle timeout is a fault, not a limit"
        );
    }

    #[test]
    fn the_floor_itself_is_allowed_and_so_is_no_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CONFIG_FILENAME);

        let config = Config {
            bandwidth_max: Some(MIN_BANDWIDTH),
            ..Config::default()
        };
        config.save(&path).unwrap();
        assert_eq!(
            Config::load(&path).unwrap().bandwidth_max,
            Some(MIN_BANDWIDTH)
        );

        Config::default().save(&path).unwrap();
        assert_eq!(
            Config::load(&path).unwrap().bandwidth_max,
            Some(DEFAULT_BANDWIDTH_MAX),
            "the default is a limit, not the absence of one"
        );
    }

    /// The floor rejects anything below 8 KB/s, and no limit at all is written as `0`. One
    /// has to be read as the other before the check runs, or asking for no limit fails as
    /// though it were an absurdly slow one.
    #[test]
    fn no_limit_is_not_mistaken_for_a_limit_below_the_floor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CONFIG_FILENAME);
        fs::write(&path, "listen = []\nmdns = true\nbandwidth_max = 0\n").unwrap();

        assert_eq!(Config::load(&path).unwrap().bandwidth_max, None);
    }

    #[test]
    fn asking_for_no_limit_survives_a_round_trip_rather_than_reverting() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CONFIG_FILENAME);

        let config = Config {
            storage_max: None,
            bandwidth_max: None,
            ..Config::default()
        };
        config.save(&path).unwrap();

        let read = Config::load(&path).unwrap();
        assert_eq!(read.storage_max, None, "not quietly back to 500 GB");
        assert_eq!(read.bandwidth_max, None);
    }

    /// The on-disk contract, for whoever opens config.toml in an editor: both keys are always
    /// present, and `0` is the way to write "no limit".
    #[test]
    fn the_written_file_states_both_limits_outright() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CONFIG_FILENAME);

        Config::default().save(&path).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(
            text.contains(&format!("storage_max = {DEFAULT_STORAGE_MAX}")),
            "got {text}"
        );
        assert!(
            text.contains(&format!("bandwidth_max = {DEFAULT_BANDWIDTH_MAX}")),
            "got {text}"
        );

        Config {
            storage_max: None,
            bandwidth_max: None,
            ..Config::default()
        }
        .save(&path)
        .unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("storage_max = 0"), "got {text}");
        assert!(text.contains("bandwidth_max = 0"), "got {text}");
    }

    /// The case that matters most: a config file written before these keys existed. Its
    /// silence has to read as the default, not as no limit.
    #[test]
    fn a_config_that_predates_the_limits_picks_them_up() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CONFIG_FILENAME);
        fs::write(&path, "listen = []\nmdns = true\n").unwrap();

        let config = Config::load(&path).unwrap();
        assert_eq!(config.storage_max, Some(DEFAULT_STORAGE_MAX));
        assert_eq!(config.bandwidth_max, Some(DEFAULT_BANDWIDTH_MAX));
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
            storage_root: Some(PathBuf::from(ABSOLUTE_ROOT)),
            storage_max: Some(200 * 1024 * 1024 * 1024),
            bandwidth_max: Some(5 * 1024 * 1024),
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
            storage_root: Some(PathBuf::from(ABSOLUTE_ROOT)),
            ..Config::default()
        };

        assert_eq!(config.storage_root(&paths), PathBuf::from(ABSOLUTE_ROOT));
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
        fs::write(&path, format!("storage_root = \"{ABSOLUTE_ROOT}\"\n")).unwrap();

        assert_eq!(
            Config::load(&path).unwrap().storage_root,
            Some(PathBuf::from(ABSOLUTE_ROOT))
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

        // Under a directory of the app's own, but not necessarily the last one: on Windows
        // the OS convention puts the data in `…\archiverclient-test\data`.
        assert!(
            paths
                .root
                .components()
                .any(|c| c.as_os_str() == "archiverclient-test"),
            "{} is not under a directory named for the app",
            paths.root.display()
        );
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
    fn a_node_told_nothing_still_holds_a_ceiling_and_a_rate() {
        assert_eq!(Config::default().storage_max, Some(DEFAULT_STORAGE_MAX));
        assert_eq!(Config::default().bandwidth_max, Some(DEFAULT_BANDWIDTH_MAX));
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
