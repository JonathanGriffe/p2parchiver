use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ac_net::config::{Config, Paths};
use ac_node::ops;
use ac_node::ops::format::human_size;
use anyhow::{Context, Result, anyhow};
use slint::ComponentHandle;

use crate::node::Node;
use crate::ui::MainWindow;
use crate::work::{self, Nudge};
use crate::{autostart, log};

pub type Shared = Arc<Mutex<Node>>;

pub fn load(window: &MainWindow, paths: &Paths) {
    let config = Config::load(&paths.config_file()).unwrap_or_default();

    window.set_listen(join_addrs(&config.listen).into());
    window.set_external(join_addrs(&config.external).into());
    window.set_mdns(config.mdns);
    window.set_config_storage_root(
        config
            .storage_root
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default()
            .into(),
    );
    window.set_storage_max(size_field(config.storage_max).into());
    window.set_bandwidth_max(size_field(config.bandwidth_max).into());
    window.set_server(
        config
            .server
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default()
            .into(),
    );
    window.set_enrolled(config.server.is_some());

    load_autostart(window);
}

/// The tick, and the warning that goes with a recorded path that is no longer this binary.
fn load_autostart(window: &MainWindow) {
    let (on, warning) = match autostart::state() {
        Ok(autostart::State::On) => (true, String::new()),
        Ok(autostart::State::Off) => (false, String::new()),
        Ok(autostart::State::Stale { was }) => (
            false,
            format!(
                "The recorded entry points at {}, which is not this program. Turn this on \
                 again to correct it.",
                was.display()
            ),
        ),
        Err(e) => (false, format!("could not read the autostart entry: {e:#}")),
    };

    window.set_autostart(on);
    window.set_autostart_warning(warning.into());
}

pub fn wire(window: &MainWindow, paths: &Paths, node: &Shared, nudge: &Nudge) {
    let weak = window.as_weak();

    window.on_save({
        let weak = weak.clone();
        let paths = paths.clone();
        let nudge = nudge.clone();
        move |listen, external, mdns, root, max, bandwidth| {
            let (paths, nudge) = (paths.clone(), nudge.clone());
            let fields = Fields {
                listen: listen.to_string(),
                external: external.to_string(),
                mdns,
                root: root.to_string(),
                max: max.to_string(),
                bandwidth: bandwidth.to_string(),
            };
            work::begin(&weak);

            let reload = paths.clone();
            work::action(
                &weak,
                move || save(&paths, fields),
                move |window, outcome| {
                    load(window, &reload);
                    work::finish(window, outcome, &nudge);
                },
            );
        }
    });

    window.on_set_autostart({
        let weak = weak.clone();
        let nudge = nudge.clone();
        move |wanted| {
            let result = if wanted {
                autostart::enable()
            } else {
                autostart::disable()
            };
            if let Some(window) = weak.upgrade() {
                // The tick follows what is recorded, not what was asked for.
                load_autostart(&window);
                let said = match (&result, wanted) {
                    (Ok(()), true) => "this app will start when you log in".to_owned(),
                    (Ok(()), false) => "this app will not start when you log in".to_owned(),
                    (Err(e), _) => format!("{e:#}"),
                };
                work::finish(
                    &window,
                    result.map(|()| said).map_err(|e| anyhow!("{e:#}")),
                    &nudge,
                );
            }
        }
    });

    window.on_open_logs({
        let weak = weak.clone();
        let paths = paths.clone();
        let nudge = nudge.clone();
        move || {
            let dir = log::dir(&paths);
            let outcome = open(&dir).map(|()| format!("opened {}", dir.display()));
            if let Some(window) = weak.upgrade() {
                work::finish(&window, outcome, &nudge);
            }
        }
    });

    window.on_restart({
        let weak = weak.clone();
        let paths = paths.clone();
        let node = node.clone();
        let nudge = nudge.clone();
        move || {
            let (paths, node, nudge) = (paths.clone(), node.clone(), nudge.clone());
            work::run(&weak, &nudge, move || {
                restart(&node, &paths).map(|()| "the node restarted".to_owned())
            });
        }
    });

    window.on_join({
        let paths = paths.clone();
        let node = node.clone();
        let nudge = nudge.clone();
        move |token, username| {
            let (paths, node, nudge) = (paths.clone(), node.clone(), nudge.clone());
            let (token, username) = (token.to_string(), username.to_string());
            work::begin(&weak);

            let reload = paths.clone();
            work::action(
                &weak,
                move || {
                    stop(&node)?;
                    let enrolled = ops::join::from_token(&paths, &token, &username);
                    start(&node, &paths)?;

                    let enrolled = enrolled?;
                    Ok(format!(
                        "enrolled as {} with {}, attested for {}h. That server is pinned now.",
                        enrolled.username, enrolled.server, enrolled.attested_for
                    ))
                },
                move |window, outcome| {
                    load(window, &reload);
                    // Only once it actually worked: a failed attempt leaves the dialog up
                    // with the message underneath saying why.
                    if window.get_enrolled() {
                        window.set_show_enrol(false);
                    }
                    work::finish(window, outcome, &nudge);
                },
            );
        }
    });
}

struct Fields {
    listen: String,
    external: String,
    mdns: bool,
    root: String,
    max: String,
    bandwidth: String,
}

fn save(paths: &Paths, fields: Fields) -> Result<String> {
    let path = paths.config_file();
    let mut config =
        Config::load(&path).with_context(|| format!("loading config from {}", path.display()))?;

    config.listen = parse_addrs(&fields.listen).context("the listen addresses")?;
    config.external = parse_addrs(&fields.external).context("the announced addresses")?;
    config.mdns = fields.mdns;
    config.storage_root = blank_to_none(&fields.root).map(PathBuf::from);
    config.storage_max = parse_size(&fields.max).context("the storage ceiling")?;
    config.bandwidth_max = parse_size(&fields.bandwidth).context("the bandwidth limit")?;

    if let Some(rate) = config.bandwidth_max
        && rate < ac_net::config::MIN_BANDWIDTH
    {
        anyhow::bail!(
            "a bandwidth limit of {} a second is below the {} a second this node will \
             honour. A limit that slow stalls a transfer long enough to look like a dead \
             connection. Raise it, or say \"{UNLIMITED}\" for no limit.",
            human_size(rate),
            human_size(ac_net::config::MIN_BANDWIDTH),
        );
    }

    config
        .save(&path)
        .with_context(|| format!("saving config to {}", path.display()))?;

    Ok("saved. Restart the node for this to take effect.".to_owned())
}

/// Multiaddrs, one per line. Anything unparseable is refused by name rather than dropped.
fn parse_addrs(text: &str) -> Result<Vec<ac_net::Multiaddr>> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            line.parse()
                .with_context(|| format!("{line:?} is not an address"))
        })
        .collect()
}

fn join_addrs(addrs: &[ac_net::Multiaddr]) -> String {
    addrs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}

fn blank_to_none(text: &str) -> Option<String> {
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

const KB: u64 = 1_000;
const MB: u64 = 1_000 * KB;
const GB: u64 = 1_000 * MB;
const TB: u64 = 1_000 * GB;

/// The word these fields use for no limit, and accept back.
const UNLIMITED: &str = "unlimited";

/// A size as the field shows it
fn size_field(bytes: Option<u64>) -> String {
    let Some(bytes) = bytes else {
        return UNLIMITED.to_owned();
    };

    for (unit, scale) in [("TB", TB), ("GB", GB), ("MB", MB), ("KB", KB)] {
        if bytes >= scale && bytes % scale == 0 {
            return format!("{} {unit}", bytes / scale);
        }
    }
    bytes.to_string()
}

fn parse_size(text: &str) -> Result<Option<u64>> {
    let text = text.trim().to_lowercase();
    if text.is_empty() || text == UNLIMITED || text == "none" {
        return Ok(None);
    }

    let count = text.trim_end_matches(|c: char| c.is_ascii_alphabetic() || c.is_whitespace());
    let scale = match text[count.len()..].trim() {
        "" | "b" => 1,
        "k" | "kb" => KB,
        "m" | "mb" => MB,
        "g" | "gb" => GB,
        "t" | "tb" => TB,
        "kib" => 1024,
        "mib" => 1024 * 1024,
        "gib" => 1024 * 1024 * 1024,
        "tib" => 1024_u64.pow(4),
        unit => anyhow::bail!("{unit:?} is not a unit. Use B, KB, MB, GB or TB"),
    };

    let count: f64 = count
        .parse()
        .with_context(|| format!("{count:?} is not a number"))?;
    anyhow::ensure!(count >= 0.0, "a limit cannot be negative");

    // Zero is how the config file asks for no limit, so the field agrees with it.
    let bytes = (count * scale as f64) as u64;
    Ok((bytes > 0).then_some(bytes))
}

fn restart(node: &Shared, paths: &Paths) -> Result<()> {
    stop(node)?;
    start(node, paths)
}

fn stop(node: &Shared) -> Result<()> {
    node.lock()
        .map_err(|_| anyhow!("the node is in an unknown state after an earlier panic"))?
        .stop()
        .context("stopping the node")
}

fn start(node: &Shared, paths: &Paths) -> Result<()> {
    let mut node = node
        .lock()
        .map_err(|_| anyhow!("the node is in an unknown state after an earlier panic"))?;
    *node = Node::start(paths.clone()).context("starting the node again")?;
    Ok(())
}

/// Hand a directory to whatever the desktop opens directories with.
fn open(dir: &std::path::Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    let mut command = {
        let mut command = std::process::Command::new("xdg-open");
        command.arg(dir);
        command
    };

    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = std::process::Command::new("explorer");
        command.arg(dir);
        command
    };

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    let mut command = {
        let _ = dir;
        anyhow::bail!("opening a folder is not supported on this platform");
    };

    command
        .spawn()
        .with_context(|| format!("opening {}", dir.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_way_of_saying_no_limit_means_the_same_thing() {
        for said in ["", "   ", "unlimited", "UNLIMITED", "none", "0", "0 GB"] {
            assert_eq!(parse_size(said).unwrap(), None, "for {said:?}");
        }
    }

    #[test]
    fn a_size_is_read_the_way_a_person_writes_one() {
        assert_eq!(parse_size("500 GB").unwrap(), Some(500 * GB));
        assert_eq!(parse_size("10 MB").unwrap(), Some(10 * MB));
        assert_eq!(
            parse_size("10mb").unwrap(),
            Some(10 * MB),
            "spacing is optional"
        );
        assert_eq!(parse_size("2T").unwrap(), Some(2 * TB));
        assert_eq!(parse_size("1.5 GB").unwrap(), Some(GB + GB / 2));
        assert_eq!(parse_size("1000000").unwrap(), Some(MB), "bare bytes");
    }

    #[test]
    fn the_binary_spellings_keep_their_own_meaning() {
        assert_eq!(parse_size("1 GiB").unwrap(), Some(1024 * 1024 * 1024));
        assert_eq!(parse_size("1 GB").unwrap(), Some(1_000_000_000));
        assert_ne!(parse_size("1 GiB").unwrap(), parse_size("1 GB").unwrap());
    }

    #[test]
    fn what_the_field_shows_parses_back_to_the_same_bytes() {
        for bytes in [
            500 * GB,
            10 * MB,
            ac_net::config::DEFAULT_STORAGE_MAX,
            ac_net::config::DEFAULT_BANDWIDTH_MAX,
            123_456_789,
            1,
        ] {
            let shown = size_field(Some(bytes));
            assert_eq!(
                parse_size(&shown).unwrap(),
                Some(bytes),
                "{bytes} showed as {shown:?}"
            );
        }
    }

    #[test]
    fn the_defaults_are_shown_as_the_round_numbers_they_are() {
        assert_eq!(
            size_field(Some(ac_net::config::DEFAULT_STORAGE_MAX)),
            "500 GB"
        );
        assert_eq!(
            size_field(Some(ac_net::config::DEFAULT_BANDWIDTH_MAX)),
            "10 MB"
        );
        assert_eq!(size_field(None), "unlimited");
    }

    #[test]
    fn a_size_that_is_not_one_says_what_was_wrong_with_it() {
        let e = parse_size("ten gigs").unwrap_err();
        assert!(format!("{e:#}").contains("ten gigs"), "got {e:#}");

        let e = parse_size("10 furlongs").unwrap_err();
        assert!(format!("{e:#}").contains("furlongs"), "got {e:#}");
    }

    #[test]
    fn addresses_survive_the_round_trip() {
        let text = "/ip4/0.0.0.0/udp/0/quic-v1\n/ip6/::/udp/0/quic-v1";
        let parsed = parse_addrs(text).unwrap();

        assert_eq!(parsed.len(), 2);
        assert_eq!(join_addrs(&parsed), text);
    }

    #[test]
    fn blank_lines_between_addresses_are_not_addresses() {
        let parsed = parse_addrs("\n/ip4/0.0.0.0/udp/0/quic-v1\n\n  \n").unwrap();
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn a_bad_address_is_refused_by_name_rather_than_dropped() {
        let e = parse_addrs("/ip4/0.0.0.0/udp/0/quic-v1\nnot-an-address").unwrap_err();
        assert!(format!("{e:#}").contains("not-an-address"), "got {e:#}");
    }

    #[test]
    fn no_addresses_at_all_is_an_empty_list_not_an_error() {
        assert!(parse_addrs("").unwrap().is_empty());
    }
}
