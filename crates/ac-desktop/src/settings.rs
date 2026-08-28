use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ac_net::config::{Config, Paths};
use ac_node::ops;
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
    window.set_storage_max(
        config
            .storage_max
            .map(|n| n.to_string())
            .unwrap_or_default()
            .into(),
    );
    window.set_bandwidth_max(
        config
            .bandwidth_max
            .map(|n| n.to_string())
            .unwrap_or_default()
            .into(),
    );
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
        move |address, code, username| {
            let (paths, node, nudge) = (paths.clone(), node.clone(), nudge.clone());
            let (address, code, username) =
                (address.to_string(), code.to_string(), username.to_string());
            work::begin(&weak);

            let reload = paths.clone();
            work::action(
                &weak,
                move || {
                    let server = address
                        .parse()
                        .with_context(|| format!("{address} is not an address"))?;

                    stop(&node)?;
                    let enrolled = ops::join::run(&paths, &server, &code, &username);
                    start(&node, &paths)?;

                    let enrolled = enrolled?;
                    Ok(format!(
                        "enrolled as {} with {}, attested for {}h. That server is pinned now.",
                        enrolled.username, enrolled.server, enrolled.attested_for
                    ))
                },
                move |window, outcome| {
                    load(window, &reload);
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
    config.storage_max = parse_bytes(&fields.max).context("the storage ceiling")?;
    config.bandwidth_max = parse_bytes(&fields.bandwidth).context("the bandwidth limit")?;

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

/// Empty means no limit, which is not the same as zero.
fn parse_bytes(text: &str) -> Result<Option<u64>> {
    match blank_to_none(text) {
        None => Ok(None),
        Some(value) => value
            .parse()
            .map(Some)
            .with_context(|| format!("{value:?} is not a number of bytes")),
    }
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
    fn an_empty_limit_means_no_limit_rather_than_zero() {
        assert_eq!(parse_bytes("").unwrap(), None);
        assert_eq!(parse_bytes("   ").unwrap(), None);
        assert_eq!(parse_bytes("0").unwrap(), Some(0), "zero is a real answer");
        assert_eq!(parse_bytes("1048576").unwrap(), Some(1048576));
    }

    #[test]
    fn a_limit_that_is_not_a_number_says_which_one() {
        let e = parse_bytes("10 GB").unwrap_err();
        assert!(format!("{e:#}").contains("\"10 GB\""), "got {e:#}");
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
        // Silently discarding one line of six would leave a node listening somewhere the
        // settings page claims it is not.
        let e = parse_addrs("/ip4/0.0.0.0/udp/0/quic-v1\nnot-an-address").unwrap_err();
        assert!(format!("{e:#}").contains("not-an-address"), "got {e:#}");
    }

    #[test]
    fn no_addresses_at_all_is_an_empty_list_not_an_error() {
        assert!(parse_addrs("").unwrap().is_empty());
    }
}
