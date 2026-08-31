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
use crate::{autostart, log, view};

pub type Shared = Arc<Mutex<Node>>;

/// What the enrolment dialog is showing. Mirrored in `views/enrol.slint`, which is why
/// these are the ints the property takes rather than an enum.
pub const ENROL_FORM: i32 = 0;
pub const ENROL_WORKING: i32 = 1;
pub const ENROL_DONE: i32 = 2;

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
            if let Some(window) = weak.upgrade() {
                window.set_enrol_phase(ENROL_WORKING);
                window.set_enrol_error("".into());
            }

            let reload = paths.clone();
            work::action(
                &weak,
                move || {
                    stop(&node)?;
                    let enrolled = ops::join::from_token(&paths, &token, &username);
                    // Started again whichever way it went: a node left stopped by a
                    // refusal would look like the app itself had given up.
                    start(&node, &paths)?;
                    enrolled
                },
                move |window, outcome| {
                    load(window, &reload);
                    // The window reads these once at startup, and enrolling is the one
                    // thing that changes them: without this the name and the server stay
                    // blank until the app is opened again.
                    if let Err(e) = view::describe_node(window, &reload) {
                        tracing::warn!(error = %e, "could not re-read this node's details");
                    }

                    match &outcome {
                        Ok(enrolled) => {
                            // The dialog has the name in front of someone who just typed
                            // it; the rest is on the Status page behind it.
                            window.set_enrol_summary(
                                format!("Enrolled as {}.", enrolled.username).into(),
                            );
                            window.set_enrol_phase(ENROL_DONE);
                        }
                        Err(e) => {
                            // `{:#}` so the server's reason comes through, not just the
                            // outermost context.
                            window.set_enrol_error(format!("{e:#}").into());
                            window.set_enrol_phase(ENROL_FORM);
                        }
                    }

                    if window.get_show_enrol() {
                        // The dialog is saying it; the shared line would only repeat it,
                        // out of sight behind the dialog.
                        work::quiet(window, &nudge);
                    } else {
                        // Nobody is looking at a dialog, so the one line has to carry it.
                        let said = outcome.map(|enrolled| {
                            format!(
                                "Enrolled as {} with {}, attested for {}h. That server is \
                                 pinned now.",
                                enrolled.username, enrolled.server, enrolled.attested_for
                            )
                        });
                        work::finish(window, said, &nudge);
                    }
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
    use i_slint_backend_testing::ElementHandle;

    use super::*;

    /// The dialog stays up for the whole of enrolling, so what it shows is the only thing
    /// saying whether anything is happening. Drawn into memory, so this needs no display.
    #[test]
    fn the_enrol_dialog_shows_one_thing_at_a_time() {
        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().unwrap();
        window.set_show_enrol(true);

        let showing = |label: &str| ElementHandle::find_by_accessible_label(&window, label).count();
        let enrolling = "Enrolling. The node stops and starts again, which takes a moment.";

        window.set_enrol_phase(ENROL_FORM);
        assert_eq!(showing("Enrol"), 1, "the form offers to enrol");
        assert_eq!(showing("Not now"), 1);
        assert_eq!(showing(enrolling), 0);
        assert_eq!(showing("Close"), 0);

        // A refusal comes back into the form, with the reason above it.
        window.set_enrol_error("that invite token is damaged".into());
        assert_eq!(showing("that invite token is damaged"), 1);
        assert_eq!(showing("Enrol"), 1, "and it can be tried again");

        window.set_enrol_phase(ENROL_WORKING);
        assert_eq!(showing(enrolling), 1);
        assert_eq!(showing("Enrol"), 0, "nothing to press while it runs");
        assert_eq!(showing("Not now"), 0);
        assert_eq!(
            showing("that invite token is damaged"),
            0,
            "the last failure is not still on screen while the next attempt runs"
        );

        window.set_enrol_phase(ENROL_DONE);
        window.set_enrol_summary("Enrolled as alice.".into());
        assert_eq!(showing("Successfully enrolled"), 1, "the title says so too");
        assert_eq!(showing("Enrol this node"), 0);
        assert_eq!(showing("Enrolled as alice."), 1);
        assert_eq!(showing("Close"), 1);
        assert_eq!(showing("Enrol"), 0, "there is nothing left to enrol");

        ElementHandle::find_by_accessible_label(&window, "Close")
            .next()
            .unwrap()
            .invoke_accessible_default_action();
        assert!(!window.get_show_enrol(), "Close puts the dialog away");
    }

    /// Enrolling is the one thing that changes the name and the server a node shows, and it
    /// happens with the window already open. Read only at startup, the Status page went on
    /// saying "not enrolled" until the app was opened again.
    #[test]
    fn the_window_picks_up_an_enrolment_without_being_restarted() {
        use ac_net::attest::{self, Attestation};
        use ac_net::identity::Keypair;

        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().unwrap();

        let home = tempfile::tempdir().unwrap();
        let paths = Paths::rooted_at(home.path());
        view::describe_node(&window, &paths).unwrap();
        assert_eq!(window.get_username(), "");
        assert_eq!(window.get_server_host(), "not enrolled");

        // What enrolling leaves on disk: the server in the config, and the attestation it
        // was issued.
        let me = ops::identity(&paths).unwrap();
        let attestation = Attestation::issue(
            &Keypair::generate_ed25519(),
            &me.peer_id(),
            "alice",
            attest::now(),
            attest::LIFETIME,
        )
        .unwrap();
        attest::save(&paths.attestation_file(), &attestation).unwrap();

        let mut config = Config::load(&paths.config_file()).unwrap();
        config.server = Some("/dns4/ac.example.net/udp/4001/quic-v1".parse().unwrap());
        config.save(&paths.config_file()).unwrap();

        view::describe_node(&window, &paths).unwrap();
        assert_eq!(window.get_username(), "alice");
        assert_eq!(window.get_server_host(), "ac.example.net");
    }

    /// A refusal over the username should not cost someone the token they pasted, so the
    /// fields have to survive the trip out to the phase that has no fields at all.
    #[test]
    fn what_was_typed_survives_a_failed_attempt() {
        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().unwrap();
        window.set_show_enrol(true);
        window.set_enrol_phase(ENROL_FORM);

        let field = |id: &str| {
            ElementHandle::find_by_element_id(&window, id)
                .next()
                .unwrap()
        };
        field("EnrolDialog::token").set_accessible_value("ac1thetoken");
        field("EnrolDialog::who").set_accessible_value("alice");

        window.set_enrol_phase(ENROL_WORKING);
        window.set_enrol_phase(ENROL_FORM);

        assert_eq!(
            field("EnrolDialog::token").accessible_value().unwrap(),
            "ac1thetoken"
        );
        assert_eq!(
            field("EnrolDialog::who").accessible_value().unwrap(),
            "alice"
        );
    }

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
