use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use ac_net::config::{Config, Paths};
use ac_node::ops;
use ac_node::ops::format::human_size;
use anyhow::{Context, Result, anyhow};
use slint::{ComponentHandle, ModelRc, VecModel};

use crate::node::Node;
use crate::ui::MainWindow;
use crate::work::{self, Nudge};
use crate::{autostart, log, shell};

pub type Shared = Arc<Mutex<Node>>;

pub fn load(window: &MainWindow, paths: &Paths) {
    let config = ops::config(paths).unwrap_or_default();

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
    window.set_enrolled(ops::enrolled(paths).ok().flatten().is_some());

    // The Sources section, which is read here rather than on the poll for the same reason as
    // everything above it: these are boxes somebody types into, and a poll would take the
    // text back out from under them. What an implementation shares is fixed by the build, so
    // reading it once is reading it whenever it could have changed.
    window.set_source_settings(ModelRc::from(Rc::new(VecModel::from(
        crate::sources::shared_settings(paths),
    ))));

    show_autostart(window, autostart::state());
}

/// The tick, and the warning that goes with a recorded path that is no longer this binary.
/// Where the platform has no way to start with the session, the option is not shown at all.
fn show_autostart(window: &MainWindow, state: Result<autostart::State>) {
    let (supported, on, warning) = match state {
        Ok(autostart::State::Unsupported) => (false, false, String::new()),
        Ok(autostart::State::On) => (true, true, String::new()),
        Ok(autostart::State::Off) => (true, false, String::new()),
        Ok(autostart::State::Stale { was }) => (
            true,
            false,
            format!(
                "The recorded entry starts {}, which is not this program. Turn this on to \
                 start this one instead.",
                was.display()
            ),
        ),
        Err(e) => (
            true,
            false,
            format!("could not read the autostart entry: {e:#}"),
        ),
    };

    window.set_autostart_supported(supported);
    window.set_autostart(on);
    window.set_autostart_warning(warning.into());
}

pub fn wire(window: &MainWindow, paths: &Paths, node: &Shared, nudge: &Nudge) {
    let weak = window.as_weak();

    window.on_save({
        let weak = weak.clone();
        let paths = paths.clone();
        let nudge = nudge.clone();
        move |mdns, root, max, bandwidth| {
            let (paths, nudge) = (paths.clone(), nudge.clone());
            let fields = Fields {
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

    window.on_pick_storage_root({
        let paths = paths.clone();
        move |current| {
            let start = match current.is_empty() {
                // Where the files are now, which is the only folder worth opening on.
                true => Config::load(&paths.config_file())
                    .unwrap_or_default()
                    .storage_root(&paths),
                false => PathBuf::from(current.as_str()),
            };

            rfd::FileDialog::new()
                .set_title("Keep files in")
                .set_directory(start)
                .pick_folder()
                .map(|dir| dir.display().to_string().into())
                // Dismissed, so the field keeps whatever it already read.
                .unwrap_or(current)
        }
    });

    window.on_set_autostart({
        let weak = weak.clone();
        let nudge = nudge.clone();
        move |wanted| {
            let nudge = nudge.clone();
            work::begin(&weak);
            work::action(
                &weak,
                move || match wanted {
                    true => autostart::enable(),
                    false => autostart::disable(),
                },
                move |window, outcome| {
                    // The tick follows what is recorded, not what was asked for, and it is
                    // all a success needs to say.
                    show_autostart(window, autostart::state());
                    work::finish(window, outcome.map(|()| String::new()), &nudge);
                },
            );
        }
    });

    window.on_open_logs({
        let weak = weak.clone();
        let paths = paths.clone();
        let nudge = nudge.clone();
        move || {
            let dir = log::dir(&paths);
            let outcome = shell::open(&dir).map(|()| format!("opened {}", dir.display()));
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

    window.on_stop_phone_code(ops::import::stop_signing_in);

    window.on_backup({
        let weak = weak.clone();
        let paths = paths.clone();
        let nudge = nudge.clone();
        move || {
            let (paths, nudge) = (paths.clone(), nudge.clone());
            work::begin(&weak);
            if let Some(window) = weak.upgrade() {
                window.set_backing_up(true);
            }
            work::nudge_when_code_shows(&nudge);

            work::action(
                &weak,
                move || ops::backup::backup(&paths),
                move |window, outcome| {
                    window.set_backing_up(false);
                    // Nothing else on screen changes, so the line says how it went.
                    let said = match outcome {
                        Ok(Some(())) => Ok("backed up to the phone".to_owned()),
                        Ok(None) => Ok(String::new()),
                        Err(e) => Err(e),
                    };
                    work::finish(window, said, &nudge);
                },
            );
        }
    });
}

struct Fields {
    mdns: bool,
    root: String,
    max: String,
    bandwidth: String,
}

fn save(paths: &Paths, fields: Fields) -> Result<String> {
    let path = paths.config_file();
    let mut config =
        Config::load(&path).with_context(|| format!("loading config from {}", path.display()))?;

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

pub(crate) fn stop(node: &Shared) -> Result<()> {
    node.lock()
        .map_err(|_| anyhow!("the node is in an unknown state after an earlier panic"))?
        .stop()
        .context("stopping the node")
}

pub(crate) fn start(node: &Shared, paths: &Paths) -> Result<()> {
    let mut node = node
        .lock()
        .map_err(|_| anyhow!("the node is in an unknown state after an earlier panic"))?;
    *node = Node::start(paths.clone()).context("starting the node again")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use i_slint_backend_testing::ElementHandle;
    use slint::Model as _;

    use super::*;
    use crate::view::{self, SETTINGS};

    #[test]
    fn a_backup_is_offered_only_once_enrolled() {
        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().unwrap();
        window
            .window()
            .set_size(slint::PhysicalSize::new(1200, 3000));
        window.set_tab(SETTINGS);
        let showing = |label: &str| ElementHandle::find_by_accessible_label(&window, label).count();

        window.set_enrolled(false);
        assert_eq!(showing("Back up to phone"), 0);

        window.set_enrolled(true);
        assert_eq!(showing("Back up to phone"), 1);

        window.set_backing_up(true);
        assert_eq!(showing("Back up to phone"), 0, "one at a time");
        assert_eq!(showing("Cancel"), 1, "and it can be given up");
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

    /// The Settings tab is where a source's shared settings are changed, and it is reachable
    /// without ever opening the Sources tab. Filled only by the Sources page's own poll, the
    /// section was gated on a list that was still empty and did not appear at all.
    #[test]
    fn the_sources_section_is_there_without_opening_the_sources_tab() {
        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().unwrap();
        let (_tmp, paths) = crate::groups::tests::home("jonathan");
        ops::import::set_setting(&paths, "drive", "client_secret", "shh-1234").unwrap();

        // Tall enough that the whole page is laid out: a lookup finds only what is on screen.
        window
            .window()
            .set_size(slint::PhysicalSize::new(1200, 3000));

        // Straight to Settings, which is what somebody changing a credential does.
        window.set_tab(SETTINGS);
        assert_eq!(
            window.get_source_settings().iter().count(),
            0,
            "nothing has filled it yet"
        );

        load(&window, &paths);

        let showing = |label: &str| ElementHandle::find_by_accessible_label(&window, label).count();
        assert_eq!(showing("SOURCES"), 1, "the section is on the page");
        assert!(
            window
                .get_source_settings()
                .iter()
                .any(|item| item.key == "client_secret" && item.value == "shh-1234"),
            "with what is stored in it, ready to be changed"
        );
    }

    /// The "Start when I log in" box itself, not the text inside it that carries the same label.
    fn start_at_login(window: &MainWindow) -> impl Iterator<Item = ElementHandle> {
        ElementHandle::find_by_accessible_label(window, "Start when I log in").filter(|e| {
            e.accessible_role() == Some(i_slint_backend_testing::AccessibleRole::Checkbox)
        })
    }

    /// Where the platform has no way to start with the session there is nothing to offer; where
    /// it has, the tick says what is recorded, and an entry naming another binary is said out
    /// loud rather than left to fail at the next login.
    #[test]
    fn start_at_login_is_offered_only_where_it_works_and_says_what_is_recorded() {
        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().unwrap();
        window
            .window()
            .set_size(slint::PhysicalSize::new(1200, 3000));
        window.set_tab(SETTINGS);

        let showing = |label: &str| ElementHandle::find_by_accessible_label(&window, label).count();
        let checkboxes = || start_at_login(&window).count();
        let ticked = || {
            start_at_login(&window)
                .next()
                .unwrap()
                .accessible_checked()
                .unwrap()
        };

        show_autostart(&window, Ok(autostart::State::Unsupported));
        assert_eq!(checkboxes(), 0, "hidden where there is no implementation");

        show_autostart(&window, Ok(autostart::State::Off));
        assert_eq!(checkboxes(), 1, "shown where there is one");
        assert!(!ticked(), "and clear when nothing is recorded");

        show_autostart(&window, Ok(autostart::State::On));
        assert!(ticked());
        assert_eq!(window.get_autostart_warning(), "");

        let was = PathBuf::from("/gone/ac-desktop");
        show_autostart(&window, Ok(autostart::State::Stale { was }));
        assert!(
            !ticked(),
            "an entry that starts something else is not this one on"
        );
        let warning = window.get_autostart_warning().to_string();
        assert!(warning.contains("/gone/ac-desktop"), "got {warning:?}");
        assert_eq!(showing(&warning), 1, "and the warning is on the page");

        show_autostart(&window, Ok(autostart::State::Unsupported));
        assert_eq!(showing(&warning), 0, "nor is a warning about it");
    }

    /// The tick follows what is recorded, not the click: a refused write leaves it clear.
    #[test]
    fn the_tick_follows_what_was_recorded_rather_than_the_click() {
        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().unwrap();
        window
            .window()
            .set_size(slint::PhysicalSize::new(1200, 3000));
        window.set_tab(SETTINGS);
        show_autostart(&window, Ok(autostart::State::Off));

        let asked = Rc::new(std::cell::Cell::new(None));
        window.on_set_autostart({
            let weak = window.as_weak();
            let asked = asked.clone();
            move |wanted| {
                asked.set(Some(wanted));
                // What a failed write reads back as.
                show_autostart(&weak.upgrade().unwrap(), Ok(autostart::State::Off));
            }
        });

        let checkbox = || start_at_login(&window).next().unwrap();
        checkbox().invoke_accessible_default_action();

        assert_eq!(asked.get(), Some(true), "the click asked to turn it on");
        assert_eq!(checkbox().accessible_checked(), Some(false));
        assert!(!window.get_autostart());

        // And a later success still gets through to the box.
        show_autostart(&window, Ok(autostart::State::On));
        assert_eq!(checkbox().accessible_checked(), Some(true));
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
}
