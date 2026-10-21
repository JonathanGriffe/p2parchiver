use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use ac_net::config::{Config, Paths};
use ac_node::ops;
use ac_node::ops::backup::Recovered;
use ac_node::ops::format::human_size;
use ac_node::ops::join::Enrolled;
use anyhow::{Context, Result, anyhow};
use slint::{ComponentHandle, ModelRc, VecModel};

use crate::node::Node;
use crate::ui::MainWindow;
use crate::work::{self, Nudge};
use crate::{autostart, log, shell, view};

pub type Shared = Arc<Mutex<Node>>;

/// What the enrolment dialog is showing. Mirrored in `views/enrol.slint`, which is why
/// these are the ints the property takes rather than an enum.
pub const ENROL_IDENTITY: i32 = 0;
pub const ENROL_RESTORING: i32 = 1;
pub const ENROL_FORM: i32 = 2;
pub const ENROL_WORKING: i32 = 3;
pub const ENROL_DONE: i32 = 4;

/// An identity restored from the phone, held until enrolling with it, and lost with the app.
type Restored = Arc<Mutex<Option<ops::backup::Recovered>>>;

/// How the enrol dialog enrols.
enum Enrol {
    Token { token: String, username: String },
    Continue,
}

pub fn load(window: &MainWindow, paths: &Paths) {
    let config = Config::load(&paths.config_file()).unwrap_or_default();

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

    let restored: Restored = Arc::default();
    // Whether the code on screen was given up on by hand, which needs no message.
    let stopped = Arc::new(AtomicBool::new(false));

    window.on_stop_phone_code({
        let stopped = stopped.clone();
        move || {
            stopped.store(true, Ordering::SeqCst);
            ops::import::stop_signing_in();
        }
    });

    window.on_enrol_new({
        let weak = weak.clone();
        let restored = restored.clone();
        move || {
            if let Ok(mut held) = restored.lock() {
                *held = None;
            }
            if let Some(window) = weak.upgrade() {
                window.set_enrol_restored(false);
                window.set_enrol_error("".into());
                window.set_enrol_phase(ENROL_FORM);
            }
        }
    });

    window.on_enrol_restore({
        let weak = weak.clone();
        let paths = paths.clone();
        let nudge = nudge.clone();
        let restored = restored.clone();
        let stopped = stopped.clone();
        move || {
            let (paths, nudge, restored, stopped) = (
                paths.clone(),
                nudge.clone(),
                restored.clone(),
                stopped.clone(),
            );
            work::begin(&weak);
            stopped.store(false, Ordering::SeqCst);
            if let Some(window) = weak.upgrade() {
                window.set_enrol_error("".into());
                window.set_enrol_phase(ENROL_RESTORING);
            }
            nudge_when_shown(&nudge);

            work::action(
                &weak,
                move || ops::backup::restore(&paths),
                move |window, outcome| {
                    match outcome {
                        Ok(recovered) => {
                            window.set_enrol_username(recovered.username.as_str().into());
                            window.set_enrol_restored(true);
                            if let Ok(mut held) = restored.lock() {
                                *held = Some(recovered);
                            }
                            window.set_enrol_phase(ENROL_FORM);
                        }
                        Err(e) => {
                            if !stopped.load(Ordering::SeqCst) {
                                window.set_enrol_error(format!("{e:#}").into());
                            }
                            window.set_enrol_phase(ENROL_IDENTITY);
                        }
                    }
                    work::quiet(window, &nudge);
                },
            );
        }
    });

    window.on_backup({
        let weak = weak.clone();
        let paths = paths.clone();
        let nudge = nudge.clone();
        let stopped = stopped.clone();
        move || {
            let (paths, nudge, stopped) = (paths.clone(), nudge.clone(), stopped.clone());
            work::begin(&weak);
            stopped.store(false, Ordering::SeqCst);
            if let Some(window) = weak.upgrade() {
                window.set_backing_up(true);
            }
            nudge_when_shown(&nudge);

            work::action(
                &weak,
                move || ops::backup::backup(&paths),
                move |window, outcome| {
                    window.set_backing_up(false);
                    // Nothing else on screen changes, so the line says how it went.
                    let said = match outcome {
                        Ok(()) => Ok("backed up to the phone".to_owned()),
                        Err(_) if stopped.load(Ordering::SeqCst) => Ok(String::new()),
                        Err(e) => Err(e),
                    };
                    work::finish(window, said, &nudge);
                },
            );
        }
    });

    window.on_enrol_continue({
        let weak = weak.clone();
        let paths = paths.clone();
        let node = node.clone();
        let nudge = nudge.clone();
        let restored = restored.clone();
        move || enrol(&weak, &paths, &node, &nudge, &restored, Enrol::Continue)
    });

    window.on_join({
        let paths = paths.clone();
        let node = node.clone();
        let nudge = nudge.clone();
        move |token, username| {
            let how = Enrol::Token {
                token: token.to_string(),
                username: username.to_string(),
            };
            enrol(&weak, &paths, &node, &nudge, &restored, how);
        }
    });
}

/// Have the poller read as soon as a code to scan is up, rather than at its next tick.
fn nudge_when_shown(nudge: &Nudge) {
    let nudge = nudge.clone();
    std::thread::spawn(move || {
        for _ in 0..100 {
            std::thread::sleep(std::time::Duration::from_millis(50));
            if ops::import::showing().is_some() {
                nudge.now();
                return;
            }
        }
    });
}

/// Enrol from the dialog, with the restored identity if there is one, else this node's own.
fn enrol_with(paths: &Paths, restored: Option<Recovered>, how: Enrol) -> Result<Enrolled> {
    match (how, restored) {
        (Enrol::Continue, Some(r)) => ops::join::from_server(paths, &r.identity, &r.server),
        (Enrol::Continue, None) => Err(anyhow!("no identity has been restored from the phone")),
        (Enrol::Token { token, username }, Some(r)) => {
            ops::join::from_token(paths, &r.identity, &token, &username)
        }
        (Enrol::Token { token, username }, None) => {
            ops::join::from_token(paths, &ops::identity(paths)?, &token, &username)
        }
    }
}

/// Stop the node, enrol, and start the node again whatever the outcome.
fn enrol(
    weak: &slint::Weak<MainWindow>,
    paths: &Paths,
    node: &Shared,
    nudge: &Nudge,
    restored: &Restored,
    how: Enrol,
) {
    let (paths, node, nudge) = (paths.clone(), node.clone(), nudge.clone());
    let (held, kept) = (restored.clone(), restored.clone());
    work::begin(weak);
    if let Some(window) = weak.upgrade() {
        window.set_enrol_phase(ENROL_WORKING);
        window.set_enrol_error("".into());
    }

    let reload = paths.clone();
    work::action(
        weak,
        move || {
            let restored = held
                .lock()
                .map_err(|_| anyhow!("the restored identity is in an unknown state"))?
                .clone();
            stop(&node)?;
            let enrolled = enrol_with(&paths, restored, how);
            // Started again whichever way it went: a node left stopped by a
            // refusal would look like the app itself had given up.
            start(&node, &paths)?;
            enrolled
        },
        move |window, outcome| {
            if outcome.is_ok() {
                if let Ok(mut held) = kept.lock() {
                    *held = None;
                }
                window.set_enrol_restored(false);
            }
            load(window, &reload);
            // The window reads these once at startup, and enrolling is the one thing that
            // changes them, the peer id too after a restore: without this the name and the
            // server stay blank until the app is opened again.
            if let Err(e) = view::describe_node(window, &reload) {
                tracing::warn!(error = %e, "could not re-read this node's details");
            }

            match &outcome {
                Ok(enrolled) => {
                    // The dialog has the name in front of someone who just typed it; the
                    // rest is on the Status page behind it.
                    window.set_enrol_summary(format!("Enrolled as {}.", enrolled.username).into());
                    window.set_enrol_phase(ENROL_DONE);
                }
                Err(e) => {
                    // `{:#}` so the server's reason comes through, not just the outermost
                    // context.
                    window.set_enrol_error(format!("{e:#}").into());
                    window.set_enrol_phase(ENROL_FORM);
                }
            }

            if window.get_show_enrol() {
                // The dialog is saying it; the shared line would only repeat it, out of
                // sight behind the dialog.
                work::quiet(window, &nudge);
            } else {
                // Nobody is looking at a dialog, so the one line has to carry it.
                let said = outcome.map(|enrolled| {
                    format!(
                        "Enrolled as {} with {}, attested for {}h. That server is pinned now.",
                        enrolled.username, enrolled.server, enrolled.attested_for
                    )
                });
                work::finish(window, said, &nudge);
            }
        },
    );
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

#[cfg(test)]
mod tests {
    use i_slint_backend_testing::ElementHandle;
    use slint::Model as _;

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

        window.set_enrol_phase(ENROL_IDENTITY);
        assert_eq!(showing("New identity"), 1, "first, which identity");
        assert_eq!(showing("Restore from phone"), 1);
        assert_eq!(showing("Not now"), 1);
        assert_eq!(showing("Enrol"), 0, "the server comes after");

        window.set_enrol_phase(ENROL_RESTORING);
        assert_eq!(showing("Cancel"), 1, "waiting on the phone can be given up");
        assert_eq!(showing("New identity"), 0);
        assert_eq!(showing("Not now"), 0);

        window.set_enrol_phase(ENROL_FORM);
        assert_eq!(showing("Enrol"), 1, "the form offers to enrol");
        assert_eq!(showing("Continue"), 0, "with nothing restored to continue");
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

    /// A restored identity can enrol again with its own server, under the name it came with.
    #[test]
    fn a_restored_identity_can_continue_under_its_own_name() {
        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().unwrap();
        window.set_show_enrol(true);
        window.set_enrol_phase(ENROL_FORM);

        let continued = Rc::new(std::cell::Cell::new(false));
        window.on_enrol_continue({
            let continued = continued.clone();
            move || continued.set(true)
        });

        window.set_enrol_restored(true);
        window.set_enrol_username("alice".into());
        let field = ElementHandle::find_by_element_id(&window, "EnrolDialog::who")
            .next()
            .unwrap();
        assert_eq!(field.accessible_value().unwrap(), "alice", "prefilled");

        let button = ElementHandle::find_by_accessible_label(&window, "Continue")
            .next()
            .expect("offered once restored");
        button.invoke_accessible_default_action();
        assert!(continued.get());
    }

    #[test]
    fn a_backup_is_offered_only_once_enrolled() {
        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().unwrap();
        window
            .window()
            .set_size(slint::PhysicalSize::new(1200, 3000));
        window.set_tab(SETTINGS_TAB);
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

    /// The Settings page, as `app.slint` numbers the tabs. Only here: nothing in the poll
    /// narrows by it, which is the whole reason this page is loaded instead.
    const SETTINGS_TAB: i32 = 6;

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
        window.set_tab(SETTINGS_TAB);
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
        window.set_tab(SETTINGS_TAB);

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
        window.set_tab(SETTINGS_TAB);
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
}
