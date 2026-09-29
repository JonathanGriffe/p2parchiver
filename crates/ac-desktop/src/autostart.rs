//! Starting with the session: an XDG autostart entry on Linux, a `Run` value on Windows.
//!
//! On unless turned off: the first run of a released build turns it on, once, and after that
//! the toggle in Settings owns it. Nothing else writes the entry, so what Settings shows is
//! what is recorded.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use ac_net::config::Paths;
use anyhow::{Context, Result};

use imp::SUPPORTED;

/// The name under which the entry is recorded, on either platform.
const ENTRY: &str = "archiverclient";

/// The flag the recorded command carries, and the one `Cli` declares with it. A node started
/// with the session belongs in the tray, not in a window nobody asked for.
pub const BACKGROUND: &str = "background";

/// Set by the AppImage runtime to the image itself, which is what outlives this session.
const APPIMAGE: &str = "APPIMAGE";

/// Left in the node's directory by the run that turned the entry on by default, so that it
/// happens once and turning it off stays off.
const DEFAULTED_FILENAME: &str = "autostart-defaulted";

#[derive(Debug, PartialEq, Eq)]
pub enum State {
    /// This platform has no way to start with the session, so there is nothing to offer.
    Unsupported,
    Off,
    On,
    Stale {
        was: PathBuf,
    },
}

/// Whether this binary starts with the session.
pub fn state() -> Result<State> {
    if !SUPPORTED {
        return Ok(State::Unsupported);
    }
    Ok(classify(imp::read()?, &this_binary()?))
}

pub fn enable() -> Result<()> {
    imp::write(&this_binary()?)
}

pub fn disable() -> Result<()> {
    imp::clear()
}

/// Point an existing entry at this binary, if the one it names is gone.
///
/// Only a dangling entry is rewritten. One that names another binary that still exists, say
/// an installed copy while a development build runs, is left alone and Settings reports it
/// instead: whichever copy happened to launch last should not quietly take over the login.
pub fn repair() -> Result<bool> {
    let exe = this_binary()?;
    match classify(imp::read()?, &exe) {
        State::Stale { was } if !was.exists() => {
            imp::write(&exe)?;
            tracing::info!(was = %was.display(), now = %exe.display(), "moved the autostart entry");
            Ok(true)
        }
        State::Stale { was } => {
            tracing::info!(
                recorded = %was.display(),
                this = %exe.display(),
                "the autostart entry starts another copy of this app, leaving it"
            );
            Ok(false)
        }
        _ => Ok(false),
    }
}

/// Turn the entry on the first time a released build runs here, which is what makes this
/// opt-out rather than opt-in.
///
/// Once only, and the marker is written before the entry: if anything fails in between, the
/// box shows off and can be ticked, which beats turning back on someone who turned it off.
/// An entry that is already there, even one naming another copy, is left as it is.
pub fn default_on(paths: &Paths) -> Result<()> {
    if !SUPPORTED || !released() || !first_time(&paths.root.join(DEFAULTED_FILENAME))? {
        return Ok(());
    }

    if state()? == State::Off {
        enable()?;
        tracing::info!("starting with the session from now on, which is the default");
    }
    Ok(())
}

/// A build CI stamped with a release version. Everything else, `cargo run` included, is
/// still 0.0.0, and running one of those once should not make it start at every login.
fn released() -> bool {
    env!("CARGO_PKG_VERSION") != "0.0.0"
}

/// Leave the marker, and say whether this call is the one that did.
fn first_time(marker: &Path) -> Result<bool> {
    match std::fs::File::create_new(marker) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e).with_context(|| format!("creating {}", marker.display())),
    }
}

/// The path the entry should name for this process.
fn this_binary() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("finding this binary")?;
    Ok(launched_from(std::env::var_os(APPIMAGE), exe))
}

/// Inside an AppImage, `current_exe` is under a mount that goes away when the app exits, so
/// an entry naming it would be dead by the next login. The image itself is what to start.
fn launched_from(appimage: Option<OsString>, exe: PathBuf) -> PathBuf {
    match appimage {
        Some(image) if !image.is_empty() => PathBuf::from(image),
        _ => exe,
    }
}

fn classify(recorded: Option<PathBuf>, exe: &Path) -> State {
    match recorded {
        None => State::Off,
        Some(recorded) if same_target(&recorded, exe) => State::On,
        Some(was) => State::Stale { was },
    }
}

fn same_target(recorded: &Path, exe: &Path) -> bool {
    match (recorded.canonicalize(), exe.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => recorded == exe,
    }
}

fn command(exe: &Path) -> String {
    format!("\"{}\" --{BACKGROUND}", exe.display())
}

/// Take the path back out of something [`command`] produced.
fn recorded_path(value: &str) -> &str {
    let value = value.trim();

    if let Some(rest) = value.strip_prefix('"') {
        return rest.split('"').next().unwrap_or(rest);
    }

    value.split_whitespace().next().unwrap_or(value)
}

#[cfg(target_os = "linux")]
mod imp {
    use super::{ENTRY, Result, command};
    use anyhow::{Context, anyhow};
    use std::path::PathBuf;

    pub const SUPPORTED: bool = true;

    fn path() -> Result<PathBuf> {
        let dirs = directories::BaseDirs::new()
            .ok_or_else(|| anyhow!("could not find this user's config directory"))?;
        Ok(dirs
            .config_dir()
            .join("autostart")
            .join(format!("{ENTRY}.desktop")))
    }

    pub fn read() -> Result<Option<PathBuf>> {
        super::linux::read_at(&path()?)
    }

    pub fn write(exe: &std::path::Path) -> Result<()> {
        let path = path()?;
        let dir = path
            .parent()
            .ok_or_else(|| anyhow!("{} has no parent", path.display()))?;
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        std::fs::write(&path, super::linux::entry(&command(exe)))
            .with_context(|| format!("writing {}", path.display()))
    }

    pub fn clear() -> Result<()> {
        let path = path()?;
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::path::{Path, PathBuf};

    use anyhow::{Context, Result};

    pub fn entry(exec: &str) -> String {
        format!(
            "[Desktop Entry]\n\
             Type=Application\n\
             Name=ArchiverClient\n\
             Comment=Keeps your groups in sync in the background\n\
             Exec={exec}\n\
             Terminal=false\n\
             X-GNOME-Autostart-enabled=true\n"
        )
    }

    /// The path an entry names, or `None` if there is no entry.
    pub fn read_at(path: &Path) -> Result<Option<PathBuf>> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };

        Ok(text
            .lines()
            .find_map(|line| line.strip_prefix("Exec="))
            .map(|exec| PathBuf::from(super::recorded_path(exec))))
    }
}

#[cfg(target_os = "windows")]
mod imp {
    use super::{ENTRY, Result, command, recorded_path};
    use anyhow::Context;
    use std::path::{Path, PathBuf};

    pub const SUPPORTED: bool = true;

    /// Where Windows looks for things to start when this user logs in.
    const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

    /// `HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)`, which is how `windows-registry` says there
    /// is no such value. Anything else is a real failure, and has to be said as one.
    const NOT_FOUND: i32 = 0x8007_0002_u32 as i32;

    /// Per-user, deliberately: the app writes this itself and an installer must not, so that
    /// the toggle in the UI is the only thing that owns it.
    fn key() -> Result<windows_registry::Key> {
        windows_registry::CURRENT_USER
            .create(RUN_KEY)
            .with_context(|| format!("opening HKCU\\{RUN_KEY}"))
    }

    pub fn read() -> Result<Option<PathBuf>> {
        match key()?.get_string(ENTRY) {
            Ok(value) => Ok(Some(PathBuf::from(recorded_path(&value)))),
            // Absent is the normal "not enabled" answer, not a failure.
            Err(e) if e.code().0 == NOT_FOUND => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading HKCU\\{RUN_KEY}\\{ENTRY}")),
        }
    }

    pub fn write(exe: &Path) -> Result<()> {
        key()?
            .set_string(ENTRY, command(exe))
            .with_context(|| format!("writing HKCU\\{RUN_KEY}\\{ENTRY}"))
    }

    pub fn clear() -> Result<()> {
        match key()?.remove_value(ENTRY) {
            Err(e) if e.code().0 == NOT_FOUND => Ok(()),
            other => other.with_context(|| format!("removing HKCU\\{RUN_KEY}\\{ENTRY}")),
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod imp {
    use super::Result;
    use std::path::{Path, PathBuf};

    pub const SUPPORTED: bool = false;

    pub fn read() -> Result<Option<PathBuf>> {
        Ok(None)
    }
    pub fn write(_exe: &Path) -> Result<()> {
        anyhow::bail!("starting with the session is not supported on this platform")
    }
    pub fn clear() -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_quoted_path_survives_the_round_trip() {
        // Home directories have spaces in them, so the recorded command is quoted.
        let path = PathBuf::from("/home/a b/ac-desktop");
        assert_eq!(command(&path), "\"/home/a b/ac-desktop\" --background");
        assert_eq!(recorded_path(&command(&path)), "/home/a b/ac-desktop");
    }

    #[test]
    fn the_recorded_command_is_one_this_binary_accepts_and_asks_for_the_tray() {
        // A flag the parser does not know fails every login with no window to say so, and
        // one it knows but is not this starts a window nobody asked for.
        use clap::Parser;

        let line = command(Path::new("/home/a b/ac-desktop"));
        let args = line.rsplit('"').next().unwrap().split_whitespace();
        let cli = crate::Cli::try_parse_from(std::iter::once("ac-desktop").chain(args)).unwrap();
        assert!(cli.background);
    }

    #[test]
    fn the_default_is_applied_once() {
        // Turning it off in Settings only sticks if the run that turned it on is remembered.
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join(DEFAULTED_FILENAME);
        assert!(first_time(&marker).unwrap());
        assert!(!first_time(&marker).unwrap());
    }

    #[test]
    fn the_flag_is_not_mistaken_for_part_of_the_path() {
        // The bug this guards is silent: read the whole line back as the path and it can
        // never equal this binary, so `state()` answers Stale forever and `repair()` rewrites
        // the entry on every single launch.
        let path = PathBuf::from("/opt/archiverclient/ac-desktop");
        let line = command(&path);
        let recorded = recorded_path(&line);

        assert_eq!(recorded, "/opt/archiverclient/ac-desktop");
        assert!(
            same_target(Path::new(recorded), &path),
            "must read as On, not Stale"
        );
    }

    #[test]
    fn an_unquoted_value_is_still_read() {
        // Entries written by hand, or by an older version, should not be mistaken for absent.
        assert_eq!(recorded_path("/usr/bin/ac-desktop"), "/usr/bin/ac-desktop");
        assert_eq!(
            recorded_path("/usr/bin/ac-desktop --background"),
            "/usr/bin/ac-desktop"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn no_entry_reads_as_off() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archiverclient.desktop");
        assert_eq!(linux::read_at(&path).unwrap(), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_entry_names_the_binary_that_wrote_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archiverclient.desktop");
        let exe = PathBuf::from("/opt/archiverclient/ac-desktop");

        std::fs::write(&path, linux::entry(&command(&exe))).unwrap();

        assert_eq!(linux::read_at(&path).unwrap(), Some(exe));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_entry_pointing_elsewhere_is_recognised_as_stale() {
        // What `cargo clean`, or an install that relocated the binary, leaves behind.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archiverclient.desktop");
        std::fs::write(&path, linux::entry("\"/gone/ac-desktop\"")).unwrap();

        let recorded = linux::read_at(&path).unwrap().unwrap();
        assert!(!same_target(&recorded, Path::new("/opt/ac-desktop")));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_entry_says_it_is_an_application_and_wants_no_terminal() {
        // A .desktop file missing either is skipped by some session managers and opens a
        // terminal in others.
        let entry = linux::entry("\"/opt/ac-desktop\"");
        assert!(entry.contains("Type=Application"));
        assert!(entry.contains("Terminal=false"));
        assert!(entry.starts_with("[Desktop Entry]"));
    }

    #[test]
    fn an_appimage_records_the_image_rather_than_its_mount() {
        // The mount under /tmp is gone by the next login; the image is not.
        let mounted = PathBuf::from("/tmp/.mount_ArchivXYZ/usr/bin/ac-desktop");
        assert_eq!(
            launched_from(
                Some("/home/a/Apps/ArchiverClient.AppImage".into()),
                mounted.clone()
            ),
            PathBuf::from("/home/a/Apps/ArchiverClient.AppImage")
        );
        assert_eq!(launched_from(None, mounted.clone()), mounted);
        assert_eq!(
            launched_from(Some(OsString::new()), mounted.clone()),
            mounted,
            "an empty variable is not an image"
        );
    }

    #[test]
    fn the_state_follows_what_is_recorded() {
        let exe = Path::new("/opt/archiverclient/ac-desktop");
        assert_eq!(classify(None, exe), State::Off);
        assert_eq!(classify(Some(exe.to_path_buf()), exe), State::On);
        assert_eq!(
            classify(Some(PathBuf::from("/gone/ac-desktop")), exe),
            State::Stale {
                was: PathBuf::from("/gone/ac-desktop")
            }
        );
    }
}
