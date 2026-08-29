use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// The name under which the entry is recorded, on either platform.
pub const ENTRY: &str = "archiverclient";

/// The flag the recorded command carries. A node started with the session belongs in the tray,
/// not in a window nobody asked for.
pub const BACKGROUND: &str = "background";

#[derive(Debug, PartialEq, Eq)]
pub enum State {
    Off,
    On,
    Stale { was: PathBuf },
}

/// Whether this binary starts with the session.
pub fn state() -> Result<State> {
    let exe = std::env::current_exe().context("finding this binary")?;
    Ok(match imp::read()? {
        None => State::Off,
        Some(recorded) if same_target(&recorded, &exe) => State::On,
        Some(was) => State::Stale { was },
    })
}

pub fn enable() -> Result<()> {
    let exe = std::env::current_exe().context("finding this binary")?;
    imp::write(&exe)
}

pub fn disable() -> Result<()> {
    imp::clear()
}

/// Point an existing entry at where this binary now is
pub fn repair() -> Result<bool> {
    match state()? {
        State::Stale { was } => {
            let exe = std::env::current_exe().context("finding this binary")?;
            imp::write(&exe)?;
            tracing::info!(was = %was.display(), now = %exe.display(), "moved the autostart entry");
            Ok(true)
        }
        _ => Ok(false),
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

    /// Where Windows looks for things to start when this user logs in.
    const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

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
            Err(_) => Ok(None),
        }
    }

    pub fn write(exe: &Path) -> Result<()> {
        key()?
            .set_string(ENTRY, command(exe))
            .with_context(|| format!("writing HKCU\\{RUN_KEY}\\{ENTRY}"))
    }

    pub fn clear() -> Result<()> {
        match key()?.remove_value(ENTRY) {
            Ok(()) => Ok(()),
            Err(_) => Ok(()),
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod imp {
    use super::Result;
    use std::path::{Path, PathBuf};

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
    fn the_recorded_command_asks_for_the_tray_rather_than_a_window() {
        // Without this the session opens a window at every login, which is not what a
        // background sync client is for.
        assert!(command(Path::new("/opt/ac-desktop")).ends_with(" --background"));
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
}
