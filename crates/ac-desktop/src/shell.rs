use std::path::Path;

use anyhow::{Context, Result};

/// Hand a directory to whatever the desktop opens directories with.
pub fn open(dir: &Path) -> Result<()> {
    anyhow::ensure!(
        dir.exists(),
        "{} does not exist yet, so there is nothing to open",
        dir.display()
    );

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

    /// Spawning succeeds even when the path is nonsense, so the check has to come first or
    /// the window would report having opened something that was never there.
    #[test]
    fn a_folder_that_is_not_there_is_refused_rather_than_reported_as_opened() {
        let e = open(Path::new("/no/such/folder/anywhere")).unwrap_err();
        assert!(
            format!("{e:#}").contains("/no/such/folder/anywhere"),
            "{e:#}"
        );
    }
}
