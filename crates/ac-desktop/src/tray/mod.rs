pub mod icon;

#[cfg_attr(target_os = "linux", path = "linux.rs")]
#[cfg_attr(target_os = "windows", path = "windows.rs")]
#[cfg_attr(
    not(any(target_os = "linux", target_os = "windows")),
    path = "unsupported.rs"
)]
mod backend;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use slint::{ComponentHandle, Weak};

use crate::ui::MainWindow;

pub use backend::Tray;

/// Whether the tray can bring the window back *right now*.
#[derive(Clone)]
pub struct Live(Arc<AtomicBool>);

impl Live {
    pub(crate) fn new(live: bool) -> Self {
        Self(Arc::new(AtomicBool::new(live)))
    }

    pub(crate) fn set(&self, live: bool) {
        self.0.store(live, Ordering::Relaxed);
    }

    pub fn get(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// Put an icon in the tray.
pub fn spawn(window: Weak<MainWindow>) -> Option<Tray> {
    match backend::spawn(window) {
        Ok(tray) => Some(tray),
        Err(e) => {
            tracing::warn!(
                error = format!("{e:#}"),
                "no tray icon; the window is the only way to reach this app"
            );
            None
        }
    }
}

/// Bring the window back, from whichever thread the tray menu runs on.
pub(crate) fn show(window: &Weak<MainWindow>) {
    let window = window.clone();
    let posted = slint::invoke_from_event_loop(move || {
        if let Some(window) = window.upgrade() {
            let _ = window.show();
            window.window().set_minimized(false);
        }
    });
    if let Err(e) = posted {
        tracing::warn!(error = %e, "could not reach the window");
    }
}

pub(crate) fn set_autostart(wanted: bool) {
    let result = if wanted {
        crate::autostart::enable()
    } else {
        crate::autostart::disable()
    };
    if let Err(e) = result {
        tracing::warn!(error = %e, wanted, "could not change whether this starts at login");
    }
}

pub(crate) fn quit() {
    if let Err(e) = slint::invoke_from_event_loop(|| {
        if let Err(e) = slint::quit_event_loop() {
            tracing::warn!(error = %e, "could not stop the event loop");
        }
    }) {
        tracing::warn!(error = %e, "could not reach the event loop to stop it");
    }
}
