//! The code a wait has put on screen, a sign-in or a companion code, and how to give up on it.

pub use ac_import::prompt::Qr;

/// What a wait is asking somebody to look at, if one is up.
pub fn showing() -> Option<Qr> {
    ac_import::prompt::showing()
}

/// Give up on whatever is waiting on somebody, such as when they closed the window it was
/// asking through. Safe to call when nothing is waiting.
pub fn stop() {
    ac_import::prompt::stop();
}
