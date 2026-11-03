//! What a wait for a person puts in front of them, a sign-in or a companion code, and how to
//! give up on it.

use std::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Qr {
    pub size: usize,
    pub dark: Vec<bool>,
}

impl Qr {
    pub fn at(&self, row: usize, column: usize) -> bool {
        self.dark.get(row * self.size + column).copied() == Some(true)
    }
}

/// What a sign-in currently wants a person to look at, if one is waiting.
static SHOWING: Mutex<Option<Qr>> = Mutex::new(None);

pub fn showing() -> Option<Qr> {
    SHOWING.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// How to give up on the sign-in that is waiting, left here by the sign-in itself.
static STOP: Mutex<Option<fn()>> = Mutex::new(None);

/// Give up on whatever sign-in is waiting, if it left a way to.
///
/// A sign-in blocks a thread until somebody acts, and somebody may instead close the window
/// it was asking through. Without this, the button that started it would stay disabled until
/// the wait gave up on its own — minutes later, for no reason a person could see.
///
/// Nothing waiting, or a sign-in that cannot be interrupted, is a no-op: this is called from
/// a window closing, which is not a place to be refusing things.
pub fn stop() {
    let hook = *STOP.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(stop) = hook {
        stop();
    }
}

/// Say how to be given up on, around a wait. `None` takes it back.
pub fn stoppable(with: Option<fn()>) {
    *STOP.lock().unwrap_or_else(|e| e.into_inner()) = with;
}

/// Put something up, or take it down, around a wait.
pub fn show(qr: Option<Qr>) {
    *SHOWING.lock().unwrap_or_else(|e| e.into_inner()) = qr;
}
