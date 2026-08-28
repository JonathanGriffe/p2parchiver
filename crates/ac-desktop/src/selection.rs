//! Which group the window is looking at.
//!
//! The poller reads on its own thread and so cannot ask the window what is selected; the
//! window changes the selection on the event loop and cannot wait for the poller. One small
//! shared string is the whole conversation between them.

use std::sync::{Arc, Mutex};

/// Empty means nothing is selected, which is the state the app starts in.
#[derive(Clone, Default)]
pub struct Selection(Arc<Mutex<String>>);

impl Selection {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self) -> String {
        // A poisoned lock would mean a panic while holding a `String`, which cannot leave it
        // in a state worth refusing to read.
        match self.0.lock() {
            Ok(current) => current.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    pub fn set(&self, value: &str) {
        match self.0.lock() {
            Ok(mut current) => value.clone_into(&mut current),
            Err(poisoned) => value.clone_into(&mut poisoned.into_inner()),
        }
    }
}
