use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub struct State {
    pub group: String,
    pub prefix: String,
    pub removed: bool,
}

#[derive(Clone, Default)]
pub struct Selection(Arc<Mutex<State>>);

impl Selection {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self) -> State {
        self.with(|state| state.clone())
    }

    pub fn set_group(&self, group: &str) {
        self.with(|state| group.clone_into(&mut state.group));
    }

    pub fn set_filter(&self, prefix: &str, removed: bool) {
        self.with(|state| {
            prefix.clone_into(&mut state.prefix);
            state.removed = removed;
        });
    }

    fn with<T>(&self, f: impl FnOnce(&mut State) -> T) -> T {
        match self.0.lock() {
            Ok(mut state) => f(&mut state),
            Err(poisoned) => f(&mut poisoned.into_inner()),
        }
    }
}
