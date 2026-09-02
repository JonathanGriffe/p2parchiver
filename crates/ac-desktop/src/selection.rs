use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub struct State {
    pub group: String,
    pub prefix: String,
    pub removed: bool,
    pub sorting: Sorting,
}

/// Where the Sort tab has got to
#[derive(Clone, Default)]
pub struct Sorting {
    pub trail: Vec<(i64, String)>,
    pub group: String,
}

impl Sorting {
    pub fn at(&self) -> Option<(i64, &str)> {
        self.trail.last().map(|(at, hash)| (*at, hash.as_str()))
    }
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

    /// Step to the next file, remembering the one being left so `back` can return to it.
    pub fn forward(&self, from: (i64, String)) {
        self.with(|state| state.sorting.trail.push(from));
    }

    pub fn back(&self) {
        self.with(|state| {
            state.sorting.trail.pop();
        });
    }

    /// Start again at the oldest
    pub fn rewind(&self) {
        self.with(|state| state.sorting.trail.clear());
    }

    pub fn set_sort_group(&self, group: &str) {
        self.with(|state| group.clone_into(&mut state.sorting.group));
    }

    fn with<T>(&self, f: impl FnOnce(&mut State) -> T) -> T {
        match self.0.lock() {
            Ok(mut state) => f(&mut state),
            Err(poisoned) => f(&mut poisoned.into_inner()),
        }
    }
}
