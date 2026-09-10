use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub struct State {
    /// Which page is up. The poller reads only what that page needs, so this has to be
    /// somewhere a thread other than the window's can see it.
    pub tab: i32,
    pub group: String,
    pub prefix: String,
    pub removed: bool,
    pub sorting: Sorting,
}

/// Where the Sort tab has got to
#[derive(Clone, Default)]
pub struct Sorting {
    /// Behind an `Arc` because [`Selection::get`] clones the whole state on every poll and
    /// on every step, and this grows by one hash for every file stepped past.
    pub trail: Arc<Vec<(i64, String)>>,
    pub group: String,
    /// What has been done that can still be taken back, oldest first. Session-only: a
    /// decision survives a restart, and taking it back does not.
    pub undo: Vec<Undoable>,
    /// A folder within that group to file into. Empty for its root, which is not a folder
    /// but the absence of one. A name typed into "Add folder" lives here until a file is
    /// filed under it, because until then it exists nowhere else.
    pub destination: String,
}

/// How many decisions can be taken back. Small on purpose: undo here is for the click you
/// did not mean, not a history of the afternoon.
pub const UNDO_DEPTH: usize = 5;

/// One thing done, kept so it can be undone. Only what is needed to reverse it: the files
/// themselves are found by hash.
///
/// A whole folder thrown away is one of these and not forty, because it was one press and the
/// button that takes it back is one press too.
#[derive(Clone, PartialEq, Eq)]
pub struct Undoable {
    pub hashes: Vec<String>,
    pub name: String,
    /// True when it was thrown away rather than filed. What tells the message which it was,
    /// and what says whether bytes are still waiting to be deleted.
    pub dropped: bool,
}

impl Undoable {
    /// Whether this was a bulk action, which is what decides how much of the stack it takes.
    fn bulk(&self) -> bool {
        self.hashes.len() > 1
    }
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
        self.with(|state| Arc::make_mut(&mut state.sorting.trail).push(from));
    }

    pub fn back(&self) {
        self.with(|state| {
            Arc::make_mut(&mut state.sorting.trail).pop();
        });
    }

    /// Start again at the oldest
    pub fn rewind(&self) {
        self.with(|state| Arc::make_mut(&mut state.sorting.trail).clear());
    }

    pub fn set_sort_group(&self, group: &str) {
        self.with(|state| {
            group.clone_into(&mut state.sorting.group);
            // A folder belongs to the group it is in, so changing group forgets it.
            state.sorting.destination.clear();
        });
    }

    pub fn set_tab(&self, tab: i32) {
        self.with(|state| state.tab = tab);
    }

    pub fn set_sort_destination(&self, folder: &str) {
        self.with(|state| folder.clone_into(&mut state.sorting.destination));
    }

    /// Remember one, and hand back whatever it pushed off — which the caller has to finish
    /// with, because nothing can take those back any more.
    ///
    /// A bulk action arrives on an empty stack: it holds the bytes of a whole folder, and
    /// five of those waiting on a decision nobody is going to make is a great deal of disk.
    /// It reads right, too — the big destructive thing is the one you can take back, until
    /// you do something else.
    pub fn did(&self, action: Undoable) -> Vec<Undoable> {
        self.with(|state| {
            let mut fell_off = match action.bulk() {
                true => std::mem::take(&mut state.sorting.undo),
                false => Vec::new(),
            };

            state.sorting.undo.push(action);
            if state.sorting.undo.len() > UNDO_DEPTH {
                fell_off.push(state.sorting.undo.remove(0));
            }
            fell_off
        })
    }

    /// The most recent one, taken off the stack.
    pub fn take_back(&self) -> Option<Undoable> {
        self.with(|state| state.sorting.undo.pop())
    }

    fn with<T>(&self, f: impl FnOnce(&mut State) -> T) -> T {
        match self.0.lock() {
            Ok(mut state) => f(&mut state),
            Err(poisoned) => f(&mut poisoned.into_inner()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn done(name: &str) -> Undoable {
        Undoable {
            hashes: vec![name.to_owned()],
            name: name.to_owned(),
            dropped: true,
        }
    }

    /// A whole folder in one action, which is what a bulk delete leaves behind.
    fn done_all(names: &[&str]) -> Undoable {
        Undoable {
            hashes: names.iter().map(|name| (*name).to_owned()).collect(),
            name: "a folder".to_owned(),
            dropped: true,
        }
    }

    fn only(fell: &[Undoable]) -> &str {
        assert_eq!(fell.len(), 1, "one action fell off");
        assert_eq!(fell[0].hashes.len(), 1);
        &fell[0].hashes[0]
    }

    #[test]
    fn the_stack_holds_five_and_hands_back_what_falls_off() {
        let selection = Selection::new();

        for at in 0..UNDO_DEPTH {
            assert!(
                selection.did(done(&format!("{at}"))).is_empty(),
                "nothing falls off until it is full"
            );
        }

        // The sixth pushes the first out, and the caller is handed it: nothing can take
        // that one back any more, so its bytes may go.
        let fell = selection.did(done("5"));
        assert_eq!(only(&fell), "0");
        assert_eq!(selection.get().sorting.undo.len(), UNDO_DEPTH);

        // Taken back newest first.
        let taken = |u: Undoable| u.hashes;
        assert_eq!(selection.take_back().map(taken), Some(vec!["5".to_owned()]));
        assert_eq!(selection.take_back().map(taken), Some(vec!["4".to_owned()]));
        for _ in 0..3 {
            assert!(selection.take_back().is_some());
        }
        assert!(selection.take_back().is_none(), "and then there are none");
    }

    /// A folder is one action however many files it held, and it arrives on an empty stack:
    /// five folders' worth of bytes waiting on a decision nobody will make is a great deal
    /// of disk, and everything before it is handed back to be finished with.
    #[test]
    fn a_bulk_action_is_one_entry_and_takes_the_stack() {
        let selection = Selection::new();

        selection.did(done("a"));
        selection.did(done("b"));

        let fell = selection.did(done_all(&["c", "d", "e"]));
        assert_eq!(
            fell.iter().flat_map(|action| &action.hashes).count(),
            2,
            "both of the singles came back to be finished with"
        );
        assert_eq!(selection.get().sorting.undo.len(), 1, "and only it is left");

        // One press took forty away, so one press brings them back.
        let back = selection.take_back().expect("the folder is undoable");
        assert_eq!(back.hashes, ["c", "d", "e"]);
        assert!(selection.take_back().is_none());
    }
}
