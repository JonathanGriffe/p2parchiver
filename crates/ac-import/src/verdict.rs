//! What to do with content that has just arrived, once its hash is known.
//!
//! Neither the ledger's question nor a source's: it is the host's, and it is answered by
//! putting the two answers side by side. Its own module so that [`crate::source`] — which
//! every source implementation is written against — has no reason to know what a [`State`]
//! is, and so the rule lives in one place rather than in each caller of it.

use crate::ledger::State;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Keep,
    Imported(State),
    Held,
}

/// Asked once the hash is known, which is the earliest either question can be answered.
pub fn decide(seen: Option<State>, held: bool) -> Verdict {
    match seen {
        Some(state) => Verdict::Imported(state),
        None if held => Verdict::Held,
        None => Verdict::Keep,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_is_imported_twice_and_nothing_deleted_comes_back() {
        assert_eq!(decide(None, false), Verdict::Keep);
        assert_eq!(decide(None, true), Verdict::Held);
        for state in [State::Unsorted, State::Sorted, State::Dropped] {
            assert_eq!(decide(Some(state), false), Verdict::Imported(state));
            // `imported` wins over the group: it is the answer that outlives someone
            // removing the file from the group later.
            assert_eq!(decide(Some(state), true), Verdict::Imported(state));
        }
    }
}
