use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::time::Duration;

use ac_net::config::Paths;
use slint::Weak;

use crate::selection::Selection;
use crate::ui::MainWindow;
use crate::view;

/// The daemon republishes its snapshot every 5s, so reading faster than this buys nothing.
const POLL: Duration = Duration::from_secs(2);

/// Asks the poller to read now rather than at the next tick, so what an action did shows up
/// at once instead of up to [`POLL`] later.
#[derive(Clone)]
pub struct Nudge(Sender<()>);

impl Nudge {
    pub fn now(&self) {
        // A closed channel means the poller has already stopped, which is not a failure.
        let _ = self.0.send(());
    }
}

pub fn poll(window: Weak<MainWindow>, paths: Paths, selection: Selection) -> Nudge {
    let (tx, rx) = channel();
    std::thread::spawn(move || run(&window, &paths, &selection, &rx));
    Nudge(tx)
}

fn run(window: &Weak<MainWindow>, paths: &Paths, selection: &Selection, rx: &Receiver<()>) {
    loop {
        let snapshot = view::read(paths, selection);

        if window
            .upgrade_in_event_loop(move |window| view::apply(&window, snapshot))
            .is_err()
        {
            return;
        }

        match rx.recv_timeout(POLL) {
            Ok(()) => {
                // Several actions can finish while one read is in flight. Take the whole
                // backlog, so they cost one extra read between them rather than one each.
                while rx.try_recv().is_ok() {}
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

/// Do one thing the user asked for, off the event loop, and report the outcome back on it.
///
/// `done` is handed whatever `work` returned, error included: every action has to say
/// something about a failure, because one that silently does nothing is the worst option.
pub fn action<T, F, G>(window: &Weak<MainWindow>, work: F, done: G)
where
    T: Send + 'static,
    F: FnOnce() -> anyhow::Result<T> + Send + 'static,
    G: FnOnce(&MainWindow, anyhow::Result<T>) + Send + 'static,
{
    let window = window.clone();
    std::thread::spawn(move || {
        let outcome = work();
        let _ = window.upgrade_in_event_loop(move |window| done(&window, outcome));
    });
}
