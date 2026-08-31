use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
pub struct Nudge {
    tx: Sender<()>,
    visible: Arc<AtomicBool>,
}

impl Nudge {
    pub fn now(&self) {
        // A closed channel means the poller has already stopped, which is not a failure.
        let _ = self.tx.send(());
    }

    /// The window is back. Wakes the poller, which has been waiting for exactly this.
    pub fn shown(&self) {
        self.visible.store(true, Ordering::Relaxed);
        self.now();
    }

    /// The window is gone to the tray. Nothing reads until it comes back.
    pub fn hidden(&self) {
        self.visible.store(false, Ordering::Relaxed);
    }
}

/// The handle the window holds, and the channel the poller waits on.
pub fn nudge() -> (Nudge, Receiver<()>) {
    let (tx, rx) = channel();
    let nudge = Nudge {
        tx,
        visible: Arc::new(AtomicBool::new(true)),
    };
    (nudge, rx)
}

pub fn poll(
    window: Weak<MainWindow>,
    paths: Paths,
    selection: Selection,
    nudge: &Nudge,
    rx: Receiver<()>,
) {
    let visible = Arc::clone(&nudge.visible);
    std::thread::spawn(move || polling(&window, &paths, &selection, &visible, &rx));
}

fn polling(
    window: &Weak<MainWindow>,
    paths: &Paths,
    selection: &Selection,
    visible: &AtomicBool,
    rx: &Receiver<()>,
) {
    loop {
        if visible.load(Ordering::Relaxed) {
            let snapshot = view::read(paths, selection);

            if window
                .upgrade_in_event_loop(move |window| view::apply(&window, snapshot))
                .is_err()
            {
                return;
            }
        }

        let waited = if visible.load(Ordering::Relaxed) {
            rx.recv_timeout(POLL)
        } else {
            rx.recv().map_err(|_| RecvTimeoutError::Disconnected)
        };

        match waited {
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

/// Shut the window's buttons while an action is in flight, and clear what was last said.
pub fn begin(weak: &Weak<MainWindow>) {
    if let Some(window) = weak.upgrade() {
        window.set_busy(true);
        window.set_message("".into());
    }
}

/// The whole of what a page button does: shut the buttons, run off the event loop, then say
/// what happened and get the change on screen.
pub fn run<F>(weak: &Weak<MainWindow>, nudge: &Nudge, work: F)
where
    F: FnOnce() -> anyhow::Result<String> + Send + 'static,
{
    begin(weak);
    let nudge = nudge.clone();
    action(weak, work, move |window, outcome| {
        finish(window, outcome, &nudge)
    });
}

/// Let the buttons go without saying anything, for an action that reports its own outcome
/// somewhere the shared line would only duplicate.
pub fn quiet(window: &MainWindow, nudge: &Nudge) {
    window.set_busy(false);
    window.set_message("".into());
    nudge.now();
}

/// Say what an action did, let the buttons go, and get the change on screen at once.
pub fn finish(window: &MainWindow, outcome: anyhow::Result<String>, nudge: &Nudge) {
    window.set_busy(false);
    match outcome {
        Ok(said) => {
            window.set_message(said.into());
            window.set_message_bad(false);
        }
        Err(e) => {
            // `{:#}` so the reason comes through, not just the outermost context.
            window.set_message(format!("{e:#}").into());
            window.set_message_bad(true);
        }
    }
    nudge.now();
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
