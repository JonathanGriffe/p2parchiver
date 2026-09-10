use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::time::Duration;

use ac_net::config::Paths;
use slint::{ComponentHandle, Weak};

use crate::selection::Selection;
use crate::ui::MainWindow;
use crate::view;

/// The daemon republishes its snapshot every 5s, so reading faster than this buys nothing.
const POLL: Duration = Duration::from_secs(2);

/// How long a result stays on screen. Long enough to read a count off, short enough that it
/// is gone before it can be mistaken for something the next action did.
const SAID_FOR: Duration = Duration::from_secs(5);

thread_local! {
    /// Which line the running timer belongs to. Everything here happens on the event loop's
    /// thread, and the count is what stops a finished action's timer wiping the next one's
    /// line: a timer clears only what it was armed for.
    static SHOWING: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Claim the line, and say which claim this is.
fn claim() -> u64 {
    SHOWING.with(|showing| {
        let next = showing.get().wrapping_add(1);
        showing.set(next);
        next
    })
}

/// Take the line away, whoever put it there.
pub fn clear(window: &MainWindow) {
    claim();
    window.set_message("".into());
    window.set_message_bad(false);
}

/// Put a line up and take it down again after [`SAID_FOR`].
fn say(window: &MainWindow, text: String, bad: bool) {
    let mine = claim();
    window.set_message(text.as_str().into());
    window.set_message_bad(bad);
    if text.is_empty() {
        return;
    }

    let window = window.as_weak();
    slint::Timer::single_shot(SAID_FOR, move || {
        if SHOWING.with(std::cell::Cell::get) != mine {
            return;
        }
        if let Some(window) = window.upgrade() {
            clear(&window);
        }
    });
}

/// Put a line up and leave it there: what an action in flight is waiting on, which is not a
/// result and goes when the result arrives.
pub fn holding(window: &MainWindow, text: &str) {
    claim();
    window.set_message(text.into());
    window.set_message_bad(false);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window() -> (MainWindow, Nudge) {
        i_slint_backend_testing::init_no_event_loop();
        let (nudge, rx) = nudge();
        // Held for the life of the test: a closed channel makes `Nudge::now` a no-op, which
        // would not fail anything here but would stop testing what the real one does.
        std::mem::forget(rx);
        (MainWindow::new().unwrap(), nudge)
    }

    #[test]
    fn a_result_goes_once_it_has_had_time_to_be_read() {
        let (window, nudge) = window();

        finish(&window, Ok("40 filed".to_owned()), &nudge);
        assert_eq!(window.get_message(), "40 filed");

        i_slint_backend_testing::mock_elapsed_time(SAID_FOR + Duration::from_millis(1));
        assert_eq!(window.get_message(), "", "gone on its own");
    }

    #[test]
    fn the_line_a_later_action_put_up_outlives_the_one_before_it() {
        let (window, nudge) = window();

        finish(&window, Ok("first".to_owned()), &nudge);
        i_slint_backend_testing::mock_elapsed_time(SAID_FOR - Duration::from_secs(1));
        finish(&window, Ok("second".to_owned()), &nudge);

        // Where the first line's timer falls due. It is not this line's timer.
        i_slint_backend_testing::mock_elapsed_time(Duration::from_secs(2));
        assert_eq!(
            window.get_message(),
            "second",
            "the first action's timer cleared the second action's line"
        );

        i_slint_backend_testing::mock_elapsed_time(SAID_FOR);
        assert_eq!(
            window.get_message(),
            "",
            "and this one goes in its own time"
        );
    }

    #[test]
    fn what_an_action_is_waiting_on_stays_until_it_reports() {
        let (window, nudge) = window();

        holding(&window, "finish signing in, in your browser");
        i_slint_backend_testing::mock_elapsed_time(SAID_FOR * 4);
        assert_eq!(
            window.get_message(),
            "finish signing in, in your browser",
            "a sign-in takes as long as it takes"
        );

        finish(&window, Ok(String::new()), &nudge);
        assert_eq!(window.get_message(), "", "and the result replaces it");
    }

    #[test]
    fn a_failure_goes_the_same_way_as_anything_else() {
        let (window, nudge) = window();

        finish(&window, Err(anyhow::anyhow!("no such contact")), &nudge);
        assert!(window.get_message_bad(), "said in red");

        i_slint_backend_testing::mock_elapsed_time(SAID_FOR + Duration::from_millis(1));
        assert_eq!(window.get_message(), "");
        assert!(
            !window.get_message_bad(),
            "and not left red for the next one"
        );
    }
}

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
        clear(&window);
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
    clear(window);
    nudge.now();
}

/// Say what an action did, let the buttons go, and get the change on screen at once.
///
/// **An empty message says nothing, and that is the usual answer for an action that worked.**
/// The line is worth spending on a failure, or on something the screen does not already show
/// — a count nobody could total by looking, a consequence that is not visible, a restart that
/// will be needed. A row vanishing from a table has already said it was removed, and saying
/// so again is a line of furniture that has to be read to be dismissed.
pub fn finish(window: &MainWindow, outcome: anyhow::Result<String>, nudge: &Nudge) {
    window.set_busy(false);
    match outcome {
        Ok(said) => say(window, said, false),
        // `{:#}` so the reason comes through, not just the outermost context.
        Err(e) => say(window, format!("{e:#}"), true),
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
