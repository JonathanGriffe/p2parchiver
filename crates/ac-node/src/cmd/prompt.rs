//! Printing the code a wait puts on screen, for a terminal that has nothing else to show it.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::ops;

/// Watch for a wait raising something to look at, and print it when it does.
///
/// A thread because the wait owns the calling one until somebody acts on what it shows.
pub(crate) fn watch_for_a_code(waiting: Option<&'static str>) -> Watching {
    let stop = Arc::new(AtomicBool::new(false));
    let watcher = std::thread::spawn({
        let stop = Arc::clone(&stop);
        move || {
            let mut shown = false;
            while !stop.load(Ordering::Relaxed) {
                if !shown && let Some(qr) = ops::prompt::showing() {
                    println!("\n{}", as_blocks(&qr));
                    if let Some(waiting) = waiting {
                        println!("{waiting}\n");
                    }
                    shown = true;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    });
    Watching { stop, watcher }
}

pub(crate) struct Watching {
    stop: Arc<AtomicBool>,
    watcher: JoinHandle<()>,
}

impl Watching {
    pub(crate) fn stop(self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.watcher.join();
    }
}

/// A QR as text. Two characters per cell, because a terminal cell is about half as wide as it
/// is tall and a squashed code will not scan.
fn as_blocks(qr: &ops::prompt::Qr) -> String {
    const QUIET: usize = 2;

    let mut out = String::new();
    for _ in 0..QUIET {
        out.push_str(&"  ".repeat(qr.size + QUIET * 2));
        out.push('\n');
    }
    for row in 0..qr.size {
        out.push_str(&"  ".repeat(QUIET));
        for column in 0..qr.size {
            // Dark cells as spaces on a light field: a terminal's own background is not
            // reliably white, so the light half is drawn rather than left to it.
            out.push_str(if qr.at(row, column) { "  " } else { "██" });
        }
        out.push_str(&"  ".repeat(QUIET));
        out.push('\n');
    }
    for _ in 0..QUIET {
        out.push_str(&"  ".repeat(qr.size + QUIET * 2));
        out.push('\n');
    }
    out
}
