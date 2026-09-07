use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::mpsc;

use ac_files::Content;
use ac_import::ledger::{Ledger, SCAN_INTERVAL, due};
use ac_import::source::SourceType;
use ac_net::config::{Config, Paths};
use ac_peers::sync::{Limits, Space};

use crate::ops::import::{self, Brought, Outcome, Pace, Scanned, UNSORTED};
use crate::ops::now;
use crate::throttle::Throttle;

/// Downloads in flight, matching what the rest of this node already allows itself.
const FETCH_CONCURRENCY: usize = 8;

/// How many references one worker leases at a time.
///
/// Not how long a worker runs — it runs until the queue is dry — but how much of the queue it
/// holds while it does. A claim is a lease, so whatever one worker takes, the other seven
/// cannot see: take the queue whole and a fifty-photograph import runs on one thread while
/// seven others find nothing and go home. One worker's worth, so eight of them between them
/// hold [`FETCH_CONCURRENCY`] times this and a short queue is still shared out.
const CLAIM: usize = 8;

/// First wait after a failed scan, doubling up to a full cadence.
const MIN_BACKOFF: i64 = 60;
const MAX_BACKOFF: i64 = SCAN_INTERVAL;

/// How long a source that was not there is left alone before it is probed again.
///
/// Being absent is neither a scan nor a failure, so it leaves `scanned_at` where it was and
/// the cadence has nothing to measure from. This is what stands in for it: short enough that
/// a phone which comes home is found while it is still here, long enough that one which is
/// out for the day is not asked about on every tick.
const AWAY_RETRY: i64 = 5 * 60;

/// How long a partial sits untouched before a sweep removes it.
const STAGING_IDLE: Duration = Duration::from_secs(60 * 60);

/// The scanner and the download pump, driven from the daemon's tick.
pub struct ImportLink {
    paths: Paths,
    ledger: Ledger,
    limits: Limits,
    pace: Arc<dyn Pace>,
    /// The one scan running across this node, if any.
    scanning: Option<String>,
    /// Per-source scan backoff. In memory: a restart just scans again.
    backoff: HashMap<String, i64>,
    /// The earliest a source may be tried again, for the ones a scan left no mark on.
    /// In memory beside `backoff`, and for the same reason. See [`ready`].
    retry_at: HashMap<String, i64>,
    running: usize,
    /// Set when a claim came back empty, so an idle node probes once a tick rather than
    /// eight times.
    idle: bool,
    /// Whether the last check said there was no room, so it is said once rather than
    /// every five seconds.
    full: bool,
    /// Told to the workers when they are to stop taking new files: the disk filled, or the
    /// node is going down. Read between one file and the next, never during one, so a
    /// download already under way is finished rather than abandoned.
    ///
    /// A worker holds a blocking thread, and a blocking thread cannot be cancelled — the
    /// runtime waits for every one of them on the way out. Without this, a worker part-way
    /// through a long queue would hold up the whole shutdown.
    hold: Arc<AtomicBool>,
    space: Option<Space>,
    done: mpsc::UnboundedSender<Done>,
    inbox: mpsc::UnboundedReceiver<Done>,
}

/// What a spawned scan or fetch reports back.
pub enum Done {
    Scan {
        dir: String,
        name: String,
        outcome: std::result::Result<Scanned, String>,
    },
    /// One file a worker has been through, whatever became of it. Sent as it happens, so a
    /// long run is reported as it goes rather than in a heap at the end.
    Fetch(Brought),
    /// A worker has ended and given its thread back. `brought` is nought when it found
    /// nothing waiting, which is what tells an idle node to send one worker looking next
    /// time rather than eight.
    RunEnded { brought: u64 },
}

/// The shared inbound budget, taken from a blocking thread.
struct Budget {
    down: Arc<Throttle>,
    handle: tokio::runtime::Handle,
}

impl Pace for Budget {
    fn take(&self, bytes: usize) {
        // Entering the runtime costs more than the accounting does, and an uncapped node
        // has nothing to wait for.
        if !self.down.is_limited() {
            return;
        }
        // A blocking thread, so waiting here holds up nothing but this one fetch.
        self.handle.block_on(self.down.consume(bytes));
    }
}

impl ImportLink {
    pub fn open(paths: &Paths, down: Arc<Throttle>) -> Result<Self> {
        let db = paths.db_file();
        let ledger = Ledger::open(&db)
            .with_context(|| format!("opening the import ledger at {}", db.display()))?;

        let config = Config::load(&paths.config_file())
            .with_context(|| format!("reading the config at {}", paths.config_file().display()))?;
        let content = Content::new(config.storage_root(paths));
        sweep_staging(&content);

        // Taking a deletion back lasts as long as the session that made it, so by the time
        // a node is starting there is nothing left to take back.
        match import::sweep_dropped(paths) {
            Ok(0) => {}
            Ok(gone) => tracing::info!(gone, "finished with files thrown away before"),
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), "could not finish with them")
            }
        }

        import::start_services(paths);

        let (sender, inbox) = mpsc::unbounded_channel();
        Ok(Self {
            paths: paths.clone(),
            ledger,
            limits: Limits {
                storage_max: config.storage_max,
                ..Limits::default()
            },
            pace: Arc::new(Budget {
                down,
                handle: tokio::runtime::Handle::current(),
            }),
            scanning: None,
            backoff: HashMap::new(),
            retry_at: HashMap::new(),
            running: 0,
            idle: false,
            full: false,
            hold: Arc::new(AtomicBool::new(false)),
            space: None,
            done: sender,
            inbox,
        })
    }

    /// Bytes held by files imported and not yet sorted. Content this node is holding, so it
    /// counts against the same budget peer transfers answer to.
    pub fn unsorted_bytes(&self) -> u64 {
        self.ledger.unsorted_bytes().unwrap_or(0)
    }

    /// Start a scan if one is due, and keep the download pool full.
    pub fn housekeeping(&mut self, at: i64, space: Option<Space>) {
        self.space = space;
        self.collect();
        self.start_scan(at);
        self.top_up();

        // A one-shot is done with when its last file has been sorted or thrown away, and
        // that can happen on any tab. Looked for here rather than at each of those places,
        // because the tick is the one thing every route passes through.
        if let Err(error) = import::tidy(&self.paths) {
            tracing::debug!(error = %format!("{error:#}"), "could not tidy finished imports");
        }
    }

    /// Wait for a scan or a fetch to end.
    pub async fn finished(&mut self) -> Option<Done> {
        let done = self.inbox.recv().await?;
        self.settle(&done);
        Some(done)
    }

    /// Act on what a spawned job reported, and start the next one straight away rather
    /// than waiting up to a tick for it.
    ///
    /// Nothing is started when the queue has already come back empty: the probe that says
    /// so would start another probe, and an idle node would spin. Going looking again is
    /// the tick's job.
    pub fn on_done(&mut self, done: Done) {
        self.report(done);
        if !self.idle {
            self.top_up();
        }
    }

    fn collect(&mut self) {
        while let Ok(done) = self.inbox.try_recv() {
            self.settle(&done);
            self.report(done);
        }
    }

    /// The bookkeeping a completion implies, which has to happen however it is drained.
    fn settle(&mut self, done: &Done) {
        match done {
            Done::Scan { dir, outcome, .. } => {
                if self.scanning.as_deref() == Some(dir.as_str()) {
                    self.scanning = None;
                }
                match outcome {
                    // Not there. Not a failure and not a scan either, so nothing else
                    // records it: this is the only thing holding the next probe back.
                    Ok(scanned) if !scanned.reachable => {
                        self.retry_at.insert(dir.clone(), now() + AWAY_RETRY);
                    }
                    Ok(scanned) => {
                        self.backoff.remove(dir);
                        // It answered, so whatever it was waiting out is over.
                        self.retry_at.remove(dir);
                        if scanned.owed > 0 {
                            self.idle = false;
                        }
                    }
                    Err(_) => {
                        let was = self.backoff.get(dir).copied().unwrap_or(0);
                        let next = (was * 2).clamp(MIN_BACKOFF, MAX_BACKOFF);
                        self.backoff.insert(dir.clone(), next);
                        // The backoff only means anything if it is what the next attempt
                        // is actually held back by: see [`ready`].
                        self.retry_at.insert(dir.clone(), now() + next);
                    }
                }
            }
            // A file is not the end of anything: the worker that brought it is still
            // holding its thread and still working through what it claimed.
            Done::Fetch(_) => {}
            Done::RunEnded { brought } => {
                self.running = self.running.saturating_sub(1);
                self.idle = *brought == 0;
            }
        }
    }

    fn report(&mut self, done: Done) {
        match done {
            Done::Scan { name, outcome, .. } => match outcome {
                Ok(scanned) if !scanned.reachable => {
                    tracing::debug!(source = %name, "not reachable right now");
                }
                Ok(scanned) => tracing::info!(
                    source = %name,
                    found = scanned.found,
                    owed = scanned.owed,
                    retired = scanned.retired,
                    "scanned"
                ),
                Err(why) => tracing::warn!(source = %name, %why, "scan failed"),
            },
            Done::Fetch(brought) => match brought.outcome {
                Outcome::Kept { size } => {
                    tracing::info!(source = %brought.source, file = %brought.name, size, "imported")
                }
                Outcome::Failed(why) => {
                    tracing::warn!(source = %brought.source, file = %brought.name, %why, "not imported")
                }
                Outcome::Known | Outcome::Held | Outcome::Gone => {
                    tracing::debug!(source = %brought.source, file = %brought.name, "nothing to bring in")
                }
            },
            Done::RunEnded { brought } => tracing::debug!(brought, "an import worker finished"),
        }
    }

    fn start_scan(&mut self, at: i64) {
        if self.scanning.is_some() {
            return;
        }

        let pollable = match import::pollable(&self.ledger) {
            Ok(pollable) => pollable,
            Err(error) => {
                tracing::warn!(%error, "could not read the configured sources");
                return;
            }
        };
        // Stalest first, so several coming due together go in the order they went stale.
        let Some((row, _)) = pollable.into_iter().find(|(row, kind)| {
            ready(
                *kind,
                row.scanned_at,
                self.backoff.get(&row.dir).copied().unwrap_or(0),
                self.retry_at.get(&row.dir).copied(),
                at,
            )
        }) else {
            return;
        };

        let (paths, done) = (self.paths.clone(), self.done.clone());
        let (dir, name) = (row.dir.clone(), row.name.clone());
        self.scanning = Some(dir.clone());

        tokio::task::spawn_blocking(move || {
            let outcome = import::scan(&paths, &dir).map_err(|e| format!("{e:#}"));
            let _ = done.send(Done::Scan { dir, name, outcome });
        });
    }

    /// Fill the pool back up to [`FETCH_CONCURRENCY`], unless the disk says stop.
    fn top_up(&mut self) {
        if let Some(space) = self.space
            && let Some(why) = self.limits.room(space)
        {
            if !self.full {
                tracing::warn!(?why, "no room for more imports; the queue will wait");
            }
            self.full = true;
            // Not only the ones not started yet: a worker runs until the queue is dry, so
            // without this the disk filling would go unnoticed until it was.
            self.hold.store(true, Ordering::Relaxed);
            return;
        }
        if self.full {
            tracing::info!("there is room again; imports resume");
            self.full = false;
        }
        self.hold.store(false, Ordering::Relaxed);

        // Nothing was owed last time we looked, so one probe answers for all eight.
        let want = match self.idle {
            true => 1,
            false => FETCH_CONCURRENCY,
        };
        while self.running < want {
            self.spawn_fetch();
        }
    }

    fn spawn_fetch(&mut self) {
        let (paths, pace) = (self.paths.clone(), self.pace.clone());
        let (done, hold) = (self.done.clone(), self.hold.clone());
        self.running += 1;

        tokio::task::spawn_blocking(move || {
            let brought = fetch_run(&paths, pace, &hold, &done);
            let _ = done.send(Done::RunEnded { brought });
        });
    }
}

/// Tell the workers to stop, so a node on its way out is not waiting for the queue.
///
/// The runtime waits for every blocking thread it handed out, and a fetch holds one. This
/// runs before that wait — it is the difference between a shutdown that takes one file and
/// one that takes the whole import.
impl Drop for ImportLink {
    fn drop(&mut self) {
        self.hold.store(true, Ordering::Relaxed);
    }
}

/// Whether one source may be scanned now.
///
/// Being due is not enough on its own. `due` measures from `scanned_at`, and only a scan that
/// reached the end moves that — a source that was absent, or that failed, keeps the
/// `scanned_at` it already had and so is due for ever after. It is also the stalest row in
/// the list it is picked from, and one scan runs at a time: left to `due` alone, a phone that
/// is out of the house takes the slot on every tick and nothing behind it is scanned at all.
///
/// `waiting_until` is what holds those two back — an absence for [`AWAY_RETRY`], a failure
/// for its backoff — until they are worth a tick again.
fn ready(
    kind: SourceType,
    scanned_at: i64,
    backoff: i64,
    waiting_until: Option<i64>,
    at: i64,
) -> bool {
    waiting_until.is_none_or(|until| at >= until) && due(kind, scanned_at, backoff, at)
}

/// One worker's whole run, on a blocking thread: everything owed, a batch at a time, until
/// the queue is dry or the node says stop. Answers with how many files it went through.
///
/// The pump is built once and kept for the run, which is the whole point of it. It holds the
/// identity, two database connections and — once it reaches the first file — the opened
/// source, with the sign-in that opening one costs. Built per file instead, as this used to
/// be, every one of those is paid for every photograph, and nothing the pump caches is ever
/// read a second time: it claims one reference, opens one source, and is thrown away.
///
/// Errors are logged rather than returned: a claim that could not be taken is not this
/// tick's problem, and the row it would have taken is still owed.
fn fetch_run(
    paths: &Paths,
    pace: Arc<dyn Pace>,
    hold: &AtomicBool,
    done: &mpsc::UnboundedSender<Done>,
) -> u64 {
    let mut pump = match import::pump(paths, None) {
        Ok(pump) => pump.taking(CLAIM).paced(pace),
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "could not open the import pump");
            return 0;
        }
    };

    let mut brought = 0;
    // Asked between files and never during one, so stopping costs at most the download in
    // hand rather than throwing it away part-written.
    while !hold.load(Ordering::Relaxed) {
        match pump.next() {
            Ok(Some(one)) => {
                brought += 1;
                let _ = done.send(Done::Fetch(one));
            }
            // Nothing more is owed that this worker may take.
            Ok(None) => break,
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), "an import fetch could not run");
                break;
            }
        }
    }

    // Whatever is still claimed goes back, however the run ended: stopped part-way through a
    // batch, the rest of it is owed again rather than waiting out the lease.
    if let Err(error) = pump.finish() {
        tracing::debug!(error = %format!("{error:#}"), "could not give back what was claimed");
    }
    brought
}

/// Drop partials a crash left behind. Nothing is kept: an import fetch always starts at
/// zero, so there is no partial any later attempt could resume into.
fn sweep_staging(content: &Content) {
    match content.sweep_staging(UNSORTED, std::iter::empty(), STAGING_IDLE) {
        Ok(0) => {}
        Ok(swept) => tracing::info!(swept, "removed abandoned import partials"),
        Err(error) => tracing::warn!(%error, "could not sweep the import staging area"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::now;

    /// A fixed moment, so the scheduling arithmetic reads as arithmetic.
    const AT: i64 = 1_000_000;

    fn home() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    /// An import already set up and scanned, as `ac import from` would leave it, with
    /// nothing brought in yet.
    fn owed(home: &tempfile::TempDir, files: &[&str]) -> (Paths, String) {
        let paths = Paths::rooted_at(home.path());
        let album = home.path().join("album");
        for file in files {
            let path = album.join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, file.as_bytes()).unwrap();
        }

        let picked = import::from_folder(&paths, None, &album).unwrap();
        let scanned = import::scan(&paths, &picked.row.dir).unwrap();
        assert_eq!(scanned.owed as usize, files.len(), "nothing to drain");
        (paths, picked.row.dir)
    }

    fn link(paths: &Paths) -> ImportLink {
        ImportLink::open(paths, Arc::new(Throttle::none())).unwrap()
    }

    /// Room on the disk, and no budget in the way.
    fn roomy() -> Option<Space> {
        Some(Space {
            free: 500 * 1024 * 1024 * 1024,
            held: 0,
        })
    }

    /// Tick, then work through everything the tick started, as the daemon's select loop
    /// does between one tick and the next.
    async fn settle(link: &mut ImportLink, space: Option<Space>) {
        link.housekeeping(now(), space);
        while link.running > 0 {
            match link.finished().await {
                Some(done) => link.on_done(done),
                None => break,
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_queue_left_in_the_ledger_is_drained_with_nothing_typed() {
        let home = home();
        let (paths, dir) = owed(&home, &["a.jpg", "DCIM/b.jpg", "DCIM/c.jpg"]);

        // A fresh link, as a relaunch would build: it finds the queue in the database and
        // works through it without listing anything again.
        let mut link = link(&paths);
        settle(&mut link, roomy()).await;

        let ledger = import::ledger(&paths).unwrap();
        assert_eq!(ledger.waiting().unwrap(), 3, "every one of them came in");
        assert_eq!(ledger.owed(&dir).unwrap(), 0);
        assert!(link.scanning.is_none(), "a one-shot source is never due");
        assert!(link.idle, "and it knows there is nothing left");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_full_disk_stops_the_pump_and_a_freed_one_starts_it_again() {
        let home = home();
        let (paths, dir) = owed(&home, &["a.jpg", "b.jpg"]);
        let mut link = link(&paths);

        // Under the free-space floor: nothing is taken, and nothing is lost either.
        let full = Some(Space { free: 0, held: 0 });
        settle(&mut link, full).await;
        assert_eq!(link.running, 0, "no fetch was started");
        assert_eq!(import::ledger(&paths).unwrap().waiting().unwrap(), 0);
        assert_eq!(import::ledger(&paths).unwrap().owed(&dir).unwrap(), 2);

        settle(&mut link, roomy()).await;
        assert_eq!(import::ledger(&paths).unwrap().waiting().unwrap(), 2);
    }

    /// The whole of what the pump is for: a worker keeps it for the run.
    ///
    /// With more owed than there are workers, some worker has to come back having brought in
    /// more than one — and every file after its first is one it did not pay a fresh identity,
    /// two database connections and a source sign-in for. Built per file, as this used to be,
    /// every run brings exactly one and the caches inside the pump are never read twice.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_worker_keeps_its_pump_for_the_whole_run() {
        let home = home();
        let names: Vec<String> = (0..20).map(|n| format!("{n}.jpg")).collect();
        let (paths, dir) = owed(&home, &names.iter().map(String::as_str).collect::<Vec<_>>());

        let mut link = link(&paths);
        let mut runs = Vec::new();
        link.housekeeping(now(), roomy());
        while link.running > 0 {
            let Some(done) = link.finished().await else {
                break;
            };
            if let Done::RunEnded { brought } = &done {
                runs.push(*brought);
            }
            link.on_done(done);
        }

        assert_eq!(
            import::ledger(&paths).unwrap().owed(&dir).unwrap(),
            0,
            "the queue drained"
        );
        assert_eq!(runs.iter().sum::<u64>(), 20, "every file went through once");
        assert!(
            runs.iter().any(|brought| *brought > 1),
            "a pump per file would make every one of these a 1: {runs:?}"
        );
        // The other half of it: a run that keeps its pump must not keep the queue as well.
        // Leasing all twenty would leave the other seven workers nothing to do, and an
        // import small enough to fit in one claim would come in on one thread.
        assert!(
            runs.iter().filter(|brought| **brought > 0).count() > 1,
            "one worker took the lot and the rest went home: {runs:?}"
        );
    }

    /// The disk filling has to reach the workers already running, not only the ones not
    /// started yet: a run lasts until the queue is dry, and a queue can be longer than the
    /// disk it is landing on.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_full_disk_tells_the_workers_already_running_to_stop() {
        let home = home();
        let (paths, _) = owed(&home, &["a.jpg"]);
        let mut link = link(&paths);
        let hold = link.hold.clone();

        link.housekeeping(now(), Some(Space { free: 0, held: 0 }));
        assert!(hold.load(Ordering::Relaxed), "stop where you are");

        settle(&mut link, roomy()).await;
        assert!(!hold.load(Ordering::Relaxed), "and carry on again");
    }

    /// A blocking thread cannot be cancelled and the runtime waits for every one, so a node
    /// on its way out has to ask rather than simply stop listening.
    #[tokio::test(flavor = "multi_thread")]
    async fn dropping_the_link_tells_the_workers_to_stop() {
        let home = home();
        let (paths, _) = owed(&home, &["a.jpg"]);
        let link = link(&paths);
        let hold = link.hold.clone();

        assert!(!hold.load(Ordering::Relaxed));
        drop(link);
        assert!(hold.load(Ordering::Relaxed), "asked on the way out");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn what_is_waiting_to_be_sorted_fills_the_same_disk_peers_answer_to() {
        let home = home();
        let (paths, _) = owed(&home, &["a.jpg", "b.jpg"]);
        let mut link = link(&paths);
        settle(&mut link, roomy()).await;

        let unsorted = link.unsorted_bytes();
        assert!(unsorted > 0, "the import is holding bytes");

        // The number the peer machine is given: unsorted content has no row in `files`, so
        // without this it would be invisible to the budget.
        let identity = crate::ops::identity(&paths).unwrap();
        let files = crate::file_link::FileLink::open(&paths, &identity).unwrap();
        let peers = crate::peer_link::PeerLink::open(
            &paths,
            &identity,
            None,
            now(),
            Arc::new(Throttle::none()),
        )
        .unwrap();

        let space = peers.space(&files, unsorted).unwrap();
        assert_eq!(
            space.held, unsorted,
            "no group holds anything, so this is all of it"
        );

        let tight = Limits {
            storage_max: Some(1),
            ..Limits::default()
        };
        assert!(
            tight.room(space).is_some(),
            "a node filled by imports reports no room"
        );
    }

    /// Nothing in this build is polled yet, so the rule is put to `ready` directly rather
    /// than through a source that could be absent. It is what a `drive` or a `phone` will
    /// meet, and it is the whole of what decides the order.
    ///
    /// `scanned_at` moves only for a scan that reached the end. An absent or failing source
    /// keeps the one it had, so `due` says yes to it for ever — and it is the stalest row in
    /// the list besides. One scan runs at a time, so without a wait of its own it takes the
    /// slot on every tick and nothing behind it is scanned at all.
    #[test]
    fn a_source_still_waiting_is_stepped_over_however_stale_it_looks() {
        // Never scanned, so as due as anything can be.
        let never = 0;
        assert!(ready(SourceType::Remote, never, 0, None, AT));

        // Absent a moment ago. Still due by the cadence, and still not to be asked.
        assert!(!ready(
            SourceType::Remote,
            never,
            0,
            Some(AT + AWAY_RETRY),
            AT
        ));
        // Once the wait is up it is picked again.
        assert!(ready(SourceType::Remote, never, 0, Some(AT), AT));

        // The same for a failure, held back by its backoff — which the cadence cannot do,
        // being anchored on a `scanned_at` that a failed scan does not move.
        assert!(!ready(
            SourceType::Remote,
            never,
            MIN_BACKOFF,
            Some(AT + MIN_BACKOFF),
            AT
        ));

        // And a one-shot is never picked on a cadence, waiting or not.
        assert!(!ready(SourceType::OneShot, never, 0, None, AT));
    }

    /// Driven through `settle` with a made-up report, so the arithmetic can be watched
    /// without a source that actually fails.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_scan_that_fails_waits_longer_each_time_and_a_good_one_forgets_it() {
        let home = home();
        let (paths, _) = owed(&home, &["a.jpg"]);
        let mut link = link(&paths);

        let failed = || Done::Scan {
            dir: "phone".to_owned(),
            name: "Phone".to_owned(),
            outcome: Err("no route to host".to_owned()),
        };

        link.scanning = Some("phone".to_owned());
        link.settle(&failed());
        assert!(link.scanning.is_none(), "the one scan slot is free again");
        assert_eq!(link.backoff.get("phone"), Some(&MIN_BACKOFF));

        link.settle(&failed());
        assert_eq!(link.backoff.get("phone"), Some(&(MIN_BACKOFF * 2)));
        // And the backoff is what the next attempt is actually held back by, rather than a
        // number nothing consults: a failed scan leaves `scanned_at` alone.
        assert!(link.retry_at.contains_key("phone"));

        // `reachable` spelled out: a defaulted `Scanned` is an *absent* one, and what this
        // is about is the scan that reached the end.
        link.settle(&Done::Scan {
            dir: "phone".to_owned(),
            name: "Phone".to_owned(),
            outcome: Ok(Scanned {
                reachable: true,
                ..Scanned::default()
            }),
        });
        assert_eq!(
            link.backoff.get("phone"),
            None,
            "it is due again on cadence"
        );
        assert!(!link.retry_at.contains_key("phone"), "and at once");
    }

    /// Absent is not failed: it earns a wait of its own, but no backoff and no error.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_source_that_was_not_there_waits_without_being_called_broken() {
        let home = home();
        let (paths, _) = owed(&home, &["a.jpg"]);
        let mut link = link(&paths);

        link.settle(&Done::Scan {
            dir: "phone".to_owned(),
            name: "Phone".to_owned(),
            outcome: Ok(Scanned {
                reachable: false,
                ..Scanned::default()
            }),
        });

        assert!(link.retry_at.contains_key("phone"), "it waits its turn");
        assert_eq!(link.backoff.get("phone"), None, "but it has not failed");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_one_shot_source_is_never_picked_for_a_scan() {
        let home = home();
        let (paths, _) = owed(&home, &["a.jpg"]);

        let ledger = import::ledger(&paths).unwrap();
        assert!(
            import::pollable(&ledger).unwrap().is_empty(),
            "the only source in this build runs when asked, never on a cadence"
        );

        let mut link = link(&paths);
        link.housekeeping(now(), roomy());
        assert!(link.scanning.is_none());
    }
}
