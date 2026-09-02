//! Bringing the bytes in: the pump, and what one fetch does.

use std::collections::VecDeque;
use std::sync::Arc;

use ac_files::{Content, Files, RelPath};
use ac_import::ledger::{Imported, Ledger, Owed, SourceRow, State};
use ac_import::source::{Digest, Held, Source, SourceError, Verify};
use ac_import::verdict::{Verdict, decide};
use ac_net::config::Paths;
use anyhow::{Context, Result};

use super::sources::open_source;
use super::{HeldHere, UNSORTED, ledger};
use crate::ops::now;

/// How many owed references one claim takes at a time. The pump holds a batch in memory
/// and leases them all at once, so it is a bound on both.
const BATCH: usize = 64;

/// What one run of the pump brought in.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Fetched {
    /// References taken off the queue, whatever became of them.
    pub tried: u64,
    /// New files, now waiting to be sorted.
    pub kept: u64,
    pub bytes: u64,
    /// Bytes this node had already imported, under this source or another.
    pub known: u64,
    /// Bytes a group already holds.
    pub held: u64,
    /// References the source answered for by saying they are no longer there.
    pub gone: u64,
    /// One line per file that did not come in. Each stays owed until its attempts run out.
    pub failed: Vec<String>,
}

impl Fetched {
    /// Fold one file's outcome into the totals, so a caller working the pump itself reports
    /// the same numbers [`drain`] does.
    pub fn count(&mut self, brought: &Brought) {
        self.tried += 1;
        match &brought.outcome {
            Outcome::Kept { size } => {
                self.kept += 1;
                self.bytes += size;
            }
            Outcome::Known => self.known += 1,
            Outcome::Held => self.held += 1,
            Outcome::Gone => self.gone += 1,
            Outcome::Failed(why) => self.failed.push(format!("{}: {why}", brought.name)),
        }
    }
}

/// One file the pump worked through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Brought {
    /// The source it was offered by, as the Sources list names it.
    pub source: String,
    /// The file, under the name the source offered it.
    pub name: String,
    pub outcome: Outcome,
}

/// What became of one file, once the bytes were here to decide on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// New, and now waiting to be sorted.
    Kept { size: u64 },
    /// Content this node had already imported, under this source or another.
    Known,
    /// Content a group already holds.
    Held,
    /// The source no longer has it. Nothing is owed for it any more.
    Gone,
    /// It stays owed, and is tried again until its attempts run out.
    Failed(String),
}

/// Work through what is owed: at most `limit` files, or everything if it is `None`.
pub fn drain(paths: &Paths, limit: Option<usize>) -> Result<Fetched> {
    let mut pump = pump(paths, limit)?;
    let mut out = Fetched::default();
    while let Some(brought) = pump.next()? {
        out.count(&brought);
    }
    pump.finish()?;
    Ok(out)
}

/// Open the pump
pub fn pump(paths: &Paths, limit: Option<usize>) -> Result<Pump> {
    let identity = crate::ops::identity(paths)?;
    let (files, content) = crate::ops::open_files(paths, &identity)?;

    Ok(Pump {
        files,
        content,
        ledger: ledger(paths)?,
        left: limit,
        queue: VecDeque::new(),
        open: None,
        put_back: Vec::new(),
        pace: None,
    })
}

/// A download budget an import answers to, so the daemon can hold imports and peer
/// transfers to one allowance. Called with what is about to be written, and blocks.
pub trait Pace: Send + Sync {
    fn take(&self, bytes: usize);
}

/// The bytes on their way to the sink, held to whatever budget the caller set.
struct Paced<'a> {
    pace: Option<&'a dyn Pace>,
    into: &'a mut dyn std::io::Write,
}

impl std::io::Write for Paced<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Paid for before it moves, as a peer transfer pays before its own write.
        if let Some(pace) = self.pace {
            pace.take(buf.len());
        }
        self.into.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.into.flush()
    }
}

/// A run of the pump: the handles it needs, and the claim it is working through.
pub struct Pump {
    files: Files,
    content: Content,
    ledger: Ledger,
    /// How many more references may be claimed, or every one of them.
    left: Option<usize>,
    /// The claim in hand, in source order so each source is opened once.
    queue: VecDeque<Owed>,
    /// The source the front of the queue belongs to, opened once for the run of it.
    open: Option<(SourceRow, Box<dyn Source>)>,
    /// Attempts spent on nothing, given back when the run ends.
    put_back: Vec<(String, String)>,
    /// The download budget, when there is one to answer to.
    pace: Option<Arc<dyn Pace>>,
}

impl Pump {
    /// Hold this run to a download budget.
    pub fn paced(mut self, pace: Arc<dyn Pace>) -> Self {
        self.pace = Some(pace);
        self
    }

    /// The next file, or `None` once nothing more is owed. Claims another batch when the
    /// one in hand runs out.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Brought>> {
        loop {
            if self.queue.is_empty() && !self.refill()? {
                return Ok(None);
            }
            let Some(owed) = self.queue.pop_front() else {
                continue;
            };

            if !self
                .open
                .as_ref()
                .is_some_and(|(row, _)| row.dir == owed.source_dir)
            {
                self.open = None;
                // A queue outlives the source it was written for: the row can be gone.
                let Some(row) = self.ledger.source(&owed.source_dir)? else {
                    self.spare(&owed);
                    continue;
                };
                match open_source(&self.ledger, &row) {
                    Ok(source) => self.open = Some((row, source)),
                    Err(e) => {
                        // The whole chain: the outermost context alone is "opening
                        // Pictures", which says nothing about what is wrong with it.
                        let why = format!("{e:#}");
                        self.spare(&owed);
                        self.ledger.failed(&row.dir, &why)?;
                        return Ok(Some(Brought {
                            source: row.name,
                            name: owed.name,
                            outcome: Outcome::Failed(why),
                        }));
                    }
                }
            }

            let Some((row, source)) = self.open.as_ref() else {
                continue;
            };
            return Ok(Some(fetch_one(
                self.pace.as_deref(),
                &self.ledger,
                &HeldHere(&self.files),
                &self.content,
                row,
                source.as_ref(),
                &owed,
            )?));
        }
    }

    /// Take the next claim. False when nothing more is owed, or the limit is reached.
    fn refill(&mut self) -> Result<bool> {
        let room = match self.left {
            Some(0) => return Ok(false),
            Some(left) => left.min(BATCH),
            None => BATCH,
        };

        let mut taken = self
            .ledger
            .claim(now(), room)
            .context("taking what is owed")?;
        if taken.is_empty() {
            return Ok(false);
        }
        if let Some(left) = &mut self.left {
            *left -= taken.len();
        }
        // In source order, so one `open` serves every reference of a source however the
        // queue happened to interleave them.
        taken.sort_by(|a, b| a.source_dir.cmp(&b.source_dir));
        self.queue = taken.into();
        Ok(true)
    }

    fn spare(&mut self, first: &Owed) {
        let dir = first.source_dir.clone();
        self.put_back.push((dir.clone(), first.source_ref.clone()));

        let mut kept = VecDeque::with_capacity(self.queue.len());
        while let Some(owed) = self.queue.pop_front() {
            match owed.source_dir == dir {
                true => self.put_back.push((owed.source_dir, owed.source_ref)),
                false => kept.push_back(owed),
            }
        }
        self.queue = kept;
    }

    /// End the run, putting back what was claimed and never fetched.
    pub fn finish(mut self) -> Result<()> {
        while let Some(owed) = self.queue.pop_front() {
            self.put_back.push((owed.source_dir, owed.source_ref));
        }
        for (dir, source_ref) in &self.put_back {
            self.ledger.offer_again(dir, &[source_ref.as_str()])?;
        }
        Ok(())
    }
}

fn fetch_one(
    pace: Option<&dyn Pace>,
    ledger: &Ledger,
    held: &dyn Held,
    content: &Content,
    row: &SourceRow,
    source: &dyn Source,
    owed: &Owed,
) -> Result<Brought> {
    let item = owed.item();
    let brought = |outcome| {
        Ok(Brought {
            source: row.name.clone(),
            name: item.name.clone(),
            outcome,
        })
    };
    let dest = destination(ledger, owed)?;
    let mut sink = content
        .resume(UNSORTED, &dest, 0)
        .with_context(|| format!("opening {} to write {}", dest, item.name))?;

    // Only a digest the sink is not already keeping costs a second pass over the bytes.
    let second = item
        .checksum
        .as_ref()
        .map(|sum| sum.algo)
        .filter(|algo| *algo != Digest::Sha256);
    let arrived = {
        let mut paced = Paced {
            pace,
            into: &mut sink,
        };
        match second {
            None => source.fetch(&item, &mut paced).map(|()| None),
            Some(algo) => {
                let mut verify = Verify::new(algo, &mut paced);
                source
                    .fetch(&item, &mut verify)
                    .map(|()| Some(verify.digest()))
            }
        }
    };

    let computed = match arrived {
        Ok(digest) => digest,
        Err(e) => {
            // Whatever arrived before the failure is thrown away rather than resumed: the
            // next attempt starts the fetch again, and a stale partial would outlive it.
            if let Ok(partial) = sink.finish() {
                let _ = content.discard(partial);
            }
            return match e {
                SourceError::Gone { reference } => {
                    ledger.forget(&row.dir, &reference)?;
                    brought(Outcome::Gone)
                }
                e => brought(Outcome::Failed(e.to_string())),
            };
        }
    };

    let staged = sink
        .finish()
        .with_context(|| format!("finishing the copy of {}", item.name))?;

    if let Some(promised) = item.size
        && promised != staged.size
    {
        let arrived = staged.size;
        let _ = content.discard(staged);
        return brought(Outcome::Failed(format!(
            "{} said it would be {promised} bytes, and it is {arrived}",
            row.name
        )));
    }

    let computed = computed.unwrap_or_else(|| staged.hash.clone());
    if let Some(promised) = &item.checksum
        && !promised.matches(&computed)
    {
        let _ = content.discard(staged);
        return brought(Outcome::Failed(format!(
            "{} said it would be {} {}, and it is {computed}",
            row.name, promised.algo, promised.value
        )));
    }

    let (hash, size) = (staged.hash.clone(), staged.size);
    let held = held
        .held(&hash)
        .with_context(|| format!("asking whether {} is already held", item.name))?;
    let outcome = match decide(ledger.seen(&hash)?, held) {
        Verdict::Keep => {
            content
                .commit(staged)
                .with_context(|| format!("putting {dest} in place"))?;
            ledger.keep(&Imported {
                hash: hash.clone(),
                state: State::Unsorted,
                name: dest.file_name().to_owned(),
                size,
                at: now(),
                group_id: None,
                source_dir: row.dir.clone(),
                source_name: row.name.clone(),
                source_ref: owed.source_ref.clone(),
                folder: owed.folder.clone(),
            })?;
            Outcome::Kept { size }
        }
        Verdict::Imported(_) => {
            let _ = content.discard(staged);
            Outcome::Known
        }
        Verdict::Held => {
            let _ = content.discard(staged);
            Outcome::Held
        }
    };
    ledger.settled(&row.dir, &owed.source_ref, &hash)?;
    brought(outcome)
}

/// Where one owed file lands
fn destination(ledger: &Ledger, owed: &Owed) -> Result<RelPath> {
    let raw = match owed.folder.trim_matches('/') {
        "" => format!("{}/{}", owed.source_dir, owed.name),
        folder => format!("{}/{folder}/{}", owed.source_dir, owed.name),
    };
    let dest = RelPath::parse(&raw)
        .or_else(|_| RelPath::under(&owed.source_dir, &owed.name))
        .with_context(|| format!("{} cannot be given a name on disk", owed.source_ref))?;

    if ledger.name_taken(
        &owed.source_dir,
        &owed.folder,
        dest.file_name(),
        &owed.source_ref,
    )? {
        return Ok(dest.conflict_name(&mark(&owed.source_ref)));
    }
    Ok(dest)
}

fn mark(source_ref: &str) -> String {
    use sha2::Digest as _;

    hex::encode(sha2::Sha256::digest(source_ref.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::import::fixtures::*;
    use crate::ops::import::scan;
    use crate::ops::import::scan::scan_with;
    use crate::ops::import::sources::add_source;
    use ac_groups::id::GroupId;
    use ac_import::config::Fields;
    use ac_import::source::{Item, SourceType};

    fn pump(
        ledger: &mut Ledger,
        files: &Files,
        content: &Content,
        row: &SourceRow,
        source: &dyn Source,
    ) -> Fetched {
        let taken = ledger.claim(now(), BATCH).unwrap();
        let mut out = Fetched::default();
        for owed in &taken {
            let brought =
                fetch_one(None, ledger, &HeldHere(files), content, row, source, owed).unwrap();
            out.count(&brought);
        }
        out
    }

    /// The file index and the storage root, opened as the pump opens them.
    fn store(paths: &Paths) -> (Files, Content) {
        let identity = crate::ops::identity(paths).unwrap();
        crate::ops::open_files(paths, &identity).unwrap()
    }

    /// Everything under `.unsorted`, as paths relative to it.
    fn unsorted(content: &Content) -> Vec<String> {
        let mut found: Vec<String> = content
            .walk(UNSORTED)
            .unwrap()
            .iter()
            .map(|path| path.as_str().to_owned())
            .collect();
        found.sort();
        found
    }

    #[test]
    fn what_is_owed_arrives_where_the_source_filed_it_and_is_written_down() {
        let home = home();
        let paths = paths(&home);
        let album = home.path().join("album");
        tree(&album, &["a.jpg", "DCIM/b.jpg"]);

        let row = add_source(&paths, "folder", "Pictures 2024", picked(&album)).unwrap();
        scan(&paths, &row.dir).unwrap();

        let fetched = drain(&paths, None).unwrap();
        assert_eq!(fetched.kept, 2);
        assert_eq!(fetched.tried, 2);
        assert!(fetched.failed.is_empty(), "{:?}", fetched.failed);
        // `tree` writes each file its own path as its bytes.
        assert_eq!(
            fetched.bytes,
            "a.jpg".len() as u64 + "DCIM/b.jpg".len() as u64
        );

        // The source's own shape is kept, under the directory the source was given.
        let (_, content) = store(&paths);
        assert_eq!(
            unsorted(&content),
            ["pictures-2024/DCIM/b.jpg", "pictures-2024/a.jpg"]
        );
        assert_eq!(
            std::fs::read(
                content.locate(UNSORTED, &RelPath::parse("pictures-2024/a.jpg").unwrap())
            )
            .unwrap(),
            b"a.jpg"
        );

        // And the ledger agrees with the disk, down to where each file came from.
        let ledger = ledger(&paths).unwrap();
        assert_eq!(ledger.owed(&row.dir).unwrap(), 0, "nothing is still owed");
        assert_eq!(ledger.waiting().unwrap(), 2);
        let waiting = ledger.in_folder(&row.dir, "DCIM").unwrap();
        assert_eq!(waiting.len(), 1);
        assert_eq!(waiting[0].name, "b.jpg");
        assert_eq!(waiting[0].source_ref, "DCIM/b.jpg");
        assert_eq!(waiting[0].source_name, "Pictures 2024");
        assert_eq!(waiting[0].state, State::Unsorted);

        // A second run has nothing left to take.
        assert_eq!(drain(&paths, None).unwrap(), Fetched::default());
    }

    #[test]
    fn one_content_is_kept_once_however_many_references_offer_it() {
        let home = home();
        let paths = paths(&home);
        let album = home.path().join("album");
        std::fs::create_dir_all(album.join("copy")).unwrap();
        for at in ["a.jpg", "copy/a.jpg"] {
            std::fs::write(album.join(at), b"the same bytes").unwrap();
        }

        let row = add_source(&paths, "folder", "Pictures", picked(&album)).unwrap();
        scan(&paths, &row.dir).unwrap();

        let fetched = drain(&paths, None).unwrap();
        assert_eq!(fetched.kept, 1);
        assert_eq!(fetched.known, 1, "the second one was already here");

        let (_, content) = store(&paths);
        assert_eq!(unsorted(&content).len(), 1, "and only one file was written");
        // Both references are settled: neither is owed, and neither comes back.
        assert_eq!(ledger(&paths).unwrap().owed(&row.dir).unwrap(), 0);
    }

    #[test]
    fn bytes_a_group_already_holds_are_not_imported_again() {
        let home = home();
        let paths = paths(&home);
        let album = home.path().join("album");
        tree(&album, &["a.jpg"]);

        let row = add_source(&paths, "folder", "Pictures", picked(&album)).unwrap();
        scan(&paths, &row.dir).unwrap();

        // The same bytes, already filed in a group, as a re-import of a folder would find.
        let (mut files, content) = store(&paths);
        let hash = {
            let source = album.join("a.jpg");
            let staged = content
                .stage("g", &RelPath::parse("kept.jpg").unwrap(), &source)
                .unwrap();
            let hash = staged.hash.clone();
            content.commit(staged).unwrap();
            hash
        };
        files
            .record(
                GroupId::ZERO,
                &ac_files::FileRow {
                    path: RelPath::parse("kept.jpg").unwrap(),
                    size: 5,
                    hash: hash.clone(),
                    modified: now(),
                    added_at: now(),
                    added_by: files.me(),
                    removed_at: None,
                    have: true,
                    seen_seq: 0,
                },
                true,
            )
            .unwrap();

        let fetched = drain(&paths, None).unwrap();
        assert_eq!(fetched.held, 1);
        assert_eq!(fetched.kept, 0);

        let ledger = ledger(&paths).unwrap();
        assert_eq!(ledger.owed(&row.dir).unwrap(), 0, "asked and answered");
        assert_eq!(ledger.waiting().unwrap(), 0, "nothing is waiting to sort");
        assert!(unsorted(&content).is_empty(), "and no second copy was made");
    }

    #[test]
    fn what_arrives_has_to_be_what_the_source_promised() {
        let home = home();
        let paths = paths(&home);
        let mut ledger = ledger(&paths).unwrap();
        let (files, content) = store(&paths);
        let row = add_source(&paths, "folder", "Drive", picked(home.path())).unwrap();

        // "a.jpg" hashes to something; the source says it will be something else.
        let drive = fake(SourceType::Remote, &["a.jpg"]).promises(
            "a.jpg",
            Digest::Md5,
            "00000000000000000000000000000000",
        );
        scan_with(&ledger, &row, &drive).unwrap();

        let fetched = pump(&mut ledger, &files, &content, &row, &drive);
        assert_eq!(fetched.kept, 0);
        assert_eq!(fetched.failed.len(), 1);
        let why = &fetched.failed[0];
        assert!(why.contains("Drive said it would be md5"), "{why}");

        assert!(unsorted(&content).is_empty(), "nothing was put in place");
        assert_eq!(ledger.waiting().unwrap(), 0);
        // Still owed, with one attempt spent: a source having a bad day is not a deletion.
        assert_eq!(ledger.owed(&row.dir).unwrap(), 1);
        assert_eq!(
            ledger.known_refs(&row.dir, &["a.jpg"]).unwrap(),
            vec![("a.jpg".to_owned(), 1)]
        );
    }

    #[test]
    fn a_size_that_disagrees_is_caught_on_its_own_with_no_digest_involved() {
        let home = home();
        let paths = paths(&home);
        let mut ledger = ledger(&paths).unwrap();
        let (files, content) = store(&paths);
        let row = add_source(&paths, "folder", "Phone", picked(home.path())).unwrap();

        // A truncated transfer, which is what this catches: the source offered more bytes
        // than it went on to serve, and promised no digest to notice it by.
        let phone = fake(SourceType::Intermittent, &["a.jpg", "b.jpg"]).claims_size("a.jpg", 4096);
        scan_with(&ledger, &row, &phone).unwrap();

        let fetched = pump(&mut ledger, &files, &content, &row, &phone);
        assert_eq!(fetched.kept, 1, "the honest one still comes in");
        assert_eq!(fetched.failed.len(), 1);
        let why = &fetched.failed[0];
        assert!(why.contains("Phone said it would be 4096 bytes"), "{why}");
        assert!(why.contains("and it is 5"), "{why}");

        assert_eq!(unsorted(&content).len(), 1, "the short one was not kept");
        assert_eq!(ledger.waiting().unwrap(), 1);
        // Still owed, one attempt spent, exactly as a dropped connection would leave it.
        assert_eq!(ledger.owed(&row.dir).unwrap(), 1);
        assert_eq!(
            ledger.known_refs(&row.dir, &["a.jpg"]).unwrap(),
            vec![("a.jpg".to_owned(), 1)]
        );
    }

    #[test]
    fn a_promise_the_bytes_keep_lets_them_through_whichever_it_was_made_in() {
        // The digests of "a.jpg", which is what the fake serves under that reference. The
        // sha256 is the one the pump would have computed anyway; the others cost a pass.
        for (algo, value) in [
            (Digest::Md5, "394659692a460258b45a99f1424ea357"),
            (Digest::Sha1, "56ceeb905c2d3070cd9f26b4d60ce7ef1e86e26d"),
            (
                Digest::Sha256,
                "509b0d4641a7c3ba088ffa28559d1f57207ea980447bc1773b1d406d788386ee",
            ),
        ] {
            let home = home();
            let paths = paths(&home);
            let mut ledger = ledger(&paths).unwrap();
            let (files, content) = store(&paths);
            let row = add_source(&paths, "folder", "Drive", picked(home.path())).unwrap();

            let drive = fake(SourceType::Remote, &["a.jpg"]).promises("a.jpg", algo, value);
            scan_with(&ledger, &row, &drive).unwrap();

            let fetched = pump(&mut ledger, &files, &content, &row, &drive);
            assert_eq!(fetched.kept, 1, "{algo}: {:?}", fetched.failed);
            assert_eq!(unsorted(&content), ["drive/a.jpg"], "{algo}");
            assert_eq!(ledger.owed(&row.dir).unwrap(), 0, "{algo}");
        }
    }

    #[test]
    fn a_reference_the_source_has_lost_stops_being_owed_at_once() {
        let home = home();
        let paths = paths(&home);
        let mut ledger = ledger(&paths).unwrap();
        let (files, content) = store(&paths);
        let row = add_source(&paths, "folder", "Drive", picked(home.path())).unwrap();

        let drive = fake(SourceType::Remote, &["here.jpg", "gone.jpg"]);
        scan_with(&ledger, &row, &drive).unwrap();
        assert_eq!(ledger.owed(&row.dir).unwrap(), 2);

        // It was offered by the scan and deleted before the fetch reached it.
        let drive = drive.lost("gone.jpg");
        let fetched = pump(&mut ledger, &files, &content, &row, &drive);
        assert_eq!(fetched.kept, 1);
        assert_eq!(fetched.gone, 1);
        assert!(fetched.failed.is_empty(), "a deletion is not a failure");

        // Nothing waits three attempts for a file the source has answered about.
        assert_eq!(ledger.owed(&row.dir).unwrap(), 0);
        assert!(
            ledger
                .known_refs(&row.dir, &["gone.jpg"])
                .unwrap()
                .is_empty()
        );
        assert_eq!(unsorted(&content), ["drive/here.jpg"]);
    }

    #[test]
    fn two_references_offering_one_name_do_not_land_on_each_other() {
        let home = home();
        let paths = paths(&home);
        let mut ledger = ledger(&paths).unwrap();
        let (files, content) = store(&paths);
        let row = add_source(&paths, "folder", "Drive", picked(home.path())).unwrap();

        // What an id-addressed source looks like: two ids, one name, different bytes.
        let mut drive = fake(SourceType::Remote, &["id-1", "id-2"]);
        for item in &mut drive.items {
            item.name = "IMG_1.jpg".to_owned();
            item.folder = "DCIM".to_owned();
        }
        scan_with(&ledger, &row, &drive).unwrap();

        let fetched = pump(&mut ledger, &files, &content, &row, &drive);
        assert_eq!(fetched.kept, 2);

        let found = unsorted(&content);
        assert_eq!(found.len(), 2, "both files are here: {found:?}");
        assert!(
            found.contains(&"drive/DCIM/IMG_1.jpg".to_owned()),
            "{found:?}"
        );
        let marked = found
            .iter()
            .find(|path| path.contains(".conflict-"))
            .unwrap_or_else(|| panic!("one of them takes a mark: {found:?}"));

        // The row says the name the file actually has, so sorting it later can find it.
        let waiting = ledger.in_folder(&row.dir, "DCIM").unwrap();
        assert_eq!(waiting.len(), 2);
        assert!(waiting.iter().any(|row| marked.ends_with(&row.name)));
    }

    #[test]
    fn a_source_that_will_not_open_gives_back_the_attempts_it_took() {
        let home = home();
        let paths = paths(&home);
        let ledger = ledger(&paths).unwrap();

        // A row the implementation would refuse: written straight in, as one left by an
        // older build, or by a folder whose config was edited by hand.
        let mut config = Fields::new();
        config.push("path", "relative/pictures");
        ledger
            .add_source(&SourceRow {
                dir: "broken".to_owned(),
                name: "Broken".to_owned(),
                source: "folder".to_owned(),
                config,
                added_at: now(),
                scanned_at: 0,
                last_error: None,
            })
            .unwrap();
        ledger
            .owe(
                "broken",
                &Item {
                    reference: "a.jpg".to_owned(),
                    folder: String::new(),
                    name: "a.jpg".to_owned(),
                    size: Some(1),
                    checksum: None,
                },
            )
            .unwrap();

        let fetched = drain(&paths, None).unwrap();
        assert_eq!(fetched.failed.len(), 1);
        assert!(fetched.failed[0].contains("Broken"), "{:?}", fetched.failed);

        // The reference keeps its attempts: nothing that happened is its fault.
        assert_eq!(
            ledger.known_refs("broken", &["a.jpg"]).unwrap(),
            vec![("a.jpg".to_owned(), 0)]
        );
        assert_eq!(ledger.owed("broken").unwrap(), 1);
        // And the source itself says what is wrong with it.
        let back = ledger.source("broken").unwrap().unwrap();
        assert!(back.last_error.is_some_and(|why| why.contains("absolute")));
    }

    #[test]
    fn a_run_of_the_pump_stops_where_it_was_told_to() {
        let home = home();
        let paths = paths(&home);
        let album = home.path().join("album");
        tree(&album, &["a.jpg", "b.jpg", "c.jpg"]);

        let row = add_source(&paths, "folder", "Pictures", picked(&album)).unwrap();
        scan(&paths, &row.dir).unwrap();

        let fetched = drain(&paths, Some(2)).unwrap();
        assert_eq!(fetched.tried, 2);
        assert_eq!(fetched.kept, 2);
        assert_eq!(ledger(&paths).unwrap().owed(&row.dir).unwrap(), 1);

        assert_eq!(drain(&paths, Some(2)).unwrap().kept, 1, "the rest follows");
    }
}
