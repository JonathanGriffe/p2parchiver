//! What became of the bytes: the backlog waiting to be sorted, and filing, dropping
//! or giving one back.

use std::path::Path;

use ac_files::{Content, FileRow, Files, RelPath};
use ac_import::ledger::{Imported, Ledger, State};
use ac_net::config::Paths;
use anyhow::{Context, Result, anyhow, bail};

use super::{UNSORTED, ledger, ledger_at, unsorted_path};
use crate::ops::now;

/// One file waiting to be sorted.
pub struct Waiting {
    pub row: Imported,
    /// Where it sits under the storage root, inside [`UNSORTED`].
    pub path: RelPath,
    /// Whether a group has since come to hold these bytes anyway. The tab says so, and
    /// leaves the decision alone.
    pub held: bool,
}

/// How many files are waiting, in total and in the folder one of them came from.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Backlog {
    pub total: u64,
    pub in_folder: u64,
}

pub fn backlog(paths: &Paths, folder: Option<(&str, &str)>) -> Result<Backlog> {
    backlog_with(&ledger(paths)?, folder)
}

/// The same, for a caller that already has the ledger open.
pub fn backlog_with(ledger: &Ledger, folder: Option<(&str, &str)>) -> Result<Backlog> {
    Ok(Backlog {
        total: ledger.waiting()?,
        in_folder: match folder {
            Some((dir, folder)) => ledger.waiting_in(dir, folder)?,
            None => 0,
        },
    })
}

/// The ledger and the file index, held open across a walk of the backlog. Opening them
/// costs a schema check each time, which is worth paying once for a listing rather than
/// once for every page of it.
pub struct Inbox {
    ledger: Ledger,
    files: Files,
}

impl Inbox {
    pub fn open(paths: &Paths) -> Result<Self> {
        let identity = crate::ops::identity(paths)?;
        let (files, _) = crate::ops::open_files(paths, &identity)?;
        Ok(Self {
            ledger: ledger(paths)?,
            files,
        })
    }

    /// How many are waiting, off the ledger this inbox already holds.
    pub fn backlog(&self, folder: Option<(&str, &str)>) -> Result<Backlog> {
        backlog_with(&self.ledger, folder)
    }

    /// One page of what is waiting, oldest first.
    pub fn page(&self, after: Option<(i64, &str)>, len: usize) -> Result<Vec<Waiting>> {
        let rows = self.ledger.unsorted(after, len)?;
        let hashes: Vec<&str> = rows.iter().map(|row| row.hash.as_str()).collect();
        let held = self.files.held_any_of(&hashes)?;

        rows.into_iter()
            .map(|row| {
                Ok(Waiting {
                    path: located(&row)?,
                    held: held.contains(&row.hash),
                    row,
                })
            })
            .collect()
    }
}

/// One page, opening the inbox for it. Only the tests ask that way — anything walking the
/// backlog holds an [`Inbox`], so the API cannot express the per-page reopen.
#[cfg(test)]
pub fn unsorted(paths: &Paths, after: Option<(i64, &str)>, len: usize) -> Result<Vec<Waiting>> {
    Inbox::open(paths)?.page(after, len)
}

/// The waiting file a hash
pub fn find(paths: &Paths, hash: &str) -> Result<Imported> {
    let ledger = ledger(paths)?;
    if let Some(row) = ledger.get(hash)? {
        return Ok(row);
    }

    let mut found: Option<Imported> = None;
    let mut after: Option<(i64, String)> = None;
    loop {
        let page = ledger.unsorted(after.as_ref().map(|(at, h)| (*at, h.as_str())), 500)?;
        let Some(last) = page.last() else { break };
        after = Some((last.at, last.hash.clone()));

        for row in page {
            if !row.hash.starts_with(hash) {
                continue;
            }
            if found.is_some() {
                bail!("{hash} names more than one file; give more of it");
            }
            found = Some(row);
        }
    }

    found.ok_or_else(|| anyhow!("nothing waiting has the hash {hash}"))
}

/// What one action did, over one file or a whole folder.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Filed {
    pub done: u64,
    pub missing: u64,
    pub failed: Vec<String>,
    /// What was thrown away, so the whole action can be offered back at once. Empty for a
    /// filing: that comes back out of the group it went into, and the caller filing one file
    /// already knows which.
    pub dropped: Vec<String>,
}

pub fn sort(paths: &Paths, hash: &str, group: &str, into: &str) -> Result<Filed> {
    let ledger = ledger(paths)?;
    let row = ledger
        .get(hash)?
        .ok_or_else(|| anyhow!("nothing imported has the hash {hash}"))?;

    let mut session = crate::ops::file::session(paths, group)?;
    crate::ops::file::writable(&session.row)?;

    let mut out = Filed::default();
    sort_one(&ledger, &mut session, &row, into, &mut out)?;
    Ok(out)
}

/// File everything that came from one source folder.
pub fn sort_folder(
    paths: &Paths,
    source_dir: &str,
    folder: &str,
    group: &str,
    into: &str,
) -> Result<Filed> {
    let ledger = ledger(paths)?;
    let mut session = crate::ops::file::session(paths, group)?;
    crate::ops::file::writable(&session.row)?;

    let mut out = Filed::default();
    for row in ledger.in_folder(source_dir, folder)? {
        sort_one(&ledger, &mut session, &row, into, &mut out)?;
    }
    Ok(out)
}

fn sort_one(
    ledger: &Ledger,
    session: &mut crate::ops::file::Session,
    row: &Imported,
    into: &str,
    out: &mut Filed,
) -> Result<()> {
    if row.state != State::Unsorted {
        out.failed
            .push(format!("{} is already {}", row.name, row.state.as_str()));
        return Ok(());
    }

    let from = located(row)?;
    if !session.content.exists(UNSORTED, &from) {
        settle_missing(ledger, session, row, out)?;
        return Ok(());
    }

    // The same refusal `add_one` gives: a group keeps one copy of any file.
    if let Some(held) = session.files.path_of_hash(session.id, &row.hash)? {
        out.failed.push(format!(
            "{} is already in {}, at {held}",
            row.name, session.row.name
        ));
        return Ok(());
    }

    let to = free_name(session, row, into)?;
    let source = session.content.locate(UNSORTED, &from);
    let modified = std::fs::metadata(&source)
        .and_then(|meta| meta.modified())
        .map(|at| {
            at.duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |since| since.as_secs() as i64)
        })
        .unwrap_or_else(|_| now());

    match session.content.adopt(UNSORTED, &from, &session.dir, &to) {
        Ok(()) => {}
        // Only reachable if a filesystem was mounted under one group's directory, which
        // makes the move a cross-device one. Copying is slower and always works.
        Err(e) if e.kind() == std::io::ErrorKind::CrossesDevices => {
            crate::ops::file::add_one(session, &source, &to, false)
                .with_context(|| format!("copying {} into {}", row.name, session.row.name))?;
            session.content.remove(UNSORTED, &from).ok();
            ledger.sorted(&row.hash, &session.id.to_string())?;
            out.done += 1;
            return Ok(());
        }
        Err(e) => {
            return Err(e)
                .with_context(|| format!("moving {} into {}", row.name, session.row.name));
        }
    }

    let file = FileRow {
        path: to.clone(),
        size: row.size,
        hash: row.hash.clone(),
        modified,
        added_at: now(),
        added_by: session.files.me(),
        removed_at: None,
        have: true,
        seen_seq: 0,
    };
    session.files.record(session.id, &file, false)?;
    ledger.sorted(&row.hash, &session.id.to_string())?;
    out.done += 1;
    Ok(())
}

/// Throw one away, permanently.
pub fn drop(paths: &Paths, hash: &str) -> Result<Filed> {
    let ledger = ledger(paths)?;
    let row = ledger
        .get(hash)?
        .ok_or_else(|| anyhow!("nothing imported has the hash {hash}"))?;

    let identity = crate::ops::identity(paths)?;
    let (_, content) = crate::ops::open_files(paths, &identity)?;

    let mut out = Filed::default();
    drop_one(&ledger, &content, &row, &mut out)?;
    Ok(out)
}

/// Throw away everything that came from one source folder.
pub fn drop_folder(paths: &Paths, source_dir: &str, folder: &str) -> Result<Filed> {
    let ledger = ledger(paths)?;
    let identity = crate::ops::identity(paths)?;
    let (_, content) = crate::ops::open_files(paths, &identity)?;

    let mut out = Filed::default();
    for row in ledger.in_folder(source_dir, folder)? {
        drop_one(&ledger, &content, &row, &mut out)?;
    }
    Ok(out)
}

fn drop_one(ledger: &Ledger, content: &Content, row: &Imported, out: &mut Filed) -> Result<()> {
    if row.state != State::Unsorted {
        out.failed
            .push(format!("{} is already {}", row.name, row.state.as_str()));
        return Ok(());
    }

    // Marked, not deleted. The row is what makes it permanent — a dropped hash is never
    // fetched again, whatever offers it — and the bytes are what make it undoable, so they
    // stay until someone is finished with the decision. See [`forget`].
    let _ = content;
    ledger.dropped(&row.hash)?;
    out.done += 1;
    out.dropped.push(row.hash.clone());
    Ok(())
}

/// The hashes of everything still waiting in one source folder.
pub fn in_folder(paths: &Paths, source_dir: &str, folder: &str) -> Result<Vec<String>> {
    Ok(ledger(paths)?
        .in_folder(source_dir, folder)?
        .into_iter()
        .map(|row| row.hash)
        .collect())
}

/// Delete the bytes behind something already thrown away.
///
/// Split from [`drop`] so that throwing away and being finished with it are two moments
/// rather than one. Between them the file can be put back, which is all undo is.
pub fn forget(paths: &Paths, hash: &str) -> Result<bool> {
    let ledger = ledger(paths)?;
    let Some(row) = ledger.get(hash)? else {
        return Ok(false);
    };
    if row.state != State::Dropped {
        return Ok(false);
    }

    let identity = crate::ops::identity(paths)?;
    let (_, content) = crate::ops::open_files(paths, &identity)?;
    content
        .remove(UNSORTED, &located(&row)?)
        .with_context(|| format!("deleting {}", row.name))?;
    Ok(true)
}

/// Finish with everything thrown away that nobody is still deciding about.
///
/// Taking a deletion back only lasts as long as the session that made it, so by the time a
/// node is starting there is nothing left to take back and the bytes can go. Without this a
/// session that ended mid-sort would leave them on disk for good.
pub fn sweep_dropped(paths: &Paths) -> Result<u64> {
    let ledger = ledger(paths)?;
    let mut gone = 0;
    for row in ledger.discarded()? {
        if forget(paths, &row.hash)? {
            gone += 1;
        }
    }
    Ok(gone)
}

/// Put back what one action did: a sorted file comes back out of its group, a dropped one is
/// simply not dropped any more.
///
/// The whole action rather than one file, because a folder thrown away was one press and has
/// to be one press back. What can be put back is, whatever became of the rest: a file whose
/// bytes somebody has since finished with cannot come back, and that is no reason to leave
/// the others where they are.
///
/// Only ever the reverse of something a moment old — see `Ledger::undone` for why that is
/// the one move backwards the rows allow.
pub fn undo(paths: &Paths, hashes: &[String]) -> Result<String> {
    let ledger = ledger(paths)?;

    let mut back = Vec::new();
    let mut refused = Vec::new();
    for hash in hashes {
        match undo_one(paths, &ledger, hash) {
            Ok(name) => back.push(name),
            Err(e) => refused.push(format!("{e:#}")),
        }
    }

    // Nothing came back, so the only thing worth saying is why not. The first refusal
    // rather than all of them: they will be the same sentence about different files.
    let said = match (back.len(), refused.first()) {
        (0, Some(why)) => bail!("{why}"),
        (0, None) => bail!("there was nothing to take back"),
        (1, _) => format!("{} is waiting again", back[0]),
        (many, _) => format!("{many} are waiting again"),
    };

    Ok(match refused.is_empty() {
        true => said,
        false => format!("{said}; {} could not be", refused.len()),
    })
}

fn undo_one(paths: &Paths, ledger: &Ledger, hash: &str) -> Result<String> {
    let row = ledger
        .get(hash)?
        .ok_or_else(|| anyhow!("nothing imported has the hash {hash}"))?;

    match (row.state, row.group_id.clone()) {
        // Its bytes were never deleted, so there is nothing to carry back — unless
        // something has since been finished with it, and then there is nothing to put back
        // either. Refused rather than leaving a row pointing at a file that is gone.
        (State::Dropped, _) => {
            let identity = crate::ops::identity(paths)?;
            let (_, content) = crate::ops::open_files(paths, &identity)?;
            if !content.exists(UNSORTED, &located(&row)?) {
                bail!("{} has already been deleted for good", row.name);
            }
            ledger.undone(hash)?;
        }
        (State::Sorted, Some(group)) => {
            let mut session = crate::ops::file::session(paths, &group)?;
            let at = session
                .files
                .path_of_hash(session.id, hash)?
                .ok_or_else(|| anyhow!("{} is not in {} any more", row.name, session.row.name))?;

            session
                .content
                .adopt(&session.dir, &at, UNSORTED, &located(&row)?)
                .with_context(|| format!("carrying {} back out of {}", row.name, group))?;
            // A tombstone rather than a deletion: the peers who were told it arrived have
            // to be told it left.
            session.files.remove(session.id, &at, now())?;
            ledger.undone(hash)?;
        }
        _ => bail!("{} was not filed or thrown away", row.name),
    }
    Ok(row.name)
}

fn settle_missing(
    ledger: &Ledger,
    session: &mut crate::ops::file::Session,
    row: &Imported,
    out: &mut Filed,
) -> Result<()> {
    match session.files.held_anywhere(&row.hash)? {
        true => ledger.sorted(&row.hash, &session.id.to_string())?,
        false => ledger.dropped(&row.hash)?,
    };
    out.missing += 1;
    Ok(())
}

/// Where an imported file sits under [`UNSORTED`], which is derived rather than stored.
fn located(row: &Imported) -> Result<RelPath> {
    unsorted_path(&row.source_dir, &row.folder, &row.name)
        .with_context(|| format!("{} has no path on disk", row.name))
}

fn free_name(session: &crate::ops::file::Session, row: &Imported, into: &str) -> Result<RelPath> {
    let into = into.trim_matches('/');
    let plain = match into.is_empty() {
        true => RelPath::parse(&row.name),
        false => RelPath::under(into, &row.name),
    }
    .with_context(|| format!("{} cannot be given a name in a group", row.name))?;

    match session.files.get(session.id, &plain)? {
        Some(existing) if !existing.is_removed() => Ok(plain.conflict_name(&row.hash)),
        _ => Ok(plain),
    }
}

/// Take bytes already waiting to be sorted, instead of fetching them from a peer.
///
/// The reverse of the redundancy the pump already avoids: there, a file being imported turns
/// out to be in a group already and is not kept. Here it is the other way round — we imported
/// a photo, and before anybody sorted it a friend added the same photo to a group we are in.
/// The catalogue says the group is missing those bytes, and it is, but they are on this disk.
///
/// Filing it is what makes this safe rather than merely quick. The bytes leave `.unsorted`, so
/// leaving the import waiting would leave the Sort tab offering a file that is no longer
/// there; marking it sorted into that group is exactly what sorting it by hand would have
/// done, and it is what already happens when a group is found to hold a file at import time.
///
/// `false` means nothing here matched, and it has to be fetched after all — including when
/// the move itself fails, because downloading is always a correct answer and this is only ever
/// an optimisation.
pub fn adopt_unsorted(
    db: &Path,
    content: &Content,
    group: &str,
    dir: &str,
    to: &RelPath,
    hash: &str,
) -> Result<bool> {
    let ledger = ledger_at(db)?;
    let Some(row) = ledger.get(hash)? else {
        return Ok(false);
    };
    // Only one that is still waiting. A sorted row's bytes are in some group already, and a
    // dropped one's are gone or going.
    if row.state != State::Unsorted {
        return Ok(false);
    }

    let from = located(&row)?;
    if !content.exists(UNSORTED, &from) {
        return Ok(false);
    }

    // A rename, so it either happened or nothing did. The one failure worth naming is a
    // filesystem mounted under the group's directory, which makes this a cross-device move;
    // sorting by hand copies instead, but here there is a peer holding the bytes and asking
    // it is simpler than reimplementing the copy.
    if let Err(e) = content.adopt(UNSORTED, &from, dir, to) {
        tracing::debug!(%hash, error = %e, "could not take the unsorted copy; fetching instead");
        return Ok(false);
    }

    // After the move, the same order sorting by hand uses: the bytes are the thing that is
    // hard to put back, so they move first and the row follows.
    ledger
        .sorted(hash, group)
        .with_context(|| format!("filing {} into {group}", row.name))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::import::fetch::drain;
    use crate::ops::import::fixtures::*;
    use crate::ops::import::scan::scan;

    /// The fetch writes at this path and the sort reads back from it, so what matters is
    /// that one answer serves both — including for a folder that is no kind of path, where
    /// the file still has to land somewhere the sort will look.
    #[test]
    fn where_an_unsorted_file_sits_is_one_answer_however_it_is_asked() {
        let path = |folder| unsorted_path("phone-a1b2", folder, "IMG_1.jpg").unwrap();

        assert_eq!(path("DCIM/2024").as_str(), "phone-a1b2/DCIM/2024/IMG_1.jpg");
        assert_eq!(path("").as_str(), "phone-a1b2/IMG_1.jpg");
        assert_eq!(path("/DCIM/").as_str(), "phone-a1b2/DCIM/IMG_1.jpg");

        // No kind of path: the source's own directory is still somewhere.
        assert_eq!(path("../../etc").as_str(), "phone-a1b2/IMG_1.jpg");
    }

    /// The reverse of the redundancy the pump avoids: we imported a photo, and before anybody
    /// sorted it a friend added the same photo to a group we are in. The catalogue says the
    /// group is missing those bytes, and it is — but they are already on this disk.
    #[test]
    fn a_file_already_waiting_to_be_sorted_is_taken_rather_than_fetched() {
        let home = home();
        let (paths, _) = imported(&home, &["DCIM/a.jpg"]);
        let group = group(&paths, "Holidays");

        let waiting = super::unsorted(&paths, None, 10).unwrap();
        let file = &waiting[0];

        let (mut files, content) = store(&paths);
        let dir = files.dir_for(group, "Holidays").unwrap();
        let landed = RelPath::parse("a.jpg").unwrap();
        assert!(content.exists(UNSORTED, &file.path));

        let took = adopt_unsorted(
            &paths.db_file(),
            &content,
            &group.to_string(),
            &dir,
            &landed,
            &file.row.hash,
        )
        .unwrap();
        assert!(took, "the bytes were here, so nothing had to be fetched");

        assert!(!content.exists(UNSORTED, &file.path), "it left");
        assert!(
            content.exists(&dir, &landed),
            "and arrived where the group wants it"
        );

        // Filed, not merely moved. Leaving it waiting would leave the Sort tab offering a
        // file whose bytes are no longer where it would look for them.
        let back = ledger(&paths)
            .unwrap()
            .get(&file.row.hash)
            .unwrap()
            .unwrap();
        assert_eq!(back.state, State::Sorted);
        assert_eq!(back.group_id, Some(group.to_string()));
        assert_eq!(super::unsorted(&paths, None, 10).unwrap().len(), 0);

        // Asked again it declines, which is what makes it safe to ask before every fetch.
        let again = adopt_unsorted(
            &paths.db_file(),
            &content,
            &group.to_string(),
            &dir,
            &landed,
            &file.row.hash,
        )
        .unwrap();
        assert!(!again, "nothing is waiting under that hash any more");
    }

    /// It is asked before every blob fetch, so the ordinary answer is no — and saying no has
    /// to be cheap and total, because saying yes wrongly would skip a download that was owed.
    #[test]
    fn nothing_waiting_under_that_hash_means_fetch_it_as_usual() {
        let home = home();
        let (paths, _) = imported(&home, &["DCIM/a.jpg"]);
        let group = group(&paths, "Holidays");

        let (mut files, content) = store(&paths);
        let dir = files.dir_for(group, "Holidays").unwrap();
        let landed = RelPath::parse("a.jpg").unwrap();

        let ask = |hash: &str| {
            adopt_unsorted(
                &paths.db_file(),
                &content,
                &group.to_string(),
                &dir,
                &landed,
                hash,
            )
            .unwrap()
        };

        // A hash nothing here ever imported: the ordinary case, every fetch.
        assert!(!ask(&"ab".repeat(32)));

        // One that was imported and thrown away. Its bytes are gone or going, and taking a
        // deleted file back into a group is the one thing the state rules exist to prevent.
        let file = super::unsorted(&paths, None, 10).unwrap().remove(0);
        super::drop(&paths, &file.row.hash).unwrap();
        assert!(!ask(&file.row.hash));
    }

    #[test]
    fn a_sorted_file_leaves_the_unsorted_folder_for_the_group_it_was_filed_into() {
        let home = home();
        let (paths, _) = imported(&home, &["DCIM/a.jpg"]);
        let group = group(&paths, "Holidays");

        let waiting = super::unsorted(&paths, None, 10).unwrap();
        assert_eq!(waiting.len(), 1);
        let file = &waiting[0];
        assert_eq!(file.path.as_str(), "pictures/DCIM/a.jpg");
        assert!(!file.held, "no group has these bytes yet");

        let filed = sort(&paths, &file.row.hash, "Holidays", "").unwrap();
        assert_eq!(filed.done, 1);
        assert!(filed.failed.is_empty(), "{:?}", filed.failed);

        // It moved: gone from `.unsorted`, and in the group's own directory.
        let (mut files, content) = store(&paths);
        assert!(!content.exists(UNSORTED, &file.path), "it left");
        let group_dir = files.dir_for(group, "Holidays").unwrap();
        let landed = RelPath::parse("a.jpg").unwrap();
        assert!(content.exists(&group_dir, &landed), "and arrived");

        // With a row of its own, which is what a peer will sync and then pull.
        let recorded = files.get(group, &landed).unwrap().unwrap();
        assert_eq!(recorded.hash, file.row.hash);
        assert_eq!(recorded.size, file.row.size);
        assert!(recorded.have);
        assert!(files.held_anywhere(&file.row.hash).unwrap());

        // And the ledger says where it went, so it is never offered for sorting again.
        let back = ledger(&paths)
            .unwrap()
            .get(&file.row.hash)
            .unwrap()
            .unwrap();
        assert_eq!(back.state, State::Sorted);
        assert_eq!(back.group_id, Some(group.to_string()));
        assert_eq!(ledger(&paths).unwrap().waiting().unwrap(), 0);
        assert_eq!(super::unsorted(&paths, None, 10).unwrap().len(), 0);
    }

    #[test]
    fn a_file_lands_in_the_folder_it_was_filed_into() {
        let home = home();
        let (paths, _) = imported(&home, &["a.jpg", "b.jpg"]);
        let group = group(&paths, "Holidays");
        let waiting = super::unsorted(&paths, None, 10).unwrap();

        // Into a folder that does not exist yet: a folder in a group is the directory some
        // file is under, so filing into it is what brings it about.
        assert_eq!(
            sort(&paths, &waiting[0].row.hash, "Holidays", "2024/summer")
                .unwrap()
                .done,
            1
        );

        let (mut files, content) = store(&paths);
        let dir = files.dir_for(group, "Holidays").unwrap();
        let landed = RelPath::parse("2024/summer/a.jpg").unwrap();
        assert!(content.exists(&dir, &landed), "it is under the folder");
        assert!(
            files.get(group, &landed).unwrap().is_some(),
            "and recorded there"
        );

        // Which is what makes it offerable next time.
        assert_eq!(
            crate::ops::file::folders(&paths, "Holidays").unwrap(),
            ["2024", "2024/summer"],
            "every directory above it, so a nested one can be filed into directly"
        );

        // And the root is still the root: an empty destination is not a folder called "".
        sort(&paths, &waiting[1].row.hash, "Holidays", "").unwrap();
        assert!(content.exists(&dir, &RelPath::parse("b.jpg").unwrap()));
    }

    #[test]
    fn a_dropped_file_is_gone_from_disk_and_stays_remembered() {
        let home = home();
        let (paths, dir) = imported(&home, &["a.jpg"]);
        let file = super::unsorted(&paths, None, 10).unwrap().remove(0);

        assert_eq!(drop(&paths, &file.row.hash).unwrap().done, 1);

        // Thrown away and finished with are two moments. Until the second, the bytes are
        // still there, which is the only reason it can be taken back.
        let (_, content) = store(&paths);
        assert!(content.exists(UNSORTED, &file.path), "not deleted yet");
        assert!(forget(&paths, &file.row.hash).unwrap());
        assert!(!content.exists(UNSORTED, &file.path), "the bytes are gone");

        let ledger = ledger(&paths).unwrap();
        assert_eq!(
            ledger.get(&file.row.hash).unwrap().unwrap().state,
            State::Dropped
        );
        assert_eq!(ledger.waiting().unwrap(), 0);

        // The whole point of remembering: offering it again brings back nothing.
        assert_eq!(
            scan(&paths, &dir).unwrap().owed,
            0,
            "the ref is still settled"
        );
        assert_eq!(drain(&paths, None).unwrap().kept, 0);
        assert!(!content.exists(UNSORTED, &file.path), "and it stayed gone");
    }

    #[test]
    fn a_filing_can_be_taken_back_and_the_file_comes_home() {
        let home = home();
        let (paths, _) = imported(&home, &["DCIM/a.jpg"]);
        let group = group(&paths, "Holidays");
        let file = super::unsorted(&paths, None, 10).unwrap().remove(0);

        sort(&paths, &file.row.hash, "Holidays", "2024").unwrap();
        let (mut files, content) = store(&paths);
        let dir = files.dir_for(group, "Holidays").unwrap();
        assert!(content.exists(&dir, &RelPath::parse("2024/a.jpg").unwrap()));

        undo(&paths, std::slice::from_ref(&file.row.hash)).unwrap();

        // Carried back out of the group, and waiting where it was.
        assert!(!content.exists(&dir, &RelPath::parse("2024/a.jpg").unwrap()));
        assert!(content.exists(UNSORTED, &file.path), "it is home again");
        assert_eq!(ledger(&paths).unwrap().waiting().unwrap(), 1);
        assert_eq!(super::unsorted(&paths, None, 10).unwrap().len(), 1);

        // Nothing was ever served out of this group, so there is nobody to tell and no
        // tombstone to leave: the row goes with the file.
        let row = files
            .get(group, &RelPath::parse("2024/a.jpg").unwrap())
            .unwrap();
        assert!(row.is_none(), "left no residue");
    }

    #[test]
    fn taking_back_a_filing_a_peer_was_told_about_leaves_a_tombstone() {
        let home = home();
        let (paths, _) = imported(&home, &["DCIM/a.jpg"]);
        let group = group(&paths, "Holidays");
        let file = super::unsorted(&paths, None, 10).unwrap().remove(0);

        sort(&paths, &file.row.hash, "Holidays", "2024").unwrap();

        // Somebody asked for the catalogue, so the row has been out of this node.
        let (mut files, _) = store(&paths);
        files.changes_since(group, 0, 100).unwrap();

        undo(&paths, std::slice::from_ref(&file.row.hash)).unwrap();

        let row = files
            .get(group, &RelPath::parse("2024/a.jpg").unwrap())
            .unwrap();
        assert!(row.is_some_and(|row| row.is_removed()), "left a tombstone");
    }

    #[test]
    fn a_deletion_can_be_taken_back_until_it_is_finished_with() {
        let home = home();
        let (paths, _) = imported(&home, &["a.jpg"]);
        let file = super::unsorted(&paths, None, 10).unwrap().remove(0);

        drop(&paths, &file.row.hash).unwrap();
        undo(&paths, std::slice::from_ref(&file.row.hash)).unwrap();

        let (_, content) = store(&paths);
        assert!(content.exists(UNSORTED, &file.path), "the bytes never went");
        assert_eq!(ledger(&paths).unwrap().waiting().unwrap(), 1);

        // But once it is finished with there is nothing left to take back.
        drop(&paths, &file.row.hash).unwrap();
        assert_eq!(sweep_dropped(&paths).unwrap(), 1);
        assert!(!content.exists(UNSORTED, &file.path));
        let err = undo(&paths, std::slice::from_ref(&file.row.hash)).unwrap_err();
        assert!(
            err.to_string().contains("deleted for good"),
            "taking it back would put a row on a file that is gone: {err}"
        );
        assert_eq!(ledger(&paths).unwrap().waiting().unwrap(), 0);
    }

    /// A folder thrown away is one decision, so it comes back as one: `drop_folder` says
    /// which files it was, and every one of them goes back in a single press.
    #[test]
    fn a_whole_folder_thrown_away_comes_back_in_one_go() {
        let home = home();
        let (paths, _) = imported(&home, &["DCIM/a.jpg", "DCIM/b.jpg", "c.jpg"]);
        let row = super::unsorted(&paths, None, 10)
            .unwrap()
            .into_iter()
            .find(|file| file.row.folder == "DCIM")
            .unwrap()
            .row;

        let filed = drop_folder(&paths, &row.source_dir, &row.folder).unwrap();
        assert_eq!(filed.done, 2);
        assert_eq!(
            filed.dropped.len(),
            2,
            "it says which, so they can come back"
        );
        assert_eq!(ledger(&paths).unwrap().waiting().unwrap(), 1, "c.jpg only");

        // The bytes were never touched, which is what makes the whole thing undoable.
        let (_, content) = store(&paths);
        for row in ledger(&paths).unwrap().discarded().unwrap() {
            assert!(
                content.exists(UNSORTED, &located(&row).unwrap()),
                "still on disk"
            );
        }

        undo(&paths, &filed.dropped).unwrap();
        assert_eq!(
            ledger(&paths).unwrap().waiting().unwrap(),
            3,
            "both came back, and c.jpg never went"
        );
    }

    /// One press put forty away and one press brought them back, so a file that cannot come
    /// back must not hold up the rest of them.
    #[test]
    fn taking_a_folder_back_puts_back_what_it_can() {
        let home = home();
        let (paths, _) = imported(&home, &["DCIM/a.jpg", "DCIM/b.jpg"]);
        let row = super::unsorted(&paths, None, 10).unwrap().remove(0).row;

        let filed = drop_folder(&paths, &row.source_dir, &row.folder).unwrap();
        assert_eq!(filed.dropped.len(), 2);

        // One of them is finished with behind the undo's back, as the sweep at startup
        // would have done had the session ended in between.
        assert!(forget(&paths, &filed.dropped[0]).unwrap());

        let said = undo(&paths, &filed.dropped).unwrap();
        assert!(said.contains("could not"), "it says one was left: {said}");
        assert_eq!(
            ledger(&paths).unwrap().waiting().unwrap(),
            1,
            "the one whose bytes were still there came back"
        );
    }

    #[test]
    fn a_whole_source_folder_is_filed_in_one_go() {
        let home = home();
        let (paths, _) = imported(&home, &["DCIM/a.jpg", "DCIM/b.jpg", "other/c.jpg"]);
        group(&paths, "Holidays");

        let waiting = super::unsorted(&paths, None, 10).unwrap();
        let one = waiting
            .iter()
            .find(|file| file.row.folder == "DCIM")
            .unwrap();

        let backlog = backlog(&paths, Some((&one.row.source_dir, &one.row.folder))).unwrap();
        assert_eq!(backlog.total, 3);
        assert_eq!(backlog.in_folder, 2, "what the bulk button would name");

        let filed = sort_folder(&paths, &one.row.source_dir, "DCIM", "Holidays", "").unwrap();
        assert_eq!(filed.done, 2, "both of that folder's, and nothing else");
        assert_eq!(ledger(&paths).unwrap().waiting().unwrap(), 1);
        assert_eq!(
            super::unsorted(&paths, None, 10).unwrap()[0].row.folder,
            "other"
        );
    }

    #[test]
    fn two_files_of_one_name_do_not_land_on_each_other_in_a_group() {
        let home = home();
        let (paths, _) = imported(&home, &["one/x.jpg", "two/x.jpg"]);
        let group = group(&paths, "Holidays");

        for file in super::unsorted(&paths, None, 10).unwrap() {
            assert_eq!(
                sort(&paths, &file.row.hash, "Holidays", "").unwrap().done,
                1
            );
        }

        let (files, _) = store(&paths);
        let listed = files.list(group, None, false).unwrap();
        assert_eq!(listed.len(), 2, "both are there: {listed:?}");
    }

    #[test]
    fn a_row_whose_file_has_gone_is_settled_from_what_is_held_now() {
        let home = home();
        let (paths, _) = imported(&home, &["a.jpg"]);
        group(&paths, "Holidays");
        let file = super::unsorted(&paths, None, 10).unwrap().remove(0);

        // A crash between moving a file and recording where it went leaves exactly this.
        let (_, content) = store(&paths);
        content.remove(UNSORTED, &file.path).unwrap();

        let filed = sort(&paths, &file.row.hash, "Holidays", "").unwrap();
        assert_eq!(filed.done, 0);
        assert_eq!(filed.missing, 1);

        let back = ledger(&paths)
            .unwrap()
            .get(&file.row.hash)
            .unwrap()
            .unwrap();
        assert_eq!(back.state, State::Dropped);
        assert_eq!(ledger(&paths).unwrap().waiting().unwrap(), 0);
    }

    #[test]
    fn a_page_of_the_backlog_reads_the_same_however_much_is_behind_it() {
        let home = home();
        let names: Vec<String> = (0..25).map(|i| format!("IMG_{i:02}.jpg")).collect();
        let files: Vec<&str> = names.iter().map(String::as_str).collect();
        let (paths, _) = imported(&home, &files);

        // Paged by the last row seen rather than by OFFSET, so every page costs the same.
        let mut seen: Vec<String> = Vec::new();
        let mut after: Option<(i64, String)> = None;
        loop {
            let page = super::unsorted(&paths, after.as_ref().map(|(at, h)| (*at, h.as_str())), 10)
                .unwrap();
            let Some(last) = page.last() else { break };
            after = Some((last.row.at, last.row.hash.clone()));
            seen.extend(page.iter().map(|file| file.row.name.clone()));
        }

        assert_eq!(seen.len(), 25, "every one of them, once");
        let mut unique = seen.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), 25, "and no row read twice");
    }

    #[test]
    fn a_hash_is_found_by_as_much_of_it_as_was_printed() {
        let home = home();
        let (paths, _) = imported(&home, &["a.jpg"]);
        let file = super::unsorted(&paths, None, 10).unwrap().remove(0);

        let found = find(&paths, &file.row.hash[..12]).unwrap();
        assert_eq!(found.hash, file.row.hash);
        assert_eq!(find(&paths, &file.row.hash).unwrap().hash, file.row.hash);
        assert!(find(&paths, "zzzzzzzz").is_err());
    }
}
