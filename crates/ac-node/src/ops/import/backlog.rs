//! What became of the bytes: the backlog waiting to be sorted, and filing, dropping
//! or giving one back.

use ac_files::{Content, FileRow, Files, RelPath};
use ac_import::ledger::{Imported, Ledger, State};
use ac_net::config::Paths;
use anyhow::{Context, Result, anyhow, bail};

use super::{UNSORTED, ledger, unsorted_path};
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
    let ledger = ledger(paths)?;
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

/// Put back what was just done with one file: a sorted one comes back out of its group, a
/// dropped one is simply not dropped any more.
///
/// Only ever the reverse of something a moment old — see `Ledger::undone` for why that is
/// the one move backwards the rows allow.
pub fn undo(paths: &Paths, hash: &str) -> Result<String> {
    let ledger = ledger(paths)?;
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
    Ok(format!("{} is waiting again", row.name))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::import::fetch::drain;
    use crate::ops::import::fixtures::*;
    use crate::ops::import::scan::scan;

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
    fn a_hash_is_found_by_as_much_of_it_as_was_printed() {
        let home = home();
        let (paths, _) = imported(&home, &["a.jpg"]);
        let file = super::unsorted(&paths, None, 10).unwrap().remove(0);

        let found = find(&paths, &file.row.hash[..12]).unwrap();
        assert_eq!(found.hash, file.row.hash);
        assert_eq!(find(&paths, &file.row.hash).unwrap().hash, file.row.hash);
        assert!(find(&paths, "zzzzzzzz").is_err());
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
    fn a_filing_can_be_taken_back_and_the_file_comes_home() {
        let home = home();
        let (paths, _) = imported(&home, &["DCIM/a.jpg"]);
        let group = group(&paths, "Holidays");
        let file = super::unsorted(&paths, None, 10).unwrap().remove(0);

        sort(&paths, &file.row.hash, "Holidays", "2024").unwrap();
        let (mut files, content) = store(&paths);
        let dir = files.dir_for(group, "Holidays").unwrap();
        assert!(content.exists(&dir, &RelPath::parse("2024/a.jpg").unwrap()));

        undo(&paths, &file.row.hash).unwrap();

        // Carried back out of the group, and waiting where it was.
        assert!(!content.exists(&dir, &RelPath::parse("2024/a.jpg").unwrap()));
        assert!(content.exists(UNSORTED, &file.path), "it is home again");
        assert_eq!(ledger(&paths).unwrap().waiting().unwrap(), 1);
        assert_eq!(super::unsorted(&paths, None, 10).unwrap().len(), 1);

        // A tombstone rather than a deletion: the peers told it arrived are told it left.
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
        undo(&paths, &file.row.hash).unwrap();

        let (_, content) = store(&paths);
        assert!(content.exists(UNSORTED, &file.path), "the bytes never went");
        assert_eq!(ledger(&paths).unwrap().waiting().unwrap(), 1);

        // But once it is finished with there is nothing left to take back.
        drop(&paths, &file.row.hash).unwrap();
        assert_eq!(sweep_dropped(&paths).unwrap(), 1);
        assert!(!content.exists(UNSORTED, &file.path));
        let err = undo(&paths, &file.row.hash).unwrap_err();
        assert!(
            err.to_string().contains("deleted for good"),
            "taking it back would put a row on a file that is gone: {err}"
        );
        assert_eq!(ledger(&paths).unwrap().waiting().unwrap(), 0);
    }
}
