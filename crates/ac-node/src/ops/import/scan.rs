//! Asking a source what it has, and writing down what it owes.

use ac_import::ledger::{Ledger, SourceRow};
use ac_import::registry;
use ac_import::source::{Source, SourceType};
use ac_net::config::Paths;
use anyhow::{Context, Result, anyhow};

use super::ledger;
use super::sources::{find_source, open_source};
use crate::ops::now;

/// What a scan found, and what it changed
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Scanned {
    pub name: String,
    /// Items the source offered, over every page.
    pub found: u64,
    /// References written down for the first time.
    pub owed: u64,
    /// Exhausted references the source still offers, put back on the queue.
    pub again: u64,
    /// Exhausted references it no longer offers: the file has gone from the source.
    pub retired: u64,
    /// Offered but not media: documents, spreadsheets, whatever else the source holds. Never
    /// downloaded, and counted rather than listed because there can be very many.
    pub ignored: u64,
    pub skipped: Vec<String>,
    /// False when the source could not be reached. Not a failure, and not recorded as one.
    pub reachable: bool,
    /// A scan that reached the end. Only a complete one may retire rows or stamp `scanned_at`.
    pub complete: bool,
}

/// Every source that is polled at all, stalest first: what the daemon picks its next scan
/// from. A one-shot source is never here, which is what "one-shot" means.
pub fn pollable(ledger: &Ledger) -> Result<Vec<(SourceRow, SourceType)>> {
    Ok(ledger
        .stalest()?
        .into_iter()
        .filter_map(|row| {
            let kind = registry::find(&row.source)?.kind;
            kind.polled().then_some((row, kind))
        })
        .collect())
}

/// Scan one source now, ignoring both its cadence and its backoff.
pub fn scan(paths: &Paths, needle: &str) -> Result<Scanned> {
    let ledger = ledger(paths)?;
    let row = find_source(&ledger, needle)?;

    let source = open_source(&ledger, &row)?;
    scan_with(&ledger, &row, source.as_ref())
}

/// The scan itself, over an already-opened source, so the daemon and a test can drive it
/// without going back through the registry.
/// The source is somewhere else. Whatever the scan had got through stands; what it did not
/// reach is simply not known yet.
///
/// Written down rather than merely returned: the Sources tab is read long after any scan ran,
/// and "not there when we last looked" is what it shows. `complete` stays false, so nothing is
/// retired on the strength of a listing that ended early.
fn away(ledger: &Ledger, row: &SourceRow, mut out: Scanned) -> Result<Scanned> {
    out.reachable = false;
    ledger.unreachable(&row.dir)?;
    Ok(out)
}

pub fn scan_with(ledger: &Ledger, row: &SourceRow, source: &dyn Source) -> Result<Scanned> {
    let mut out = Scanned {
        name: row.name.clone(),
        reachable: true,
        ..Scanned::default()
    };

    if !source.reachable() {
        return away(ledger, row, out);
    }

    let mut cursor = None;
    loop {
        let page = match source.scan(cursor.as_ref()) {
            Ok(page) => page,
            Err(e) => {
                // Asked again before it is called a failure. The check above is one moment,
                // and a phone can walk out of the house during the pages that follow — which
                // is not the source breaking, it is the source leaving. Recorded as a failure
                // it goes red on the Sources tab, and the daemon backs off for hours instead
                // of looking again in minutes, so a phone that came home would sit unread.
                if !source.reachable() {
                    return away(ledger, row, out);
                }
                let why = e.to_string();
                ledger.failed(&row.dir, &why)?;
                return Err(anyhow!(why)).with_context(|| format!("scanning {}", row.name));
            }
        };

        let refs: Vec<&str> = page
            .items
            .iter()
            .map(|item| item.reference.as_str())
            .collect();
        let known = ledger.known_refs(&row.dir, &refs)?;

        let mut stale = Vec::new();
        for item in &page.items {
            out.found += 1;

            // Decided here rather than in each source, so one list governs every one of them
            // and a new source cannot forget to have the rule. Counted rather than named: a
            // Drive can hold thousands of documents and none of them is news.
            if !ac_import::source::is_media(&item.name) {
                out.ignored += 1;
                continue;
            }

            match known.iter().find(|(seen, _)| *seen == item.reference) {
                Some((_, fails)) if *fails < ac_import::ledger::MAX_FETCH_ATTEMPTS => {}
                Some(_) => stale.push(item.reference.as_str()),
                None => {
                    ledger.owe(&row.dir, item)?;
                    out.owed += 1;
                }
            }
        }
        out.again += ledger.offer_again(&row.dir, &stale)? as u64;
        out.skipped.extend(page.skipped);

        match page.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }

    out.complete = true;
    out.retired = ledger.retire_gone(&row.dir)? as u64;
    ledger.scanned(&row.dir, now())?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::import::fixtures::*;
    use crate::ops::import::scan;
    use crate::ops::import::sources::add_source;
    use ac_import::source::SourceType;

    #[test]
    fn a_scan_writes_down_what_it_owes_and_moves_no_bytes() {
        let home = home();
        let paths = paths(&home);
        let album = home.path().join("album");
        tree(&album, &["a.jpg", "DCIM/b.jpg", "DCIM/c.jpg"]);

        let row = add_source(&paths, "folder", "Pictures 2024", picked(&album)).unwrap();
        assert_eq!(row.dir, "pictures-2024");

        let scanned = scan(&paths, &row.dir).unwrap();
        assert_eq!(scanned.found, 3);
        assert_eq!(scanned.owed, 3);
        assert!(scanned.complete);

        let ledger = ledger(&paths).unwrap();
        assert_eq!(ledger.owed(&row.dir).unwrap(), 3);
        assert_eq!(ledger.waiting().unwrap(), 0, "a scan imports nothing");
        assert_eq!(ledger.unsorted_bytes().unwrap(), 0);
        assert!(ledger.source(&row.dir).unwrap().unwrap().scanned_at > 0);
    }

    #[test]
    fn scanning_a_source_that_has_not_changed_owes_nothing_new() {
        let home = home();
        let paths = paths(&home);
        let album = home.path().join("album");
        tree(&album, &["a.jpg", "b.jpg"]);

        let row = add_source(&paths, "folder", "Pictures", picked(&album)).unwrap();
        scan(&paths, &row.dir).unwrap();

        let again = scan(&paths, &row.dir).unwrap();
        assert_eq!(again.found, 2);
        assert_eq!(again.owed, 0, "everything is already written down");
        assert_eq!(ledger(&paths).unwrap().owed(&row.dir).unwrap(), 2);
    }

    #[test]
    fn an_unreachable_source_is_skipped_without_being_called_a_failure() {
        let home = home();
        let paths = paths(&home);
        let ledger = ledger(&paths).unwrap();

        let row = add_source(&paths, "folder", "Phone", picked(home.path())).unwrap();
        let mut phone = fake(SourceType::Intermittent, &["a.jpg"]);
        phone.reachable = false;

        let scanned = scan_with(&ledger, &row, &phone).unwrap();
        assert!(!scanned.reachable);
        assert!(!scanned.complete);
        assert_eq!(scanned.found, 0);

        let back = ledger.source(&row.dir).unwrap().unwrap();
        assert_eq!(back.last_error, None, "elsewhere is not broken");
        assert_eq!(back.scanned_at, 0, "and it is still overdue");
    }

    /// Being there is asked once, and the pages are read after that. A phone that leaves the
    /// house in between is still only elsewhere — recorded as a failure it would go red on the
    /// Sources tab, and the daemon would back off for hours rather than looking again in
    /// minutes, leaving a phone that came home unread.
    #[test]
    fn a_source_that_leaves_partway_through_is_elsewhere_rather_than_broken() {
        let home = home();
        let paths = paths(&home);
        let ledger = ledger(&paths).unwrap();

        let row = add_source(&paths, "folder", "Phone", picked(home.path())).unwrap();
        let phone = fake(SourceType::Intermittent, &["a.jpg"]).walks_out();
        assert!(phone.reachable(), "it is here when the scan starts");

        let scanned = scan_with(&ledger, &row, &phone).unwrap();
        assert!(!scanned.reachable, "and elsewhere by the time it is read");
        assert!(!scanned.complete, "so nothing may be retired on it");

        let back = ledger.source(&row.dir).unwrap().unwrap();
        assert_eq!(back.last_error, None, "leaving is not breaking");
        assert!(!back.reachable, "it is simply not there");
        assert_eq!(back.scanned_at, 0, "and it has not been scanned");
    }

    /// The other half: a source that is still there and still will not answer has broken, and
    /// has to keep saying so. Without this the fix above would swallow every failure.
    #[test]
    fn a_source_that_is_there_and_still_fails_is_broken() {
        let home = home();
        let paths = paths(&home);
        let ledger = ledger(&paths).unwrap();

        let row = add_source(&paths, "folder", "Drive", picked(home.path())).unwrap();
        assert!(scan_with(&ledger, &row, &Stubborn).is_err(), "it failed");

        let back = ledger.source(&row.dir).unwrap().unwrap();
        assert_eq!(
            back.last_error.as_deref(),
            Some("the drive said no"),
            "and the reason is kept for the list to show"
        );
    }

    #[test]
    fn a_scan_puts_back_what_it_still_offers_and_retires_what_it_does_not() {
        let home = home();
        let paths = paths(&home);
        let mut ledger = ledger(&paths).unwrap();
        let row = add_source(&paths, "folder", "Drive", picked(home.path())).unwrap();

        let both = fake(SourceType::Remote, &["kept.jpg", "gone.jpg"]);
        assert_eq!(scan_with(&ledger, &row, &both).unwrap().owed, 2);

        // Both run out of attempts, as an unreadable file would.
        let mut at = now();
        for _ in 0..ac_import::ledger::MAX_FETCH_ATTEMPTS {
            ledger.claim(at, 8).unwrap();
            at += ac_import::ledger::FETCH_RETRY_DELAY + 1;
        }
        assert!(ledger.claim(at, 8).unwrap().is_empty());

        // The next scan offers only one of them.
        let one = fake(SourceType::Remote, &["kept.jpg"]);
        let scanned = scan_with(&ledger, &row, &one).unwrap();
        assert_eq!(scanned.again, 1, "still offered, so back on the queue");
        assert_eq!(
            scanned.retired, 1,
            "no longer offered, so the file has gone"
        );
        assert_eq!(ledger.owed(&row.dir).unwrap(), 1);
        assert_eq!(ledger.claim(at, 8).unwrap().len(), 1);
    }

    /// A source offers everything it has; only pictures and video are taken. Enforced once
    /// here rather than in each source, so a source added later cannot forget the rule.
    #[test]
    fn a_scan_owes_the_pictures_and_leaves_the_documents_where_they_are() {
        let home = home();
        let paths = paths(&home);
        let album = home.path().join("album");
        tree(
            &album,
            &[
                "DCIM/a.jpg",
                "DCIM/b.mp4",
                "DCIM/c.CR3",
                "notes.pdf",
                "deck.pptx",
                "budget.xlsx",
                "README",
            ],
        );

        let row = add_source(&paths, "folder", "Pictures", picked(&album)).unwrap();
        let scanned = scan(&paths, &row.dir).unwrap();

        assert_eq!(scanned.found, 7, "the source offered all of it");
        assert_eq!(scanned.owed, 3, "and only the photographs are owed");
        assert_eq!(scanned.ignored, 4);

        // Nothing was written down for them, so nothing will ever fetch them — and a second
        // scan does not keep rediscovering them as new.
        assert_eq!(ledger(&paths).unwrap().owed(&row.dir).unwrap(), 3);

        let claimed: Vec<String> = ledger(&paths)
            .unwrap()
            .claim(now(), 50)
            .unwrap()
            .into_iter()
            .map(|owed| owed.name)
            .collect();
        assert_eq!(claimed.len(), 3, "{claimed:?}");
        assert!(
            claimed.iter().all(|at| !at.ends_with(".pdf")),
            "only what the pump would fetch: {claimed:?}"
        );

        let again = scan(&paths, &row.dir).unwrap();
        assert_eq!(again.owed, 0, "nothing new the second time");
        assert_eq!(again.ignored, 4, "and the documents are still not media");
    }
}
