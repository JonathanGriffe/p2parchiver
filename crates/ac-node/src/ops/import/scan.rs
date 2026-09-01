//! Asking a source what it has, and writing down what it owes.

use ac_import::ledger::{Ledger, SourceRow};
use ac_import::source::Source;
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
    pub skipped: Vec<String>,
    /// False when the source could not be reached. Not a failure, and not recorded as one.
    pub reachable: bool,
    /// A scan that reached the end. Only a complete one may retire rows or stamp `scanned_at`.
    pub complete: bool,
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
pub fn scan_with(ledger: &Ledger, row: &SourceRow, source: &dyn Source) -> Result<Scanned> {
    let mut out = Scanned {
        name: row.name.clone(),
        reachable: true,
        ..Scanned::default()
    };

    if !source.reachable() {
        out.reachable = false;
        return Ok(out);
    }

    let mut cursor = None;
    loop {
        let page = match source.scan(cursor.as_ref()) {
            Ok(page) => page,
            Err(e) => {
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
}
