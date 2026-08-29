use std::rc::Rc;

use ac_net::config::{Config, Paths};
use ac_node::ops;
use ac_node::ops::file::Storage;
use ac_node::ops::format::human_size;
use ac_node::ops::peer::{Liveness, PeerProgress, StatusReport};
use slint::{ModelRc, VecModel};

use crate::files;
use crate::groups;
use crate::peers;
use crate::selection::Selection;
use crate::ui::{MainWindow, StorageSlice, TrafficRow};

const IDLE: i32 = 0;
const WORKING: i32 = 1;
const WAITING: i32 = 2;
/// Shared with the Peers page, so one number cannot drift from the other.
pub const QUIET: i32 = 3;

/// What the daemon last published, in the words the window shows
pub struct Status {
    pub running: bool,
    pub node_state: String,
    /// Stands in for the group list, which has its own page now.
    pub groups_line: String,
    pub storage: StoragePanel,
    /// The Bandwidth section: one row down, one row up.
    pub traffic: Vec<crate::ui::TrafficRow>,
}

/// The Storage section, in the order it is drawn.
#[derive(Default)]
pub struct StoragePanel {
    pub free: String,
    pub used: String,
    /// How much room is left, as the colour each line is shown in.
    pub free_room: i32,
    pub used_room: i32,
    /// One segment per group, already laid out along the bar.
    pub slices: Vec<crate::ui::StorageSlice>,
}

pub struct Snapshot {
    pub status: Status,
    pub page: groups::Page,
    pub directory: peers::Page,
    pub files: files::Page,
}

pub fn read(paths: &Paths, selection: &Selection) -> Snapshot {
    let looking_at = selection.get();
    let page = groups::read(paths, &looking_at.group);
    let files = files::read(paths, &looking_at);

    let report = match ops::peer::status(paths) {
        Ok(report) => Some(report),
        Err(e) => {
            tracing::warn!(error = %e, "could not read the node's status");
            None
        }
    };
    let directory = peers::read(paths, report.as_ref());

    let (running, node_state) = match &report {
        Some(report) => describe_liveness(report),
        None => (false, "could not read the node's status".to_owned()),
    };

    let storage = ops::file::storage(paths).ok();
    let bandwidth_max = Config::load(&paths.config_file())
        .unwrap_or_default()
        .bandwidth_max;

    let status = Status {
        running,
        node_state,
        groups_line: describe_groups(page.items.len(), report.as_ref()),
        storage: describe_storage(storage.as_ref(), &page),
        traffic: describe_traffic(report.as_ref(), running, bandwidth_max),
    };

    Snapshot {
        status,
        page,
        directory,
        files,
    }
}

/// Whether the node is running, and the sentence that says so.
fn describe_liveness(report: &StatusReport) -> (bool, String) {
    match report.liveness {
        Liveness::Never => (false, "the node has never run".to_owned()),
        Liveness::Stale { seconds } => (
            false,
            format!("last seen {seconds}s ago, the node is not running"),
        ),
        Liveness::Live => (true, "running".to_owned()),
    }
}

fn describe_groups(count: usize, report: Option<&StatusReport>) -> String {
    if count == 0 {
        // The sentence the CLI prints for the same state.
        return "none yet. create one with: ac group create --name <name>".to_owned();
    }

    let groups = match count {
        1 => "1 group".to_owned(),
        n => format!("{n} groups"),
    };
    match report.map_or(0, |r| r.groups.iter().map(|g| g.missing).sum::<u64>()) {
        0 => format!("{groups}, nothing to fetch"),
        1 => format!("{groups}, 1 file to fetch"),
        n => format!("{groups}, {n} files to fetch"),
    }
}

pub fn apply(window: &MainWindow, snapshot: Snapshot) {
    let Snapshot {
        status,
        page,
        directory,
        files,
    } = snapshot;

    window.set_running(status.running);
    window.set_node_state(status.node_state.into());
    window.set_groups_line(status.groups_line.into());
    window.set_storage_free(status.storage.free.into());
    window.set_storage_used(status.storage.used.into());
    window.set_storage_free_room(status.storage.free_room);
    window.set_storage_used_room(status.storage.used_room);
    window.set_storage_slices(ModelRc::from(Rc::new(VecModel::from(
        status.storage.slices,
    ))));
    window.set_traffic(ModelRc::from(Rc::new(VecModel::from(status.traffic))));
    groups::apply(window, page);
    peers::apply(window, directory);
    files::apply(window, files);
}

pub fn describe_peer(peer: &PeerProgress, now: i64) -> (i32, String) {
    if peer.connected {
        let mut busy = Vec::new();
        if peer.rounds > 0 {
            busy.push(format!("{} round(s)", peer.rounds));
        }
        if peer.transfers > 0 {
            busy.push(format!("{} transfer(s)", peer.transfers));
        }
        if peer.closing {
            busy.push("closing".to_owned());
        }
        if busy.is_empty() {
            (IDLE, "connected, idle".to_owned())
        } else {
            (WORKING, format!("connected, {}", busy.join(", ")))
        }
    } else if now < peer.retry_at {
        (WAITING, format!("backed off for {}s", peer.retry_at - now))
    } else if peer.online {
        (QUIET, "online, not connected".to_owned())
    } else {
        (QUIET, "not seen".to_owned())
    }
}

const GB: u64 = 1_000_000_000;
/// Room enough not to think about it.
const AMPLE: u64 = 50 * GB;
/// Enough to finish what is in flight, not enough to ignore.
const SPARSE: u64 = 10 * GB;

/// How much room is left, as the colour the line is shown in. A separate scale from the peer
/// tones: same idea, different question, so the numbers are not shared.
const ROOM_OK: i32 = 0;
const ROOM_LOW: i32 = 1;
const ROOM_FULL: i32 = 2;
const ROOM_UNKNOWN: i32 = 3;

fn room(left: Option<u64>) -> i32 {
    match left {
        None => ROOM_UNKNOWN,
        Some(bytes) if bytes >= AMPLE => ROOM_OK,
        Some(bytes) if bytes >= SPARSE => ROOM_LOW,
        Some(_) => ROOM_FULL,
    }
}

/// The Storage section: what is left, what is used, and one bar segment per group.
fn describe_storage(storage: Option<&Storage>, page: &groups::Page) -> StoragePanel {
    let Some(storage) = storage else {
        return StoragePanel::default();
    };

    // With no ceiling set, the disk is the ceiling.
    let capacity = storage
        .max
        .unwrap_or_else(|| storage.held.saturating_add(storage.free.unwrap_or(0)))
        .max(1);

    let mut offset = 0.0_f32;
    let slices = storage
        .by_group
        .iter()
        .enumerate()
        .map(|(at, (id, bytes))| {
            let fraction = (*bytes as f64 / capacity as f64) as f32;
            let slice = StorageSlice {
                label: name_of(id, page).into(),
                size: human_size(*bytes).into(),
                offset,
                fraction,
                shade: (1.0 - 0.18 * at as f32).max(0.4),
            };
            offset += fraction;
            slice
        })
        .collect();

    StoragePanel {
        free: match storage.free {
            Some(free) => format!("{} free on disk", human_size(free)),
            None => String::new(),
        },
        free_room: room(storage.free),
        used: match storage.max {
            Some(max) => format!(
                "{} of {} allowed",
                human_size(storage.held),
                human_size(max)
            ),
            None => format!("{} held, no limit set", human_size(storage.held)),
        },
        used_room: match storage.max {
            None => ROOM_OK,
            Some(max) => room(Some(max.saturating_sub(storage.held))),
        },
        slices,
    }
}

/// The Bandwidth section: what this node has moved, and whether it is moving anything now.
fn describe_traffic(
    report: Option<&StatusReport>,
    running: bool,
    bandwidth_max: Option<u64>,
) -> Vec<TrafficRow> {
    let moved = report.map(|r| r.bandwidth).unwrap_or_default();

    let (down_rate, up_rate) = match running {
        true => (moved.down_rate, moved.up_rate),
        false => (0, 0),
    };

    let limit = match bandwidth_max {
        Some(max) => format!("limit {}/s", human_size(max)),
        None => String::new(),
    };

    vec![
        TrafficRow {
            label: "download".into(),
            total: human_size(moved.down).into(),
            rate: rate(down_rate).into(),
            limit: limit.clone().into(),
            live: down_rate > 0,
        },
        TrafficRow {
            label: "upload".into(),
            total: human_size(moved.up).into(),
            rate: rate(up_rate).into(),
            limit: limit.into(),
            live: up_rate > 0,
        },
    ]
}

fn rate(bytes_per_second: u64) -> String {
    match bytes_per_second {
        0 => "idle".to_owned(),
        n => format!("{}/s", human_size(n)),
    }
}

/// A group's name, falling back to a short id for one the Groups page has not listed.
fn name_of(id: &str, page: &groups::Page) -> String {
    page.items
        .iter()
        .find(|item| item.id == id)
        .map(|item| item.name.to_string())
        .unwrap_or_else(|| id.chars().take(8).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn storage(held: u64, max: Option<u64>, free: Option<u64>) -> Storage {
        Storage {
            root: std::path::PathBuf::from("/tmp"),
            held,
            free,
            max,
            by_group: Vec::new(),
        }
    }

    #[test]
    fn free_space_is_coloured_by_how_much_of_it_is_left() {
        let page = groups::Page::default();
        let at = |free| describe_storage(Some(&storage(0, None, Some(free))), &page).free_room;

        assert_eq!(at(60 * GB), ROOM_OK);
        assert_eq!(at(50 * GB), ROOM_OK, "the threshold itself is still fine");
        assert_eq!(at(49 * GB), ROOM_LOW);
        assert_eq!(at(10 * GB), ROOM_LOW, "ditto");
        assert_eq!(at(9 * GB), ROOM_FULL);
    }

    #[test]
    fn the_used_line_is_coloured_by_the_room_left_not_the_room_taken() {
        let page = groups::Page::default();
        let panel = |held, max| describe_storage(Some(&storage(held, Some(max), None)), &page);

        assert_eq!(panel(9 * GB, 500 * GB).used_room, ROOM_OK);
        assert_eq!(panel(9 * GB, 10 * GB).used_room, ROOM_FULL);
    }

    #[test]
    fn a_volume_that_cannot_be_measured_says_nothing_rather_than_guessing() {
        let panel = describe_storage(Some(&storage(500, None, None)), &groups::Page::default());

        assert_eq!(panel.free, "", "no reading, so nothing to say");
        assert_eq!(panel.free_room, ROOM_UNKNOWN);
    }

    #[test]
    fn no_ceiling_reads_as_fine_however_much_is_held() {
        let panel = describe_storage(
            Some(&storage(900 * GB, None, Some(20 * GB))),
            &groups::Page::default(),
        );

        assert!(panel.used.contains("no limit set"), "got {:?}", panel.used);
        assert_eq!(panel.used_room, ROOM_OK);
        assert_eq!(
            panel.free_room, ROOM_LOW,
            "the disk still speaks for itself"
        );
    }

    #[test]
    fn segments_are_laid_end_to_end_and_scaled_to_the_limit() {
        let mut held = storage(750, Some(1_000), Some(9_000));
        held.by_group = vec![("a".to_owned(), 500), ("b".to_owned(), 250)];

        let slices = describe_storage(Some(&held), &groups::Page::default()).slices;

        assert_eq!(slices.len(), 2);
        assert_eq!(slices[0].offset, 0.0);
        assert!(
            (slices[0].fraction - 0.5).abs() < 1e-6,
            "half of the ceiling"
        );
        // The second starts exactly where the first ends, or the bar has a seam in it.
        assert!((slices[1].offset - 0.5).abs() < 1e-6);
        assert!((slices[1].fraction - 0.25).abs() < 1e-6);
    }

    fn report(bandwidth: ac_node::ops::peer::Bandwidth) -> StatusReport {
        StatusReport {
            liveness: Liveness::Live,
            now: 0,
            groups: Vec::new(),
            peers: Vec::new(),
            bandwidth,
        }
    }

    #[test]
    fn an_idle_direction_says_so_rather_than_showing_a_zero() {
        let moved = ac_node::ops::peer::Bandwidth {
            down: 2_000,
            up: 0,
            down_rate: 0,
            up_rate: 0,
        };

        let rows = describe_traffic(Some(&report(moved)), true, None);

        assert_eq!(rows[0].total, "2.0 KB");
        assert_eq!(
            rows[0].rate, "idle",
            "0 B/s is a number that reads as broken"
        );
        assert!(!rows[0].live);
        assert_eq!(
            rows[1].total, "0 B",
            "nothing sent is still a fact worth stating"
        );
    }

    #[test]
    fn a_moving_direction_carries_its_rate_and_lights_up() {
        let moved = ac_node::ops::peer::Bandwidth {
            down: 5_000_000,
            up: 0,
            down_rate: 1_000_000,
            up_rate: 0,
        };

        let rows = describe_traffic(Some(&report(moved)), true, Some(10_000_000));

        assert_eq!(rows[0].rate, "1.0 MB/s");
        assert_eq!(rows[0].limit, "limit 10.0 MB/s");
        assert_eq!(rows[1].limit, "limit 10.0 MB/s", "stated on both lines");
        assert!(rows[0].live);
        assert!(!rows[1].live, "the other direction is not moving");
    }

    #[test]
    fn a_stopped_node_shows_no_rate_however_busy_it_was_when_it_stopped() {
        let moved = ac_node::ops::peer::Bandwidth {
            down: 900,
            up: 100,
            down_rate: 1024 * 1024,
            up_rate: 4096,
        };

        let rows = describe_traffic(Some(&report(moved)), false, None);

        assert_eq!(rows[0].rate, "idle");
        assert_eq!(rows[1].rate, "idle");
        assert!(!rows[0].live && !rows[1].live);
        assert_eq!(rows[0].total, "900 B", "but what it did move still stands");
    }

    #[test]
    fn a_node_whose_status_could_not_be_read_still_has_both_rows() {
        let rows = describe_traffic(None, false, None);

        assert_eq!(rows.len(), 2, "the section keeps its shape");
        assert_eq!(rows[0].total, "0 B");
        assert_eq!(rows[1].total, "0 B");
    }

    #[test]
    fn a_group_the_listing_does_not_name_falls_back_to_its_id() {
        let mut held = storage(10, None, None);
        held.by_group = vec![("0123456789abcdef".to_owned(), 10)];

        let slices = describe_storage(Some(&held), &groups::Page::default()).slices;

        assert_eq!(slices[0].label, "01234567", "short id, not the whole thing");
    }
}
