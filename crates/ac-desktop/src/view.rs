use std::rc::Rc;

use ac_net::config::{Config, Paths};
use ac_node::ops;
use ac_node::ops::file::Storage;
use ac_node::ops::format::human_size;
use ac_node::ops::peer::{Liveness, PeerProgress, StatusReport};
use slint::{ComponentHandle, ModelRc, VecModel};

use crate::files;
use crate::groups;
use crate::peers;
use crate::selection::Selection;
use crate::sort;
use crate::sources;
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

/// What one read found, for the page that is showing and nothing else.
///
/// Every field is optional because a read only does the work the visible tab needs. The
/// window is one thing, but its pages are not: rebuilding the file list on every step of
/// the Sort tab costs more than everything the step itself does, and grows with the number
/// of files rather than staying still.
#[derive(Default)]
pub struct Snapshot {
    pub status: Option<Status>,
    pub page: Option<groups::Page>,
    pub directory: Option<peers::Page>,
    pub files: Option<files::Page>,
    pub sort: Option<sort::Page>,
    pub sources: Option<sources::Page>,
}

/// Which page is up. The nav sets it, and it is what a read is narrowed by.
pub const STATUS: i32 = 0;
pub const GROUPS: i32 = 1;
pub const PEERS: i32 = 2;
pub const FILES: i32 = 3;
pub const SORT: i32 = 4;
pub const SOURCES: i32 = 5;

pub fn read(paths: &Paths, selection: &Selection) -> Snapshot {
    let looking_at = selection.get();
    let tab = looking_at.tab;

    // The pages that stand alone, each read only where it is being looked at.
    let files = (tab == FILES).then(|| files::read(paths, &looking_at));
    let sort = (tab == SORT).then(|| sort::read(paths, &looking_at.sorting));
    let sources = (tab == SOURCES).then(|| sources::read(paths));

    if !matches!(tab, STATUS | GROUPS | PEERS) {
        return Snapshot {
            files,
            sort,
            sources,
            ..Snapshot::default()
        };
    }

    // Read once and shared: both the Groups page and the Peers page name the same people, and
    // they have to agree about what each is called.
    let known = ops::peer::list(paths).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "could not list peers");
        Vec::new()
    });
    let report = match ops::peer::status(paths) {
        Ok(report) => Some(report),
        Err(e) => {
            tracing::warn!(error = %e, "could not read the node's status");
            None
        }
    };
    // Before the groups page, which offers the same people as candidates to add to one.
    let directory = peers::read(&known, report.as_ref());
    let page = groups::read(paths, &known, &directory, &looking_at.group);

    let (running, node_state) = match &report {
        Some(report) => describe_liveness(report),
        None => (false, "could not read the node's status".to_owned()),
    };

    // The storage bar is the Status page's alone, and measuring it walks two tables.
    let status = (tab == STATUS).then(|| {
        let storage = ops::file::storage(paths).ok();
        let bandwidth_max = Config::load(&paths.config_file())
            .unwrap_or_default()
            .bandwidth_max;

        Status {
            running,
            node_state,
            groups_line: describe_groups(page.items.len(), report.as_ref()),
            storage: describe_storage(storage.as_ref(), &page),
            traffic: describe_traffic(report.as_ref(), running, bandwidth_max),
        }
    });

    Snapshot {
        status,
        page: Some(page),
        directory: Some(directory),
        files,
        sort,
        sources,
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
        // The Groups page is one click away and says how; a summary line only has to say
        // what is true.
        return "no groups".to_owned();
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

/// Put on screen whatever was read. What was not read is left exactly as it was, which is
/// what makes a narrow read safe: a page nobody is looking at keeps the last thing it knew.
pub fn apply(window: &MainWindow, snapshot: Snapshot) {
    let Snapshot {
        status,
        page,
        directory,
        files,
        sort,
        sources,
    } = snapshot;

    if let Some(status) = status {
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
    }
    if let Some(page) = page {
        groups::apply(window, page);
    }
    if let Some(directory) = directory {
        peers::apply(window, directory);
    }
    if let Some(sort) = sort {
        sort::apply(window, sort);
    }
    if let Some(sources) = sources {
        sources::apply(window, sources);
    }
    if let Some(files) = files {
        files::apply(window, files);
    }
}

/// The Status page's one button. Copying happens in the markup, through the same clipboard
/// the platform gives any text field; this only says that it did.
pub fn wire(window: &MainWindow, selection: &Selection, nudge: &crate::work::Nudge) {
    window.on_showing({
        let selection = selection.clone();
        let nudge = nudge.clone();
        move |tab| {
            selection.set_tab(tab);
            // The page that just came up has whatever it last knew on it, which may be
            // nothing at all. Read now rather than at the next tick.
            nudge.now();
        }
    });

    let weak = window.as_weak();
    let nudge = nudge.clone();

    window.on_copy_peer_id(move || {
        if let Some(window) = weak.upgrade() {
            crate::work::finish(&window, Ok("copied the peer id".to_owned()), &nudge);
        }
    });
}

/// The facts that only change when this node enrols: read at startup, and again the moment
/// it does. Everything else on screen comes from the poll.
pub fn describe_node(window: &MainWindow, paths: &Paths) -> anyhow::Result<()> {
    let identity = ops::identity(paths)?;
    let config = Config::load(&paths.config_file()).unwrap_or_default();

    let enrolled = ops::enrolment(paths).unwrap_or_default();
    window.set_username(enrolled.map(|e| e.username).unwrap_or_default().into());
    window.set_server_host(
        config
            .server
            .as_ref()
            .map(server_host)
            .unwrap_or_else(|| "not enrolled".to_owned())
            .into(),
    );

    window.set_version(env!("CARGO_PKG_VERSION").into());
    window.set_peer_id(identity.peer_id().to_string().into());
    window.set_home(paths.root.display().to_string().into());
    window.set_storage_root(config.storage_root(paths).display().to_string().into());
    window.set_log_dir(crate::log::dir(paths).display().to_string().into());
    Ok(())
}

fn server_host(server: &ac_net::Multiaddr) -> String {
    use ac_net::Protocol;

    server
        .iter()
        .find_map(|part| match part {
            Protocol::Ip4(ip) => Some(ip.to_string()),
            Protocol::Ip6(ip) => Some(ip.to_string()),
            Protocol::Dns(name)
            | Protocol::Dns4(name)
            | Protocol::Dns6(name)
            | Protocol::Dnsaddr(name) => Some(name.to_string()),
            _ => None,
        })
        .unwrap_or_else(|| server.to_string())
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
    let mut slices: Vec<StorageSlice> = storage
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
                at: at as i32,
            };
            offset += fraction;
            slice
        })
        .collect();

    if storage.unsorted > 0 {
        slices.push(StorageSlice {
            label: "unsorted".into(),
            size: human_size(storage.unsorted).into(),
            offset,
            fraction: (storage.unsorted as f64 / capacity as f64) as f32,
            // Not a group, and the only slice without a colour: what is waiting to be sorted
            // has not been put anywhere yet, and grey is what says so.
            at: -1,
        });
    }

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

    /// The button copies in the markup, so what a test can hold to is that pressing it is
    /// wired to the node's own id and says so. Whether the platform took the text is the
    /// platform's business, and the testing backend has no clipboard to check.
    #[test]
    fn the_peer_id_is_offered_with_a_button_that_copies_it() {
        use i_slint_backend_testing::ElementHandle;

        const PEER: &str = "12D3KooWDmPLKCjUV7snQBQVod5bNQnDmZ5X4MYNnPx8NM95zxke";

        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().unwrap();
        let (nudge, _ticks) = crate::work::nudge();
        wire(&window, &Selection::new(), &nudge);

        window.set_tab(0);
        window.set_peer_id(PEER.into());

        // The id it carries is this node's, not whatever was last drawn beside it.
        let copier = ElementHandle::find_by_element_id(&window, "CopyButton::carrier")
            .next()
            .unwrap();
        assert_eq!(copier.accessible_value().unwrap(), PEER);

        let button = ElementHandle::find_by_accessible_label(&window, "Copy")
            .next()
            .unwrap();
        button.invoke_accessible_default_action();

        assert_eq!(window.get_message(), "copied the peer id");
        assert!(!window.get_message_bad());
    }

    fn storage(held: u64, max: Option<u64>, free: Option<u64>) -> Storage {
        Storage {
            root: std::path::PathBuf::from("/tmp"),
            held,
            free,
            max,
            by_group: Vec::new(),
            unsorted: 0,
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

#[cfg(test)]
mod reading {
    use super::*;

    /// Every group gets a colour of its own, in a fixed order; what is waiting to be sorted
    /// gets none, because it has not been put anywhere yet.
    #[test]
    fn the_storage_bar_colours_groups_and_leaves_the_unsorted_slice_grey() {
        use ac_node::ops::file::Storage;

        let group = |name: &str| crate::ui::GroupItem {
            name: name.into(),
            ..Default::default()
        };
        let storage = Storage {
            root: std::path::PathBuf::from("/tmp"),
            held: 300,
            free: Some(700),
            max: Some(1000),
            unsorted: 100,
            by_group: vec![
                ("g1".to_owned(), 100),
                ("g2".to_owned(), 100),
                ("g3".to_owned(), 100),
            ],
        };
        let page = groups::Page {
            items: vec![group("Holidays"), group("Family"), group("Work")],
            detail: None,
        };

        let panel = describe_storage(Some(&storage), &page);
        let at: Vec<i32> = panel.slices.iter().map(|slice| slice.at).collect();

        // Counted from zero and never repeated, which is what the theme indexes the hues by.
        assert_eq!(at, [0, 1, 2, -1]);
        assert_eq!(
            panel.slices.last().map(|slice| slice.label.as_str()),
            Some("unsorted"),
            "and the one without a colour is the one that is not a group"
        );
    }

    /// A read does the work the page on screen needs, and no other page's.
    ///
    /// This is what stepping through the Sort tab used to cost: the file list was rebuilt
    /// on every press, and its cost grows with the number of files filed rather than
    /// staying still. Nothing about a step touches it.
    #[test]
    fn only_the_page_on_screen_is_read() {
        let (_tmp, paths) = crate::groups::tests::home("jonathan");
        let selection = Selection::new();

        selection.set_tab(SORT);
        let snapshot = read(&paths, &selection);
        assert!(snapshot.sort.is_some(), "the page being looked at");
        assert!(snapshot.files.is_none(), "and not the one that is not");
        assert!(snapshot.sources.is_none());
        assert!(snapshot.status.is_none(), "nor the storage bar");
        assert!(snapshot.page.is_none(), "nor the group list");

        selection.set_tab(FILES);
        let snapshot = read(&paths, &selection);
        assert!(snapshot.files.is_some());
        assert!(snapshot.sort.is_none());

        selection.set_tab(SOURCES);
        assert!(read(&paths, &selection).sources.is_some());

        // The Status page is the one that needs more than itself: it counts the groups and
        // names the slices of the storage bar after them.
        selection.set_tab(STATUS);
        let snapshot = read(&paths, &selection);
        assert!(snapshot.status.is_some() && snapshot.page.is_some());
        assert!(snapshot.files.is_none(), "but still not the file list");
    }

    /// What is not read is left alone, which is what makes a narrow read safe.
    #[test]
    fn a_page_that_was_not_read_keeps_what_it_had() {
        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().unwrap();
        window.set_sort_name("beach.jpg".into());

        // A snapshot with nothing in it at all: every page keeps what it knew.
        apply(&window, Snapshot::default());
        assert_eq!(window.get_sort_name(), "beach.jpg");
    }

    /// A window narrower than its contents clips them: the right-hand buttons go over the
    /// edge and there is nothing to say they are there. So the declared minimum has to be
    /// at least as wide as the widest tab, and every tab has to be able to reach it.
    #[test]
    fn nothing_falls_off_the_edge_at_the_smallest_window() {
        use i_slint_backend_testing::ElementHandle;

        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().unwrap();

        // The Sort tab holds the widest row, and only once it has a file to show.
        window.set_sort_have(true);
        window.set_sort_name("IMG_20240817_181203.jpg".into());
        window.set_sort_position("3 of 412".into());
        window.set_sort_in_folder(128);
        window.set_sort_folder("holidays/2024/corsica".into());
        window.set_sort_group_id("g1".into());
        window.set_sort_path("/photos/a.jpg".into());
        window.set_sort_has_next(true);
        window.set_sort_undo("Undo delete".into());

        let narrowest = window.get_narrowest();
        window
            .window()
            .set_size(slint::LogicalSize::new(narrowest, 420.0));

        // Every tab in the nav, the two Rust never reads for (Settings, About) included.
        const TABS: i32 = 8;

        for tab in STATUS..TABS {
            window.set_tab(tab);

            for kind in ["Button", "ComboBox", "LineEdit", "CheckBox"] {
                for control in ElementHandle::find_by_element_type_name(&window, kind) {
                    let right = control.absolute_position().x + control.size().width;
                    assert!(
                        right <= narrowest,
                        "tab {tab}: {kind} {:?} reaches {right}, past the {narrowest} edge",
                        control.accessible_label().unwrap_or_default()
                    );
                }
            }
        }
    }
}
