use ac_node::ops::file::Storage;
use ac_node::ops::format::human_size;
use ac_node::ops::peer::{Liveness, StatusReport};

use crate::ui::{GroupRow, PeerRow};

const IDLE: i32 = 0;
const WORKING: i32 = 1;
const WAITING: i32 = 2;
const QUIET: i32 = 3;

pub struct Snapshot {
    pub running: bool,
    pub node_state: String,
    pub storage: String,
    pub groups: Vec<GroupRow>,
    pub peers: Vec<PeerRow>,
}

pub fn present(report: &StatusReport, storage: Option<&Storage>) -> Snapshot {
    let now = report.now;

    let (running, node_state) = match report.liveness {
        Liveness::Never => (false, "the node has never run".to_owned()),
        Liveness::Stale { seconds } => (
            false,
            format!("last seen {seconds}s ago, the node is not running"),
        ),
        Liveness::Live => (true, "running".to_owned()),
    };

    let groups = report
        .groups
        .iter()
        .map(|group| GroupRow {
            name: group.label.clone().into(),
            id: group.group.short().into(),
            missing: group.missing.to_string().into(),
            news: match group.owed {
                0 => "nobody left to call".to_owned(),
                1 => "1 member to call".to_owned(),
                n => format!("{n} members to call"),
            }
            .into(),
            pulling: match &group.source {
                Some(name) => format!("from {name}"),
                None if now < group.content_until => {
                    format!("paused for {}s", group.content_until - now)
                }
                None if group.missing > 0 => "nobody has offered them".to_owned(),
                None => "nothing to fetch".to_owned(),
            }
            .into(),
            next: group.next.clone().unwrap_or_default().into(),
            heartbeat: format!("in {}s", (group.heartbeat_at - now).max(0)).into(),
            waiting: group.missing > 0,
        })
        .collect();

    let peers = report
        .peers
        .iter()
        .map(|peer| {
            let (tone, state) = if peer.connected {
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
            };

            PeerRow {
                name: peer.name.clone().into(),
                state: state.into(),
                tone,
            }
        })
        .collect();

    Snapshot {
        running,
        node_state,
        storage: describe_storage(storage),
        groups,
        peers,
    }
}

fn describe_storage(storage: Option<&Storage>) -> String {
    let Some(storage) = storage else {
        return String::new();
    };

    let mut parts = vec![format!("{} held", human_size(storage.held))];
    if let Some(max) = storage.max {
        parts.push(format!("of {} allowed", human_size(max)));
    }
    if let Some(free) = storage.free {
        parts.push(format!("{} free", human_size(free)));
    }
    parts.join(" · ")
}
