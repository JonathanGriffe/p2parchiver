use std::str::FromStr;

use ac_groups::id::GroupId;
use ac_net::PeerId;
use ac_net::identity::Keypair;

use crate::path::RelPath;
use crate::store::{FileRow, Files};

pub const AT: i64 = 1_000_000;

pub fn peer() -> PeerId {
    Keypair::generate_ed25519().public().to_peer_id()
}

pub fn group_id(seed: u8) -> GroupId {
    GroupId::from_str(&hex::encode([seed; 32])).unwrap()
}

pub fn store() -> (Files, PeerId) {
    let me = peer();
    (Files::in_memory(me).unwrap(), me)
}

pub fn row(me: PeerId, path: &str, hash: &str) -> FileRow {
    FileRow {
        path: RelPath::parse(path).unwrap(),
        size: 3,
        hash: hash.to_owned(),
        modified: AT,
        added_at: AT,
        added_by: me,
        removed_at: None,
        have: true,
        // Assigned by the store on write, so what a caller puts here is ignored.
        seen_seq: 0,
    }
}
