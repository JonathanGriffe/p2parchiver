use ac_files::path::RelPath;
use ac_files::store::{Files, FilesError};
use ac_groups::id::GroupId;
use ac_groups::store::StoreError;

pub fn next_missing(
    files: &Files,
    group: GroupId,
    limit: usize,
) -> Result<Vec<(RelPath, String)>, PeersError> {
    Ok(files
        .missing(group, limit)?
        .into_iter()
        .map(|row| (row.path, row.hash))
        .collect())
}

#[derive(Debug, thiserror::Error)]
pub enum PeersError {
    #[error(transparent)]
    Files(#[from] FilesError),
    #[error(transparent)]
    Groups(#[from] StoreError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ac_files::store::FileRow;
    use ac_groups::store::Groups;
    use ac_net::PeerId;
    use ac_net::identity::Keypair;

    const AT: i64 = 1_000_000;

    /// A node's two stores and the group it admins.
    struct Node {
        files: Files,
        groups: Groups,
        key: Keypair,
        me: PeerId,
        _dir: tempfile::TempDir,
    }

    impl Node {
        fn new() -> Self {
            let key = Keypair::generate_ed25519();
            let me = key.public().to_peer_id();
            let dir = tempfile::tempdir().unwrap();
            Self {
                files: Files::in_memory(me).unwrap(),
                groups: Groups::in_memory(me).unwrap(),
                key,
                me,
                _dir: dir,
            }
        }

        fn group(&mut self) -> GroupId {
            let key = self.key.clone();
            self.groups.create(&key, "holiday", "alice", AT).unwrap()
        }

        /// A row we hold the bytes for.
        fn add(&mut self, group: GroupId, path: &str) {
            self.record(group, path, true);
        }

        /// A row we know about and do not hold — what a catalogue sync leaves behind.
        fn learn(&mut self, group: GroupId, path: &str) {
            self.record(group, path, false);
        }

        fn record(&mut self, group: GroupId, path: &str, have: bool) {
            let path = RelPath::parse(path).unwrap();
            let row = FileRow {
                size: 1,
                hash: hex::encode(sha_of(path.as_str())),
                modified: AT,
                added_at: AT,
                added_by: self.me,
                removed_at: None,
                have,
                seen_seq: 0,
                path: path.clone(),
            };
            self.files.record(group, &row, true).unwrap();
            if !have {
                self.files.mark_have(group, &path, false).unwrap();
            }
        }
    }

    fn sha_of(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in s.bytes().enumerate() {
            out[i % 32] ^= b;
        }
        out
    }

    #[test]
    fn missing_counts_only_what_is_live_and_unheld() {
        // The count the content loop starts from. It used to reach this through `behind`, which
        // is why the property was asserted there; it asks the index directly now, so this
        // belongs to the index.
        let mut node = Node::new();
        let id = node.group();

        node.add(id, "held.jpg");
        node.learn(id, "wanted-a.jpg");
        node.learn(id, "wanted-b.jpg");

        let gone = RelPath::parse("wanted-b.jpg").unwrap();
        node.files.remove(id, &gone, AT + 1).unwrap();

        assert_eq!(
            node.files.missing_count(id).unwrap(),
            1,
            "the held file and the tombstone are both excluded"
        );
    }

    #[test]
    fn wanted_files_come_first() {
        // Under auto-mirror everything arrives eventually, so `ac file get` is a statement
        // about order and nothing else. This is the whole of what it now does.
        let mut node = Node::new();
        let id = node.group();
        node.learn(id, "a-early.jpg");
        node.learn(id, "z-late.jpg");

        let wanted = RelPath::parse("z-late.jpg").unwrap();
        node.files.want(id, &wanted).unwrap();

        let next = next_missing(&node.files, id, 10).unwrap();
        assert_eq!(
            next.first().map(|(p, _)| p.as_str()),
            Some("z-late.jpg"),
            "the wanted row jumps the queue despite sorting last"
        );
        assert_eq!(next.len(), 2, "and the rest still follow");
    }

    #[test]
    fn next_missing_honours_its_limit() {
        let mut node = Node::new();
        let id = node.group();
        for i in 0..10 {
            node.learn(id, &format!("f{i}.jpg"));
        }

        assert_eq!(next_missing(&node.files, id, 4).unwrap().len(), 4);
    }

    #[test]
    fn nothing_is_asked_for_when_we_hold_it_all() {
        let mut node = Node::new();
        let id = node.group();
        node.add(id, "a.jpg");
        node.add(id, "b.jpg");

        assert_eq!(node.files.missing_count(id).unwrap(), 0);
        assert!(next_missing(&node.files, id, 10).unwrap().is_empty());
    }
}
