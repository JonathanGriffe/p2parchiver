#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Instant;

use ac_files::path::RelPath;
use ac_files::store::{FileRow, Files};
use ac_files::sync::{FileAction, FileEvent, FileSync, may_serve};
use ac_files::wire::{ManifestRequest, ManifestResponse};
use ac_files::{Content, ManifestEntry};
use ac_groups::chain::Op;
use ac_groups::id::GroupId;
use ac_groups::standing::Position;
use ac_groups::store::Groups;
use ac_net::PeerId;
use ac_net::connectivity::Connectivity;
use ac_net::identity::Keypair;
use ac_net::roster::Roster;

const AT: i64 = 1_000_000;

fn peer_of(k: &Keypair) -> PeerId {
    k.public().to_peer_id()
}

/// Everything one side needs to be driven, plus the temp directory its content lives in.
struct Node {
    key: Keypair,
    roster: Roster,
    sync: FileSync,
    _dir: tempfile::TempDir,
}

impl Node {
    fn new() -> Self {
        let key = Keypair::generate_ed25519();
        let me = peer_of(&key);
        let dir = tempfile::tempdir().unwrap();
        let sync = FileSync::new(
            Files::in_memory(me).unwrap(),
            Groups::in_memory(me).unwrap(),
            Content::new(dir.path().join("files")),
        );
        Self {
            key,
            roster: Roster::default(),
            sync,
            _dir: dir,
        }
    }

    fn peer(&self) -> PeerId {
        peer_of(&self.key)
    }

    /// Admit a peer and promote them, as the daemon's roster would.
    ///
    /// An empty `Connectivity` promotes everyone: `settled` is false only while a hole punch
    /// is still in flight, and these tests have no connections at all.
    fn verify(&mut self, other: PeerId) -> Vec<FileAction> {
        self.roster.admitted(other);
        self.roster.promote(&Connectivity::default());
        Vec::new()
    }

    /// Every call into the machine carries the roster, so who is admitted is asked rather
    /// than remembered.
    fn sync_on(&mut self, event: FileEvent) -> Vec<FileAction> {
        self.sync.on(event, &self.roster)
    }

    fn sync_on_request(
        &mut self,
        peer: PeerId,
        request: ManifestRequest,
    ) -> (ManifestResponse, Vec<FileAction>) {
        self.sync.on_request(peer, request, &self.roster)
    }

    /// The free function, which is the one the blob path actually calls.
    ///
    /// It takes no roster: a blob stream cannot exist without an admitted connection, so the
    /// only question left is whether the stores entitle this peer to these bytes.
    fn sync_may_serve(&mut self, peer: PeerId, group: GroupId, path: &RelPath) -> Option<u64> {
        may_serve(self.sync.files(), self.sync.groups(), &peer, group, path)
    }

    /// A peer that has gone. The roster forgets them; nothing else needs telling.
    fn forget(&mut self, other: PeerId) {
        self.roster.disconnected(&other, false);
    }

    fn tick(&mut self) -> Vec<FileAction> {
        self.sync_on(FileEvent::Tick {
            now: Instant::now(),
            at: AT,
        })
    }

    /// Put a file in this node's catalogue, with its bytes on disk.
    fn add(&mut self, group: GroupId, path: &str, content: &[u8], at: i64) -> RelPath {
        let path = RelPath::parse(path).unwrap();
        let dir = self.sync.dir_of(group).unwrap();

        let src = self._dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        let file = src.join("incoming");
        std::fs::write(&file, content).unwrap();

        let staged = self.sync.content().stage(&dir, &path, &file).unwrap();
        let row = FileRow {
            path: path.clone(),
            size: staged.size,
            hash: staged.hash.clone(),
            modified: at,
            added_at: at,
            added_by: self.peer(),
            removed_at: None,
            have: true,
            seen_seq: 0,
        };
        self.sync.content().commit(staged).unwrap();
        self.sync.files_mut().record(group, &row, true).unwrap();
        path
    }

    fn paths(&mut self, group: GroupId) -> Vec<String> {
        self.sync
            .files()
            .list(group, None, false)
            .unwrap()
            .iter()
            .map(|r| r.path.to_string())
            .collect()
    }

    fn digest(&self, group: GroupId) -> [u8; 32] {
        self.sync.files().digest(group).unwrap()
    }
}

/// Give every node the same group, with all of them as members and locally active.
///
/// The first node is its admin. Membership is what `shared_with` reads, and `shared_with` is
/// the only thing allowed to name a group's content to a peer, so without this nothing is
/// exchanged.
fn share_group(nodes: &mut [&mut Node]) -> GroupId {
    let admin_key = nodes[0].key.clone();
    let members: Vec<PeerId> = nodes[1..].iter().map(|n| n.peer()).collect();

    let id = nodes[0]
        .sync
        .groups_mut()
        .create(&admin_key, "holiday", "admin", AT)
        .unwrap();

    for (i, peer) in members.iter().enumerate() {
        nodes[0]
            .sync
            .groups_mut()
            .author(
                &admin_key,
                id,
                Op::Add {
                    peer: peer.to_base58(),
                    username: format!("member{i}"),
                },
                AT,
            )
            .unwrap();
    }

    let entries: Vec<_> = nodes[0]
        .sync
        .groups_mut()
        .chain(id)
        .unwrap()
        .entries()
        .cloned()
        .collect();

    for node in nodes[1..].iter_mut() {
        let key = node.key.clone();
        node.sync.groups_mut().adopt(&entries, &[], AT).unwrap();
        node.sync
            .groups_mut()
            .author_standing(&key, id, Position::In, AT)
            .unwrap();
    }
    id
}

#[derive(Clone, Debug)]
enum Step {
    /// The question the supervisor would put; which peers is decided by `Side`.
    Ask,
    Act(FileAction),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    A,
    B,
}

impl Side {
    fn other(self) -> Self {
        match self {
            Side::A => Side::B,
            Side::B => Side::A,
        }
    }
}

/// Dispatch actions between two nodes until nothing is left to send.
fn settle(a: &mut Node, b: &mut Node, seed: Vec<(Side, Step)>) -> Vec<FileAction> {
    let mut queue = seed;
    let mut seen = Vec::new();

    for _ in 0..500 {
        let Some((side, action)) = queue.pop() else {
            return seen;
        };
        if let Step::Act(act) = &action {
            seen.push(act.clone());
        }
        match side {
            Side::A => step(a, b, Side::A, action, &mut queue),
            Side::B => step(b, a, Side::B, action, &mut queue),
        }
    }
    panic!("the exchange never settled");
}

fn step(
    sender: &mut Node,
    receiver: &mut Node,
    side: Side,
    action: Step,
    queue: &mut Vec<(Side, Step)>,
) {
    match action {
        // A report, not an instruction. `ac-node` turns it into the supervisor's round
        // bookkeeping; here it only has to not be work.
        Step::Act(FileAction::Settled { .. }) => {}

        Step::Ask => {
            let (response, theirs) = receiver.sync_on_request(sender.peer(), ManifestRequest::Ask);
            queue.extend(theirs.into_iter().map(|x| (side.other(), Step::Act(x))));

            if let ManifestResponse::Heads(heads) = response {
                let mine = sender.sync_on(FileEvent::Heads {
                    peer: receiver.peer(),
                    heads,
                });
                queue.extend(mine.into_iter().map(|x| (side, Step::Act(x))));
            }
        }

        Step::Act(FileAction::FetchChanges { group, after, .. }) => {
            let (response, theirs) =
                receiver.sync_on_request(sender.peer(), ManifestRequest::Changes { group, after });
            queue.extend(theirs.into_iter().map(|x| (side.other(), Step::Act(x))));

            let event = match response {
                ManifestResponse::Changes {
                    group,
                    entries,
                    next,
                    more,
                    digest,
                } => FileEvent::Changes {
                    peer: receiver.peer(),
                    group,
                    after,
                    entries,
                    next,
                    more,
                    digest,
                },
                _ => FileEvent::Unavailable {
                    peer: receiver.peer(),
                    group,
                },
            };
            let mine = sender.sync_on(event);
            queue.extend(mine.into_iter().map(|x| (side, Step::Act(x))));
        }
    }
}

/// Connect two nodes and let them sync to quiescence. `a` is [`Side::A`].
/// Verify both ways and let each side offer, as the supervisor does on a fresh connection.
fn connect(a: &mut Node, b: &mut Node) -> Vec<FileAction> {
    a.verify(b.peer());
    b.verify(a.peer());

    let seed = vec![(Side::A, Step::Ask), (Side::B, Step::Ask)];
    settle(a, b, seed)
}

fn disconnect(a: &mut Node, b: &mut Node) {
    let (ap, bp) = (a.peer(), b.peer());
    a.forget(bp);
    b.forget(ap);
}

// ---- the regression this design exists for ----

#[test]
fn a_file_learned_late_still_reaches_the_third_member() {
    // Alice creates F and keeps it to herself. Bob and Carol sync, and both end up holding a
    // *newer* file. Only then does Bob learn F from Alice.
    //
    // A cursor over `added_at` fails here: Bob would offer Carol "everything since T5", and F
    // is stamped before that, so Carol never hears of it and nothing reports an error. A
    // cursor over Bob's own change log passes, because F is new *to Bob* whatever its age.
    let (mut alice, mut bob, mut carol) = (Node::new(), Node::new(), Node::new());
    let id = share_group(&mut [&mut alice, &mut bob, &mut carol]);

    // The old file, which nobody but Alice has.
    alice.add(id, "ancient.jpg", b"ancient", AT - 100_000);

    // Bob and Carol sync something newer, moving both their logs well past it.
    bob.add(id, "recent.jpg", b"recent", AT);
    connect(&mut bob, &mut carol);
    assert_eq!(carol.paths(id), vec!["recent.jpg"]);
    disconnect(&mut bob, &mut carol);

    // Bob meets Alice and learns the old file.
    connect(&mut alice, &mut bob);
    assert!(
        bob.paths(id).contains(&"ancient.jpg".to_owned()),
        "bob learned it from alice"
    );
    disconnect(&mut alice, &mut bob);

    // Bob meets Carol again. The old file must travel.
    connect(&mut bob, &mut carol);
    assert!(
        carol.paths(id).contains(&"ancient.jpg".to_owned()),
        "a file created before bob and carol last spoke still reaches carol"
    );
    assert_eq!(bob.digest(id), carol.digest(id));
}

// ---- ordinary reconciliation ----

#[test]
fn two_members_converge_on_one_catalogue() {
    let (mut alice, mut bob) = (Node::new(), Node::new());
    let id = share_group(&mut [&mut alice, &mut bob]);

    alice.add(id, "photos/a.jpg", b"a", AT);
    alice.add(id, "photos/b.jpg", b"b", AT);
    bob.add(id, "docs/c.md", b"c", AT);

    connect(&mut alice, &mut bob);

    assert_eq!(alice.digest(id), bob.digest(id));
    assert_eq!(alice.paths(id).len(), 3);
    assert_eq!(bob.paths(id).len(), 3);
}

#[test]
fn a_catalogue_that_already_matches_costs_nothing() {
    let (mut alice, mut bob) = (Node::new(), Node::new());
    let id = share_group(&mut [&mut alice, &mut bob]);
    alice.add(id, "a.jpg", b"a", AT);
    connect(&mut alice, &mut bob);
    disconnect(&mut alice, &mut bob);

    // Reconnecting with equal digests must exchange no rows at all.
    alice.verify(bob.peer());
    bob.verify(alice.peer());
    let seed = vec![(Side::A, Step::Ask), (Side::B, Step::Ask)];
    let acted = settle(&mut alice, &mut bob, seed);

    // The digests already agree, so neither side even asks for a page. Stronger than checking
    // that nothing was learned: nothing was *read*.
    assert!(
        !acted
            .iter()
            .any(|a| matches!(a, FileAction::FetchChanges { .. })),
        "equal digests must exchange no rows at all: {acted:?}"
    );
}

#[test]
fn a_removal_propagates_and_does_not_come_back() {
    let (mut alice, mut bob) = (Node::new(), Node::new());
    let id = share_group(&mut [&mut alice, &mut bob]);
    let path = alice.add(id, "a.jpg", b"a", AT);
    connect(&mut alice, &mut bob);

    alice.sync.files_mut().remove(id, &path, AT + 100).unwrap();

    // Three reconnections: a tombstone that could be undone would show up here.
    for _ in 0..3 {
        disconnect(&mut alice, &mut bob);
        connect(&mut alice, &mut bob);
        assert!(bob.paths(id).is_empty(), "it stays gone");
    }
    assert_eq!(alice.digest(id), bob.digest(id));
}

// ---- authorization ----

#[test]
fn a_non_member_is_told_nothing_however_it_asks() {
    let (mut alice, mut bob) = (Node::new(), Node::new());
    let id = share_group(&mut [&mut alice, &mut bob]);
    alice.add(id, "secret.jpg", b"s", AT);

    let mut stranger = Node::new();
    alice.verify(stranger.peer());
    stranger.verify(alice.peer());

    let (offer, _) = alice.sync_on_request(stranger.peer(), ManifestRequest::Ask);
    assert_eq!(offer, ManifestResponse::Heads(Vec::new()));

    let (changes, _) = alice.sync_on_request(
        stranger.peer(),
        ManifestRequest::Changes {
            group: id,
            after: 0,
        },
    );
    assert_eq!(changes, ManifestResponse::Unavailable);

    let path = RelPath::parse("secret.jpg").unwrap();
    assert_eq!(
        alice.sync_may_serve(stranger.peer(), id, &path),
        None,
        "and no bytes either"
    );
}

#[test]
fn an_unverified_peer_is_answered_nothing() {
    let (mut alice, mut bob) = (Node::new(), Node::new());
    let id = share_group(&mut [&mut alice, &mut bob]);

    // Bob is a member but has not completed attestation.
    let (response, _) = alice.sync_on_request(
        bob.peer(),
        ManifestRequest::Changes {
            group: id,
            after: 0,
        },
    );
    assert_eq!(response, ManifestResponse::Unavailable);
}

#[test]
fn bytes_are_not_served_for_a_file_we_do_not_hold() {
    let (mut alice, mut bob) = (Node::new(), Node::new());
    let id = share_group(&mut [&mut alice, &mut bob]);
    alice.add(id, "a.jpg", b"a", AT);
    connect(&mut alice, &mut bob);

    // Bob knows the file exists but has not downloaded it.
    let path = RelPath::parse("a.jpg").unwrap();
    assert!(!bob.sync.row(id, &path).unwrap().have);
    assert_eq!(bob.sync_may_serve(alice.peer(), id, &path), None);
    assert!(alice.sync_may_serve(bob.peer(), id, &path).is_some());
}

#[test]
fn a_flood_of_requests_is_refused_and_refills_on_the_tick() {
    let (mut alice, mut bob) = (Node::new(), Node::new());
    let id = share_group(&mut [&mut alice, &mut bob]);
    alice.verify(bob.peer());

    let ask = |a: &mut Node| {
        a.sync_on_request(
            bob.peer(),
            ManifestRequest::Changes {
                group: id,
                after: 0,
            },
        )
        .0
    };

    let refused = (0..40)
        .filter(|_| ask(&mut alice) == ManifestResponse::Unavailable)
        .count();
    assert!(refused > 0, "a flood is throttled");
    assert_eq!(ask(&mut alice), ManifestResponse::Unavailable);

    alice.tick();
    assert_ne!(ask(&mut alice), ManifestResponse::Unavailable, "refilled");
}

#[test]
fn a_holdings_query_answers_only_for_what_is_actually_held() {
    let (mut alice, mut bob) = (Node::new(), Node::new());
    let id = share_group(&mut [&mut alice, &mut bob]);
    alice.add(id, "held.jpg", b"here", AT);
    let gone = alice.add(id, "removed.jpg", b"deleted", AT);
    alice.sync.files_mut().remove(id, &gone, AT + 5).unwrap();

    connect(&mut alice, &mut bob);

    let paths = vec![
        "held.jpg".to_owned(),
        "removed.jpg".to_owned(),
        "never-existed.jpg".to_owned(),
        "../escape".to_owned(),
    ];
    let (response, _) = alice.sync_on_request(
        bob.peer(),
        ManifestRequest::Holdings {
            group: id,
            paths: paths.clone(),
        },
    );

    let ManifestResponse::Holdings { held, .. } = response else {
        panic!("expected a bitmap, got {response:?}");
    };

    assert!(ac_files::wire::holds(&held, 0), "held.jpg");
    assert!(!ac_files::wire::holds(&held, 1), "a tombstone is not held");
    assert!(
        !ac_files::wire::holds(&held, 2),
        "an unknown path is not held"
    );
    assert!(
        !ac_files::wire::holds(&held, 3),
        "an unparseable path answers false rather than failing the whole query"
    );
}

#[test]
fn a_holdings_query_from_a_non_member_is_refused() {
    // The same membership-oracle argument as `Changes`: naming the group exactly must not
    // reveal whether it exists, let alone what anyone holds.
    let (mut alice, mut bob) = (Node::new(), Node::new());
    let id = share_group(&mut [&mut alice, &mut bob]);
    alice.add(id, "secret.jpg", b"s", AT);

    let stranger = Node::new();
    alice.verify(stranger.peer());

    let (response, _) = alice.sync_on_request(
        stranger.peer(),
        ManifestRequest::Holdings {
            group: id,
            paths: vec!["secret.jpg".to_owned()],
        },
    );
    assert_eq!(response, ManifestResponse::Unavailable);
}

#[test]
fn a_peer_that_knows_a_file_but_lacks_it_says_so() {
    let (mut alice, mut bob) = (Node::new(), Node::new());
    let id = share_group(&mut [&mut alice, &mut bob]);
    alice.add(id, "big.bin", b"contents", AT);
    connect(&mut alice, &mut bob);

    assert_eq!(
        alice.digest(id),
        bob.digest(id),
        "catalogues agree, which is why no entries would be exchanged"
    );

    let (response, _) = bob.sync_on_request(
        alice.peer(),
        ManifestRequest::Holdings {
            group: id,
            paths: vec!["big.bin".to_owned()],
        },
    );
    let ManifestResponse::Holdings { held, .. } = response else {
        panic!("expected a bitmap");
    };
    assert!(
        !ac_files::wire::holds(&held, 0),
        "bob knows the file exists and does not hold it"
    );
}

// ---- reporting a settled round ----

#[test]
fn agreeing_about_a_group_is_reported_as_settled() {
    let (mut alice, mut bob) = (Node::new(), Node::new());
    let id = share_group(&mut [&mut alice, &mut bob]);
    alice.add(id, "beach.jpg", b"a photograph", AT);
    connect(&mut alice, &mut bob);

    // They now agree. Asking again should settle immediately, reading nothing.
    let (response, _) = bob.sync_on_request(alice.peer(), ManifestRequest::Ask);
    let ManifestResponse::Heads(theirs) = response else {
        panic!("expected heads back");
    };

    let actions = alice.sync_on(FileEvent::Heads {
        peer: bob.peer(),
        heads: theirs,
    });

    assert!(
        actions.iter().any(|a| matches!(
            a,
            FileAction::Settled { peer, group } if *peer == bob.peer() && *group == id
        )),
        "an agreed group settles at once: {actions:?}"
    );
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, FileAction::FetchChanges { .. })),
        "and reads nothing: {actions:?}"
    );
}

#[test]
fn a_round_that_had_to_read_pages_settles_when_it_runs_out() {
    // The other end of the same signal. A group that *did* have something to transfer must
    // report settled once the last page has been applied, or the round never completes and the
    // supervisor never records the member as told.
    let (mut alice, mut bob) = (Node::new(), Node::new());
    let id = share_group(&mut [&mut alice, &mut bob]);
    alice.add(id, "beach.jpg", b"a photograph", AT);

    connect(&mut alice, &mut bob);

    // Bob learned the file, which means he read at least one page. Asking again proves the
    // settle arrives on the reading path too.
    let (response, _) = alice.sync_on_request(bob.peer(), ManifestRequest::Ask);
    let ManifestResponse::Heads(theirs) = response else {
        panic!("expected heads back");
    };
    let actions = bob.sync_on(FileEvent::Heads {
        peer: alice.peer(),
        heads: theirs,
    });

    assert!(
        actions
            .iter()
            .any(|a| matches!(a, FileAction::Settled { .. })),
        "a group both sides agree on settles however it got there: {actions:?}"
    );
    assert_eq!(bob.paths(id), alice.paths(id), "and they do agree");
}

// ---- this machine is catalogue-only ----

#[test]
fn a_sync_moves_no_bytes() {
    let (mut alice, mut bob) = (Node::new(), Node::new());
    let id = share_group(&mut [&mut alice, &mut bob]);
    alice.add(id, "big.bin", b"a large file", AT);

    let path = RelPath::parse("big.bin").unwrap();

    connect(&mut alice, &mut bob);

    let row = bob.sync.row(id, &path).expect("the catalogue arrived");
    assert!(!row.have, "the catalogue arrived without the bytes");

    let dir = bob.sync.dir_of(id).unwrap();
    assert!(
        !bob.sync.content().locate(&dir, &path).exists(),
        "nothing here may put a file on disk"
    );
}

// ---- collisions ----

#[test]
fn two_different_files_at_one_path_both_survive_a_sync() {
    let (mut alice, mut bob) = (Node::new(), Node::new());
    let id = share_group(&mut [&mut alice, &mut bob]);

    // Added while apart, same name, different content.
    alice.add(id, "photos/beach.jpg", b"alice's photo", AT);
    bob.add(id, "photos/beach.jpg", b"bob's photo", AT + 10);

    connect(&mut alice, &mut bob);

    assert_eq!(alice.digest(id), bob.digest(id), "they agree");
    assert_eq!(alice.paths(id).len(), 2, "nothing was thrown away");
    assert_eq!(bob.paths(id).len(), 2);
    assert_eq!(alice.paths(id), bob.paths(id));
    assert!(
        alice.paths(id).iter().any(|p| p.contains(".conflict-")),
        "the loser kept its content under a derived name: {:?}",
        alice.paths(id)
    );
}

#[test]
fn duplicate_content_collapses_the_same_way_on_both_sides() {
    let (mut alice, mut bob) = (Node::new(), Node::new());
    let id = share_group(&mut [&mut alice, &mut bob]);

    // The same bytes, filed under two names.
    alice.add(id, "albums/beach.jpg", b"one photo", AT);
    bob.add(id, "favourites/beach.jpg", b"one photo", AT + 10);

    connect(&mut alice, &mut bob);

    assert_eq!(alice.digest(id), bob.digest(id));
    assert_eq!(
        alice.paths(id),
        vec!["albums/beach.jpg"],
        "the earlier path is the one that survives"
    );
    assert_eq!(bob.paths(id), alice.paths(id));
}

#[test]
fn a_conflict_converges_whatever_order_three_members_meet_in() {
    // The winner is a pure function of the rows, so the order the pairings happen in must not
    // change where anything ends up.
    let mut ends = Vec::new();

    for order in [[(0, 1), (1, 2), (0, 2)], [(1, 2), (0, 2), (0, 1)]] {
        let mut nodes = [Node::new(), Node::new(), Node::new()];
        let id = {
            let mut refs: Vec<&mut Node> = nodes.iter_mut().collect();
            share_group(&mut refs)
        };

        nodes[0].add(id, "p.jpg", b"first", AT);
        nodes[1].add(id, "p.jpg", b"second", AT + 5);
        nodes[2].add(id, "p.jpg", b"third", AT + 10);

        // Twice around, so everything has a chance to reach everyone.
        for _ in 0..2 {
            for (i, j) in order {
                let (lo, hi) = nodes.split_at_mut(j.max(i));
                connect(&mut lo[i.min(j)], &mut hi[0]);
                disconnect(&mut lo[i.min(j)], &mut hi[0]);
            }
        }

        let mut paths = nodes[0].paths(id);
        paths.sort();
        assert_eq!(nodes[0].digest(id), nodes[1].digest(id), "{order:?}");
        assert_eq!(nodes[1].digest(id), nodes[2].digest(id), "{order:?}");
        assert_eq!(paths.len(), 3, "three files, three names: {paths:?}");
        ends.push(paths);
    }

    assert_eq!(
        ends[0], ends[1],
        "the meeting order does not decide anything"
    );
}

// ---- the cursor is an optimisation; the digest is the check ----

#[test]
fn a_wrong_cursor_is_repaired_rather_than_losing_a_file() {
    let (mut alice, mut bob) = (Node::new(), Node::new());
    let id = share_group(&mut [&mut alice, &mut bob]);
    alice.add(id, "a.jpg", b"a", AT);
    alice.add(id, "b.jpg", b"b", AT);

    // Bob's cursor claims he has read Alice's whole log, which he has not. Without the digest
    // check this would silently skip both files for ever.
    bob.sync
        .files_mut()
        .set_cursor(id, &alice.peer(), 9_999)
        .unwrap();

    connect(&mut alice, &mut bob);

    assert_eq!(bob.paths(id).len(), 2, "the full re-read recovered them");
    assert_eq!(alice.digest(id), bob.digest(id));
}

#[test]
fn a_page_larger_than_the_limit_converges_over_several_rounds() {
    let (mut alice, mut bob) = (Node::new(), Node::new());
    let id = share_group(&mut [&mut alice, &mut bob]);

    // More rows than one response carries, so `more` has to be honoured.
    let many = ac_files::wire::MAX_ENTRIES_PER_RESPONSE + 50;
    for i in 0..many {
        alice.add(id, &format!("f{i:05}.bin"), format!("{i}").as_bytes(), AT);
    }

    connect(&mut alice, &mut bob);

    assert_eq!(bob.paths(id).len(), many);
    assert_eq!(alice.digest(id), bob.digest(id));
}

#[test]
fn an_unsolicited_page_is_ignored() {
    let (mut alice, mut bob) = (Node::new(), Node::new());
    let id = share_group(&mut [&mut alice, &mut bob]);
    alice.verify(bob.peer());
    bob.verify(alice.peer());

    // A valid-looking page nobody asked for. Only the request actually in flight may move
    // our state, or a peer could write to us whenever it liked.
    let row = FileRow {
        path: RelPath::parse("injected.jpg").unwrap(),
        size: 1,
        hash: hex::encode([1u8; 32]),
        modified: AT,
        added_at: AT,
        added_by: alice.peer(),
        removed_at: None,
        have: false,
        seen_seq: 0,
    };
    let actions = bob.sync_on(FileEvent::Changes {
        peer: alice.peer(),
        group: id,
        after: 0,
        entries: vec![ManifestEntry::of(&row).unwrap()],
        next: 1,
        more: false,
        digest: [0u8; 32],
    });

    assert!(actions.is_empty());
    assert!(
        bob.paths(id).is_empty(),
        "nothing was asked for, so nothing may be applied"
    );
}

#[test]
fn a_refused_reading_still_reports_the_round_as_over() {
    let (mut alice, mut bob) = (Node::new(), Node::new());
    let id = share_group(&mut [&mut alice, &mut bob]);
    connect(&mut alice, &mut bob);

    let refused = alice.sync_on(FileEvent::Unavailable {
        peer: bob.peer(),
        group: id,
    });
    assert!(
        refused
            .iter()
            .any(|a| matches!(a, FileAction::Settled { group, .. } if *group == id)),
        "a refusal ends the round: {refused:?}"
    );

    let failed = alice.sync_on(FileEvent::RequestFailed {
        peer: bob.peer(),
        group: Some(id),
    });
    assert!(
        failed
            .iter()
            .any(|a| matches!(a, FileAction::Settled { group, .. } if *group == id)),
        "and so does a request that never arrived: {failed:?}"
    );
}

#[test]
fn a_peer_that_disconnects_is_forgotten() {
    let (mut alice, mut bob) = (Node::new(), Node::new());
    let id = share_group(&mut [&mut alice, &mut bob]);
    alice.add(id, "a.jpg", b"a", AT);
    connect(&mut alice, &mut bob);
    disconnect(&mut alice, &mut bob);

    let (response, _) = alice.sync_on_request(
        bob.peer(),
        ManifestRequest::Changes {
            group: id,
            after: 0,
        },
    );
    assert_eq!(
        response,
        ManifestResponse::Unavailable,
        "a gone peer is not verified"
    );
}
