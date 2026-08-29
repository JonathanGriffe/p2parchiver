#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashSet;

use ac_files::Content;
use ac_files::path::RelPath;
use ac_files::store::{FileRow, Files};
use ac_groups::chain::Op;
use ac_groups::id::GroupId;
use ac_groups::standing::{Position, Standing};
use ac_groups::store::Groups;
use ac_net::PeerId;
use ac_net::identity::Keypair;
use ac_peers::sync::{
    CLOSE_TIMEOUT, DIAL_ATTEMPTS, DIAL_WINDOW, DIALS_PER_ROUND, DIALS_PER_WINDOW, HEARTBEAT,
    Limits, MAX_TRANSFERS, MIN_BACKOFF, NoRoom, Offering, PRESENCE_INTERVAL, PeerAction, PeerEvent,
    Peers, RETRY_AFTER, RETRY_ATTEMPTS, ROUND_TIMEOUT, SHARE_AFTER_IDLE,
};
use tempfile::TempDir;

const AT: i64 = 1_000_000;

/// One node's supervisor, plus the keys of everyone it shares a group with.
struct Node {
    peers: Peers,
    key: Keypair,
    me: PeerId,
    /// Where `merge` would put bytes. Nothing in these tests transfers any, but a row that
    /// arrives from a peer goes through the real merge path, and that is what it wants.
    root: TempDir,
}

impl Node {
    fn new() -> Self {
        Self::with_limits(Limits::default())
    }

    fn with_limits(limits: Limits) -> Self {
        let key = Keypair::generate_ed25519();
        let me = key.public().to_peer_id();
        let root = tempfile::tempdir().unwrap();
        Self {
            root,
            peers: Peers::new(
                Files::in_memory(me).unwrap(),
                Groups::in_memory(me).unwrap(),
                AT,
            )
            .with_limits(limits),
            key,
            me,
        }
    }

    /// A group this node admins, with `members` added and accepted by us.
    fn group_with(&mut self, members: &[PeerId]) -> GroupId {
        let key = self.key.clone();
        let id = self
            .peers
            .groups_mut()
            .create(&key, "holiday", "alice", AT)
            .unwrap();

        for peer in members.iter() {
            self.peers
                .groups_mut()
                .author(
                    &key,
                    id,
                    Op::Add {
                        peer: peer.to_base58(),
                    },
                    AT,
                )
                .unwrap();
        }
        id
    }

    fn add_file(&mut self, group: GroupId, path: &str) {
        self.record(group, path, true);
    }

    fn learn_file(&mut self, group: GroupId, path: &str) {
        let row = self.row(path, false);
        let dir = self.peers.files_mut().dir_for(group, "holiday").unwrap();
        let content = Content::new(self.root.path().to_path_buf());
        self.peers
            .files_mut()
            .merge(group, &row, &content, &dir)
            .unwrap();
    }

    fn record(&mut self, group: GroupId, path: &str, have: bool) {
        let row = self.row(path, have);
        self.peers.files_mut().record(group, &row, true).unwrap();
    }

    fn row(&self, path: &str, have: bool) -> FileRow {
        let path = RelPath::parse(path).unwrap();
        let mut hash = [0u8; 32];
        for (i, b) in path.as_str().bytes().enumerate() {
            hash[i % 32] ^= b;
        }
        FileRow {
            path: path.clone(),
            size: 1,
            hash: hex::encode(hash),
            modified: AT,
            added_at: AT,
            added_by: self.me,
            removed_at: None,
            have,
            seen_seq: 0,
        }
    }

    fn tick(&mut self, at: i64) -> Vec<PeerAction> {
        self.peers.on(PeerEvent::Tick { at })
    }

    /// Every group this node holds, which is what an offer to any member names.
    fn shared_groups(&mut self) -> Vec<GroupId> {
        self.peers
            .groups_mut()
            .list()
            .unwrap_or_default()
            .into_iter()
            .map(|row| row.id)
            .collect()
    }

    /// `ac group add`, after the group exists.
    fn add_member(&mut self, group: GroupId, peer: PeerId) {
        let key = self.key.clone();
        self.peers
            .groups_mut()
            .author(
                &key,
                group,
                Op::Add {
                    peer: peer.to_base58(),
                },
                AT,
            )
            .unwrap();
    }

    fn accept_invite(&mut self, group: GroupId, key: &Keypair) {
        let standing = Standing::author(key, group, 1, Position::In, "someone", AT).unwrap();
        let entries: Vec<_> = self
            .peers
            .groups_mut()
            .chain(group)
            .unwrap()
            .entries()
            .cloned()
            .collect();
        self.peers
            .groups_mut()
            .adopt(&entries, &[standing], AT)
            .unwrap();
    }

    /// Tick, then answer whatever circuit it opened and whatever hang-up it proposed.
    fn tick_connecting(&mut self, at: i64) -> Vec<PeerAction> {
        let actions = self.tick(at);
        let mut out = Vec::new();
        for action in &actions {
            match action {
                PeerAction::Dial { peer } => {
                    out.extend(self.peers.on(PeerEvent::Verified { peer: *peer }));
                }
                // The other half of the lifecycle, and it matters now: a member is told nothing
                // while we hold a connection to them, so the hang-up is what lets the next call
                // deliver. A test that never closes never gets a second round.
                PeerAction::ProposeClose { peer } => {
                    out.extend(self.peers.on(PeerEvent::CloseAnswered {
                        peer: *peer,
                        ready: true,
                    }));
                }
                PeerAction::Disconnect { peer } => {
                    out.extend(self.peers.on(PeerEvent::Gone { peer: *peer }));
                }
                _ => {}
            }
        }
        // A close answered inside the loop above yields the `Disconnect` that ends it.
        let follow: Vec<PeerAction> = out.clone();
        for action in &follow {
            if let PeerAction::Disconnect { peer } = action {
                self.peers.on(PeerEvent::Gone { peer: *peer });
            }
        }
        out.extend(actions);
        out
    }

    /// The connections close, as `closes` and the daemon would have them.
    ///
    /// A member is told nothing while we hold a connection to them, so a test that wants a
    /// change delivered has to let the call end first.
    fn hang_up(&mut self, members: &[PeerId]) {
        for peer in members {
            self.peers.on(PeerEvent::Gone { peer: *peer });
        }
    }

    /// Everyone reachable and nobody connected, which is the ordinary state here.
    fn all_online(&mut self, members: &[PeerId]) {
        self.peers.on(PeerEvent::Presence {
            asked: members.to_vec(),
            online: members.to_vec(),
        });
    }

    /// Everyone online and connected, as a settled network would be.
    fn all_up(&mut self, members: &[PeerId]) -> Vec<PeerAction> {
        self.peers.on(PeerEvent::Presence {
            asked: members.to_vec(),
            online: members.to_vec(),
        });
        let mut seen = Vec::new();
        for peer in members {
            let actions = self.peers.on(PeerEvent::Verified { peer: *peer });
            seen.extend(self.settle_all(&actions));
        }
        seen
    }

    fn settle_all(&mut self, actions: &[PeerAction]) -> Vec<PeerAction> {
        let groups = self.shared_groups();
        let mut queue: Vec<PeerAction> = actions.to_vec();
        let mut seen = Vec::new();

        while let Some(action) = queue.pop() {
            if let PeerAction::Ask { peer, offering } = action {
                for group in &groups {
                    queue.extend(self.peers.on(PeerEvent::Synced {
                        peer,
                        group: *group,
                        offering,
                    }));
                }
                queue.extend(self.peers.on(PeerEvent::Asked { peer, offering }));
            }
            seen.push(action);
        }
        seen
    }
}

fn peers(n: usize) -> Vec<PeerId> {
    (0..n)
        .map(|_| Keypair::generate_ed25519().public().to_peer_id())
        .collect()
}

/// One tick, answering every holdings query with exactly `held` of what it named.
fn step_holding(node: &mut Node, at: i64, held: &[RelPath]) -> Vec<PeerAction> {
    let mut seen = Vec::new();
    let mut queue = node.tick_connecting(at);

    while let Some(action) = queue.pop() {
        match &action {
            PeerAction::Ask { peer, offering } => {
                for group in node.shared_groups() {
                    queue.extend(node.peers.on(PeerEvent::Synced {
                        peer: *peer,
                        group,
                        offering: *offering,
                    }));
                }
                queue.extend(node.peers.on(PeerEvent::Asked {
                    peer: *peer,
                    offering: *offering,
                }));
            }
            PeerAction::AskHoldings { peer, group, paths } => {
                let answer: Vec<bool> = paths.iter().map(|p| held.contains(p)).collect();
                queue.extend(node.peers.on(PeerEvent::Holdings {
                    peer: *peer,
                    group: *group,
                    held: answer,
                    paths: paths.clone(),
                }));
            }
            _ => {}
        }
        seen.push(action);
    }
    seen
}

/// One tick, with any offer it starts reported as settled.
///
/// A peer may have one offer outstanding, so a test that ticks several times without answering
/// finds the peer busy and then looks quiet for the wrong reason.
fn answered(node: &mut Node, at: i64, group: GroupId) -> Vec<PeerAction> {
    let actions = node.tick_connecting(at);
    settle_offers(node, &actions, group);
    actions
}

/// Answer every question the way the daemon would, on the protocol it was put on.
///
/// Two events, because the links report two facts. `Asked` is the pull's own: the question was
/// answered, so that half is over and the other follows on it. `Synced` is what the reading side
/// reports per group once there is nothing further to read from them.
///
/// Membership and the catalogue are separate exchanges, so a peer is reconciled in two steps;
/// answering both as though they were the second leaves the first outstanding for ever.
fn settle_offers(node: &mut Node, actions: &[PeerAction], group: GroupId) -> Vec<PeerId> {
    let mut asked = Vec::new();
    // A settled chain round hands back the catalogue round behind it, so the answering carries
    // on from what the answer produced rather than waiting for another tick to be driven.
    let mut queue: Vec<PeerAction> = actions.to_vec();

    while let Some(action) = queue.pop() {
        if let PeerAction::Ask { peer, offering } = action {
            node.peers.on(PeerEvent::Synced {
                peer,
                group,
                offering,
            });
            queue.extend(node.peers.on(PeerEvent::Asked { peer, offering }));
            asked.push(peer);
        }
    }
    asked
}

/// Tick once to notice an edit, and answer when the pause it must wait out has elapsed.
fn after_editing_pause(node: &mut Node, at: i64) -> i64 {
    node.tick(at);
    at + SHARE_AFTER_IDLE + 1
}

fn presence_asked(actions: &[PeerAction]) -> Vec<PeerId> {
    actions
        .iter()
        .filter_map(|a| match a {
            PeerAction::AskPresence { peers } => Some(peers.clone()),
            _ => None,
        })
        .flatten()
        .collect()
}

fn fetched_paths(actions: &[PeerAction]) -> Vec<RelPath> {
    actions
        .iter()
        .filter_map(|a| match a {
            PeerAction::FetchBlob { path, .. } => Some(path.clone()),
            _ => None,
        })
        .collect()
}

fn dials(actions: &[PeerAction]) -> Vec<PeerId> {
    actions
        .iter()
        .filter_map(|a| match a {
            PeerAction::Dial { peer } => Some(*peer),
            _ => None,
        })
        .collect()
}

/// One tick, with every action answered the way a cooperative network would.
fn step(node: &mut Node, at: i64, holds: bool) -> Vec<PeerAction> {
    let mut seen = Vec::new();
    let mut queue = node.tick(at);

    while let Some(action) = queue.pop() {
        match &action {
            PeerAction::Ask { peer, offering } => {
                for group in node.shared_groups() {
                    queue.extend(node.peers.on(PeerEvent::Synced {
                        peer: *peer,
                        group,
                        offering: *offering,
                    }));
                }
                // The question is answered, whatever the answer was. Without this the exchange
                // stays open, is swept as a failure, and the node never goes quiet.
                queue.extend(node.peers.on(PeerEvent::Asked {
                    peer: *peer,
                    offering: *offering,
                }));
            }
            // A dial that is answered, which is what makes the question that follows it happen:
            // the supervisor asks on `Verified`, not on the tick that opened the circuit.
            PeerAction::Dial { peer } => {
                queue.extend(node.peers.on(PeerEvent::Verified { peer: *peer }));
            }

            PeerAction::AskHoldings { peer, group, paths } => {
                queue.extend(node.peers.on(PeerEvent::Holdings {
                    peer: *peer,
                    group: *group,
                    held: vec![holds; paths.len()],
                    paths: paths.clone(),
                }));
            }
            _ => {}
        }
        seen.push(action);
    }
    seen
}

/// Run until the node stops asking for things, returning when that happened and everything
/// it did on the way.
fn settle(node: &mut Node, from: i64) -> (i64, Vec<PeerAction>) {
    let mut seen = Vec::new();
    for at in (from..).take(20) {
        let actions = step(node, at, false);
        let busy = actions.iter().any(|a| {
            matches!(
                a,
                PeerAction::Ask { .. } | PeerAction::AskHoldings { .. } | PeerAction::Dial { .. }
            )
        });
        seen.extend(actions);
        if !busy {
            return (at, seen);
        }
    }
    panic!("the node never settled");
}

fn proposed_close(actions: &[PeerAction]) -> bool {
    actions
        .iter()
        .any(|a| matches!(a, PeerAction::ProposeClose { .. }))
}

fn rounds(actions: &[PeerAction]) -> Vec<PeerId> {
    actions
        .iter()
        .filter_map(|a| match a {
            PeerAction::Ask { peer, .. } => Some(*peer),
            _ => None,
        })
        .collect()
}

// ---- regressions for failures found while reviewing the design ----

#[test]
fn a_node_that_knows_no_groups_still_asks_whoever_it_meets() {
    let mut node = Node::new();
    let stranger = peers(1)[0];

    assert!(
        node.peers.groups_mut().list().unwrap().is_empty(),
        "this node is in no groups and so has nothing of its own to say"
    );

    let met = node.peers.on(PeerEvent::Verified { peer: stranger });
    assert_eq!(
        rounds(&met),
        vec![stranger],
        "and must still put the question, or it can only ever answer one"
    );
}

#[test]
fn one_change_in_a_fifty_member_group_is_not_fifty_dials() {
    let mut node = Node::new();
    let members = peers(49);
    let id = node.group_with(&members);
    node.peers.on(PeerEvent::Presence {
        asked: members.clone(),
        online: members.clone(),
    });
    node.add_file(id, "new.jpg");

    let opened = dials(&node.tick(AT)).len();
    assert!(
        opened <= DIALS_PER_ROUND,
        "one change opened {opened} circuits in a fifty-member group"
    );
}

#[test]
fn adding_a_member_provokes_a_round_although_no_file_changed() {
    // `ac group add` moves the chain head and touches no file. Watching only the catalogue
    // digest armed nothing, and a newly invited member waited four hours to hear the group
    // existed at all.
    let mut node = Node::new();
    let members = peers(1);
    let id = node.group_with(&members);
    node.all_online(&members);
    node.add_file(id, "a.jpg");

    // Settle: let the initial exchanges run themselves out.
    for _ in 0..8 {
        let actions = node.tick_connecting(AT);
        settle_offers(&mut node, &actions, id);
    }
    assert!(
        rounds(&node.tick_connecting(AT)).is_empty(),
        "quiet before the change"
    );

    let key = node.key.clone();
    let newcomer = peers(1)[0];
    node.peers
        .groups_mut()
        .author(
            &key,
            id,
            Op::Add {
                peer: newcomer.to_base58(),
            },
            AT,
        )
        .unwrap();
    node.peers.on(PeerEvent::Presence {
        asked: vec![members[0], newcomer],
        online: vec![members[0], newcomer],
    });
    let actions = node.tick_connecting(AT);
    assert!(
        !rounds(&actions).is_empty() || !dials(&actions).is_empty(),
        "a membership change is news: {actions:?}"
    );
}

#[test]
fn no_more_circuits_are_opened_than_the_relay_allows() {
    let mut node = Node::new();
    let members = peers(DIALS_PER_WINDOW * 2);
    let id = node.group_with(&members);
    node.learn_file(id, "wanted.jpg");
    node.peers.on(PeerEvent::Presence {
        asked: members.clone(),
        online: members.clone(),
    });

    let mut spent = Vec::new();
    for k in 0..DIAL_WINDOW {
        spent.extend(dials(&node.tick(AT + k)));
    }
    assert_eq!(
        spent.len(),
        DIALS_PER_WINDOW,
        "the relay allows {DIALS_PER_WINDOW} a minute and we ask for no more"
    );

    // None of them answered, which frees the connection budget without freeing the circuit one:
    // otherwise the second window would be bounded by `MAX_PEER_CONNECTIONS` and prove nothing
    // about the allowance renewing.
    for peer in spent {
        node.peers.on(PeerEvent::DialFailed { peer });
    }

    let later: usize = (0..DIAL_WINDOW)
        .map(|k| dials(&node.tick(AT + DIAL_WINDOW + k)).len())
        .sum();
    assert!(later > 0, "the window rolls over");
}

#[test]
fn a_round_nobody_answers_does_not_wedge_the_node() {
    let mut node = Node::new();
    let members = peers(3);
    let id = node.group_with(&members);
    node.add_file(id, "a.jpg");
    node.all_online(&members);

    // Start rounds and answer none of them.
    let mut started = Vec::new();
    for k in 0..4 {
        started.extend(rounds(&node.tick_connecting(AT + k)));
    }
    assert!(!started.is_empty(), "rounds should have gone out");
    assert!(
        rounds(&node.tick_connecting(AT + 5)).is_empty(),
        "the slots are full while they are outstanding"
    );

    node.add_file(id, "b.jpg");
    let swept = node.tick_connecting(AT + ROUND_TIMEOUT + 1);
    assert!(
        rounds(&swept).iter().all(|peer| !started.contains(peer)),
        "a peer whose round was written off is not asked again on the same connection: {swept:?}"
    );

    let actions = node.tick_connecting(AT + ROUND_TIMEOUT + MIN_BACKOFF + 2);
    assert!(
        !rounds(&actions).is_empty() || !dials(&actions).is_empty(),
        "a round nobody answered must not cost the slot for ever: {actions:?}"
    );
}

#[test]
fn a_backlog_larger_than_one_question_is_walked_rather_than_re_asked() {
    const PAGE: usize = ac_files::wire::MAX_HOLDINGS_QUERY;

    let mut node = Node::new();
    let members = peers(1);
    let id = node.group_with(&members);
    // A page and a bit, so the second question is about paths the first never named.
    for i in 0..PAGE + 10 {
        node.learn_file(id, &format!("f{i:05}.bin"));
    }
    node.all_online(&members);

    let mut asked: Vec<RelPath> = Vec::new();
    let mut pages = 0;
    for at in 0..20 {
        for action in step_holding(&mut node, AT + at, &[]) {
            if let PeerAction::AskHoldings { paths, .. } = action {
                pages += 1;
                asked.extend(paths);
            }
        }
        if pages >= 2 {
            break;
        }
    }

    assert!(
        pages >= 2,
        "a backlog of {} needs more than one question",
        PAGE + 10
    );
    let distinct: HashSet<&RelPath> = asked.iter().collect();
    assert_eq!(
        distinct.len(),
        asked.len(),
        "no path is named twice: the walk moves on rather than re-reading from the top"
    );
}

#[test]
fn a_page_they_can_help_with_does_not_send_the_walk_back_to_the_start() {
    // The other half: a productive page must move the cursor too. Otherwise fetching what they
    // held would shrink the backlog by that much and the next question would name the same
    // paths they had already refused, less the few that arrived.
    const PAGE: usize = ac_files::wire::MAX_HOLDINGS_QUERY;

    let mut node = Node::new();
    let members = peers(1);
    let id = node.group_with(&members);
    for i in 0..PAGE + 10 {
        node.learn_file(id, &format!("f{i:05}.bin"));
    }
    node.all_online(&members);

    // They hold exactly the first ten of whatever they are asked about.
    let mut first: Vec<RelPath> = Vec::new();
    let mut second: Vec<RelPath> = Vec::new();
    for at in 0..20 {
        let held: Vec<RelPath> = if first.is_empty() {
            Vec::new()
        } else {
            first.iter().take(10).cloned().collect()
        };
        for action in step_holding(&mut node, AT + at, &held) {
            if let PeerAction::AskHoldings { paths, .. } = action {
                if first.is_empty() {
                    first = paths;
                } else if second.is_empty() {
                    second = paths;
                }
            }
        }
        if !second.is_empty() {
            break;
        }
    }

    assert!(!second.is_empty(), "a second question goes out");
    let earlier: HashSet<&RelPath> = first.iter().collect();
    assert!(
        second.iter().all(|p| !earlier.contains(p)),
        "the second question names none of what the first already did"
    );
}

#[test]
fn a_big_offer_is_fetched_eight_at_a_time_until_none_are_left() {
    // A holdings answer may name hundreds of files, and only `MAX_TRANSFERS` can run. Issuing
    // the lot and letting the blob layer take what it could was silently lossy: it started eight
    // and refused the rest, and since the supervisor had already counted them all as running, it
    // waited for outcomes that could never arrive. Three hundred files became eight, the group
    // kept a source it could not release, and the connection stayed open with nothing on it.
    //
    // So the offer is a queue drained by completions: one ends, the next begins, and every file
    // the peer holds does arrive.
    const OFFERED: usize = 30;

    let mut node = Node::new();
    let members = peers(1);
    let id = node.group_with(&members);
    for i in 0..OFFERED {
        node.learn_file(id, &format!("f{i:02}.bin"));
    }
    node.all_up(&members);

    // The pull starts by asking; the peer holds everything.
    let asked = node.tick(AT);
    let Some(PeerAction::AskHoldings { peer, group, paths }) = asked
        .iter()
        .find(|a| matches!(a, PeerAction::AskHoldings { .. }))
        .cloned()
    else {
        panic!("a group missing files asks who has them: {asked:?}");
    };
    assert_eq!(paths.len(), OFFERED, "one page covers this many");

    let mut running: Vec<RelPath> = fetched_paths(&node.peers.on(PeerEvent::Holdings {
        peer,
        group,
        held: vec![true; paths.len()],
        paths,
    }));
    assert_eq!(
        running.len(),
        MAX_TRANSFERS,
        "the pipe is filled and no further, whatever was offered"
    );

    // Each completion starts exactly one more, until the offer runs out.
    let mut done: Vec<RelPath> = Vec::new();
    while let Some(path) = running.pop() {
        let actions = node.peers.on(PeerEvent::BlobDone {
            peer,
            group,
            path: path.clone(),
        });
        done.push(path);

        let next = fetched_paths(&actions);
        assert!(next.len() <= 1, "one out, at most one in: {next:?}");
        running.extend(next);
        assert!(
            running.len() <= MAX_TRANSFERS,
            "never more than the pool can run"
        );
    }

    assert_eq!(
        done.len(),
        OFFERED,
        "every file the peer offered is fetched, not merely the first {MAX_TRANSFERS}"
    );
}

#[test]
fn a_queue_the_slots_shut_out_is_not_abandoned_there() {
    let mut node = Node::new();
    let members = peers(2);
    let (first, second) = (
        node.group_with(&members[..1]),
        node.group_with(&members[1..]),
    );
    for i in 0..MAX_TRANSFERS {
        node.learn_file(first, &format!("f{i:02}.bin"));
    }
    node.learn_file(second, "shut-out.bin");
    node.all_up(&members);

    // Both groups find a source in the same tick, so both queries go out together.
    let asked = node.tick(AT);
    let queries: Vec<(PeerId, GroupId, Vec<RelPath>)> = asked
        .iter()
        .filter_map(|a| match a {
            PeerAction::AskHoldings { peer, group, paths } => Some((*peer, *group, paths.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(queries.len(), 2, "one source per group: {asked:?}");

    // Answered in the order that fills the pool first.
    let mut answer = |group: GroupId| {
        let (peer, group, paths) = queries
            .iter()
            .find(|(_, g, _)| *g == group)
            .cloned()
            .expect("both groups asked");
        node.peers.on(PeerEvent::Holdings {
            peer,
            group,
            held: vec![true; paths.len()],
            paths,
        })
    };

    let running = fetched_paths(&answer(first));
    assert_eq!(running.len(), MAX_TRANSFERS, "the pool is full");
    assert_eq!(
        fetches(&answer(second)),
        0,
        "and the second group's offer cannot start anything yet"
    );

    // Draining the first group frees every slot, and pumps nobody but the peer that completed.
    let (peer, group, _) = queries
        .iter()
        .find(|(_, g, _)| *g == first)
        .cloned()
        .expect("the first group asked");
    for path in running {
        let actions = node.peers.on(PeerEvent::BlobDone { peer, group, path });
        assert_eq!(
            fetches(&actions),
            0,
            "the first group has nothing left to fetch: {actions:?}"
        );
    }

    // Nothing is running, nothing is queued for the peer that just finished, and the shut-out
    // queue is still sitting there. The tick is what has to notice.
    let resumed = node.tick(AT + 1);
    assert_eq!(
        fetched_paths(&resumed)
            .iter()
            .filter(|p| p.as_str() == "shut-out.bin")
            .count(),
        1,
        "the waiting queue is driven once there is room: {resumed:?}"
    );
}

#[test]
fn a_new_file_is_fetched_although_the_group_had_given_up_before() {
    let mut node = Node::new();
    let members = peers(1);
    let id = node.group_with(&members);
    node.learn_file(id, "nobody-has-this.jpg");
    node.all_online(&members);

    // Exhaust the group: the one member holds nothing we want.
    let mut backed_off = false;
    for k in 0..8 {
        step(&mut node, AT + k, false);
        // Giving up *is* the content backoff, which `status` reports.
        if node
            .peers
            .status()
            .groups
            .iter()
            .any(|g| g.content_until > 0)
        {
            backed_off = true;
            break;
        }
    }
    assert!(backed_off, "the group should give up on what nobody has");

    // A file arrives in the catalogue while the group is serving that sentence.
    node.learn_file(id, "someone-might.jpg");

    let actions = step(&mut node, AT + 9, false);
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, PeerAction::AskHoldings { .. })),
        "a new row is a new question, whatever we concluded before: {actions:?}"
    );
}

#[test]
fn a_member_already_connected_is_asked_before_one_that_needs_a_circuit() {
    let mut node = Node::new();
    let members = peers(3);
    let id = node.group_with(&members);
    node.learn_file(id, "wanted.jpg");

    // Everyone is reachable; only one is on the other end of a connection.
    node.peers.on(PeerEvent::Presence {
        asked: members.clone(),
        online: members.clone(),
    });
    let held = members[2];

    let mut actions = node.peers.on(PeerEvent::Verified { peer: held });
    actions.extend(node.tick(AT));
    assert!(
        actions.iter().any(|a| matches!(
            a,
            PeerAction::AskHoldings { peer, .. } | PeerAction::Ask { peer, .. } if *peer == held
        )),
        "the peer we are already talking to is the one asked: {actions:?}"
    );
}

#[test]
fn every_member_is_asked_once_not_one_member_repeatedly() {
    let mut node = Node::new();
    let members = peers(3);
    node.group_with(&members);

    // Connecting is what reconciles, so this is where the claim is made: every member asked,
    // and no member asked twice over while another waits.
    let asked = rounds(&node.all_up(&members));

    let distinct: HashSet<PeerId> = asked.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        members.len(),
        "every member is asked: {distinct:?}"
    );
    // Twice each and no more: membership and the catalogue are separate exchanges, so a peer
    // is reconciled in two and then has nothing further owed to it.
    for peer in &distinct {
        assert_eq!(
            asked.iter().filter(|p| *p == peer).count(),
            2,
            "one chain round and one catalogue round, no repeats: {asked:?}"
        );
    }
}

#[test]
fn membership_is_offered_before_the_catalogue() {
    let mut node = Node::new();
    let members = peers(1);
    let id = node.group_with(&members);
    node.add_file(id, "a.jpg");
    node.all_online(&members);

    let first = node.tick_connecting(AT);
    assert!(
        matches!(
            first.iter().find(|a| matches!(a, PeerAction::Ask { .. })),
            Some(PeerAction::Ask {
                offering: Offering::Chain,
                ..
            })
        ),
        "membership goes first: {first:?}"
    );

    for group in node.shared_groups() {
        node.peers.on(PeerEvent::Synced {
            peer: members[0],
            group,
            offering: Offering::Chain,
        });
    }
    let second = node.peers.on(PeerEvent::Asked {
        peer: members[0],
        offering: Offering::Chain,
    });

    assert!(
        matches!(
            second.iter().find(|a| matches!(a, PeerAction::Ask { .. })),
            Some(PeerAction::Ask {
                offering: Offering::Catalogue,
                ..
            })
        ),
        "and the catalogue follows once they know who is in the group: {second:?}"
    );
}

#[test]
fn a_settled_membership_round_does_not_write_off_the_catalogue() {
    // Two exchanges, two halves. A chain round carries who is in the group and not one file
    // head, so it may discharge the membership and nothing else — the catalogue is still
    // outstanding and follows on the answer.
    let mut node = Node::new();
    let members = peers(1);
    let id = node.group_with(&members);
    node.add_file(id, "a.jpg");
    node.all_online(&members);

    // The first round of a fresh group goes at once.
    let first = node.tick_connecting(AT);
    assert_eq!(rounds(&first), members, "the chain round goes first");

    // Answer only the chain half, exactly as a chain exchange would.
    let mut followed = Vec::new();
    for peer in rounds(&first) {
        node.peers.on(PeerEvent::Synced {
            peer,
            group: id,
            offering: Offering::Chain,
        });
        followed.extend(node.peers.on(PeerEvent::Asked {
            peer,
            offering: Offering::Chain,
        }));
    }

    assert_eq!(
        rounds(&followed),
        members,
        "settling the chain must not write off the catalogue"
    );
    assert!(
        matches!(
            followed.first(),
            Some(PeerAction::Ask {
                offering: Offering::Catalogue,
                ..
            })
        ),
        "and what follows is the catalogue: {followed:?}"
    );
}

#[test]
fn a_change_made_by_the_cli_in_another_process_is_offered_once() {
    let mut node = Node::new();
    let members = peers(1);
    let id = node.group_with(&members);
    node.all_online(&members);
    let (settled, _) = settle(&mut node, AT);

    node.hang_up(&members);
    node.add_file(id, "new.jpg");

    let at = after_editing_pause(&mut node, settled + 1);
    let actions = answered(&mut node, at, id);
    assert_eq!(rounds(&actions), members, "the change is offered");

    assert!(
        rounds(&node.tick_connecting(at + 1)).is_empty(),
        "offered once, not every tick"
    );
}

#[test]
fn a_member_we_have_never_asked_is_due_at_once() {
    // A peer with no schedule of its own is due immediately, which is what makes a newly added
    // member reachable without waiting out an interval they were never part of. Under the push
    // this was the moment we had to *tell* them; now it is the moment they first count as
    // somebody worth asking.
    let mut node = Node::new();
    let members = peers(1);
    let id = node.group_with(&members);
    node.all_online(&members);

    assert_eq!(
        rounds(&node.tick_connecting(AT)),
        members,
        "never asked, so due on the first tick"
    );
    let _ = id;
}

#[test]
fn a_quiet_group_waits_for_its_heartbeat() {
    let mut node = Node::new();
    let members = peers(1);
    let id = node.group_with(&members);
    node.add_file(id, "a.jpg");
    node.all_online(&members);

    // Everything outstanding, dealt with.
    let (settled, _) = settle(&mut node, AT);
    assert!(
        rounds(&node.tick_connecting(settled + 1)).is_empty(),
        "nothing of ours left to say"
    );

    assert!(
        rounds(&node.tick_connecting(settled + HEARTBEAT - 1)).is_empty(),
        "still inside the interval"
    );
    assert_eq!(
        rounds(&node.tick_connecting(settled + HEARTBEAT + 1)),
        members,
        "and the group comes round once it has elapsed"
    );
    let _ = id;
}

#[test]
fn what_we_learn_from_a_peer_is_not_re_told_to_the_group() {
    let mut node = Node::new();
    let members = peers(2);
    let id = node.group_with(&members);
    node.all_online(&members);
    let (settled, _) = settle(&mut node, AT);
    assert!(
        rounds(&node.tick_connecting(settled)).is_empty(),
        "quiet before they tell us anything"
    );

    // They call us, we learn a file from them, and their exchange settles on our side too.
    node.learn_file(id, "theirs.jpg");
    node.peers.on(PeerEvent::Synced {
        peer: members[0],
        group: id,
        offering: Offering::Catalogue,
    });

    // Well past the pause a change of our own would have waited out.
    let at = after_editing_pause(&mut node, settled + 1);
    let actions = node.tick_connecting(at);
    assert!(
        rounds(&actions).is_empty() && dials(&actions).is_empty(),
        "the author is telling them; saying it again is a message per member per member: \
         {actions:?}"
    );

    // And it is theirs alone that is quiet. Something *we* do is still news to everybody.
    node.add_file(id, "ours.jpg");
    node.hang_up(&members);
    let at = after_editing_pause(&mut node, at + 1);
    let actions = node.tick_connecting(at);
    assert!(
        !rounds(&actions).is_empty() || !dials(&actions).is_empty(),
        "what we did ourselves still goes out: {actions:?}"
    );
}

#[test]
fn a_member_added_a_moment_ago_is_called_once_the_server_says_they_are_up() {
    let mut node = Node::new();
    let members = peers(1);
    let id = node.group_with(&members);
    node.add_file(id, "a.jpg");
    node.all_up(&members);
    let (settled, _) = settle(&mut node, AT);
    node.peers
        .files_mut()
        .set_cursor(id, &members[0], 1)
        .unwrap();

    let newcomer = peers(1)[0];
    node.add_member(id, newcomer);

    // Nothing yet: the chain moved, and under a pull that is not news we owe anybody.
    assert!(
        !dials(&answered(&mut node, settled + 1, id)).contains(&newcomer),
        "adding them is not by itself a reason to call"
    );

    node.peers.on(PeerEvent::Discovered { peer: newcomer });
    assert!(
        !dials(&answered(&mut node, settled + 2, id)).contains(&newcomer),
        "being listed in the registry is a claim, not a pulse"
    );

    // The server saying it has them connected is.
    node.peers.on(PeerEvent::Presence {
        asked: vec![newcomer],
        online: vec![newcomer],
    });
    let mut called = None;
    for k in 2..8 {
        let actions = answered(&mut node, settled + k, id);
        if dials(&actions).contains(&newcomer) {
            called = Some(k);
            break;
        }
    }
    assert!(
        called.is_some(),
        "a member with no standing of their own is called once we know they are there"
    );
}

#[test]
fn a_member_who_has_never_answered_the_invitation_is_told_again_when_the_server_sees_them() {
    // What the presence query is still for, now that nothing waits on its answer.
    let mut node = Node::new();
    let members = peers(1);
    let id = node.group_with(&members);
    node.add_file(id, "a.jpg");

    // They are away for every attempt we are willing to make.
    for k in 0..=(DIAL_ATTEMPTS as i64) {
        let at = AT + k * (MIN_BACKOFF * 4);
        for peer in dials(&node.tick(at)) {
            node.peers.on(PeerEvent::DialFailed { peer });
        }
    }
    assert_eq!(
        node.peers.status().groups[0].owed,
        0,
        "after {DIAL_ATTEMPTS} attempts the group stops counting them as owed"
    );

    // The server says they are up. They have never signed a standing, so the invitation is still
    // unanswered and they go back on the list.
    node.peers.on(PeerEvent::Presence {
        asked: members.clone(),
        online: members.clone(),
    });
    assert_eq!(
        node.peers.status().groups[0].owed,
        1,
        "somebody who never answered the invitation goes back on the list"
    );
}

#[test]
fn the_content_pull_still_waits_for_the_registry() {
    const { assert!(PRESENCE_INTERVAL > 0) };

    let mut node = Node::new();
    let members = peers(1);
    let id = node.group_with(&members);
    node.learn_file(id, "a.jpg");
    node.peers.on(PeerEvent::Presence {
        asked: members.clone(),
        online: Vec::new(),
    });

    let actions = node.tick(AT);
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, PeerAction::AskHoldings { .. })),
        "nothing has vouched for them, so they are not made a source: {actions:?}"
    );

    let opening = node.all_up(&members);
    let mut asked = opening
        .iter()
        .any(|a| matches!(a, PeerAction::AskHoldings { .. }));
    for k in 1..10 {
        if asked {
            break;
        }
        asked = step(&mut node, AT + k, true)
            .iter()
            .any(|a| matches!(a, PeerAction::AskHoldings { .. }));
    }
    assert!(asked, "once vouched for, they are asked what they hold");
}

#[test]
fn a_change_reaches_every_member_not_a_sample_of_them() {
    let mut node = Node::new();
    let members = peers(6);
    let id = node.group_with(&members);
    node.all_up(&members);
    node.add_file(id, "a.jpg");

    // Long enough for the pause the catalogue waits out, and then a call to each member. The
    // calls are what deliver: a question carries nothing, so a member hears about the change by
    // being dialled and pulling it, which is why the connections must be allowed to close first.
    let mut told = HashSet::new();
    for k in 0..SHARE_AFTER_IDLE + (members.len() * 4 + 8) as i64 {
        let actions = node.tick_connecting(AT + k);
        told.extend(settle_offers(&mut node, &actions, id));
    }

    assert_eq!(
        told.len(),
        members.len(),
        "every member hears it, not a sample: {told:?}"
    );
}

#[test]
fn telling_everyone_stops_by_itself() {
    let mut node = Node::new();
    let members = peers(6);
    let id = node.group_with(&members);
    node.all_up(&members);
    node.add_file(id, "a.jpg");

    for _ in 0..(members.len() * 2 + 4) {
        let actions = node.tick(AT);
        settle_offers(&mut node, &actions, id);
    }
    assert!(
        rounds(&node.tick(AT)).is_empty(),
        "everyone has it and nothing has changed since"
    );
}

#[test]
fn an_unsatisfiable_want_backs_off_instead_of_rotating_for_ever() {
    // Wanting a file no online member holds is the *normal* state of a mirror. Without the
    // backoff a node cycles the member list continuously, spending a relay circuit each time.
    let mut node = Node::new();
    let members = peers(4);
    let id = node.group_with(&members);
    node.all_online(&members);
    node.learn_file(id, "nobody-has-this.bin");

    let ticks = 200;
    let mut asked = 0;
    for offset in 0..ticks {
        for action in step(&mut node, AT + offset, false) {
            if matches!(action, PeerAction::AskHoldings { .. }) {
                asked += 1;
            }
        }
    }

    // The property is a *rate*, not a count: one rotation of the members is expected and
    // proper. What must not happen is asking on every tick for ever.
    assert!(
        asked < ticks / 4,
        "asked {asked} times over {ticks} ticks across {} members; the rotation is not \
         backing off",
        members.len()
    );
}

#[test]
fn a_peer_that_acquires_a_file_later_is_asked_again() {
    // The flip side, and why the retry is a timer rather than an event. `have` is local and
    // never travels, so a peer downloading the file moves no digest and fires no event
    // anywhere. Re-asking is the only discovery mechanism there is.
    let mut node = Node::new();
    let members = peers(1);
    let id = node.group_with(&members);
    node.all_up(&members);
    node.learn_file(id, "eventually.bin");

    // A first rotation in which they have nothing.
    for offset in 0..4 {
        step(&mut node, AT + offset, false);
    }

    let mut fetched = false;
    for offset in 200..210 {
        for action in step(&mut node, AT + offset, true) {
            if matches!(action, PeerAction::FetchBlob { .. }) {
                fetched = true;
            }
        }
    }

    assert!(
        fetched,
        "a file nobody had is still found once somebody has it"
    );
}

// ---- dialling ----

#[test]
fn a_member_the_registry_calls_away_is_dialled_anyway() {
    let mut node = Node::new();
    let members = peers(3);
    let id = node.group_with(&members);
    node.add_file(id, "a.jpg");

    // Presence says nobody is up.
    node.peers.on(PeerEvent::Presence {
        asked: members.clone(),
        online: Vec::new(),
    });

    let actions = node.tick(AT);
    assert!(
        !dials(&actions).is_empty(),
        "we owe them the news, so we call them: {actions:?}"
    );
}

#[test]
fn a_member_who_never_answers_is_dropped_after_three_attempts_not_the_first() {
    // The other half of dialling blind, and the reason it is affordable. Without an ending, a
    // member who is switched off keeps a group looking as though it had something outstanding
    // for ever and keeps spending circuits to prove it. Ending it on the *first* failure is the
    // same mistake as never calling: a node restarting is unreachable for a few seconds and has
    // done nothing to deserve being written off.
    let mut node = Node::new();
    let members = peers(1);
    let id = node.group_with(&members);
    node.add_file(id, "a.jpg");

    let mut attempts = 0;
    let mut at = AT;
    while at < AT + 4 * MIN_BACKOFF {
        for peer in dials(&node.tick(at)) {
            attempts += 1;
            node.peers.on(PeerEvent::DialFailed { peer });
        }
        if node.peers.status().groups[0].owed == 0 {
            break;
        }
        at += 1;
    }

    assert_eq!(
        attempts, DIAL_ATTEMPTS,
        "three tries, not one and not for ever"
    );
    assert_eq!(
        node.peers.status().groups[0].owed,
        0,
        "and then the group stops counting them as owed"
    );
    assert!(
        at - AT >= MIN_BACKOFF * 3,
        "spread over the backoff rather than spent in one tick: {} seconds",
        at - AT
    );

    node.add_file(id, "b.jpg");
    assert_eq!(
        node.peers.status().groups[0].owed,
        0,
        "a change of ours does not undo the giving up"
    );
    node.tick(at + 2 * HEARTBEAT);
    assert!(
        node.peers.status().groups[0].owed > 0,
        "but the interval does: giving up is the end of one attempt, not a memory"
    );
}

#[test]
fn backoff_advances_on_the_attempt_and_resets_on_verified() {
    // On the attempt, not the failure: a dial whose failure is never observed must still back
    // off. And on `Verified`, not `Connected`, so a peer that connects and then fails
    // attestation is not retried at full speed.
    let mut node = Node::new();
    let members = peers(1);
    let id = node.group_with(&members);
    node.add_file(id, "a.jpg");
    node.peers.on(PeerEvent::Presence {
        asked: members.clone(),
        online: members.clone(),
    });

    assert_eq!(dials(&node.tick(AT)), members, "first attempt");
    assert!(
        dials(&node.tick(AT + 1)).is_empty(),
        "second attempt is inside the backoff"
    );
    node.peers.on(PeerEvent::DialFailed { peer: members[0] });
    node.peers.on(PeerEvent::Presence {
        asked: members.clone(),
        online: members.clone(),
    });
    assert!(
        dials(&node.tick(AT + MIN_BACKOFF - 1)).is_empty(),
        "still inside it"
    );
    assert_eq!(
        dials(&node.tick(AT + MIN_BACKOFF + 1)),
        members,
        "and it retries once the backoff expires"
    );

    node.peers.on(PeerEvent::Verified { peer: members[0] });
    node.peers.on(PeerEvent::Gone { peer: members[0] });
    node.peers.on(PeerEvent::Presence {
        asked: members.clone(),
        online: members.clone(),
    });
    // Past the circuit window as well as the backoff: two dials have already gone out inside
    // the minute, and the allowance is deliberately not something a backoff reset can jump.
    assert_eq!(
        dials(&node.tick(AT + MIN_BACKOFF + DIAL_WINDOW + 2)),
        members,
        "a peer that verified starts from a short delay again"
    );
}

#[test]
fn a_stranger_is_called_before_a_familiar_member() {
    let mut node = Node::new();
    let keys: Vec<Keypair> = (0..5).map(|_| Keypair::generate_ed25519()).collect();
    let members: Vec<PeerId> = keys.iter().map(|k| k.public().to_peer_id()).collect();
    let id = node.group_with(&members);
    node.all_online(&members);
    node.add_file(id, "a.jpg");

    // Everyone but the last has answered, and is therefore known.
    for key in &keys[..4] {
        node.accept_invite(id, key);
    }

    // And the cursors say the opposite, so this can only come out right for the right reason:
    // the one who never answered is the only one we *have* swapped a catalogue with.
    node.peers
        .files_mut()
        .set_cursor(id, &members[4], 7)
        .unwrap();

    let actions = node.tick_connecting(AT);
    assert_eq!(
        rounds(&actions).first(),
        Some(&members[4]),
        "the one we have never met is called first"
    );
}

// ---- closing ----

#[test]
fn a_drained_peer_is_proposed_to_even_while_the_group_is_behind() {
    let mut node = Node::new();
    let members = peers(2);
    let id = node.group_with(&members);
    node.all_up(&members);
    node.learn_file(id, "still-missing.bin");

    // Everyone is asked and nobody helps.
    let mut seen = Vec::new();
    for offset in 0..10 {
        seen.extend(step(&mut node, AT + offset, false));
    }

    assert!(
        proposed_close(&seen),
        "the group is still missing a file, but these peers cannot supply it"
    );
}

#[test]
fn a_peer_being_pulled_from_is_not_proposed_to() {
    // The churn the above must not reintroduce: hanging up between two files and re-dialling
    // a second later is the most expensive mistake available at two circuits a minute.
    let mut node = Node::new();
    let members = peers(1);
    let id = node.group_with(&members);
    node.all_up(&members);
    node.learn_file(id, "big.bin");

    let mut pulling = false;
    for offset in 0..4 {
        for action in step(&mut node, AT + offset, true) {
            if matches!(action, PeerAction::FetchBlob { .. }) {
                pulling = true;
            }
        }
    }
    assert!(pulling, "the scenario needs a pull in progress");

    let proposed = step(&mut node, AT + 5, true)
        .into_iter()
        .any(|a| matches!(a, PeerAction::ProposeClose { .. }));
    assert!(!proposed, "a peer we are fetching from is not idle");
}

#[test]
fn work_arriving_before_the_answer_cancels_the_close() {
    let mut node = Node::new();
    let members = peers(1);
    let id = node.group_with(&members);
    node.all_up(&members);

    let (_, seen) = settle(&mut node, AT);
    assert!(proposed_close(&seen), "nothing to do, so a close goes out");

    // A transfer starts before they answer.
    node.learn_file(id, "urgent.bin");
    node.peers.on(PeerEvent::Holdings {
        peer: members[0],
        group: id,
        paths: vec![RelPath::parse("urgent.bin").unwrap()],
        held: vec![true],
    });

    let closed = node
        .peers
        .on(PeerEvent::CloseAnswered {
            peer: members[0],
            ready: true,
        })
        .into_iter()
        .any(|a| matches!(a, PeerAction::Disconnect { .. }));

    assert!(!closed, "the close is re-checked when the answer arrives");
}

#[test]
fn a_busy_answer_leaves_the_connection_alone() {
    let mut node = Node::new();
    let members = peers(1);
    node.group_with(&members);
    node.all_up(&members);
    settle(&mut node, AT);

    let actions = node.peers.on(PeerEvent::CloseAnswered {
        peer: members[0],
        ready: false,
    });
    assert!(actions.is_empty(), "they are busy, so nothing happens");
}

#[test]
fn a_busy_answer_is_not_re_proposed_to_on_the_next_tick() {
    // A refusal is the one answer that says the wait will be a long one, so it is paced like
    // silence rather than faster than it. Clearing the proposal on `ready: false` put another
    // on the wire every tick for as long as the peer had work for us.
    let mut node = Node::new();
    let members = peers(1);
    node.group_with(&members);
    node.all_up(&members);

    let (at, seen) = settle(&mut node, AT);
    assert!(proposed_close(&seen), "drained, so a close goes out");

    node.peers.on(PeerEvent::CloseAnswered {
        peer: members[0],
        ready: false,
    });

    let soon = step(&mut node, at + 1, false);
    assert!(
        !proposed_close(&soon),
        "the proposal still stands: {soon:?}"
    );

    let later = step(&mut node, at + CLOSE_TIMEOUT + 1, false);
    assert!(
        proposed_close(&later),
        "and is offered again once it has timed out, like one nobody answered: {later:?}"
    );
}

#[test]
fn both_ready_closes_once() {
    let mut node = Node::new();
    let members = peers(1);
    node.group_with(&members);
    node.all_up(&members);

    let (_, seen) = settle(&mut node, AT);
    assert!(proposed_close(&seen), "drained, so a close goes out");

    let actions = node.peers.on(PeerEvent::CloseAnswered {
        peer: members[0],
        ready: true,
    });
    assert_eq!(actions, vec![PeerAction::Disconnect { peer: members[0] }]);
}

// ---- quiescence ----

#[test]
fn a_settled_node_goes_quiet() {
    // The property that makes this acceptable to run continuously.
    let mut node = Node::new();
    let members = peers(3);
    let id = node.group_with(&members);
    node.all_up(&members);
    node.add_file(id, "a.jpg");

    settle(&mut node, AT);

    let quiet = step(&mut node, AT + 100, false);
    let noisy: Vec<_> = quiet
        .iter()
        .filter(|a| {
            matches!(
                a,
                PeerAction::Dial { .. } | PeerAction::Ask { .. } | PeerAction::AskHoldings { .. }
            )
        })
        .collect();

    assert!(
        noisy.is_empty(),
        "nothing changed, so nothing happens: {noisy:?}"
    );
}

// ---- disk limits ----

/// A node with a budget, two members, and a disk report to go with it.
fn cramped(storage_max: Option<u64>, free: u64, held: u64) -> (Node, GroupId) {
    let mut node = Node::with_limits(Limits {
        min_free: 1_000,
        storage_max,
    });
    let members = peers(2);
    let id = node.group_with(&members);
    node.all_up(&members);
    node.peers.on(PeerEvent::Space { free, held });
    (node, id)
}

fn source_of(node: &Peers, group: GroupId) -> Option<PeerId> {
    node.status()
        .groups
        .into_iter()
        .find(|g| g.group == group)
        .and_then(|g| g.source)
}

#[test]
fn a_source_the_budget_shut_out_is_let_go_when_the_last_transfer_ends() {
    let mut node = Node::with_limits(Limits {
        min_free: 0,
        storage_max: Some(1),
    });
    let members = peers(1);
    let id = node.group_with(&members);
    for i in 0..3 {
        node.learn_file(id, &format!("f{i}.bin"));
    }
    node.all_up(&members);
    node.peers.on(PeerEvent::Space {
        free: 1_000_000,
        held: 0,
    });

    let running = fetched_paths(&step(&mut node, AT, true));
    assert_eq!(running.len(), 1, "the budget has room for exactly one");
    assert_eq!(
        source_of(&node.peers, id),
        Some(members[0]),
        "and the group is pulling through the peer that offered them"
    );

    node.peers.on(PeerEvent::BlobDone {
        peer: members[0],
        group: id,
        path: running[0].clone(),
    });

    assert_eq!(
        source_of(&node.peers, id),
        None,
        "the rest cannot start and nothing is running, so the peer is let go at once"
    );
}

fn fetches(actions: &[PeerAction]) -> usize {
    actions
        .iter()
        .filter(|a| matches!(a, PeerAction::FetchBlob { .. }))
        .count()
}

#[test]
fn the_free_space_floor_stops_fetching_and_says_so_once() {
    let (mut node, id) = cramped(None, 500, 0);
    node.learn_file(id, "big.bin");

    let first = step(&mut node, AT, true);
    assert_eq!(fetches(&first), 0, "no room, so nothing is asked for");
    assert!(
        matches!(node.peers.room(), Some(NoRoom::Floor { .. })),
        "and it is the floor that stopped it"
    );

    let again = step(&mut node, AT + 1, true);
    assert_eq!(fetches(&again), 0, "and it stays stopped: {again:?}");
}

#[test]
fn a_budget_stops_fetching_short_of_the_disk_filling() {
    // The other limit, doing a different job: honouring what the user actually asked for while
    // there is plenty of room left.
    let (mut node, id) = cramped(Some(100), 1_000_000, 100);
    node.learn_file(id, "big.bin");

    let actions = step(&mut node, AT, true);
    assert_eq!(fetches(&actions), 0);
    assert!(
        matches!(node.peers.room(), Some(NoRoom::Budget { .. })),
        "the budget stopped it, not the floor: {actions:?}"
    );
}

#[test]
fn space_appearing_resumes_the_mirror() {
    let (mut node, id) = cramped(Some(100), 1_000_000, 100);
    node.learn_file(id, "big.bin");

    assert_eq!(fetches(&step(&mut node, AT, true)), 0);

    // The user raised the limit, or removed something.
    node.peers.on(PeerEvent::Space {
        free: 1_000_000,
        held: 0,
    });

    let mut asked = 0;
    for at in 1..200 {
        asked += fetches(&step(&mut node, AT + at, true));
        if asked > 0 {
            break;
        }
    }
    assert!(asked > 0, "with room again, the file is fetched");
}

#[test]
fn a_file_larger_than_the_headroom_is_not_started() {
    // The per-file check, which the coarse gate cannot do: a node comfortably above the floor
    // still must not begin a transfer that would bury it. The row is one byte in these tests,
    // so the floor is set just above the free space to make the arithmetic bite.
    let (mut node, id) = cramped(None, 1_000, 0);
    node.learn_file(id, "big.bin");

    // Exactly at the floor: room() passes, room_for(1) does not.
    node.peers.on(PeerEvent::Space {
        free: 1_000,
        held: 0,
    });
    let actions = step(&mut node, AT, true);
    assert_eq!(
        fetches(&actions),
        0,
        "one more byte would put it under the floor: {actions:?}"
    );
}

// ---- presence ----

#[test]
fn a_presence_answer_says_nothing_about_peers_it_was_not_asked_about() {
    let mut node = Node::new();
    let members = peers(2);
    let id = node.group_with(&members);
    node.learn_file(id, "wanted.bin");

    // One connected, one merely known to be up.
    node.peers.on(PeerEvent::Verified { peer: members[0] });
    node.peers.on(PeerEvent::Discovered { peer: members[1] });

    // A tick asks about whoever is not connected, so only about the second. Answered as it goes,
    // because a peer may have only one offer outstanding and an unanswered one would make the
    // next tick look quiet for the wrong reason.
    let asked = presence_asked(&step(&mut node, AT, true));
    assert_eq!(
        asked,
        vec![members[1]],
        "connected peers are not asked about"
    );

    // The server says that one is gone. It has said nothing whatever about the first.
    node.peers.on(PeerEvent::Presence {
        asked: vec![members[1]],
        online: Vec::new(),
    });

    let status = node.peers.status();
    let online = |peer: &PeerId| {
        status
            .peers
            .iter()
            .find(|p| p.peer == *peer)
            .is_some_and(|p| p.online)
    };

    assert!(
        online(&members[0]),
        "the connected peer was never asked about, so nothing was said about them"
    );
    assert!(
        !online(&members[1]),
        "and the one the answer did cover is taken at its word"
    );

    // Which is the judgement presence is still trusted with: the absent one is not made a
    // content source, while the connected one remains a candidate.
    node.learn_file(id, "later.bin");
    let mut actions = Vec::new();
    for k in 1..6 {
        actions.extend(step(&mut node, AT + k, true));
    }
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, PeerAction::AskHoldings { peer, .. } if *peer == members[1])),
        "the one reported absent is not made a content source: {actions:?}"
    );
}

#[test]
fn nobody_reachable_is_not_the_same_as_nobody_having_it() {
    let mut node = Node::new();
    let members = peers(2);
    let id = node.group_with(&members);
    node.learn_file(id, "wanted.bin");

    node.tick(AT);
    assert!(
        node.peers
            .status()
            .groups
            .iter()
            .all(|g| g.content_until == 0),
        "not having asked anyone is not the same as having been refused"
    );

    let opening = node.all_up(&members[..1]);
    let mut asked = opening
        .iter()
        .any(|a| matches!(a, PeerAction::AskHoldings { .. }));
    for at in 1..10 {
        let actions = step(&mut node, AT + at, true);
        if asked
            || actions
                .iter()
                .any(|a| matches!(a, PeerAction::AskHoldings { .. }))
        {
            asked = true;
            break;
        }
    }
    assert!(asked, "the first reachable member is asked at once");
}

/// The offerings put to `want` by these actions.
fn asks_of(actions: &[PeerAction], want: PeerId) -> Vec<Offering> {
    actions
        .iter()
        .filter_map(|a| match a {
            PeerAction::Ask { peer, offering } if *peer == want => Some(*offering),
            _ => None,
        })
        .collect()
}

#[test]
fn a_round_that_did_not_come_off_is_put_again() {
    let mut node = Node::new();
    let members = peers(1);
    let _ = node.group_with(&members);

    // Verified opens a chain round; the link then reports it never landed.
    node.peers.on(PeerEvent::Verified { peer: members[0] });
    node.peers.on(PeerEvent::AskFailed { peer: members[0] });

    assert!(
        asks_of(&node.tick(AT + RETRY_AFTER - 1), members[0]).is_empty(),
        "not before the wait is up"
    );
    assert_eq!(
        asks_of(&node.tick(AT + RETRY_AFTER), members[0]),
        vec![Offering::Chain],
        "and then the same round again"
    );
}

#[test]
fn a_retried_round_holds_the_connection_open_for_itself() {
    let mut node = Node::new();
    let members = peers(1);
    let _ = node.group_with(&members);

    node.peers.on(PeerEvent::Verified { peer: members[0] });
    node.peers.on(PeerEvent::AskFailed { peer: members[0] });

    let actions = node.tick(AT + RETRY_AFTER);
    assert_eq!(asks_of(&actions, members[0]), vec![Offering::Chain]);
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, PeerAction::ProposeClose { peer } if *peer == members[0])),
        "a peer with a round pending is not hung up on in the same breath"
    );
}

#[test]
fn a_round_is_put_again_only_so_many_times() {
    let mut node = Node::new();
    let members = peers(1);
    let _ = node.group_with(&members);

    node.peers.on(PeerEvent::Verified { peer: members[0] });

    let mut asked = 0;
    for k in 1..=(u32::from(RETRY_ATTEMPTS) + 2) {
        node.peers.on(PeerEvent::AskFailed { peer: members[0] });
        let at = AT + RETRY_AFTER * i64::from(k);
        asked += asks_of(&node.tick(at), members[0]).len();
    }

    assert_eq!(
        asked,
        usize::from(RETRY_ATTEMPTS),
        "it gives up rather than asking a peer that keeps refusing for ever"
    );
}

#[test]
fn a_catalogue_that_failed_is_put_again_as_a_catalogue() {
    let mut node = Node::new();
    let members = peers(1);
    let _ = node.group_with(&members);

    // Chain first, answered, which is what opens the catalogue round.
    node.peers.on(PeerEvent::Verified { peer: members[0] });
    node.peers.on(PeerEvent::Asked {
        peer: members[0],
        offering: Offering::Chain,
    });
    node.peers.on(PeerEvent::AskFailed { peer: members[0] });

    assert_eq!(
        asks_of(&node.tick(AT + RETRY_AFTER), members[0]),
        vec![Offering::Catalogue],
        "the round that failed is the round repeated, not the one before it"
    );
}

#[test]
fn a_round_owed_when_the_line_drops_goes_back_on_the_dial_list() {
    let mut node = Node::new();
    let members = peers(1);
    let _ = node.group_with(&members);
    node.all_online(&members);

    // Connected, asked, refused: the retry takes them off the dial list because it means to
    // see to them on this connection.
    node.peers.on(PeerEvent::Verified { peer: members[0] });
    node.peers.on(PeerEvent::AskFailed { peer: members[0] });
    assert!(
        dials(&node.tick(AT + 1)).is_empty(),
        "no call while the retry still has a connection to do it on"
    );

    // The connection goes before the retry comes round. Now a call is the only way back.
    node.peers.on(PeerEvent::Gone { peer: members[0] });
    assert_eq!(
        dials(&node.tick(AT + 2)),
        vec![members[0]],
        "the round is still owed, so they are called"
    );
}

#[test]
fn both_sides_of_an_agreed_hang_up_know_it_was_agreed() {
    // The one hung up on sees a transport error and nothing else, so unless it records that
    // it said yes, a clean close is indistinguishable in the log from a broken connection.
    let mut them = Node::new();
    let caller = peers(1)[0];
    let _ = them.group_with(&[caller]);
    them.peers.on(PeerEvent::Verified { peer: caller });

    assert!(
        !them.peers.close_was_agreed(&caller),
        "nothing has been agreed yet"
    );

    them.peers.on(PeerEvent::CloseProposed {
        peer: caller,
        ready: true,
    });
    assert!(
        them.peers.close_was_agreed(&caller),
        "having said yes, the disconnect that follows is the ordinary end of a call"
    );
}

#[test]
fn refusing_to_hang_up_agrees_to_nothing() {
    let mut them = Node::new();
    let caller = peers(1)[0];
    let _ = them.group_with(&[caller]);
    them.peers.on(PeerEvent::Verified { peer: caller });

    them.peers.on(PeerEvent::CloseProposed {
        peer: caller,
        ready: false,
    });
    assert!(
        !them.peers.close_was_agreed(&caller),
        "a refusal is not an agreement, and a close after one is worth the cause"
    );
}

#[test]
fn the_caller_records_the_agreement_it_asked_for() {
    let mut node = Node::new();
    let member = peers(1)[0];
    let _ = node.group_with(&[member]);
    node.peers.on(PeerEvent::Verified { peer: member });

    // Let the rounds `Verified` opened finish, so there is nothing outstanding left.
    for offering in [Offering::Chain, Offering::Catalogue] {
        node.peers.on(PeerEvent::Asked {
            peer: member,
            offering,
        });
    }

    // Drained, so the tick asks to hang up.
    let proposed = node.tick(AT + 1);
    assert!(
        proposed
            .iter()
            .any(|a| matches!(a, PeerAction::ProposeClose { peer } if *peer == member)),
        "a peer with nothing outstanding is asked to hang up: {proposed:?}"
    );

    let answered = node.peers.on(PeerEvent::CloseAnswered {
        peer: member,
        ready: true,
    });
    assert!(
        answered
            .iter()
            .any(|a| matches!(a, PeerAction::Disconnect { peer } if *peer == member)),
        "and hung up on once they agree"
    );
    assert!(
        node.peers.close_was_agreed(&member),
        "the side that asked knows it too, so neither log calls this a failure"
    );
}

#[test]
fn an_agreement_that_led_to_no_close_goes_stale() {
    let mut them = Node::new();
    let caller = peers(1)[0];
    let _ = them.group_with(&[caller]);
    them.peers.on(PeerEvent::Verified { peer: caller });

    them.peers.on(PeerEvent::CloseProposed {
        peer: caller,
        ready: true,
    });
    assert!(them.peers.close_was_agreed(&caller));

    // They asked, we agreed, and then they never hung up. Whatever ends the connection
    // after that is not the hang-up we agreed to, and the cause is worth printing.
    them.tick(AT + CLOSE_TIMEOUT);
    assert!(
        !them.peers.close_was_agreed(&caller),
        "an agreement nobody acted on stops speaking for later failures"
    );
}
