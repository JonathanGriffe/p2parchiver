#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Instant;

use ac_groups::chain::{Entry, Op};
use ac_groups::id::GroupId;
use ac_groups::standing::Position;
use ac_groups::store::{Groups, State};
use ac_groups::sync::{GroupAction, GroupEvent, GroupSync, Notice};
use ac_groups::wire::{GroupHead, GroupRequest, GroupResponse};
use ac_net::PeerId;
use ac_net::connectivity::Connectivity;
use ac_net::identity::Keypair;
use ac_net::roster::Roster;

const AT: i64 = 1_000_000;

fn key() -> Keypair {
    Keypair::generate_ed25519()
}

fn peer_of(k: &Keypair) -> PeerId {
    k.public().to_peer_id()
}

fn sync_for(k: &Keypair) -> GroupSync {
    GroupSync::new(Groups::in_memory(peer_of(k)).unwrap(), k.clone())
}

/// Everything one side needs to be driven: its machine and its own key.
struct Node {
    key: Keypair,
    roster: Roster,
    sync: GroupSync,
}

impl Node {
    fn new() -> Self {
        let key = key();
        Self {
            sync: sync_for(&key),
            roster: Roster::default(),
            key,
        }
    }

    fn peer(&self) -> PeerId {
        peer_of(&self.key)
    }

    /// Admit a peer and promote them, as the daemon's roster would.
    ///
    /// An empty `Connectivity` promotes everyone: `settled` is false only while a hole punch
    /// is still in flight, and these tests have no connections at all.
    fn verify(&mut self, other: PeerId) -> Vec<GroupAction> {
        self.roster.admitted(other);
        self.roster.promote(&Connectivity::default());
        Vec::new()
    }

    /// Every call into the machine carries the roster, so who is admitted is asked rather
    /// than remembered.
    fn sync_on(&mut self, event: GroupEvent) -> Vec<GroupAction> {
        self.sync.on(event, &self.roster)
    }

    fn sync_on_request(
        &mut self,
        peer: PeerId,
        request: GroupRequest,
    ) -> (GroupResponse, Vec<GroupAction>) {
        self.sync.on_request(peer, request, &self.roster)
    }

    /// A peer that has gone. The roster forgets them; nothing else needs telling.
    fn forget(&mut self, other: PeerId) {
        self.roster.disconnected(&other, false);
    }

    fn tick(&mut self) -> Vec<GroupAction> {
        self.sync_on(GroupEvent::Tick {
            now: Instant::now(),
            at: AT,
        })
    }
}

/// What the supervisor would do, which the machine no longer decides: put the question.
#[derive(Debug, Clone)]
enum Step {
    /// The question the supervisor would put; which peers is decided by `Side`.
    Ask,
    Act(GroupAction),
}

fn asked(node: &mut Node, peer: PeerId) -> Vec<GroupId> {
    match node.sync_on_request(peer, GroupRequest::Ask).0 {
        GroupResponse::Heads(heads) => heads.into_iter().map(|h| h.group).collect(),
        other => panic!("expected heads, got {other:?}"),
    }
}

fn fetches(actions: &[GroupAction]) -> Vec<(PeerId, GroupId, u64)> {
    actions
        .iter()
        .filter_map(|a| match a {
            GroupAction::Fetch { peer, group, from } => Some((*peer, *group, *from)),
            _ => None,
        })
        .collect()
}

/// Dispatch actions between two nodes until nothing is left to send.
fn settle(a: &mut Node, b: &mut Node, seed: Vec<(Side, Step)>) -> Vec<Notice> {
    let mut queue = seed;
    let mut notes = Vec::new();

    for _ in 0..200 {
        let Some((side, action)) = queue.pop() else {
            return notes;
        };
        match side {
            Side::A => step(a, b, Side::A, action, &mut queue, &mut notes),
            Side::B => step(b, a, Side::B, action, &mut queue, &mut notes),
        }
    }
    panic!("the exchange never settled");
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

fn step(
    sender: &mut Node,
    receiver: &mut Node,
    side: Side,
    action: Step,
    queue: &mut Vec<(Side, Step)>,
    notes: &mut Vec<Notice>,
) {
    match action {
        Step::Act(GroupAction::Note(n)) => notes.push(n),

        Step::Ask => {
            let (response, theirs) = receiver.sync_on_request(sender.peer(), GroupRequest::Ask);
            queue.extend(theirs.into_iter().map(|x| (side.other(), Step::Act(x))));

            if let GroupResponse::Heads(heads) = response {
                let back = sender.sync_on(GroupEvent::Heads {
                    peer: receiver.peer(),
                    heads,
                });
                queue.extend(back.into_iter().map(|x| (side, Step::Act(x))));
            }
        }

        Step::Act(GroupAction::Fetch { group, from, .. }) => {
            let (response, theirs) =
                receiver.sync_on_request(sender.peer(), GroupRequest::Fetch { group, from });
            queue.extend(theirs.into_iter().map(|x| (side.other(), Step::Act(x))));

            let event = match response {
                GroupResponse::Entries {
                    group,
                    from,
                    entries,
                    standings,
                } => GroupEvent::Entries {
                    peer: receiver.peer(),
                    group,
                    from,
                    entries,
                    standings,
                },
                _ => GroupEvent::Unavailable {
                    peer: receiver.peer(),
                    group,
                },
            };
            let back = sender.sync_on(event);
            queue.extend(back.into_iter().map(|x| (side, Step::Act(x))));
        }
    }
}

/// Connect two nodes and let them sync to quiescence. `a` is [`Side::A`].
/// Verify both ways and let each side offer, as the supervisor does on a fresh connection.
fn connect(a: &mut Node, b: &mut Node) -> Vec<Notice> {
    a.verify(b.peer());
    b.verify(a.peer());

    let seed = vec![(Side::A, Step::Ask), (Side::B, Step::Ask)];
    settle(a, b, seed)
}

/// An admin with one group, and a member added to it who holds nothing yet.
fn admin_and_member() -> (Node, Node, GroupId) {
    let mut admin = Node::new();
    let member = Node::new();
    let id = admin
        .sync
        .store_mut()
        .create(&admin.key, "family", "alice", AT)
        .unwrap();
    admin
        .sync
        .store_mut()
        .author(
            &admin.key,
            id,
            Op::Add {
                peer: member.peer().to_base58(),
                username: "bob".into(),
            },
            AT,
        )
        .unwrap();
    (admin, member, id)
}

/// Add `peer` to `id` as the admin.
fn add(admin: &mut Node, id: GroupId, peer: PeerId, name: &str) {
    admin
        .sync
        .store_mut()
        .author(
            &admin.key,
            id,
            Op::Add {
                peer: peer.to_base58(),
                username: name.into(),
            },
            AT,
        )
        .unwrap();
}

fn join(admin: &mut Node, member: &mut Node, id: GroupId) {
    connect(admin, member);
    member
        .sync
        .store_mut()
        .author_standing(&member.key, id, Position::In, AT)
        .unwrap();
}

#[test]
fn an_answer_names_exactly_the_shared_groups() {
    let (mut admin, member, id) = admin_and_member();
    let stranger = Node::new();
    admin.verify(member.peer());
    admin.verify(stranger.peer());

    assert_eq!(asked(&mut admin, member.peer()), vec![id]);
    assert!(asked(&mut admin, stranger.peer()).is_empty());
}

#[test]
fn a_new_member_learns_the_whole_group() {
    let (mut admin, mut member, id) = admin_and_member();
    let notes = connect(&mut admin, &mut member);

    let row = member.sync.store().get(id).unwrap().unwrap();
    assert_eq!(row.head_seq, 2);
    assert_eq!(
        row.state,
        State::Pending,
        "being added is not the same as consenting"
    );
    assert!(
        member
            .sync
            .store()
            .members(id)
            .unwrap()
            .contains(&member.peer())
    );
    assert!(
        notes.iter().any(|n| matches!(n, Notice::Invited { .. })),
        "and are told, so they can accept: {notes:?}"
    );
}

#[test]
fn receiving_an_invitation_is_answered_in_writing_and_only_once() {
    // A pending node that says nothing is indistinguishable from one that never got the chain,
    // so every member goes on re-offering the invitation on every discovery hint. `Unanswered`
    // is the smallest true thing it can say, and saying it is what stops the dialling.
    let (mut admin, mut member, id) = admin_and_member();
    connect(&mut admin, &mut member);

    assert_eq!(
        member.sync.store().get(id).unwrap().unwrap().state,
        State::Pending,
        "still not accepted"
    );
    let standings = member.sync.store().standings(id).unwrap();
    assert_eq!(standings.len(), 1, "it has spoken for itself, once");
    let body = standings[0].verify(id).unwrap();
    assert_eq!(body.peer, member.peer().to_base58());
    assert_eq!(body.position, Position::Unanswered);
    assert_eq!(body.seq, 1);

    // Syncing again must not spend another seq: having spoken at all is the condition.
    connect(&mut admin, &mut member);
    let after = member.sync.store().standings(id).unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].verify(id).unwrap().seq, 1);

    let seen = admin.sync.store().standings(id).unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].verify(id).unwrap().position, Position::Unanswered);
    assert!(
        admin.sync.store().departed(id).unwrap().is_empty(),
        "an unanswered invitation is not a departure"
    );
    assert_eq!(
        admin.sync.store().chain(id).unwrap().len(),
        2,
        "and nothing was ratified against them"
    );
}

#[test]
fn an_answer_never_provokes_another_question() {
    // Answering a set of heads with a question of our own would volley forever. `settle` panics
    // if the exchange does not terminate, so this is also checked by every other test here.
    let (mut admin, mut member, _id) = admin_and_member();
    admin.verify(member.peer());
    member.verify(admin.peer());

    let actions = member.sync_on(GroupEvent::Heads {
        peer: admin.peer(),
        heads: Vec::new(),
    });
    assert!(
        actions
            .iter()
            .all(|a| matches!(a, GroupAction::Fetch { .. } | GroupAction::Note(_))),
        "an answer must produce fetches only"
    );
}

#[test]
fn a_non_member_is_told_nothing_however_it_asks() {
    let (mut admin, _member, id) = admin_and_member();
    let stranger = Node::new();
    admin.verify(stranger.peer());

    let (offer, _) = admin.sync_on_request(stranger.peer(), GroupRequest::Ask);
    assert_eq!(offer, GroupResponse::Heads(Vec::new()));

    let (fetch, _) =
        admin.sync_on_request(stranger.peer(), GroupRequest::Fetch { group: id, from: 0 });
    assert_eq!(fetch, GroupResponse::Unavailable);
}

#[test]
fn an_unverified_peer_is_answered_nothing() {
    let (mut admin, _member, id) = admin_and_member();
    let unknown = Node::new();

    let (offer, _) = admin.sync_on_request(unknown.peer(), GroupRequest::Ask);
    assert_eq!(offer, GroupResponse::Unavailable);

    let (fetch, _) =
        admin.sync_on_request(unknown.peer(), GroupRequest::Fetch { group: id, from: 0 });
    assert_eq!(fetch, GroupResponse::Unavailable);
}

#[test]
fn a_late_or_unsolicited_response_is_ignored() {
    // Only the request we are actually waiting on may move our head.
    let (mut admin, mut member, id) = admin_and_member();
    admin.verify(member.peer());
    member.verify(admin.peer());

    let entries: Vec<Entry> = admin
        .sync
        .store()
        .chain(id)
        .unwrap()
        .entries()
        .cloned()
        .collect();

    let actions = member.sync_on(GroupEvent::Entries {
        peer: admin.peer(),
        group: id,
        from: 0,
        entries,
        standings: Vec::new(),
    });

    assert!(actions.is_empty());
    assert!(
        member.sync.store().get(id).unwrap().is_none(),
        "nothing was asked for, so nothing may be applied"
    );
}

#[test]
fn two_offers_for_one_group_produce_a_single_fetch() {
    let (admin, mut member, id) = admin_and_member();
    let other = Node::new();
    member.verify(admin.peer());
    member.verify(other.peer());

    let head = admin.sync.store().get(id).unwrap().unwrap().head();
    let first = member.sync_on(GroupEvent::Heads {
        peer: admin.peer(),
        heads: vec![head.clone()],
    });
    let second = member.sync_on(GroupEvent::Heads {
        peer: other.peer(),
        heads: vec![head],
    });

    assert_eq!(fetches(&first).len(), 1);
    assert!(
        fetches(&second).is_empty(),
        "one episode per group; the second offerer waits"
    );
}

#[test]
fn a_removed_member_finds_out_by_asking() {
    // Nobody offers a group to a non-member, so without the discrepancy check a removal would
    // be silent and permanent.
    let (mut admin, mut member, id) = admin_and_member();
    join(&mut admin, &mut member, id);

    // The admin removes them, then adds someone else the member must never see.
    admin
        .sync
        .store_mut()
        .author(
            &admin.key,
            id,
            Op::Remove {
                peer: member.peer().to_base58(),
            },
            AT,
        )
        .unwrap();
    add(&mut admin, id, Node::new().peer(), "carol");

    let notes = connect(&mut admin, &mut member);

    assert!(
        !member
            .sync
            .store()
            .members(id)
            .unwrap()
            .contains(&member.peer()),
        "they now know they are out"
    );
    assert_eq!(
        member.sync.store().get(id).unwrap().unwrap().head_seq,
        3,
        "up to and including their removal, and not one entry further"
    );
    assert!(
        notes
            .iter()
            .any(|n| matches!(n, Notice::RemovedByAdmin { .. })),
        "and are told so: {notes:?}"
    );
}

#[test]
fn the_admin_ratifies_a_departure_exactly_once() {
    let (mut admin, mut member, id) = admin_and_member();
    join(&mut admin, &mut member, id);

    let head_before = admin.sync.store().get(id).unwrap().unwrap().head_seq;
    member
        .sync
        .store_mut()
        .author_standing(&member.key, id, Position::Out, AT)
        .unwrap();

    // Three reconnections, as a restart or a digest repair would produce.
    let ratified: usize = (0..3)
        .map(|_| {
            connect(&mut admin, &mut member)
                .iter()
                .filter(|n| matches!(n, Notice::Ratified { .. }))
                .count()
        })
        .sum();

    assert_eq!(
        ratified, 1,
        "one Remove per departure, not one per delivery"
    );
    assert!(
        !admin
            .sync
            .store()
            .members(id)
            .unwrap()
            .contains(&member.peer())
    );
    assert_eq!(
        admin.sync.store().get(id).unwrap().unwrap().head_seq,
        head_before + 1,
        "exactly one entry was appended"
    );
}

#[test]
fn a_non_admin_notes_a_departure_but_does_not_ratify_it() {
    let (mut admin, mut bob, id) = admin_and_member();
    let mut carol = Node::new();
    add(&mut admin, id, carol.peer(), "carol");

    join(&mut admin, &mut bob, id);
    join(&mut admin, &mut carol, id);

    bob.sync
        .store_mut()
        .author_standing(&bob.key, id, Position::Out, AT)
        .unwrap();

    let head_before = carol.sync.store().get(id).unwrap().unwrap().head_seq;
    let notes = connect(&mut carol, &mut bob);

    assert!(
        notes.iter().any(|n| matches!(n, Notice::Departed { .. })),
        "a member notes it: {notes:?}"
    );
    assert!(
        !notes.iter().any(|n| matches!(n, Notice::Ratified { .. })),
        "but only the admin may write the Remove"
    );
    assert_eq!(
        carol.sync.store().get(id).unwrap().unwrap().head_seq,
        head_before,
        "a non-admin appends nothing"
    );
}

#[test]
fn a_node_that_has_left_still_answers_so_its_departure_can_travel() {
    // It holds the only copy of its own standing. If leaving made it refuse every request,
    // the admin could never learn, and leaving would be invisible to everyone but the leaver.
    let (mut admin, mut member, id) = admin_and_member();
    join(&mut admin, &mut member, id);

    let head_before = member.sync.store().get(id).unwrap().unwrap().head_seq;
    member
        .sync
        .store_mut()
        .author_standing(&member.key, id, Position::Out, AT)
        .unwrap();

    assert_eq!(
        member.sync.store().get(id).unwrap().unwrap().head_seq,
        head_before,
        "leaving appends nothing to the chain"
    );
    assert_eq!(
        member.sync.store().get(id).unwrap().unwrap().state,
        State::Left
    );
    assert!(
        member
            .sync
            .store()
            .shared_with(&admin.peer())
            .unwrap()
            .is_empty(),
        "it stops advertising"
    );

    member.verify(admin.peer());
    let (response, _) =
        member.sync_on_request(admin.peer(), GroupRequest::Fetch { group: id, from: 0 });
    let GroupResponse::Entries { standings, .. } = response else {
        panic!("a node that has left must still answer a member, got {response:?}");
    };
    assert_eq!(standings.len(), 1, "and hands over its own standing");
}

#[test]
fn a_peer_that_disconnects_is_forgotten() {
    let (mut admin, member, _id) = admin_and_member();
    admin.verify(member.peer());
    admin.forget(member.peer());

    let (response, _) = admin.sync_on_request(member.peer(), GroupRequest::Ask);
    assert_eq!(
        response,
        GroupResponse::Unavailable,
        "an unverified peer gets nothing, even one verified a moment ago"
    );
}

#[test]
fn a_flood_of_requests_is_refused_and_refills_on_the_tick() {
    let (mut admin, member, _id) = admin_and_member();
    admin.verify(member.peer());

    let ask = |admin: &mut Node| admin.sync_on_request(member.peer(), GroupRequest::Ask).0;

    let refused = (0..40)
        .filter(|_| ask(&mut admin) == GroupResponse::Unavailable)
        .count();
    assert!(refused > 0, "the budget must run out");
    assert_eq!(ask(&mut admin), GroupResponse::Unavailable);

    admin.tick();
    assert_ne!(ask(&mut admin), GroupResponse::Unavailable, "and refill");
}

#[test]
fn a_stranger_offering_many_unknown_groups_writes_nothing() {
    let mut node = Node::new();
    let stranger = Node::new();
    node.verify(stranger.peer());

    let junk: Vec<GroupHead> = (0..200u8)
        .map(|i| GroupHead {
            group: GroupId::of_genesis(&[i]),
            head_seq: 9,
            head_hash: ac_groups::id::EntryHash::of_body(&[i]),
            standings: [i; 32],
        })
        .collect();

    let actions = node.sync_on(GroupEvent::Heads {
        peer: stranger.peer(),
        heads: junk,
    });

    assert!(
        node.sync.store().list().unwrap().is_empty(),
        "an offer alone must never create a row"
    );
    assert!(
        fetches(&actions).len() <= 8,
        "the in-flight cap bounds the chase, got {}",
        fetches(&actions).len()
    );
}
