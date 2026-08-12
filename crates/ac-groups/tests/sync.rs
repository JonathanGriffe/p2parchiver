//! The sync policy, driven by hand.
//!
//! Every test here feeds [`GroupEvent`]s to a [`GroupSync`] backed by an in-memory store and
//! asserts on the [`GroupAction`]s that come back. No swarm, no socket, no tokio, no sleeping
//! — which is the whole point of the machine returning actions instead of performing them.

// An integration test is its own crate, so the library's test-only allow does not reach here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Instant;

use ac_groups::chain::{Entry, Op};
use ac_groups::id::GroupId;
use ac_groups::store::{Groups, State};
use ac_groups::sync::{GroupAction, GroupEvent, GroupSync, Notice};
use ac_groups::wire::{GroupHead, GroupRequest, GroupResponse};
use ac_net::PeerId;
use libp2p::identity::Keypair;

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
    sync: GroupSync,
}

impl Node {
    fn new() -> Self {
        let key = key();
        Self {
            sync: sync_for(&key),
            key,
        }
    }

    fn peer(&self) -> PeerId {
        peer_of(&self.key)
    }

    fn verify(&mut self, other: PeerId) -> Vec<GroupAction> {
        self.sync.on(GroupEvent::PeerVerified { peer: other })
    }

    fn tick(&mut self) -> Vec<GroupAction> {
        self.sync.on(GroupEvent::Tick {
            now: Instant::now(),
            at: AT,
        })
    }
}

fn offers(actions: &[GroupAction]) -> Vec<(PeerId, Vec<GroupId>)> {
    actions
        .iter()
        .filter_map(|a| match a {
            GroupAction::Offer { peer, heads } => {
                Some((*peer, heads.iter().map(|h| h.group).collect()))
            }
            _ => None,
        })
        .collect()
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
///
/// This is what the daemon does, and the reason the tests use it rather than hand-carrying
/// one message: **every** action is dispatched, including the ones a responder produces while
/// answering. A harness that quietly drops an action leaves a fetch in flight, which blocks
/// that group until it times out — and then tests fail for reasons that have nothing to do
/// with what they are checking.
fn settle(a: &mut Node, b: &mut Node, seed: Vec<(Side, GroupAction)>) -> Vec<Notice> {
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
    action: GroupAction,
    queue: &mut Vec<(Side, GroupAction)>,
    notes: &mut Vec<Notice>,
) {
    match action {
        GroupAction::Note(n) => notes.push(n),

        GroupAction::Offer { heads, .. } => {
            let (response, theirs) = receiver
                .sync
                .on_request(sender.peer(), GroupRequest::Offer(heads));
            queue.extend(theirs.into_iter().map(|x| (side.other(), x)));

            if let GroupResponse::Offer(heads) = response {
                let back = sender.sync.on(GroupEvent::Offered {
                    peer: receiver.peer(),
                    heads,
                });
                queue.extend(back.into_iter().map(|x| (side, x)));
            }
        }

        GroupAction::Fetch { group, from, .. } => {
            let (response, theirs) = receiver
                .sync
                .on_request(sender.peer(), GroupRequest::Fetch { group, from });
            queue.extend(theirs.into_iter().map(|x| (side.other(), x)));

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
            let back = sender.sync.on(event);
            queue.extend(back.into_iter().map(|x| (side, x)));
        }
    }
}

/// Connect two nodes and let them sync to quiescence. `a` is [`Side::A`].
/// Verify both ways and let each side offer, as the supervisor does on a fresh connection.
///
/// The offer is seeded here rather than produced by `PeerVerified`, because deciding *when* to
/// talk to a peer belongs to `ac-peers` — this machine only decides what to say. Playing that
/// part explicitly is what keeps these tests about the chain rules.
fn connect(a: &mut Node, b: &mut Node) -> Vec<Notice> {
    a.verify(b.peer());
    b.verify(a.peer());

    let (peer_a, peer_b) = (a.peer(), b.peer());
    let seed = vec![
        (
            Side::A,
            GroupAction::Offer {
                peer: peer_b,
                heads: a.sync.heads_for(&peer_b),
            },
        ),
        (
            Side::B,
            GroupAction::Offer {
                peer: peer_a,
                heads: b.sync.heads_for(&peer_a),
            },
        ),
    ];
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

/// Connect, sync, and accept — a member fully joined and participating.
fn join(admin: &mut Node, member: &mut Node, id: GroupId) {
    connect(admin, member);
    member
        .sync
        .store_mut()
        .author_standing(&member.key, id, true, AT)
        .unwrap();
}

#[test]
fn an_offer_names_exactly_the_shared_groups() {
    // `shared_with` is the only thing allowed to build a head bound for a peer, and this is
    // what it comes to: a member is named the group, a stranger is named nothing at all — not
    // even that it exists.
    let (admin, member, id) = admin_and_member();
    let stranger = Node::new();

    assert_eq!(
        admin
            .sync
            .heads_for(&member.peer())
            .iter()
            .map(|h| h.group)
            .collect::<Vec<_>>(),
        vec![id]
    );
    assert!(admin.sync.heads_for(&stranger.peer()).is_empty());
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
fn an_offer_response_never_provokes_another_offer() {
    // Two peers each answering an offer with an offer would volley forever. `settle` panics
    // if the exchange does not terminate, so this is also checked by every other test here.
    let (mut admin, mut member, _id) = admin_and_member();
    admin.verify(member.peer());
    member.verify(admin.peer());

    let actions = member.sync.on(GroupEvent::Offered {
        peer: admin.peer(),
        heads: Vec::new(),
    });
    assert!(
        offers(&actions).is_empty(),
        "an offer response must produce fetches only"
    );
}

#[test]
fn a_non_member_is_told_nothing_however_it_asks() {
    let (mut admin, _member, id) = admin_and_member();
    let stranger = Node::new();
    admin.verify(stranger.peer());

    let (offer, _) = admin
        .sync
        .on_request(stranger.peer(), GroupRequest::Offer(Vec::new()));
    assert_eq!(offer, GroupResponse::Offer(Vec::new()));

    // Even naming the group id exactly — which a stranger should not know — reveals nothing.
    let (fetch, _) = admin
        .sync
        .on_request(stranger.peer(), GroupRequest::Fetch { group: id, from: 0 });
    assert_eq!(fetch, GroupResponse::Unavailable);
}

#[test]
fn an_unverified_peer_is_answered_nothing() {
    let (mut admin, _member, id) = admin_and_member();
    let unknown = Node::new();

    let (offer, _) = admin
        .sync
        .on_request(unknown.peer(), GroupRequest::Offer(Vec::new()));
    assert_eq!(offer, GroupResponse::Unavailable);

    let (fetch, _) = admin
        .sync
        .on_request(unknown.peer(), GroupRequest::Fetch { group: id, from: 0 });
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

    let actions = member.sync.on(GroupEvent::Entries {
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
    let first = member.sync.on(GroupEvent::Offered {
        peer: admin.peer(),
        heads: vec![head.clone()],
    });
    let second = member.sync.on(GroupEvent::Offered {
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
        .author_standing(&member.key, id, false, AT)
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
        .author_standing(&bob.key, id, false, AT)
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
        .author_standing(&member.key, id, false, AT)
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
    let (response, _) = member
        .sync
        .on_request(admin.peer(), GroupRequest::Fetch { group: id, from: 0 });
    let GroupResponse::Entries { standings, .. } = response else {
        panic!("a node that has left must still answer a member, got {response:?}");
    };
    assert_eq!(standings.len(), 1, "and hands over its own standing");
}

#[test]
fn a_peer_that_disconnects_is_forgotten() {
    let (mut admin, member, _id) = admin_and_member();
    admin.verify(member.peer());
    admin.sync.on(GroupEvent::PeerGone {
        peer: member.peer(),
    });

    let (response, _) = admin
        .sync
        .on_request(member.peer(), GroupRequest::Offer(Vec::new()));
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

    let ask = |admin: &mut Node| {
        admin
            .sync
            .on_request(member.peer(), GroupRequest::Offer(Vec::new()))
            .0
    };

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

    let actions = node.sync.on(GroupEvent::Offered {
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
