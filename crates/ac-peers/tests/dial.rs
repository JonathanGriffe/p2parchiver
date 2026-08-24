//! The supervisor, driven by hand.
//!
//! No swarm, no socket, no tokio, no sleeping — a four-hour heartbeat and a thirty-minute
//! backoff are both a matter of choosing the `at` passed to a tick.
//!
//! The first several tests are regressions for failures this design was found to have while
//! being reviewed, before any of it was written. Each is noted as such, because every one of
//! them looks like working code from the outside.

// An integration test is its own crate, so the library's test-only allow does not reach here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashSet;

use ac_files::path::RelPath;
use ac_files::store::{FileRow, Files};
use ac_groups::chain::Op;
use ac_groups::id::GroupId;
use ac_groups::standing::{Position, Standing};
use ac_groups::store::Groups;
use ac_net::PeerId;
use ac_net::identity::Keypair;
use ac_peers::sync::{
    DIAL_ATTEMPTS, DIAL_WINDOW, DIALS_PER_WINDOW, HEARTBEAT, Limits, MAX_TRANSFERS, MIN_BACKOFF,
    Notice, Offering, PRESENCE_INTERVAL, PeerAction, PeerEvent, Peers, ROUND_TIMEOUT,
    SHARE_AFTER_IDLE,
};

const AT: i64 = 1_000_000;

/// One node's supervisor, plus the keys of everyone it shares a group with.
struct Node {
    peers: Peers,
    key: Keypair,
    me: PeerId,
}

impl Node {
    fn new() -> Self {
        Self::with_limits(Limits::default())
    }

    fn with_limits(limits: Limits) -> Self {
        let key = Keypair::generate_ed25519();
        let me = key.public().to_peer_id();
        Self {
            peers: Peers::new(
                Files::in_memory(me).unwrap(),
                Groups::in_memory(me).unwrap(),
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

        for (i, peer) in members.iter().enumerate() {
            self.peers
                .groups_mut()
                .author(
                    &key,
                    id,
                    Op::Add {
                        peer: peer.to_base58(),
                        username: format!("member{i}"),
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

    /// A row we know of and do not hold — what a catalogue sync leaves behind.
    fn learn_file(&mut self, group: GroupId, path: &str) {
        self.record(group, path, false);
    }

    fn record(&mut self, group: GroupId, path: &str, have: bool) {
        let path = RelPath::parse(path).unwrap();
        let mut hash = [0u8; 32];
        for (i, b) in path.as_str().bytes().enumerate() {
            hash[i % 32] ^= b;
        }
        let row = FileRow {
            path: path.clone(),
            size: 1,
            hash: hex::encode(hash),
            modified: AT,
            added_at: AT,
            added_by: self.me,
            removed_at: None,
            have,
            seen_seq: 0,
        };
        self.peers.files_mut().record(group, &row, true).unwrap();
        if !have {
            self.peers
                .files_mut()
                .mark_have(group, &path, false)
                .unwrap();
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
                    username: "newcomer".into(),
                },
                AT,
            )
            .unwrap();
    }

    /// A member's signed answer to the invitation, arriving as a chain sync would deliver it.
    ///
    /// Signed by them, so it cannot be faked with `author_standing` — that one writes *our* row.
    fn accept_invite(&mut self, group: GroupId, key: &Keypair) {
        let standing = Standing::author(key, group, 1, Position::In, AT).unwrap();
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

    /// Everyone online and connected, as a settled network would be.
    fn all_up(&mut self, members: &[PeerId]) {
        self.peers.on(PeerEvent::Presence {
            asked: members.to_vec(),
            online: members.to_vec(),
        });
        for peer in members {
            self.peers.on(PeerEvent::Verified { peer: *peer });
        }
    }
}

fn peers(n: usize) -> Vec<PeerId> {
    (0..n)
        .map(|_| Keypair::generate_ed25519().public().to_peer_id())
        .collect()
}

/// One tick, with any offer it starts reported as settled.
///
/// A peer may have one offer outstanding, so a test that ticks several times without answering
/// finds the peer busy and then looks quiet for the wrong reason.
fn answered(node: &mut Node, at: i64, group: GroupId) -> Vec<PeerAction> {
    let actions = node.tick(at);
    settle_offers(node, &actions, group);
    actions
}

/// Answer every offer the way the daemon would, with the protocol it was sent on.
///
/// Membership and the catalogue are two exchanges, so a member is told in two steps; answering
/// both as though they were the second leaves the first outstanding for ever.
fn settle_offers(node: &mut Node, actions: &[PeerAction], group: GroupId) -> Vec<PeerId> {
    let mut told = Vec::new();
    for action in actions {
        if let PeerAction::Offer { peer, offering } = action {
            node.peers.on(PeerEvent::Synced {
                peer: *peer,
                group,
                offering: *offering,
            });
            told.push(*peer);
        }
    }
    told
}

/// Tick once to notice an edit, and answer when the pause it must wait out has elapsed.
///
/// `SHARE_AFTER_IDLE` is deliberate and not skippable: a single `ac file add` is not told to the
/// group until the catalogue has been still for two minutes, so that an afternoon of sorting
/// photographs costs one round rather than ninety. Membership is exempt and goes at once, which
/// is why only the catalogue tests need this.
///
/// Two ticks are needed because the first is what *notices* the edit — the supervisor is told
/// nothing by the process that made it and can only compare the store against what it last saw.
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
///
/// Collects actions produced by the answers as well as by the tick itself — a round that is
/// never answered leaves the peer looking busy for ever, which silently disables every close
/// test in this file.
fn step(node: &mut Node, at: i64, holds: bool) -> Vec<PeerAction> {
    let mut seen = Vec::new();
    let mut queue = node.tick(at);

    while let Some(action) = queue.pop() {
        match &action {
            // An offer names every group shared with that peer, and each settles separately —
            // so answering one means answering for all of them, as the daemon does. Whether it
            // was the chain or the catalogue is the supervisor's business: it recorded which,
            // and settles the matching half.
            PeerAction::Offer { peer, offering } => {
                for group in node.shared_groups() {
                    queue.extend(node.peers.on(PeerEvent::Synced {
                        peer: *peer,
                        group,
                        offering: *offering,
                    }));
                }
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
///
/// The actions matter: a close proposal is emitted by whichever tick first finds the peer
/// drained, which is usually one of these — so a test that settles and *then* looks for the
/// proposal finds nothing, the proposal already being outstanding.
fn settle(node: &mut Node, from: i64) -> (i64, Vec<PeerAction>) {
    let mut seen = Vec::new();
    for at in (from..).take(20) {
        let actions = step(node, at, false);
        let busy = actions.iter().any(|a| {
            matches!(
                a,
                PeerAction::Offer { .. } | PeerAction::AskHoldings { .. } | PeerAction::Dial { .. }
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
            PeerAction::Offer { peer, .. } => Some(*peer),
            _ => None,
        })
        .collect()
}

// ---- regressions for failures found while reviewing the design ----

#[test]
fn one_change_in_a_fifty_member_group_is_not_fifty_dials() {
    // The mistake the whole design corrects. Iterating peers and asking "is there work with
    // them" answers the same for every member under auto-mirror, so all forty-nine look
    // equally worth dialling — ~2,450 dials per interval across the group to discover nothing
    // changed. The loop iterates groups instead.
    let mut node = Node::new();
    let members = peers(49);
    let id = node.group_with(&members);
    node.all_up(&members);
    node.add_file(id, "new.jpg");

    let actions = node.tick(AT);
    let contacted = rounds(&actions).len() + dials(&actions).len();

    assert!(
        contacted <= 2,
        "one change produced {contacted} contacts in a fifty-member group"
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
    node.all_up(&members);
    node.add_file(id, "a.jpg");

    // Settle: let the initial exchanges run themselves out.
    for _ in 0..8 {
        let actions = node.tick(AT);
        settle_offers(&mut node, &actions, id);
    }
    assert!(rounds(&node.tick(AT)).is_empty(), "quiet before the change");

    let key = node.key.clone();
    let newcomer = peers(1)[0];
    node.peers
        .groups_mut()
        .author(
            &key,
            id,
            Op::Add {
                peer: newcomer.to_base58(),
                username: "new".into(),
            },
            AT,
        )
        .unwrap();
    node.peers.on(PeerEvent::Presence {
        asked: vec![members[0], newcomer],
        online: vec![members[0], newcomer],
    });
    node.peers.on(PeerEvent::Verified { peer: newcomer });

    let actions = node.tick(AT);
    assert!(
        !rounds(&actions).is_empty() || !dials(&actions).is_empty(),
        "a membership change is news: {actions:?}"
    );
}

#[test]
fn no_more_circuits_are_opened_than_the_relay_allows() {
    // The allowance is the server's, and spending past it does not get us more connections —
    // it gets us refusals, each of which backs off a member who was reachable all along.
    //
    // In the lab a node spent both circuits in one tick, on a member that had been stopped and
    // a member that held nothing, and then had both of its dials to the only peer holding the
    // file it wanted refused by the relay. It reported the file unobtainable without ever
    // asking the node that had it.
    // More members than the window allows, so the cap is what stops us rather than running out
    // of people to call.
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
    // Only `MAX_CATALOGUE_ROUNDS` rounds may run at once, so a round that never settles takes a
    // slot with it for good. Two of them and this node stops gossiping entirely — while
    // reporting itself idle, connected, and with news still to send, which is what `ac peer
    // status` showed in the lab: "2 round(s)" against a peer that had answered nothing.
    //
    // The refusal that caused it is fixed at its source in `ac-files`. This is the guarantee
    // that the *next* unreported ending costs a minute rather than the node.
    let mut node = Node::new();
    let members = peers(3);
    let id = node.group_with(&members);
    node.add_file(id, "a.jpg");
    node.all_up(&members);

    // Start rounds and answer none of them.
    let mut started = Vec::new();
    for k in 0..4 {
        started.extend(rounds(&node.tick(AT + k)));
    }
    assert!(!started.is_empty(), "rounds should have gone out");
    assert!(
        rounds(&node.tick(AT + 5)).is_empty(),
        "the slots are full while they are outstanding"
    );

    // Past the timeout they are written off, and the node can work again.
    node.add_file(id, "b.jpg");
    let actions = node.tick(AT + ROUND_TIMEOUT + 6);
    assert!(
        !rounds(&actions).is_empty() || !dials(&actions).is_empty(),
        "a round nobody answered must not cost the slot for ever: {actions:?}"
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
fn a_new_file_is_fetched_although_the_group_had_given_up_before() {
    // The backoff is a conclusion about a catalogue — "no member here has what we are missing" —
    // and a catalogue that has since moved invalidates it. The plan says as much: reset on the
    // catalogue changing or on a member returning, because `have` is local and a peer acquiring
    // a file moves nothing on the wire, so re-asking is the only discovery there is.
    //
    // Neither reset existed. A group that exhausted its rotation once — which happens routinely
    // in a mirror, where members hold the same files and each finds the other has nothing for
    // it — doubled its way to a multi-minute silence and served it out even as new files
    // arrived. In the lab a member knew a file existed and never once asked for it.
    let mut node = Node::new();
    let members = peers(1);
    let id = node.group_with(&members);
    node.learn_file(id, "nobody-has-this.jpg");
    node.all_up(&members);

    // Exhaust the group: the one member holds nothing we want.
    let mut backed_off = false;
    for k in 0..8 {
        let actions = step(&mut node, AT + k, false);
        if actions
            .iter()
            .any(|a| matches!(a, PeerAction::Note(Notice::Unobtainable { .. })))
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
    // Circuits are the scarce resource — two a minute, server-enforced — and an open connection
    // costs none. Choosing by rotation alone spent the whole allowance dialling members who
    // could not be reached while an idle connection to one who could help was held and then
    // hung up on: in the lab a file stayed `remote` on a node that knew it existed and had
    // burned six refused circuits on the two peers that did not have it.
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
    node.peers.on(PeerEvent::Verified { peer: held });

    let actions = node.tick(AT);
    assert!(
        dials(&actions).is_empty(),
        "no circuit is worth spending while a connection is open: {actions:?}"
    );
    assert!(
        actions.iter().any(|a| matches!(
            a,
            PeerAction::AskHoldings { peer, .. } | PeerAction::Offer { peer, .. } if *peer == held
        )),
        "the peer we are already talking to is the one asked: {actions:?}"
    );
}

#[test]
fn news_goes_to_each_member_once_not_to_one_member_repeatedly() {
    // Telling everyone is a claim about *members*, not about how many requests went out, and
    // the difference only shows when the members are not equally callable. A peer we already
    // hold a connection to always is; the rest need a relay circuit this node may not be allowed
    // to open yet. Counting sends rather than recipients spent the whole round of propagation on
    // the peer that already knew — which looks like healthy traffic in the log and leaves the
    // group as uninformed as if nothing had been sent at all.
    let mut node = Node::new();
    let members = peers(3);
    let id = node.group_with(&members);
    node.all_up(&members);
    let (settled, _) = settle(&mut node, AT);

    node.add_file(id, "new.jpg");

    let at = after_editing_pause(&mut node, settled + 1);
    let mut told: Vec<PeerId> = Vec::new();
    for k in 0..12 {
        let actions = node.tick(at + k);
        told.extend(settle_offers(&mut node, &actions, id));
    }

    let distinct: HashSet<PeerId> = told.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        members.len(),
        "every member is told: {distinct:?}"
    );
    assert_eq!(
        told.len(),
        distinct.len(),
        "and none of them twice for the same news: {told:?}"
    );
}

#[test]
fn a_change_made_during_a_round_is_not_recorded_as_sent() {
    // A round carries what the store held when the request went out. Recording what it holds
    // when the answer comes back looks equivalent and is not: anything changed in between was
    // never on the wire, and marking it sent retires news nobody has heard.
    //
    // The lab found this as a member added while a round was in flight: the group recorded the
    // post-change head, `News` never armed, and the node sat silent until its four-hour
    // heartbeat having told nobody the member existed. Everything else about it looked healthy —
    // it had asked the registry, been told the newcomer was online, and simply never called.
    let mut node = Node::new();
    let members = peers(1);
    let id = node.group_with(&members);
    node.add_file(id, "a.jpg");
    node.all_up(&members);
    let (settled, _) = settle(&mut node, AT);

    // A round goes out...
    node.add_file(id, "b.jpg");
    let at = after_editing_pause(&mut node, settled + 1);
    let actions = node.tick(at);
    let asked = rounds(&actions);
    assert!(!asked.is_empty(), "the new file is news: {actions:?}");

    // ...and the catalogue moves again before it settles.
    node.add_file(id, "c.jpg");
    for peer in asked {
        node.peers.on(PeerEvent::Synced {
            peer,
            group: id,
            offering: Offering::Catalogue,
        });
    }

    // `c.jpg` waits out its own pause like any other edit; what must not happen is that it was
    // written off as delivered by the round that could not have carried it.
    let at = after_editing_pause(&mut node, at + 1);
    let actions = node.tick(at);
    assert!(
        !rounds(&actions).is_empty() || !dials(&actions).is_empty(),
        "the file added mid-round was never on the wire and is still news: {actions:?}"
    );
}

#[test]
fn membership_is_offered_before_the_catalogue() {
    // The chain first, always. A catalogue offer is gated on membership the other side may not
    // have yet — `shared_with` will not name the group to them — so sending both at once means
    // the file heads arrive to be refused, and the exchange has to happen again.
    //
    // Both spread by the same record and the same loop; the only difference between them is
    // this ordering, and it exists because one is the precondition for the other.
    let mut node = Node::new();
    let members = peers(1);
    let id = node.group_with(&members);
    node.add_file(id, "a.jpg");
    node.all_up(&members);

    let first = node.tick(AT);
    assert!(
        matches!(
            first.iter().find(|a| matches!(a, PeerAction::Offer { .. })),
            Some(PeerAction::Offer {
                offering: Offering::Chain,
                ..
            })
        ),
        "membership goes first: {first:?}"
    );

    // Answered, so the chain half of the record is now theirs.
    for group in node.shared_groups() {
        node.peers.on(PeerEvent::Synced {
            peer: members[0],
            group,
            offering: Offering::Chain,
        });
    }

    let second = node.tick(AT + 1);
    assert!(
        matches!(
            second
                .iter()
                .find(|a| matches!(a, PeerAction::Offer { .. })),
            Some(PeerAction::Offer {
                offering: Offering::Catalogue,
                ..
            })
        ),
        "and the catalogue follows once they know who is in the group: {second:?}"
    );
}

#[test]
fn restarting_the_daemon_does_not_restart_the_editing_pause() {
    // The pause is measured from a stamp in the store rather than from anything the supervisor
    // remembers, so that a node two seconds from telling the group about an afternoon's work
    // does not go quiet for another two minutes because it was restarted. Held in memory this
    // was unobservable in every test here, because every test here has one supervisor.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("node.db");
    let key = Keypair::generate_ed25519();
    let me = key.public().to_peer_id();
    let members = peers(1);

    let supervisor = || {
        Peers::new(
            Files::open(&db, me).unwrap(),
            Groups::open(&db, me).unwrap(),
        )
    };

    let mut node = Node {
        peers: supervisor(),
        key: key.clone(),
        me,
    };
    let id = node.group_with(&members);
    node.all_up(&members);
    let (settled, _) = settle(&mut node, AT);

    // An edit, and one tick to notice it. The pause starts here.
    node.add_file(id, "a.jpg");
    node.tick(settled + 1);

    // The daemon goes away and comes back, most of the pause having elapsed while it was down.
    let mut node = Node {
        peers: supervisor(),
        key,
        me,
    };
    // Connected, but with no presence answer — that enqueues the unanswered invitation and
    // would send a round whatever the pause said.
    node.peers.on(PeerEvent::Verified { peer: members[0] });

    // Membership *is* re-told: who has heard what is in memory, so a restarted node cannot know
    // it already said it, and saying it again is exempt from the pause. Let that finish.
    settle(&mut node, settled + 2);

    // The catalogue is not, and is still inside a pause counted from the edit — not from when
    // this process happened to start.
    assert!(
        rounds(&node.tick(settled + 1 + SHARE_AFTER_IDLE - 10)).is_empty(),
        "the pause is still running, so the restart did not skip it either"
    );

    let at = settled + 1 + SHARE_AFTER_IDLE + 1;
    assert_eq!(
        rounds(&answered(&mut node, at, id)),
        members,
        "the pause is up, and it was up whether or not we were running for it"
    );
}

#[test]
fn a_settled_membership_round_does_not_write_off_the_catalogue() {
    // Two exchanges, two records. A chain round carries who is in the group and not one file
    // head, so it may discharge the membership and nothing else — but `seen` was moved wholesale
    // by either kind, and `seen` is also what decides whether there is anything left to say.
    //
    // So a member added and a file added in the same minute got the membership and never the
    // file: by the time the editing pause elapsed, our digest already matched what we believed
    // they held, and nothing afterwards disagreed. It took the four-hour heartbeat to notice.
    let mut node = Node::new();
    let id = node.group_with(&[]);
    let (settled, _) = settle(&mut node, AT);

    // A member and a file, in the same minute.
    let newcomer = peers(1)[0];
    node.add_member(id, newcomer);
    node.add_file(id, "a.jpg");
    // Connected, but with no presence answer: that path enqueues an unanswered invitation of its
    // own accord, which would supply the catalogue this test is checking arrives by itself.
    node.peers.on(PeerEvent::Verified { peer: newcomer });

    // Membership is exempt from the pause and goes at once. Answered as the chain, because that
    // is what was sent.
    let first = node.tick(settled + 1);
    assert_eq!(
        settle_offers(&mut node, &first, id),
        vec![newcomer],
        "the chain round goes first"
    );

    // The file waited behind it, and is still owed once its pause elapses.
    let at = after_editing_pause(&mut node, settled + 2);
    assert_eq!(
        rounds(&answered(&mut node, at, id)),
        vec![newcomer],
        "the file was never on the wire, so it is still news"
    );
}

#[test]
fn a_change_made_by_the_cli_in_another_process_is_offered_once() {
    // `ac file add` runs in another process and notifies nothing; SQLite is the only channel
    // between them. The supervisor notices by comparing the store to what each peer is known to
    // hold — and having offered, it stops, rather than repeating every tick.
    //
    // This property used to live in `ac-files`, which offered on its own schedule. It moved
    // here with the responsibility.
    let mut node = Node::new();
    let members = peers(1);
    let id = node.group_with(&members);
    node.all_up(&members);
    let (settled, _) = settle(&mut node, AT);

    node.add_file(id, "new.jpg");

    let at = after_editing_pause(&mut node, settled + 1);
    let actions = answered(&mut node, at, id);
    assert_eq!(rounds(&actions), members, "the change is offered");

    assert!(
        rounds(&node.tick(at + 1)).is_empty(),
        "offered once, not every tick"
    );
}

#[test]
fn someone_who_joins_while_already_connected_still_gets_the_catalogue() {
    // The ordinary way a group grows, and the case that announces itself least: we are already
    // connected when they accept the invitation. Our catalogue has not changed, and neither has
    // the chain — *they* signed a standing, which the admin's log knows nothing about. Watching
    // the digest and the head alone finds nothing to say, and they sit with an empty catalogue
    // until we happen to add a file.
    //
    // Which is why what a peer must match includes the standings digest.
    let mut node = Node::new();
    let members = peers(1);
    let id = node.group_with(&members);
    node.add_file(id, "a.jpg");
    node.all_up(&members);
    let (settled, _) = settle(&mut node, AT);
    assert!(
        rounds(&node.tick(settled)).is_empty(),
        "quiet before they join"
    );

    // Their standing changes; no file moves and the chain does not advance.
    let key = node.key.clone();
    node.peers
        .groups_mut()
        .author_standing(&key, id, Position::In, AT)
        .unwrap();

    let actions = node.tick(settled + 1);
    assert_eq!(
        rounds(&actions),
        members,
        "joining is enough; we should not have to add a file for them to hear: {actions:?}"
    );
}

#[test]
fn a_group_left_out_of_the_answer_is_not_recorded_as_delivered() {
    // A peer that does not believe it shares a group simply omits it — refusals explain nothing,
    // so the silence covers both "invited and has not accepted yet" and "left months ago".
    // Treating it as a finished exchange records them as holding a catalogue they refused to
    // discuss, and nothing afterwards corrects that: our digest has not moved, so the ordinary
    // loop sees them as up to date and says nothing more until the four-hour heartbeat.
    //
    // The newly added member is exactly this case, since the op that adds us may still be in
    // flight when our file heads arrive.
    let mut node = Node::new();
    let members = peers(1);
    let id = node.group_with(&members);
    node.add_file(id, "a.jpg");
    node.all_up(&members);

    let offered = node.tick(AT);
    assert_eq!(rounds(&offered), members, "the member is offered to");

    node.peers.on(PeerEvent::Declined {
        peer: members[0],
        group: id,
    });
    assert_eq!(
        node.peers.status().groups[0].unheard,
        1,
        "they refused to discuss it, so they have not been told"
    );

    // Not hammered either: the retry waits rather than going out on the very next tick.
    assert!(
        rounds(&node.tick(AT + 1)).is_empty(),
        "a decline is not retried immediately"
    );
    assert_eq!(
        rounds(&node.tick(AT + MIN_BACKOFF + 1)),
        members,
        "but it is retried, because the reason may have been a chain still in flight"
    );
}

#[test]
fn what_we_learn_from_a_peer_is_not_re_told_to_the_group() {
    // This asserted the opposite until the epidemic went away, and the inversion is the point of
    // the design rather than an accident of it. Under a fanout of three, a responder had to stay
    // armed or a change reached only the members its author happened to call. Telling everybody
    // directly is now affordable — sixteen circuits a minute rather than two — so the author
    // reaches every member itself, and a second node repeating what it just heard is one message
    // per member *per member*.
    //
    // `seen` moving on every settled exchange, ours or theirs, is what makes this fall out for
    // nothing: a difference against it is a local change by construction, so there is no
    // provenance to track and nothing that arrives from a peer ever enqueues anybody.
    let mut node = Node::new();
    let members = peers(2);
    let id = node.group_with(&members);
    node.all_up(&members);
    let (settled, _) = settle(&mut node, AT);
    assert!(
        rounds(&node.tick(settled)).is_empty(),
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
    let actions = node.tick(at);
    assert!(
        rounds(&actions).is_empty() && dials(&actions).is_empty(),
        "the author is telling them; saying it again is a message per member per member: \
         {actions:?}"
    );

    // And it is theirs alone that is quiet. Something *we* do is still news to everybody.
    node.add_file(id, "ours.jpg");
    let at = after_editing_pause(&mut node, at + 1);
    assert!(
        !rounds(&node.tick(at)).is_empty(),
        "what we did ourselves still goes out"
    );
}

#[test]
fn a_member_added_a_moment_ago_is_called_without_waiting_to_be_told_they_are_there() {
    // A member added a moment ago has never appeared in a presence answer, because nobody had
    // asked about them yet — and the registry is the wrong thing to wait for. Holding the news
    // behind an answer cost the whole interval when the answer said they were away, and cost it
    // *for ever* when the query never went out at all, which is what a group whose other members
    // are all connected looks like: `presence` skips those, finds nobody to ask, and the answer
    // that would have released the news never comes.
    //
    // So the chain is enqueued the moment it moves and the dial follows on that tick. Nothing
    // has vouched for the newcomer and that is precisely the point.
    //
    // Deliberately unlike `adding_a_member_provokes_a_round_although_no_file_changed`, which
    // hand-feeds `Presence` and `Verified` for the newcomer and so proves only that the news is
    // armed. Nothing here mentions them to us at all.
    let mut node = Node::new();
    let members = peers(1);
    let id = node.group_with(&members);
    node.add_file(id, "a.jpg");
    node.all_up(&members);
    let (settled, _) = settle(&mut node, AT);
    // Someone we have actually exchanged a catalogue with, so the newcomer is the only stranger
    // and the rotation's preference for strangers is unambiguous.
    node.peers
        .files_mut()
        .set_cursor(id, &members[0], 1)
        .unwrap();

    let newcomer = peers(1)[0];
    node.add_member(id, newcomer);

    // Within a few ticks rather than on the first: a member we already hold a connection to is
    // always served before one that needs a circuit, so the newcomer's dial waits for the
    // settled member's offer and not for anybody's answer about where they are.
    // Nothing in this test ever delivers a `Presence`, so a dial here happened on no evidence
    // whatever — which is the assertion. Asking about them at the same time is not waiting on
    // the answer, and the two going out on one tick is the shape being pinned.
    let mut called = None;
    for k in 1..6 {
        let actions = answered(&mut node, settled + k, id);
        if dials(&actions).contains(&newcomer) {
            called = Some(k);
            break;
        }
    }
    assert!(
        called.is_some(),
        "the member who was just added is called, not asked about first"
    );
}

#[test]
fn a_member_who_has_never_answered_the_invitation_is_told_again_when_the_server_sees_them() {
    // What the presence query is still for, now that nothing waits on its answer.
    //
    // Someone invited and away cannot ask for the group — they do not know it exists — and under
    // author-only propagation no other member will offer it to them. Our three attempts have
    // already run out and taken them off the list. Being reported online is then the only signal
    // there is, and it costs one small request rather than a circuit.
    //
    // The test is a *standing*, not a sync cursor: a standing is signed by the member and is the
    // only thing that says they know the group exists.
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
        node.peers.status().groups[0].unheard,
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
        node.peers.status().groups[0].unheard,
        1,
        "somebody who never answered the invitation is told again"
    );
}

#[test]
fn the_content_pull_still_waits_for_the_registry() {
    // The half of presence that survives. Delivering news is an obligation to a named member and
    // is not negotiable on a five-minute-old answer; pulling gigabytes is a *choice* between
    // members, and one the server saw recently is the better candidate.
    //
    // So a member reported away is still dialled — we may owe them something — but is not asked
    // to supply a file until something vouches for them.
    const { assert!(PRESENCE_INTERVAL > 0) };

    let mut node = Node::new();
    let members = peers(1);
    let id = node.group_with(&members);
    node.learn_file(id, "a.jpg");
    node.peers.on(PeerEvent::Presence {
        asked: members.clone(),
        online: Vec::new(),
    });

    let actions = step(&mut node, AT, true);
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, PeerAction::AskHoldings { .. })),
        "nothing has vouched for them, so they are not made a source: {actions:?}"
    );

    // The server changes its mind. Now they are worth pulling through.
    node.all_up(&members);
    let mut asked = false;
    for k in 1..10 {
        if step(&mut node, AT + k, true)
            .iter()
            .any(|a| matches!(a, PeerAction::AskHoldings { .. }))
        {
            asked = true;
            break;
        }
    }
    assert!(asked, "once vouched for, they are asked what they hold");
}

#[test]
fn a_change_reaches_every_member_not_a_sample_of_them() {
    // News goes to everyone who has not heard it. An epidemic with a fanout of three was the
    // right answer to a budget of two circuits a minute — telling everybody was unaffordable, so
    // each node told a few and trusted them to pass it on. Resizing the relay's unit removed the
    // scarcity, and with it the reason to sample: one hop, fewer messages in total, and no
    // dependence on an intermediary staying up long enough to relay what it heard.
    let mut node = Node::new();
    let members = peers(6);
    let id = node.group_with(&members);
    node.all_up(&members);
    node.add_file(id, "a.jpg");

    let mut told = HashSet::new();
    for k in 0..(members.len() * 2 + 4) as i64 {
        let actions = node.tick(AT + k);
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
    // Once every member holds what we hold, the group goes quiet — rather than re-offering
    // because the store still differs from something, which is what a comparison against a
    // single per-group record would do.
    //
    // Each member takes two exchanges: membership first, then the catalogue, since a peer
    // cannot be offered a catalogue for a group it may not know it belongs to.
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
    node.all_up(&members);
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

    // Well past the backoff they are asked again — and this time they have it.
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
    // The inversion. This used to assert the opposite, and the opposite is what silenced nodes:
    // an answer is at most five minutes old, is about the moment it was taken, and a member it
    // leaves out was never called at all — so a peer that had reconnected since, or had not
    // finished starting when the question was asked, simply never heard anything again.
    //
    // A refused circuit costs one of sixteen a minute and comes back in seconds. Not calling
    // somebody who is there costs the propagation.
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
    //
    // Three attempts, paced by the backoff — 0s, 30s, 90s.
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
        if node.peers.status().groups[0].unheard == 0 {
            break;
        }
        at += 1;
    }

    assert_eq!(
        attempts, DIAL_ATTEMPTS,
        "three tries, not one and not for ever"
    );
    assert_eq!(
        node.peers.status().groups[0].unheard,
        0,
        "and then the group stops counting them as owed"
    );
    assert!(
        at - AT >= MIN_BACKOFF * 3,
        "spread over the backoff rather than spent in one tick: {} seconds",
        at - AT
    );

    // Not a verdict about them: the next thing we have to say puts them back on the list.
    node.add_file(id, "b.jpg");
    let mut told = false;
    for k in 0..(SHARE_AFTER_IDLE + 2) {
        if node.peers.status().groups[0].unheard > 0 {
            told = true;
            break;
        }
        node.tick(at + k);
    }
    assert!(
        told,
        "giving up is not a memory, it is the end of one attempt"
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
    // A newly added member has not answered the invitation, and round-robin would put them last
    // in a large group — which is exactly where being told promptly matters.
    //
    // Their standing is what says so, not a sync cursor: a member who accepted months ago and
    // has never swapped a catalogue with us is no stranger, and one we have swapped catalogues
    // with who never accepted is.
    let mut node = Node::new();
    let keys: Vec<Keypair> = (0..5).map(|_| Keypair::generate_ed25519()).collect();
    let members: Vec<PeerId> = keys.iter().map(|k| k.public().to_peer_id()).collect();
    let id = node.group_with(&members);
    node.all_up(&members);
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

    let actions = node.tick(AT);
    assert_eq!(
        rounds(&actions).first(),
        Some(&members[4]),
        "the one we have never met is called first"
    );
}

#[test]
fn heartbeats_do_not_line_up() {
    // Fifty members who joined a group together would otherwise fire within seconds of each
    // other for ever.
    //
    // Each node is settled first, which is what makes this measure the heartbeat rather than
    // the round a fresh group arms immediately: after settling there is nothing left to say,
    // so the next thing the node does is the heartbeat and nothing else. Sampling every ten
    // minutes over the jittered window is enough to tell the schedules apart — the ±25% spread
    // is two hours wide — and keeps the test to a few dozen ticks per node.
    const SAMPLE: i64 = 600;
    let mut seen = HashSet::new();

    for _ in 0..12 {
        let mut node = Node::new();
        let members = peers(1);
        node.group_with(&members);
        node.all_up(&members);
        let (settled, _) = settle(&mut node, AT);

        // The jitter puts the first heartbeat somewhere in 0.75–1.25 × HEARTBEAT, so walk a
        // little past the far end.
        let last = (HEARTBEAT * 5 / 4) / SAMPLE + 2;
        for k in 1..=last {
            let at = settled + k * SAMPLE;
            let actions = node.tick(at);
            if !rounds(&actions).is_empty() || !dials(&actions).is_empty() {
                seen.insert(k);
                break;
            }
        }
    }

    assert!(
        seen.len() > 1,
        "every node scheduled its heartbeat in the same ten-minute window: {seen:?}"
    );
}

// ---- closing ----

#[test]
fn a_drained_peer_is_proposed_to_even_while_the_group_is_behind() {
    // The second design failure. Tying idleness to the *group* is permanently false under
    // auto-mirror, so rotating through the members left every connection held for ever — each
    // one having already said it could not help.
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
                PeerAction::Dial { .. } | PeerAction::Offer { .. } | PeerAction::AskHoldings { .. }
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
///
/// The floor is 1000 bytes rather than the real two gigabytes so the arithmetic can be written
/// down: a row in these tests is one byte, so "one more file would breach the floor" is a
/// number a reader can check.
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

fn fetches(actions: &[PeerAction]) -> usize {
    actions
        .iter()
        .filter(|a| matches!(a, PeerAction::FetchBlob { .. }))
        .count()
}

fn out_of_space(actions: &[PeerAction]) -> Vec<&Notice> {
    actions
        .iter()
        .filter_map(|a| match a {
            PeerAction::Note(note @ Notice::OutOfSpace { .. }) => Some(note),
            _ => None,
        })
        .collect()
}

#[test]
fn the_free_space_floor_stops_fetching_and_says_so_once() {
    // The floor protects the machine rather than the archive: somebody who set no budget has
    // not agreed to give up the last of their root disk. And it is said *once* — a node at its
    // ceiling refuses every fetch it considers, so one line per file would bury everything.
    let (mut node, id) = cramped(None, 500, 0);
    node.learn_file(id, "big.bin");

    let first = step(&mut node, AT, true);
    assert_eq!(fetches(&first), 0, "no room, so nothing is asked for");
    assert_eq!(out_of_space(&first).len(), 1, "{first:?}");

    let again = step(&mut node, AT + 1, true);
    assert!(
        out_of_space(&again).is_empty(),
        "said once per transition, not once per tick: {again:?}"
    );
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
        matches!(
            out_of_space(&actions).first(),
            Some(Notice::OutOfSpace { floor: false, .. })
        ),
        "the budget stopped it, not the floor: {actions:?}"
    );
}

#[test]
fn space_appearing_resumes_the_mirror() {
    // Neither limit deletes anything, so the file is still missing and still wanted. This is
    // what makes hitting a ceiling legible rather than terminal — and it is the reason a
    // refusal for space must not mark the peer spent or deny the path.
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
    // The bug that silenced a whole node in the lab. The query skips peers we are already
    // connected to, so applying its answer as a *replacement* dropped every one of them from
    // the online set — and with nobody usable, the supervisor stopped dialling and stopped
    // pulling while sitting in a conversation with the very peers it had forgotten.
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

    // Fresh work, so "nothing happened" cannot be mistaken for "nothing was left to do".
    node.learn_file(id, "later.bin");
    let at = after_editing_pause(&mut node, AT + 1);
    let actions = step(&mut node, at, true);
    let worked_with: Vec<PeerId> = actions
        .iter()
        .filter_map(|a| match a {
            PeerAction::Offer { peer, .. }
            | PeerAction::AskHoldings { peer, .. }
            | PeerAction::FetchBlob { peer, .. } => Some(*peer),
            _ => None,
        })
        .collect();

    assert!(
        worked_with.contains(&members[0]),
        "the connected peer is still worth talking to: {actions:?}"
    );

    // The absent one is still *called* — we may owe them news, and an answer this old is not
    // grounds for leaving a member untold. What it does decide is that they are not asked to
    // supply anything: choosing a source is the one judgement presence is still trusted with.
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, PeerAction::AskHoldings { peer, .. } if *peer == members[1])),
        "the one reported absent is not made a content source: {actions:?}"
    );
}

#[test]
fn nobody_reachable_is_not_the_same_as_nobody_having_it() {
    // A group whose members have simply not been dialled yet must not be declared exhausted.
    // Conflating the two armed the content backoff — for minutes, doubling — and reported every
    // missing file as unobtainable, on the strength of never having asked anybody. In the lab
    // this stopped a node mirroring at all: the backoff was set while it was still connecting,
    // and by the time a member arrived the group was suppressed.
    let mut node = Node::new();
    let members = peers(2);
    let id = node.group_with(&members);
    node.learn_file(id, "wanted.bin");

    // Nobody online, nobody connected.
    let quiet = step(&mut node, AT, true);
    assert!(
        !quiet
            .iter()
            .any(|a| matches!(a, PeerAction::Note(Notice::Unobtainable { .. }))),
        "not having asked anyone is not the same as having been refused: {quiet:?}"
    );

    // A member turns up. The group must not be sitting in a backoff it should never have
    // entered — the file is asked for straight away.
    node.all_up(&members[..1]);
    let mut asked = false;
    for at in 1..10 {
        let actions = step(&mut node, AT + at, true);
        if actions
            .iter()
            .any(|a| matches!(a, PeerAction::AskHoldings { .. }))
        {
            asked = true;
            break;
        }
    }
    assert!(asked, "the first reachable member is asked at once");
}
