//! The adapter between the swarm and the group layer.
//!
//! `ac-groups` decides *what* to say and to whom; this carries it out. It is the only code in
//! the workspace naming both a `Swarm` and a `GroupSync`, which is why it lives here rather
//! than in either crate: `ac-groups` may name no libp2p networking type, and `ac-net` must not
//! depend on `ac-groups` at all.
//!
//! Two things it owns that the group layer deliberately does not:
//!
//! - **Request correlation.** A bare `Unavailable` names no group and an `OutboundFailure`
//!   carries nothing but a request id, so without a map from id to what we asked, the group
//!   layer could not be told *what* failed.
//!
//! Who is admitted and settled it does *not* own: that is `ac_net::roster::Roster`, borrowed
//! on every call rather than mirrored here.
//!
//! The wording of everything a person reads about groups is also here, so `ac-groups` can
//! return a typed `Notice` and its own tests assert on meaning rather than on phrasing.

use std::collections::HashMap;
use std::time::Instant;

use anyhow::{Context, Result};
use libp2p::{PeerId, request_response};

use ac_net::config::Paths;
use ac_net::identity::Identity;
use ac_net::roster::Roster;

use ac_groups::id::GroupId;
use ac_groups::store::Groups;
use ac_groups::sync::{GroupAction, GroupEvent, GroupSync};
use ac_groups::wire::{GroupRequest, GroupResponse};

use crate::daemon::ClientSwarm;
use crate::file_link::RoundOutcome;

/// What we asked a peer, kept so a bare reply can be matched back to it.
///
/// `GroupResponse::Unavailable` names no group and an `OutboundFailure` carries nothing but a
/// request id, so without this the group layer could not be told *what* failed. Keeping the
/// map here rather than in `ac-groups` is what keeps `OutboundRequestId` — a libp2p type — out
/// of that crate.
enum Outbound {
    Ask { peer: PeerId },
    Fetch { peer: PeerId, group: GroupId },
}

/// The only place a swarm and `ac-groups` are named together.
///
/// `ac-groups` decides *what* to do and returns [`GroupAction`]s; this performs them. The
/// separation is what lets the whole sync policy be tested with no socket, and it is enforced
/// by the compiler rather than by discipline: `ac-groups` does not depend on libp2p, so a
/// libp2p type is unnameable there.
pub struct GroupLink {
    sync: GroupSync,
    outbound: HashMap<request_response::OutboundRequestId, Outbound>,
    /// Exchange outcomes waiting to be handed to the supervisor, drained each tick.
    ///
    /// The same report `FileLink` makes, for the same reason: the supervisor decides when to
    /// talk to a peer, and the one thing it cannot work out for itself is whether a given
    /// exchange delivered anything.
    rounds: Vec<RoundOutcome>,
}

impl GroupLink {
    pub fn open(paths: &Paths, identity: &Identity) -> Result<Self> {
        let path = paths.db_file();
        let store = Groups::open(&path, identity.peer_id())
            .with_context(|| format!("opening the group store at {}", path.display()))?;

        Ok(Self {
            sync: GroupSync::new(store, identity.keypair().clone()),
            outbound: HashMap::new(),
            rounds: Vec::new(),
        })
    }

    /// Everything the supervisor needs to know about exchanges since it last asked.
    pub fn drain_rounds(&mut self) -> Vec<RoundOutcome> {
        std::mem::take(&mut self.rounds)
    }

    /// Ask this peer which groups they believe we share, because the supervisor decided it was
    /// time.
    ///
    /// Always goes out: the request carries nothing, and what we would have said is exactly what
    /// we cannot know until they answer.
    pub fn ask(&mut self, swarm: &mut ClientSwarm, peer: PeerId) {
        let id = swarm
            .behaviour_mut()
            .app
            .groups
            .send_request(&peer, GroupRequest::Ask);
        self.outbound.insert(id, Outbound::Ask { peer });
    }

    /// Whether a chain exchange with this peer is still outstanding.
    ///
    /// Asked by the supervisor before it hangs up. Membership arrives over *this* protocol, and
    /// nothing about it is visible to `ac-peers` — so without this a freshly connected peer
    /// looks idle the instant it is verified and is closed a few milliseconds later, before the
    /// group it was about to be told about has reached it.
    ///
    /// The other half of that — a peer admitted but not yet settled — is the roster's answer
    /// now, and `PeerLink::drained` asks it there.
    pub fn busy_with(&self, peer: &PeerId) -> bool {
        self.outbound.values().any(|out| match out {
            Outbound::Ask { peer: p } | Outbound::Fetch { peer: p, .. } => p == peer,
        })
    }

    /// Drive the machine's clock.
    ///
    /// `now` is passed in rather than read here, so the group layer's schedules can be driven
    /// deterministically from a test — the same reason its `Tick` carries a clock at all.
    pub fn housekeeping(
        &mut self,
        swarm: &mut ClientSwarm,
        roster: &Roster,
        now: Instant,
        at: i64,
    ) {
        let actions = self.sync.on(GroupEvent::Tick { now, at }, roster);
        self.dispatch(swarm, actions);
    }

    pub fn on_event(
        &mut self,
        swarm: &mut ClientSwarm,
        roster: &Roster,
        event: request_response::Event<GroupRequest, GroupResponse>,
    ) {
        use request_response::{Event, Message};

        let actions = match event {
            Event::Message {
                peer,
                message:
                    Message::Request {
                        request, channel, ..
                    },
                ..
            } => {
                let (response, actions) = self.sync.on_request(peer, request, roster);
                let _ = swarm
                    .behaviour_mut()
                    .app
                    .groups
                    .send_response(channel, response);
                actions
            }

            Event::Message {
                peer,
                message:
                    Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => match (self.outbound.remove(&request_id), response) {
                (Some(Outbound::Ask { .. }), GroupResponse::Heads(heads)) => {
                    self.rounds.push(RoundOutcome::Asked { peer });
                    self.sync.on(GroupEvent::Heads { peer, heads }, roster)
                }
                (
                    Some(Outbound::Fetch { group, .. }),
                    GroupResponse::Entries {
                        group: answered,
                        from,
                        entries,
                        standings,
                    },
                ) if answered == group => self.sync.on(
                    GroupEvent::Entries {
                        peer,
                        group,
                        from,
                        entries,
                        standings,
                    },
                    roster,
                ),
                (Some(Outbound::Fetch { group, .. }), GroupResponse::Unavailable) => self
                    .sync
                    .on(GroupEvent::Unavailable { peer, group }, roster),
                // A reply of the wrong shape for what we asked, or about a different group.
                // Dropped rather than guessed at: the arms above are the only pairings the
                // protocol defines, and a peer does not get to choose what we asked.
                _ => return,
            },

            Event::OutboundFailure { request_id, .. } => match self.outbound.remove(&request_id) {
                Some(Outbound::Fetch { peer, group }) => self
                    .sync
                    .on(GroupEvent::FetchFailed { peer, group }, roster),
                Some(Outbound::Ask { peer }) => {
                    self.rounds.push(RoundOutcome::Asked { peer });
                    self.rounds.push(RoundOutcome::Failed { peer });
                    self.sync.on(GroupEvent::AskFailed { peer }, roster)
                }
                None => return,
            },

            Event::InboundFailure { peer, error, .. } => {
                tracing::debug!(%peer, %error, "inbound group request failed");
                return;
            }
            Event::ResponseSent { .. } => return,
        };

        self.dispatch(swarm, actions);
    }

    /// Perform what the group layer asked for. The only code that calls into the swarm on
    /// its behalf.
    fn dispatch(&mut self, swarm: &mut ClientSwarm, actions: Vec<GroupAction>) {
        for action in actions {
            match action {
                GroupAction::Fetch { peer, group, from } => {
                    let id = swarm
                        .behaviour_mut()
                        .app
                        .groups
                        .send_request(&peer, GroupRequest::Fetch { group, from });
                    self.outbound.insert(id, Outbound::Fetch { peer, group });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use libp2p::Multiaddr;
    use libp2p::multiaddr::Protocol;
    use libp2p::swarm::SwarmEvent;

    use ac_net::authz::AcceptAnyPeer;
    use ac_net::swarm::{AcBehaviourEvent, Role, build};

    use crate::daemon::{App, app};

    // `ac_groups::tests::sync` already proves the sync *policy* against an in-process bus.
    // What it cannot prove is anything about the wire: that `/ac/group/3.0.0` is mounted and
    // reachable through the app slot, that entries survive libp2p's own CBOR codec rather
    // than just a `ciborium` round trip, that the size caps admit a realistic chain, and that
    // [`GroupLink`] correlates a bare reply back to the request that caused it.
    //
    // These live inside the crate rather than in `tests/` because `ac-node` is a binary with
    // no library target, so an integration test could not reach `GroupLink` at all — and
    // rewriting its dispatch in the test would prove only that the copy works.

    use ac_groups::chain::Op;
    use ac_groups::id::GroupId;
    use ac_groups::standing::Position;
    use ac_groups::wire::{GroupRequest, GroupResponse};
    use ac_net::config::Config;
    use ac_net::connectivity::Connectivity;
    use ac_net::roster::Roster;
    use libp2p::futures::StreamExt;

    const WIRE_TIMEOUT: Duration = Duration::from_secs(20);
    const AT: i64 = 1_000_000;

    /// One side: a real swarm, the real adapter, and somewhere to keep its files.
    struct Node {
        swarm: ClientSwarm,
        link: GroupLink,
        roster: Roster,
        peer: PeerId,
        /// Replies observed on the wire, for assertions the adapter would otherwise swallow.
        seen: Vec<GroupResponse>,
        _dir: tempfile::TempDir,
    }

    impl Node {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let paths = Paths::rooted_at(dir.path());
            let (identity, _) = Identity::load_or_generate(&paths.identity_file()).unwrap();

            let config = Config {
                listen: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
                listen_enroll: Vec::new(),
                external: Vec::new(),
                mdns: false,
                server: None,
                storage_root: None,
                storage_max: None,
            };

            Self {
                swarm: build(&identity, &config, Role::Client, AcceptAnyPeer, app()).unwrap(),
                link: GroupLink::open(&paths, &identity).unwrap(),
                roster: Roster::default(),
                peer: identity.peer_id(),
                seen: Vec::new(),
                _dir: dir,
            }
        }

        /// The daemon's own routing, minus admission.
        ///
        /// Attestation is bypassed — the peer is put in the roster straight off the
        /// connection — so these tests exercise the group path without also standing up a
        /// server to issue credentials. Admission has its own tests above and in `ac-net`.
        fn step(&mut self, event: SwarmEvent<AcBehaviourEvent<AcceptAnyPeer, App>>) {
            match &event {
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    self.roster.admitted(*peer_id);
                }
                // A peer legitimately holds two connections while an upgrade settles, so
                // one closing is not the peer leaving.
                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    let still = self.swarm.is_connected(peer_id);
                    self.roster.disconnected(peer_id, still);
                }
                _ => {}
            }

            // Only the group half of the app slot; the manifest and blob protocols are
            // `FileLink`'s and have their own tests.
            if let SwarmEvent::Behaviour(AcBehaviourEvent::App(crate::daemon::AppEvent::Groups(
                event,
            ))) = event
            {
                if let request_response::Event::Message {
                    message: request_response::Message::Response { response, .. },
                    ..
                } = &event
                {
                    self.seen.push(response.clone());
                }
                self.link.on_event(&mut self.swarm, &self.roster, event);
            }
        }

        /// Housekeeping, then offer to whoever is connected — standing in for the supervisor.
        ///
        /// `ac-peers` decides when to talk to a peer, and these tests do not run it, so without
        /// this the two nodes connect and then sit in silence. Offering on every tick is
        /// wasteful and exactly right here: it is what a supervisor with no record of the peer
        /// would do, and it lets the exchange start as soon as the connection settles.
        fn tick(&mut self) {
            self.roster.promote(&Connectivity::default());
            self.link
                .housekeeping(&mut self.swarm, &self.roster, Instant::now(), AT);

            let peers: Vec<PeerId> = self.swarm.connected_peers().copied().collect();
            for peer in peers {
                if !self.link.busy_with(&peer) {
                    self.link.ask(&mut self.swarm, peer);
                }
            }
        }

        async fn listen_addr(&mut self) -> Multiaddr {
            loop {
                if let SwarmEvent::NewListenAddr { address, .. } =
                    self.swarm.select_next_some().await
                {
                    return address;
                }
            }
        }
    }

    /// Drive both nodes until `done`, ticking regularly so deferred work happens.
    async fn run_until(a: &mut Node, b: &mut Node, mut done: impl FnMut(&Node, &Node) -> bool) {
        let deadline = Instant::now() + WIRE_TIMEOUT;
        while Instant::now() < deadline {
            if done(a, b) {
                return;
            }
            tokio::select! {
                event = a.swarm.select_next_some() => a.step(event),
                event = b.swarm.select_next_some() => b.step(event),
                _ = tokio::time::sleep(Duration::from_millis(25)) => {
                    a.tick();
                    b.tick();
                }
            }
        }
        panic!("the exchange did not finish within {WIRE_TIMEOUT:?}");
    }

    /// Dial `a` from `b`, returning the address so it can be dialled again.
    ///
    /// Calling this twice would hang: `listen_addr` waits for a `NewListenAddr`, and a swarm
    /// emits that once per address for the life of the listener. Reconnecting means re-dialling
    /// the address we already have.
    async fn connect(a: &mut Node, b: &mut Node) -> Multiaddr {
        let addr = a.listen_addr().await.with(Protocol::P2p(a.peer));
        b.swarm.dial(addr.clone()).expect("dial accepted");
        addr
    }

    /// An admin holding one group, with `member` added to it and `extra` further entries.
    ///
    /// The tail is built **in memory and stored in one call**, not by repeated
    /// [`Groups::author`]. Each `author` reloads and re-verifies the whole chain, so building
    /// n entries that way costs O(n²) signature checks — fine for the tens of entries a real
    /// group holds, ruinous for a test that wants hundreds. See the note on [`Groups::chain`].
    fn group_with(admin: &mut Node, member: &Node, extra: usize) -> GroupId {
        let key = Identity::load_or_generate(&admin._dir.path().join("identity.key"))
            .unwrap()
            .0;
        let key = key.keypair();
        let store = admin.link.sync.store_mut();

        let id = store.create(key, "family", "alice", AT).unwrap();
        let mut chain = store.chain(id).unwrap();

        let mut batch = vec![
            chain
                .author(
                    key,
                    Op::Add {
                        peer: member.peer.to_base58(),
                        username: "bob".into(),
                    },
                    AT,
                )
                .unwrap(),
        ];
        for i in 0..extra {
            batch.push(
                chain
                    .author(
                        key,
                        Op::Add {
                            peer: libp2p::identity::Keypair::generate_ed25519()
                                .public()
                                .to_peer_id()
                                .to_base58(),
                            username: format!("filler{i}"),
                        },
                        AT,
                    )
                    .unwrap(),
            );
        }
        store.put(id, 1, &batch, &[], AT).unwrap();
        id
    }

    #[tokio::test]
    async fn a_group_reaches_a_new_member_over_a_real_connection() {
        let mut alice = Node::new();
        let mut bob = Node::new();
        let id = group_with(&mut alice, &bob, 0);

        let _ = connect(&mut alice, &mut bob).await;
        run_until(&mut alice, &mut bob, |_, b| {
            b.link.sync.store().get(id).ok().flatten().is_some()
        })
        .await;

        let row = bob.link.sync.store().get(id).unwrap().unwrap();
        assert_eq!(row.head_seq, 2);
        assert_eq!(row.name, "family");
        assert_eq!(
            row.state,
            ac_groups::store::State::Pending,
            "being added is an invitation, not consent"
        );
        assert!(
            bob.link
                .sync
                .store()
                .members(id)
                .unwrap()
                .contains(&bob.peer),
            "and the fold that arrived over the wire names them"
        );
    }

    #[tokio::test]
    async fn a_long_chain_crosses_in_one_response() {
        // There is no chunking: one `Fetch` is answered by one response carrying everything.
        // This puts a chain far past anything a family group would reach through libp2p's
        // codec, so the explicit size maxima in `ac_groups::wire` are exercised for real.
        let mut alice = Node::new();
        let mut bob = Node::new();
        let id = group_with(&mut alice, &bob, 300);
        let head = alice.link.sync.store().get(id).unwrap().unwrap().head_seq;
        assert_eq!(head, 302);

        let _ = connect(&mut alice, &mut bob).await;
        run_until(&mut alice, &mut bob, |_, b| {
            b.link
                .sync
                .store()
                .get(id)
                .ok()
                .flatten()
                .is_some_and(|r| r.head_seq == head)
        })
        .await;

        assert_eq!(
            bob.seen
                .iter()
                .filter(|r| matches!(r, GroupResponse::Entries { .. }))
                .count(),
            1,
            "the whole chain arrived in a single response"
        );
        assert_eq!(
            bob.link.sync.store().chain(id).unwrap().len(),
            head,
            "and every entry still verified after the codec"
        );
    }

    #[tokio::test]
    async fn a_departure_is_collected_on_the_next_connection() {
        // Syncing happens on connection, not on a timer, so a change made while apart is what
        // the next exchange is for. This is also the only path that exercises fetch rule 2 on
        // the wire: a node that has left stops advertising, so nobody offers it anything, and
        // the admin collects its standing only by noticing the silence and asking.
        let mut alice = Node::new();
        let mut bob = Node::new();
        let id = group_with(&mut alice, &bob, 0);

        let addr = connect(&mut alice, &mut bob).await;
        run_until(&mut alice, &mut bob, |_, b| {
            b.link.sync.store().get(id).ok().flatten().is_some()
        })
        .await;

        // Apart now: bob joins and then changes his mind with nobody listening. Both sides
        // must observe the close, or the reconnection is not a fresh peer to both of them.
        let (alice_peer, bob_peer) = (alice.peer, bob.peer);
        let _ = bob.swarm.disconnect_peer_id(alice_peer);
        run_until(&mut alice, &mut bob, move |a, b| {
            !a.swarm.is_connected(&bob_peer) && !b.swarm.is_connected(&alice_peer)
        })
        .await;

        let key = Identity::load_or_generate(&bob._dir.path().join("identity.key"))
            .unwrap()
            .0;
        let store = bob.link.sync.store_mut();
        store
            .author_standing(key.keypair(), id, Position::In, AT)
            .unwrap();
        store
            .author_standing(key.keypair(), id, Position::Out, AT)
            .unwrap();
        assert!(
            alice
                .link
                .sync
                .store()
                .members(id)
                .unwrap()
                .contains(&bob_peer),
            "alice cannot know yet — nothing was connected"
        );

        bob.swarm.dial(addr).expect("re-dial accepted");
        run_until(&mut alice, &mut bob, move |a, _| {
            a.link
                .sync
                .store()
                .members(id)
                .map(|m| !m.contains(&bob_peer))
                .unwrap_or(false)
        })
        .await;

        let chain = alice.link.sync.store().chain(id).unwrap();
        assert_eq!(
            chain.len(),
            3,
            "the admin appended exactly one Remove, making the departure official"
        );
        assert_eq!(
            chain.departure_seq(&bob.peer),
            Some(2),
            "and it is the entry that removed him"
        );
    }

    #[tokio::test]
    async fn a_non_member_is_told_nothing_over_the_wire() {
        let mut alice = Node::new();
        let bob = Node::new();
        let id = group_with(&mut alice, &bob, 0);

        // Carol is a stranger: nobody has added her to anything.
        let mut carol = Node::new();
        let alice_peer = alice.peer;
        let _ = connect(&mut alice, &mut carol).await;

        let carol_peer = carol.peer;
        run_until(&mut alice, &mut carol, move |a, c| {
            // Promotion, not connection. Alice refuses everything from a peer still in
            // `settling`, so asking before she has promoted carol would test that refusal
            // instead of the membership one — and carol never re-asks, so the exchange would
            // then simply never produce the answer under test.
            a.roster.is_ready(&carol_peer) && c.roster.is_ready(&alice_peer)
        })
        .await;

        // Asked explicitly rather than relying on the offer the promotion happens to send:
        // this test is about what a non-member is told, not about when a tick fires.
        carol
            .swarm
            .behaviour_mut()
            .app
            .groups
            .send_request(&alice_peer, GroupRequest::Ask);
        carol
            .swarm
            .behaviour_mut()
            .app
            .groups
            .send_request(&alice_peer, GroupRequest::Fetch { group: id, from: 0 });

        // Waited on by *shape*, not by count. A count is satisfied by two of the same reply,
        // and then the assertions below fail for a reason that has nothing to do with
        // membership.
        run_until(&mut alice, &mut carol, |_, c| {
            c.seen
                .iter()
                .any(|r| matches!(r, GroupResponse::Heads(h) if h.is_empty()))
                && c.seen
                    .iter()
                    .any(|r| matches!(r, GroupResponse::Unavailable))
        })
        .await;

        assert!(
            carol
                .seen
                .iter()
                .any(|r| matches!(r, GroupResponse::Heads(h) if h.is_empty())),
            "an offer to a non-member names no group: {:?}",
            carol.seen
        );
        assert!(
            carol
                .seen
                .iter()
                .any(|r| matches!(r, GroupResponse::Unavailable)),
            "and a guessed group id is refused without saying why: {:?}",
            carol.seen
        );
        assert!(
            carol.link.sync.store().list().unwrap().is_empty(),
            "a stranger learns of nothing at all"
        );
    }
}
