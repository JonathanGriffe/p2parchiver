//! Where the swarm and `ac-files` meet.
//!
//! The counterpart of [`crate::group_link`], and it owns the same two things the policy layer
//! deliberately does not: **request correlation**, because a bare `Unavailable` names no group
//! and an `OutboundFailure` carries only a request id; and **waiting for a connection to
//! settle**, because a peer that has just passed attestation may be reachable only over a
//! relay circuit that a hole punch is about to replace.
//!
//! # Serving blobs, but never asking for them
//!
//! Inbound blob streams are answered here — handed to [`crate::blob`], which owns the stream,
//! the spawned task, and the only `libp2p-stream` usage in the workspace. **Outbound** ones are
//! not: deciding what to download, from whom, and when to stop belongs to
//! [`crate::peer_link`], because the answer depends on who is online, who holds what, and what
//! a peer has already failed to deliver — none of which the file layer can see.
//!
//! What this does hand upward is [`RoundOutcome`]: whether a catalogue exchange for one group
//! with one peer finished, or failed. That is the one fact the supervisor cannot work out on
//! its own, because two peers who already agree exchange nothing and silence looks identical
//! to a round that never started.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use anyhow::{Context, Result};
use libp2p::{PeerId, request_response};

use ac_net::config::{Config, Paths};
use ac_net::connectivity::Connectivity;
use ac_net::identity::Identity;

use ac_files::content::Content;
use ac_files::store::Files;
use ac_files::sync::{FileAction, FileEvent, FileSync, Notice};
use ac_files::wire::{ManifestRequest, ManifestResponse};
use ac_groups::id::GroupId;
use ac_groups::store::Groups;

use crate::blob;
use crate::daemon::ClientSwarm;

/// What we asked a peer, kept so a bare reply can be matched back to it.
enum Outbound {
    /// "Which catalogues do you believe we share?" Carries nothing, so there is nothing to
    /// remember about it beyond who was asked.
    Ask,
    /// `after` is kept because the machine re-checks it before applying a page: a peer does
    /// not get to decide what we asked for.
    Changes { group: GroupId, after: u64 },
}

/// How a catalogue exchange ended.
///
/// Reported upward rather than acted on. `ac_peers::sync` turns these into `Synced` and
/// `OfferFailed`, which is what records a member as told and lets a drained peer be closed.
/// Settling is per group, because an offer reconciles each group it names separately and they
/// may finish pages apart. Failing is per peer, because a request that never arrived failed for
/// every group it named at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundOutcome {
    Settled {
        peer: PeerId,
        group: GroupId,
    },
    /// We asked this peer what they have, and the question is now answered — whatever the
    /// answer was. Under a pull that is the whole of what the supervisor needs: it decides when
    /// to ask again from the clock, not from what came back.
    Asked {
        peer: PeerId,
    },
    Failed {
        peer: PeerId,
    },
}

/// The only place a swarm and `ac-files` are named together.
pub struct FileLink {
    sync: FileSync,
    outbound: HashMap<request_response::OutboundRequestId, (PeerId, Outbound)>,
    /// Round outcomes waiting to be handed to the supervisor, drained each tick.
    rounds: Vec<RoundOutcome>,
    /// Peers that passed attestation but whose connection has not settled yet. Same reasoning
    /// as `GroupLink::settling`, and more acute here: a transfer started on a circuit that is
    /// about to be replaced wastes the slow path for the whole of a large file.
    settling: HashSet<PeerId>,
    /// Peers the file layer has been told about, so a `PeerGone` only ever follows a
    /// `PeerVerified` it actually saw.
    announced: HashSet<PeerId>,
    /// Where a spawned task opens its own handles.
    db: std::path::PathBuf,
}

impl FileLink {
    pub fn open(paths: &Paths, identity: &Identity) -> Result<Self> {
        let path = paths.db_file();
        let me = identity.peer_id();

        let files = Files::open(&path, me)
            .with_context(|| format!("opening the file index at {}", path.display()))?;
        // A second handle on the same database. `FileSync` needs to ask `shared_with` who may
        // see what, and nothing in this workspace shares a connection behind a lock —
        // `ac-server` opens three for the same reason.
        let groups = Groups::open(&path, me)
            .with_context(|| format!("opening the group store at {}", path.display()))?;

        let config = Config::load(&paths.config_file())
            .with_context(|| format!("reading the config at {}", paths.config_file().display()))?;
        let content = Content::new(config.storage_root(paths));

        Ok(Self {
            sync: FileSync::new(files, groups, content),
            outbound: HashMap::new(),
            rounds: Vec::new(),
            settling: HashSet::new(),
            announced: HashSet::new(),
            db: path,
        })
    }

    /// The policy machine underneath, for setting up a scenario in tests.
    ///
    /// Not how the daemon works: the CLI writes through its *own* handle in another process,
    /// and the machine notices on the next tick.
    #[cfg(test)]
    pub(crate) fn sync(&mut self) -> &mut FileSync {
        &mut self.sync
    }

    /// Everything the supervisor needs to know about rounds since it last asked.
    pub fn drain_rounds(&mut self) -> Vec<RoundOutcome> {
        std::mem::take(&mut self.rounds)
    }

    /// Offer this peer our heads for every group we share with them, because the supervisor
    /// decided it was time to talk to them.
    ///
    /// Answers whether anything went out. `false` means we share no group with them at all, in
    /// which case there is nothing to wait for and the caller should not pretend otherwise.
    ///
    /// Ask this peer which catalogues they believe we share.
    ///
    /// Always goes out: the request carries nothing, so there is no "we had nothing to say" case.
    pub fn ask(&mut self, swarm: &mut ClientSwarm, peer: PeerId) {
        let id = swarm
            .behaviour_mut()
            .app
            .manifests
            .send_request(&peer, ManifestRequest::Ask);
        self.outbound.insert(id, (peer, Outbound::Ask));
    }

    /// Ask a peer which of these paths it holds. Correlated here, dispatched by the supervisor.
    pub fn holdings(
        &mut self,
        swarm: &mut ClientSwarm,
        peer: PeerId,
        group: GroupId,
        paths: Vec<String>,
    ) -> request_response::OutboundRequestId {
        swarm
            .behaviour_mut()
            .app
            .manifests
            .send_request(&peer, ManifestRequest::Holdings { group, paths })
    }

    /// Whether a catalogue exchange with this peer is still outstanding.
    ///
    /// `FileSync` still starts offers of its own — on promotion, and when our digest moves —
    /// so not every manifest request in flight is one the supervisor asked for. Hanging up on
    /// one would cut a catalogue exchange the supervisor never knew had started.
    pub fn busy_with(&self, peer: &PeerId) -> bool {
        self.settling.contains(peer) || self.outbound.values().any(|(p, _)| p == peer)
    }

    /// Bytes of content this node holds, across every group. Feeds the storage budget.
    pub fn held_bytes(&self) -> Option<u64> {
        self.sync.files().held_bytes().ok()
    }

    /// The group directory, for a transfer that needs somewhere to put bytes.
    pub fn dir_of(&mut self, group: GroupId) -> Option<String> {
        self.sync.dir_of(group)
    }

    /// A peer completed mutual attestation. It is not usable to the file layer yet.
    pub fn attested(&mut self, peer: PeerId) {
        self.settling.insert(peer);
    }

    pub fn on_disconnected(&mut self, swarm: &mut ClientSwarm, peer: PeerId) {
        self.settling.remove(&peer);
        if self.announced.remove(&peer) {
            let actions = self.sync.on(FileEvent::PeerGone { peer });
            self.dispatch(swarm, actions);
        }
    }

    /// Promote settled peers, collect finished transfers, then drive the machine's clock.
    pub fn housekeeping(
        &mut self,
        swarm: &mut ClientSwarm,
        connectivity: &Connectivity,
        now: Instant,
        at: i64,
    ) {
        let ready: Vec<PeerId> = self
            .settling
            .iter()
            .copied()
            .filter(|peer| crate::group_link::settled(connectivity, peer))
            .collect();

        for peer in ready {
            self.settling.remove(&peer);
            if self.announced.insert(peer) {
                let actions = self.sync.on(FileEvent::PeerVerified { peer });
                self.dispatch(swarm, actions);
            }
        }

        let actions = self.sync.on(FileEvent::Tick { now, at });
        self.dispatch(swarm, actions);
    }

    pub fn on_event(
        &mut self,
        swarm: &mut ClientSwarm,
        event: request_response::Event<ManifestRequest, ManifestResponse>,
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
                // Answered here, in the same turn, while the channel is still on the stack.
                // `on_request` is total — always exactly one response — so the channel is
                // always consumed and can never be stranded. That is why `FileAction` has no
                // `Respond` variant to defer.
                let (response, actions) = self.sync.on_request(peer, request);
                let _ = swarm
                    .behaviour_mut()
                    .app
                    .manifests
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
            } => {
                let Some((asked, what)) = self.outbound.remove(&request_id) else {
                    return;
                };
                if asked != peer {
                    return;
                }

                match (what, response) {
                    (Outbound::Ask, ManifestResponse::Heads(heads)) => {
                        self.rounds.push(RoundOutcome::Asked { peer });
                        self.sync.on(FileEvent::Heads { peer, heads })
                    }
                    // An ask answered with anything else — a refusal, or a reply to a question
                    // we did not put — reconciled nothing. `FileSync` sees such an answer as
                    // nothing at all, so without this the exchange would stay outstanding for
                    // ever and take a slot with it.
                    (Outbound::Ask, _) => {
                        self.rounds.push(RoundOutcome::Asked { peer });
                        self.rounds.push(RoundOutcome::Failed { peer });
                        return;
                    }
                    (
                        Outbound::Changes { group, after },
                        ManifestResponse::Changes {
                            group: answered,
                            entries,
                            next,
                            more,
                            digest,
                        },
                    ) if answered == group => self.sync.on(FileEvent::Changes {
                        peer,
                        group,
                        after,
                        entries,
                        next,
                        more,
                        digest,
                    }),
                    (Outbound::Changes { group, .. }, ManifestResponse::Unavailable) => {
                        self.sync.on(FileEvent::Unavailable { peer, group })
                    }
                    // Dropped rather than guessed at: the arms above are the only pairings the
                    // protocol defines, and a peer does not choose what we asked.
                    _ => return,
                }
            }

            Event::OutboundFailure {
                peer, request_id, ..
            } => {
                let group = match self.outbound.remove(&request_id) {
                    Some((_, Outbound::Changes { group, .. })) => Some(group),
                    Some((_, Outbound::Ask)) => {
                        self.rounds.push(RoundOutcome::Asked { peer });
                        self.rounds.push(RoundOutcome::Failed { peer });
                        None
                    }
                    _ => None,
                };
                self.sync.on(FileEvent::RequestFailed { peer, group })
            }

            _ => return,
        };

        self.dispatch(swarm, actions);
    }

    /// Serve an inbound blob stream.
    ///
    /// Handed straight to a task with its own handles. The authorization is re-checked there
    /// rather than here, because reading a file the size of a film must not happen on the
    /// event loop.
    pub fn on_inbound_blob(&self, peer: PeerId, stream: libp2p::swarm::Stream) {
        blob::serve(
            self.db.clone(),
            self.sync.content().clone(),
            self.sync.me(),
            peer,
            stream,
        );
    }

    /// A handle for accepting inbound blob streams, taken once at startup.
    pub fn accept_blobs(swarm: &mut ClientSwarm) -> Result<libp2p_stream::IncomingStreams> {
        swarm
            .behaviour()
            .app
            .blobs
            .new_control()
            .accept(libp2p::StreamProtocol::new(ac_files::wire::BLOB_PROTOCOL))
            .context("registering the blob protocol")
    }

    /// The one place the swarm is driven on the file layer's behalf.
    fn dispatch(&mut self, swarm: &mut ClientSwarm, actions: Vec<FileAction>) {
        for action in actions {
            match action {

                FileAction::FetchChanges { peer, group, after } => {
                    let id = swarm
                        .behaviour_mut()
                        .app
                        .manifests
                        .send_request(&peer, ManifestRequest::Changes { group, after });
                    self.outbound
                        .insert(id, (peer, Outbound::Changes { group, after }));
                }

                FileAction::Settled { peer, group } => {
                    self.rounds.push(RoundOutcome::Settled { peer, group });
                }

                FileAction::Note(notice) => report(&notice),
            }
        }
    }
}

/// The binary owns the wording; the machine owns the facts.
fn report(notice: &Notice) {
    match notice {
        Notice::Learned { group, count } => {
            println!("{count} file(s) in {}", group.short());
        }
        Notice::Conflicted { group, kept, moved } => {
            println!("two files wanted {kept} in {}", group.short());
            println!("  kept both; the other is now {moved}");
        }
        Notice::Deduplicated {
            group,
            kept,
            dropped,
        } => {
            println!(
                "{dropped} held the same content as {kept} ({})",
                group.short()
            );
            println!("  a group keeps one copy, so {dropped} was dropped");
        }
        Notice::Rejected { peer, why } => {
            println!("ignored something from {peer}: {why}");
        }
        Notice::Trouble { why } => {
            tracing::warn!(%why, "file sync trouble");
        }
    }
}
