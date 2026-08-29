use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use libp2p::{PeerId, request_response};

use ac_net::config::{Config, Paths};
use ac_net::identity::Identity;
use ac_net::roster::Roster;

use ac_files::content::Content;
use ac_files::path::RelPath;
use ac_files::store::Files;
use ac_files::sync::{FileAction, FileEvent, FileSync};
use ac_files::wire::{ManifestRequest, ManifestResponse, holds};
use ac_groups::id::GroupId;
use ac_groups::store::Groups;

use tokio::sync::Semaphore;

use crate::blob;
use crate::daemon::ClientSwarm;
use crate::throttle::Throttle;

/// What we asked a peer, kept so a bare reply can be matched back to it.
enum Outbound {
    Ask,
    Changes { group: GroupId, after: u64 },
    Holdings { group: GroupId, paths: Vec<RelPath> },
}

/// How a manifest exchange ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoundOutcome {
    Settled {
        peer: PeerId,
        group: GroupId,
    },
    Holdings {
        peer: PeerId,
        group: GroupId,
        paths: Vec<RelPath>,
        held: Vec<bool>,
    },
    HoldingsRefused {
        peer: PeerId,
        group: GroupId,
    },
    Asked {
        peer: PeerId,
    },
    Failed {
        peer: PeerId,
    },
}

pub struct FileLink {
    sync: FileSync,
    outbound: HashMap<request_response::OutboundRequestId, (PeerId, Outbound)>,
    rounds: Vec<RoundOutcome>,
    db: std::path::PathBuf,
    up: Arc<Throttle>,
    serving: Arc<Semaphore>,
}

/// How long a partial must sit untouched before a sweep will remove it.
const STAGING_IDLE: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// Drop partials that no transfer could still resume into.
fn sweep_staging(files: &Files, content: &Content) {
    let Ok(dirs) = files.group_dirs() else {
        return;
    };

    for (group, dir) in dirs {
        let Ok(keep) = files.unfinished(group) else {
            continue;
        };
        match content.sweep_staging(&dir, &keep, STAGING_IDLE) {
            Ok(0) => {}
            Ok(swept) => tracing::info!(%group, swept, "removed abandoned partial downloads"),
            Err(error) => tracing::warn!(%group, %error, "could not sweep staging"),
        }
    }
}

impl FileLink {
    pub fn open(paths: &Paths, identity: &Identity) -> Result<Self> {
        let path = paths.db_file();
        let me = identity.peer_id();

        let files = Files::open(&path, me)
            .with_context(|| format!("opening the file index at {}", path.display()))?;
        let groups = Groups::open(&path, me)
            .with_context(|| format!("opening the group store at {}", path.display()))?;

        let config = Config::load(&paths.config_file())
            .with_context(|| format!("reading the config at {}", paths.config_file().display()))?;
        let content = Content::new(config.storage_root(paths));
        sweep_staging(&files, &content);

        Ok(Self {
            sync: FileSync::new(files, groups, content),
            outbound: HashMap::new(),
            rounds: Vec::new(),
            db: path,
            up: Arc::new(Throttle::from_config(
                config.bandwidth_max,
                blob::THROTTLE_BURST,
            )),
            serving: Arc::new(Semaphore::new(blob::MAX_SERVING)),
        })
    }

    /// Bytes of content served since this node started.
    pub fn moved_up(&self) -> u64 {
        self.up.moved()
    }

    #[cfg(test)]
    pub(crate) fn sync(&mut self) -> &mut FileSync {
        &mut self.sync
    }

    pub fn drain_rounds(&mut self) -> Vec<RoundOutcome> {
        std::mem::take(&mut self.rounds)
    }

    pub fn ask(&mut self, swarm: &mut ClientSwarm, peer: PeerId) {
        let id = swarm
            .behaviour_mut()
            .app
            .manifests
            .send_request(&peer, ManifestRequest::Ask);
        self.outbound.insert(id, (peer, Outbound::Ask));
    }

    /// Ask a peer which of these paths it holds
    pub fn holdings(
        &mut self,
        swarm: &mut ClientSwarm,
        peer: PeerId,
        group: GroupId,
        paths: Vec<RelPath>,
    ) {
        let id = swarm.behaviour_mut().app.manifests.send_request(
            &peer,
            ManifestRequest::Holdings {
                group,
                paths: paths.iter().map(|p| p.to_string()).collect(),
            },
        );
        self.outbound
            .insert(id, (peer, Outbound::Holdings { group, paths }));
    }

    /// Whether any question we put to this peer is still outstanding.
    pub fn busy_with(&self, peer: &PeerId) -> bool {
        self.outbound.values().any(|(p, _)| p == peer)
    }

    /// Bytes of content this node holds, across every group. Feeds the storage budget.
    pub fn held_bytes(&self) -> Option<u64> {
        self.sync.files().held_bytes().ok()
    }

    /// The group directory, for a transfer that needs somewhere to put bytes.
    pub fn dir_of(&mut self, group: GroupId) -> Option<String> {
        self.sync.dir_of(group)
    }

    /// Drive the machine's clock.
    pub fn housekeeping(
        &mut self,
        swarm: &mut ClientSwarm,
        roster: &Roster,
        now: Instant,
        at: i64,
    ) {
        let actions = self.sync.on(FileEvent::Tick { now, at }, roster);
        self.dispatch(swarm, actions);
    }

    pub fn on_event(
        &mut self,
        swarm: &mut ClientSwarm,
        roster: &Roster,
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
                let (response, actions) = self.sync.on_request(peer, request, roster);
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
                        self.sync.on(FileEvent::Heads { peer, heads }, roster)
                    }
                    (Outbound::Ask, _) => {
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
                    ) if answered == group => self.sync.on(
                        FileEvent::Changes {
                            peer,
                            group,
                            after,
                            entries,
                            next,
                            more,
                            digest,
                        },
                        roster,
                    ),
                    (Outbound::Changes { group, .. }, ManifestResponse::Unavailable) => {
                        self.sync.on(FileEvent::Unavailable { peer, group }, roster)
                    }
                    (
                        Outbound::Holdings { group, paths },
                        ManifestResponse::Holdings {
                            group: answered,
                            held,
                        },
                    ) if answered == group => {
                        let held = (0..paths.len()).map(|i| holds(&held, i)).collect();
                        self.rounds.push(RoundOutcome::Holdings {
                            peer,
                            group,
                            paths,
                            held,
                        });
                        return;
                    }
                    (Outbound::Holdings { group, .. }, _) => {
                        self.rounds
                            .push(RoundOutcome::HoldingsRefused { peer, group });
                        return;
                    }
                    _ => return,
                }
            }

            Event::OutboundFailure {
                peer, request_id, ..
            } => {
                let group = match self.outbound.remove(&request_id) {
                    Some((_, Outbound::Changes { group, .. })) => {
                        // A page that never came back leaves the catalogue half read. Saying
                        // so puts the whole round on the retry, rather than reporting it
                        // settled and pulling content against a list we know is short.
                        self.rounds.push(RoundOutcome::Failed { peer });
                        Some(group)
                    }
                    Some((_, Outbound::Ask)) => {
                        self.rounds.push(RoundOutcome::Failed { peer });
                        None
                    }
                    Some((_, Outbound::Holdings { group, .. })) => {
                        self.rounds
                            .push(RoundOutcome::HoldingsRefused { peer, group });
                        return;
                    }
                    _ => None,
                };
                self.sync
                    .on(FileEvent::RequestFailed { peer, group }, roster)
            }

            _ => return,
        };

        self.dispatch(swarm, actions);
    }

    /// Serve an inbound blob stream from a peer the daemon has already found ready.
    pub fn on_inbound_blob(&self, peer: PeerId, stream: libp2p::swarm::Stream) {
        blob::serve(
            self.db.clone(),
            self.sync.content().clone(),
            self.sync.me(),
            peer,
            stream,
            self.up.clone(),
            self.serving.clone(),
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
            }
        }
    }
}
