use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use libp2p::{PeerId, request_response};

use ac_net::admitted_peers::AdmittedPeers;
use ac_net::config::{Config, Paths};
use ac_net::identity::Identity;
use ac_net::throttle::{THROTTLE_BURST, Throttle};
use ac_net::transfer::{TransferEvent, TransferId, TransferSpec, Transfers};

use ac_files::blob::{Blobs, Fetch, FetchError, Local};
use ac_files::content::Content;
use ac_files::path::RelPath;
use ac_files::store::Files;
use ac_files::sync::{FileAction, FileEvent, FileSync};
use ac_files::wire::{
    BLOB_PROTOCOL, MAX_BLOB_HEADER_BYTES, MAX_DOWNLOADS, MAX_UPLOADS, ManifestRequest,
    ManifestResponse, holds,
};
use ac_groups::id::GroupId;
use ac_groups::store::Groups;

use crate::daemon::ClientSwarm;

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

/// How a file transfer ended.
#[derive(Debug)]
pub struct TransferOutcome {
    pub peer: PeerId,
    pub group: GroupId,
    pub path: RelPath,
    pub result: Result<(), FetchError>,
}

/// Why a fetch did not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NotStarted {
    #[error("the transfer pool was full")]
    PoolFull,
    #[error("the group has no directory")]
    NoDirectory,
}

/// Imported files not yet sorted, where a download looks before asking a peer.
struct Unsorted {
    db: std::path::PathBuf,
    content: Content,
}

impl Local for Unsorted {
    fn take(&self, group: GroupId, dir: &str, path: &RelPath, hash: &str) -> bool {
        crate::ops::import::adopt_unsorted(
            &self.db,
            &self.content,
            &group.to_string(),
            dir,
            path,
            hash,
        )
        .unwrap_or_else(|e| {
            // Never fatal: a peer has the bytes, and fetching them is what would have happened
            // anyway. Worth a line, because it means the import ledger is unhappy about something.
            tracing::warn!(%hash, error = %format!("{e:#}"), "could not take the unsorted copy");
            false
        })
    }
}

pub struct FileLink {
    sync: FileSync,
    outbound: HashMap<request_response::OutboundRequestId, (PeerId, Outbound)>,
    rounds: Vec<RoundOutcome>,
    blobs: Blobs,
    transfers: Transfers<Fetch, Blobs>,
    fetching: HashMap<TransferId, (PeerId, GroupId, RelPath)>,
    fetched: Vec<TransferOutcome>,
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
    /// Open the stores, and start accepting file transfers on `swarm`. Downloads share `down`
    /// with imports.
    pub fn open(
        paths: &Paths,
        identity: &Identity,
        swarm: &ClientSwarm,
        down: Arc<Throttle>,
    ) -> Result<Self> {
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

        let unsorted = Unsorted {
            db: path.clone(),
            content: content.clone(),
        };
        let blobs = Blobs::new(path, me, content.clone(), Arc::new(unsorted));

        let transfers = Transfers::new(
            swarm.behaviour().app.blobs.new_control(),
            TransferSpec {
                protocol: BLOB_PROTOCOL,
                max_header: MAX_BLOB_HEADER_BYTES,
                max_downloads: MAX_DOWNLOADS,
                max_uploads: MAX_UPLOADS,
            },
            blobs.clone(),
            down,
            Arc::new(Throttle::from_config(config.bandwidth_max, THROTTLE_BURST)),
        )
        .context("registering the blob protocol")?;

        Ok(Self {
            sync: FileSync::new(files, groups, content),
            outbound: HashMap::new(),
            rounds: Vec::new(),
            blobs,
            transfers,
            fetching: HashMap::new(),
            fetched: Vec::new(),
        })
    }

    /// Bytes of content fetched and served since this node started.
    pub fn moved(&self) -> (u64, u64) {
        self.transfers.moved()
    }

    /// Start fetching a file from `peer`.
    pub fn fetch(
        &mut self,
        peer: PeerId,
        group: GroupId,
        path: RelPath,
        hash: String,
    ) -> Result<(), NotStarted> {
        let dir = self.sync.dir_of(group).ok_or(NotStarted::NoDirectory)?;
        let fetch = self.blobs.fetch(group, dir, path.clone(), hash);
        let id = self
            .transfers
            .fetch(peer, fetch)
            .ok_or(NotStarted::PoolFull)?;
        self.fetching.insert(id, (peer, group, path));
        Ok(())
    }

    /// Wait for a file transfer to end, or a peer to open one.
    pub async fn next_transfer(&mut self) -> TransferEvent<FetchError> {
        self.transfers.next().await
    }

    /// Serve a stream only from a ready peer, and keep a finished download for the supervisor.
    pub fn on_transfer(
        &mut self,
        event: TransferEvent<FetchError>,
        admitted_peers: &AdmittedPeers,
    ) {
        match event {
            TransferEvent::Inbound(inbound) => {
                let peer = inbound.peer();
                if admitted_peers.is_ready(&peer) {
                    self.transfers.serve(inbound);
                } else {
                    tracing::debug!(%peer, "declining a blob stream from a peer that is not ready");
                }
            }
            TransferEvent::Finished { id, result, .. } => {
                if let Some((peer, group, path)) = self.fetching.remove(&id) {
                    self.fetched.push(TransferOutcome {
                        peer,
                        group,
                        path,
                        result,
                    });
                }
            }
        }
    }

    pub fn drain_transfers(&mut self) -> Vec<TransferOutcome> {
        std::mem::take(&mut self.fetched)
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

    /// Whether any question we put to this peer is still outstanding, a catalogue read from
    /// them is still waiting to go out, or a download from them is running. Uploads to them
    /// do not count.
    pub fn busy_with(&self, peer: &PeerId) -> bool {
        self.outbound.values().any(|(p, _)| p == peer)
            || self.sync.has_work_with(peer)
            || self.fetching.values().any(|(p, ..)| p == peer)
    }

    /// Bytes of content this node holds, across every group. Feeds the storage budget.
    pub fn held_bytes(&self) -> Option<u64> {
        self.sync.files().held_bytes().ok()
    }

    /// Drive the machine's clock.
    pub fn housekeeping(
        &mut self,
        swarm: &mut ClientSwarm,
        admitted_peers: &AdmittedPeers,
        now: Instant,
        at: i64,
    ) {
        let actions = self.sync.on(FileEvent::Tick { now, at }, admitted_peers);
        self.dispatch(swarm, actions);
    }

    pub fn on_event(
        &mut self,
        swarm: &mut ClientSwarm,
        admitted_peers: &AdmittedPeers,
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
                let (response, actions) = self.sync.on_request(peer, request, admitted_peers);
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
                        self.sync
                            .on(FileEvent::Heads { peer, heads }, admitted_peers)
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
                        admitted_peers,
                    ),
                    (Outbound::Changes { group, .. }, ManifestResponse::Unavailable) => self
                        .sync
                        .on(FileEvent::Unavailable { peer, group }, admitted_peers),
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
                    .on(FileEvent::RequestFailed { peer, group }, admitted_peers)
            }

            _ => return,
        };

        self.dispatch(swarm, actions);
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
