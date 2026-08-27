use std::collections::HashMap;
use std::time::{Duration, Instant};

use ac_groups::id::GroupId;
use ac_groups::store::Groups;
use ac_net::PeerId;
use ac_net::budget::TickBudget;
use ac_net::roster::Roster;

use crate::content::Content;
use crate::path::RelPath;
use crate::store::{FileRow, Files, Merged};
use crate::wire::{
    FileHead, MAX_ENTRIES_PER_RESPONSE, MAX_HEADS_PER_ANSWER, MAX_HOLDINGS_QUERY, ManifestEntry,
    ManifestRequest, ManifestResponse,
};

/// How long a request may be outstanding before the episode is abandoned.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Requests we will *answer* from one peer between ticks.
const ANSWERS_PER_TICK: u32 = 8;

/// Catalogue reads outstanding at once, across all peers and groups.
const MAX_INFLIGHT: usize = 8;

/// What the machine wants done. The daemon is the only thing that can do any of it.
#[derive(Debug, Clone, PartialEq)]
pub enum FileAction {
    FetchChanges {
        peer: PeerId,
        group: GroupId,
        after: u64,
    },
    Settled {
        peer: PeerId,
        group: GroupId,
    },
}

/// Everything the machine reacts to.
#[derive(Debug, Clone)]
pub enum FileEvent {
    Heads {
        peer: PeerId,
        heads: Vec<FileHead>,
    },
    Changes {
        peer: PeerId,
        group: GroupId,
        after: u64,
        entries: Vec<ManifestEntry>,
        next: u64,
        more: bool,
        digest: [u8; 32],
    },
    Unavailable {
        peer: PeerId,
        group: GroupId,
    },
    RequestFailed {
        peer: PeerId,
        group: Option<GroupId>,
    },
    Tick {
        now: Instant,
        at: i64,
    },
}

/// Whether these stores say a peer may have this file's bytes, and how many.
pub fn may_serve(
    files: &Files,
    groups: &Groups,
    peer: &PeerId,
    group: GroupId,
    path: &RelPath,
) -> Option<u64> {
    let shared = groups.shared_with(peer).unwrap_or_default();
    if !shared.iter().any(|h| h.group == group) {
        return None;
    }
    let row = files.get(group, path).ok().flatten()?;
    (!row.is_removed() && row.have).then_some(row.size)
}

/// One outstanding catalogue read. Keyed by group, so there is one episode per group at a time.
#[derive(Debug, Clone)]
struct InFlight {
    peer: PeerId,
    after: u64,
    retried: bool,
    deadline: Instant,
}

pub struct FileSync {
    files: Files,
    groups: Groups,
    content: Content,
    dirs: HashMap<GroupId, String>,
    me: PeerId,
    inflight: HashMap<GroupId, InFlight>,
    budget: TickBudget,
    now_at: i64,
}

impl FileSync {
    pub fn new(files: Files, groups: Groups, content: Content) -> Self {
        let me = files.me();
        Self {
            files,
            groups,
            content,
            dirs: HashMap::new(),
            me,
            inflight: HashMap::new(),
            budget: TickBudget::new(ANSWERS_PER_TICK),
            now_at: 0,
        }
    }

    pub fn files(&self) -> &Files {
        &self.files
    }

    /// Write access, for setting up a scenario in tests.
    pub fn files_mut(&mut self) -> &mut Files {
        &mut self.files
    }

    pub fn groups(&self) -> &Groups {
        &self.groups
    }

    pub fn groups_mut(&mut self) -> &mut Groups {
        &mut self.groups
    }

    pub fn content(&self) -> &Content {
        &self.content
    }

    /// The directory a group's files live in, resolved once.
    pub fn dir_of(&mut self, group: GroupId) -> Option<String> {
        if let Some(dir) = self.dirs.get(&group) {
            return Some(dir.clone());
        }
        let name = self.groups.get(group).ok().flatten()?.name;
        let dir = self.files.dir_for(group, &name).ok()?;
        self.dirs.insert(group, dir.clone());
        Some(dir)
    }

    /// Answer an inbound request.
    pub fn on_request(
        &mut self,
        peer: PeerId,
        request: ManifestRequest,
        roster: &Roster,
    ) -> (ManifestResponse, Vec<FileAction>) {
        if !roster.is_admitted(&peer) || !self.budget.spend(peer) {
            return (ManifestResponse::Unavailable, Vec::new());
        }

        match request {
            ManifestRequest::Ask => (ManifestResponse::Heads(self.heads_for(&peer)), Vec::new()),

            ManifestRequest::Changes { group, after } => {
                if !self.shares(&peer, group) {
                    return (ManifestResponse::Unavailable, Vec::new());
                }
                match self.page(group, after) {
                    Some(response) => (response, Vec::new()),
                    None => (ManifestResponse::Unavailable, Vec::new()),
                }
            }

            ManifestRequest::Holdings { group, paths } => {
                if !self.shares(&peer, group) {
                    return (ManifestResponse::Unavailable, Vec::new());
                }

                let held =
                    crate::wire::pack_holdings(paths.iter().take(MAX_HOLDINGS_QUERY).map(|raw| {
                        RelPath::parse(raw).is_ok_and(|path| {
                            self.files
                                .get(group, &path)
                                .ok()
                                .flatten()
                                .is_some_and(|row| row.have && !row.is_removed())
                        })
                    }));
                (ManifestResponse::Holdings { group, held }, Vec::new())
            }
        }
    }

    pub fn on(&mut self, event: FileEvent, roster: &Roster) -> Vec<FileAction> {
        match event {
            FileEvent::Heads { peer, heads } => {
                if !roster.is_ready(&peer) {
                    return Vec::new();
                }
                self.on_heads(peer, heads)
            }

            FileEvent::Changes {
                peer,
                group,
                after,
                entries,
                next,
                more,
                digest,
            } => self.on_changes(peer, group, after, entries, next, more, digest),

            // A refusal ends the round as surely as agreement does, and has to say so.
            FileEvent::Unavailable { peer, group } => {
                self.finish(group, peer);
                vec![FileAction::Settled { peer, group }]
            }

            FileEvent::RequestFailed { peer, group } => {
                let Some(group) = group else {
                    return Vec::new();
                };
                // Not `Settled`: settled means there is nothing further to read from them,
                // and a request that failed says nothing of the sort. The link reports the
                // failure to the supervisor, which is what puts the round back on.
                self.finish(group, peer);
                Vec::new()
            }

            FileEvent::Tick { now, at } => self.tick(now, at, roster),
        }
    }

    // ---- inbound ----

    fn on_heads(&mut self, peer: PeerId, heads: Vec<FileHead>) -> Vec<FileAction> {
        let mut actions = Vec::new();

        for head in heads.into_iter().take(MAX_HEADS_PER_ANSWER) {
            if !self.shares(&peer, head.group) {
                continue;
            }
            let ours = self.files.digest(head.group).unwrap_or([0u8; 32]);
            let started = ours != head.digest && {
                let after = self.files.cursor(head.group, &peer).unwrap_or(0);
                self.read(&mut actions, peer, head.group, after, false)
            };

            if !started {
                actions.push(FileAction::Settled {
                    peer,
                    group: head.group,
                });
            }
        }
        actions
    }

    #[allow(clippy::too_many_arguments)]
    fn on_changes(
        &mut self,
        peer: PeerId,
        group: GroupId,
        after: u64,
        entries: Vec<ManifestEntry>,
        next: u64,
        more: bool,
        digest: [u8; 32],
    ) -> Vec<FileAction> {
        let expected = matches!(
            self.inflight.get(&group),
            Some(f) if f.peer == peer && f.after == after
        );
        if !expected {
            return Vec::new();
        }
        let retried = self.inflight.get(&group).is_some_and(|f| f.retried);
        self.inflight.remove(&group);

        let Some(dir) = self.dir_of(group) else {
            tracing::warn!(%group, "no directory for this group; cannot merge its catalogue");
            return Vec::new();
        };

        let mut actions = Vec::new();
        let mut applied = 0usize;

        for entry in entries.into_iter().take(MAX_ENTRIES_PER_RESPONSE) {
            let Some(row) = entry.into_row() else {
                tracing::warn!(%peer, %group, "ignored an unusable catalogue entry");
                continue;
            };

            match self.files.merge(group, &row, &self.content, &dir) {
                Ok(Merged::Unchanged | Merged::Rejected) => {}
                Ok(Merged::Applied) => applied += 1,
                Ok(Merged::Conflicted { moved }) => {
                    applied += 1;
                    tracing::info!(
                        %group,
                        kept = %row.path,
                        %moved,
                        "two files wanted the same path; kept both"
                    );
                }
                Ok(Merged::Deduplicated { kept, dropped }) => {
                    applied += 1;
                    // A group keeps one copy of any content, so the later path goes.
                    tracing::info!(%group, %kept, %dropped, "dropped a duplicate");
                }
                Err(e) => {
                    tracing::warn!(%group, path = %row.path, error = %e, "could not merge a row");
                }
            }
        }

        // The cursor moves only to a position the peer reported.
        if let Err(e) = self.files.set_cursor(group, &peer, next) {
            tracing::warn!(%group, %peer, error = %e, "could not record how far we read");
        }

        if applied > 0 {
            tracing::info!(%group, count = applied, "learned files");
        }

        if more && self.read(&mut actions, peer, group, next, retried) {
            return actions;
        }

        // Drained. The digest is what says whether the cursor told the truth.
        let ours = self.files.digest(group).unwrap_or([0u8; 32]);
        if ours != digest && !retried {
            let _ = self.files.set_cursor(group, &peer, 0);
            if self.read(&mut actions, peer, group, 0, true) {
                return actions;
            }
        }

        actions.push(FileAction::Settled { peer, group });
        actions
    }

    /// One page of our own log, plus where we stand.
    fn page(&mut self, group: GroupId, after: u64) -> Option<ManifestResponse> {
        let (rows, next) = self
            .files
            .changes_since(group, after, MAX_ENTRIES_PER_RESPONSE)
            .ok()?;
        let more = self.files.has_changes_after(group, next).unwrap_or(false);
        let digest = self.files.digest(group).ok()?;

        Some(ManifestResponse::Changes {
            group,
            entries: rows.iter().filter_map(ManifestEntry::of).collect(),
            next,
            more,
            digest,
        })
    }

    // ---- outbound ----
    fn read(
        &mut self,
        actions: &mut Vec<FileAction>,
        peer: PeerId,
        group: GroupId,
        after: u64,
        retried: bool,
    ) -> bool {
        if self.inflight.contains_key(&group) || self.inflight.len() >= MAX_INFLIGHT {
            return false;
        }
        self.inflight.insert(
            group,
            InFlight {
                peer,
                after,
                retried,
                deadline: Instant::now() + REQUEST_TIMEOUT,
            },
        );
        actions.push(FileAction::FetchChanges { peer, group, after });
        true
    }

    fn tick(&mut self, now: Instant, at: i64, roster: &Roster) -> Vec<FileAction> {
        self.now_at = at;
        self.budget.reset();

        // Abandon episodes that can no longer finish, so the group is free to try again:
        self.inflight
            .retain(|_, f| now < f.deadline && roster.is_ready(&f.peer));
        Vec::new()
    }

    /// What we would name to this peer: the catalogues of the groups we share with them.
    pub fn heads_for(&mut self, peer: &PeerId) -> Vec<FileHead> {
        let shared = self.groups.shared_with(peer).unwrap_or_default();
        shared
            .into_iter()
            .take(MAX_HEADS_PER_ANSWER)
            .filter_map(|head| {
                Some(FileHead {
                    group: head.group,
                    digest: self.files.digest(head.group).ok()?,
                    count: self.files.count(head.group).unwrap_or(0),
                })
            })
            .collect()
    }

    fn shares(&self, peer: &PeerId, group: GroupId) -> bool {
        self.groups
            .shared_with(peer)
            .unwrap_or_default()
            .iter()
            .any(|h| h.group == group)
    }

    fn finish(&mut self, group: GroupId, peer: PeerId) {
        if matches!(self.inflight.get(&group), Some(f) if f.peer == peer) {
            self.inflight.remove(&group);
        }
    }

    /// A row we hold, for the daemon to check a finished transfer against.
    pub fn row(&self, group: GroupId, path: &RelPath) -> Option<FileRow> {
        self.files.get(group, path).ok().flatten()
    }

    pub fn me(&self) -> PeerId {
        self.me
    }

    pub fn now_at(&self) -> i64 {
        self.now_at
    }
}
