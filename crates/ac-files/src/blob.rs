//! The rules of `/ac/blob/1.0.0`: what a download asks for and keeps, and what this node
//! agrees to serve. `ac-net` moves the bytes.

use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use ac_groups::id::GroupId;
use ac_groups::store::{Groups, StoreError};
use ac_net::PeerId;
use ac_net::stream::StreamError;
use ac_net::transfer::{Download, Serve};

use crate::content::{Content, Sink};
use crate::path::RelPath;
use crate::store::{FileRow, Files, FilesError};
use crate::wire::{BlobReply, BlobRequest};

/// Why a download did not end with the file in place.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("the peer would not serve it")]
    Unavailable,
    #[error("the content did not match the hash it was asked for")]
    WrongContent,
    #[error("the peer sent more than the size it announced")]
    Overlong,
    #[error("transfer ended early after {got} of {expected} bytes")]
    Early { got: u64, expected: u64 },
    #[error("the hash asked for is not a SHA-256 in hex")]
    BadHash,
    #[error(transparent)]
    Stream(#[from] StreamError),
    #[error("could not write the download: {0}")]
    Disk(io::Error),
    #[error(transparent)]
    Index(#[from] FilesError),
}

impl FetchError {
    /// Whether asking the same peer for the same file again cannot help.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            FetchError::Unavailable | FetchError::WrongContent | FetchError::Overlong
        )
    }
}

/// Somewhere else this node may already hold the bytes.
pub trait Local: Send + Sync {
    /// Whether the bytes were found and filed at `path` in the group's directory.
    fn take(&self, group: GroupId, dir: &str, path: &RelPath, hash: &str) -> bool;
}

/// Whether taking `n` more bytes would carry the transfer past what the sender announced.
fn overruns(got: u64, n: usize, expected: u64) -> bool {
    got.saturating_add(n as u64) > expected
}

/// Whether these stores say a peer may have this file's bytes, and its row if so.
pub fn may_serve(
    files: &Files,
    groups: &Groups,
    peer: &PeerId,
    group: GroupId,
    path: &RelPath,
) -> Option<FileRow> {
    let shared = groups.shared_with(peer).unwrap_or_default();
    if !shared.iter().any(|h| h.group == group) {
        return None;
    }
    let row = files.get(group, path).ok().flatten()?;
    (!row.is_removed() && row.have).then_some(row)
}

/// One file to fetch from one peer.
pub struct Fetch {
    db: PathBuf,
    me: PeerId,
    content: Content,
    group: GroupId,
    dir: String,
    path: RelPath,
    hash: String,
    local: Option<Arc<dyn Local>>,
    resume: u64,
}

/// A download whose peer agreed to send.
pub struct Receiving {
    fetch: Fetch,
    sink: Sink,
    got: u64,
    expected: u64,
}

impl Fetch {
    pub fn new(
        db: PathBuf,
        me: PeerId,
        content: Content,
        group: GroupId,
        dir: String,
        path: RelPath,
        hash: String,
    ) -> Self {
        Self {
            db,
            me,
            content,
            group,
            dir,
            path,
            hash,
            local: None,
            resume: 0,
        }
    }

    /// Look in `local` before asking the peer.
    pub fn with_local(mut self, local: Arc<dyn Local>) -> Self {
        self.local = Some(local);
        self
    }

    fn mark_held(&self) -> Result<(), FetchError> {
        Files::open(&self.db, self.me)?.mark_have(self.group, &self.path, true)?;
        Ok(())
    }
}

impl Download for Fetch {
    type Request = BlobRequest;
    type Reply = BlobReply;
    type Receiving = Receiving;
    type Error = FetchError;

    fn start(&mut self) -> Result<Option<BlobRequest>, FetchError> {
        if self
            .local
            .as_ref()
            .is_some_and(|l| l.take(self.group, &self.dir, &self.path, &self.hash))
        {
            tracing::info!(path = %self.path, "already on this node; filed rather than fetched");
            self.mark_held()?;
            return Ok(None);
        }

        let mut hash = [0u8; 32];
        hex::decode_to_slice(&self.hash, &mut hash).map_err(|_| FetchError::BadHash)?;
        self.resume = self.content.staged_len(&self.dir, &self.path);

        Ok(Some(BlobRequest {
            group: self.group,
            path: self.path.to_string(),
            hash,
            offset: self.resume,
        }))
    }

    fn on_reply(self, reply: BlobReply) -> Result<Receiving, FetchError> {
        let expected = match reply {
            BlobReply::Sending { size } => size,
            BlobReply::Unavailable => return Err(FetchError::Unavailable),
        };
        let sink = self
            .content
            .resume(&self.dir, &self.path, self.resume)
            .map_err(FetchError::Disk)?;
        Ok(Receiving {
            fetch: self,
            sink,
            got: 0,
            expected,
        })
    }

    fn on_chunk(receiving: &mut Receiving, chunk: &[u8]) -> Result<(), FetchError> {
        if overruns(receiving.got, chunk.len(), receiving.expected) {
            return Err(FetchError::Overlong);
        }
        receiving.sink.write(chunk).map_err(FetchError::Disk)?;
        receiving.got += chunk.len() as u64;
        Ok(())
    }

    fn on_end(receiving: Receiving, ended: Result<(), FetchError>) -> Result<(), FetchError> {
        let Receiving {
            fetch,
            sink,
            got,
            expected,
        } = receiving;

        match ended {
            Err(FetchError::Overlong) => {
                sink.park().map_err(FetchError::Disk)?;
                return Err(FetchError::Overlong);
            }
            Err(e) => return Err(e),
            Ok(()) => {}
        }

        if got != expected {
            sink.park().map_err(FetchError::Disk)?;
            return Err(FetchError::Early { got, expected });
        }

        let staged = sink.finish().map_err(FetchError::Disk)?;
        if staged.hash != fetch.hash {
            fetch.content.discard(staged).ok();
            return Err(FetchError::WrongContent);
        }
        fetch.content.commit(staged).map_err(FetchError::Disk)?;
        fetch.mark_held()
    }
}

/// What to answer one blob request.
#[derive(Debug)]
pub enum Answer {
    Send { size: u64, file: File },
    Unavailable,
}

/// Decide what to answer `peer`, from these stores.
pub fn answer(
    files: &mut Files,
    groups: &Groups,
    content: &Content,
    peer: &PeerId,
    request: &BlobRequest,
) -> Result<Answer, FilesError> {
    let Ok(path) = RelPath::parse(&request.path) else {
        return Ok(Answer::Unavailable);
    };

    let Some(row) = may_serve(files, groups, peer, request.group, &path) else {
        return Ok(Answer::Unavailable);
    };
    if row.hash != hex::encode(request.hash) {
        return Ok(Answer::Unavailable);
    }
    let Some(dir) = files.dir_of(request.group)? else {
        return Ok(Answer::Unavailable);
    };

    match content.open_at(&dir, &path, request.offset) {
        Ok(file) => Ok(Answer::Send {
            size: row.size.saturating_sub(request.offset),
            file,
        }),
        Err(e) => {
            tracing::warn!(%path, error = %e, "indexed as held, but not on disk; correcting");
            let _ = files.mark_have(request.group, &path, false);
            Ok(Answer::Unavailable)
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error(transparent)]
    Index(#[from] FilesError),
    #[error(transparent)]
    Groups(#[from] StoreError),
}

/// This node's side of `/ac/blob/1.0.0`, shared by every upload.
pub struct Server {
    db: PathBuf,
    me: PeerId,
    content: Content,
}

impl Server {
    pub fn new(db: PathBuf, me: PeerId, content: Content) -> Self {
        Self { db, me, content }
    }
}

impl Serve for Server {
    type Request = BlobRequest;
    type Reply = BlobReply;
    type Source = File;
    type Error = ServeError;

    fn answer(
        &self,
        peer: PeerId,
        request: BlobRequest,
    ) -> Result<(BlobReply, Option<File>), ServeError> {
        let mut files = Files::open(&self.db, self.me)?;
        let groups = Groups::open(&self.db, self.me)?;

        Ok(
            match answer(&mut files, &groups, &self.content, &peer, &request)? {
                Answer::Send { size, file } => (BlobReply::Sending { size }, Some(file)),
                Answer::Unavailable => (BlobReply::Unavailable, None),
            },
        )
    }

    fn busy(&self) -> BlobReply {
        BlobReply::Unavailable
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    use ac_groups::chain::Op;
    use ac_net::identity::Keypair;
    use sha2::{Digest, Sha256};

    use crate::store::fixtures::AT;

    fn bytes() -> Vec<u8> {
        (0..200_000).map(|i| (i % 251) as u8).collect()
    }

    fn hash_of(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    /// The fetching side: a database on disk, since a download opens its own.
    struct Fetcher {
        dir: tempfile::TempDir,
        me: PeerId,
        group: GroupId,
        group_dir: String,
        path: RelPath,
    }

    impl Fetcher {
        /// A node that knows of `bytes` at `photos/beach.jpg` and does not hold them.
        fn new(bytes: &[u8]) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let me = Keypair::generate_ed25519().public().to_peer_id();
            let group = crate::store::fixtures::group_id(1);
            let path = RelPath::parse("photos/beach.jpg").unwrap();

            let mut files = Files::open(&dir.path().join("state.sqlite"), me).unwrap();
            let group_dir = files.dir_for(group, "holiday").unwrap();
            let mut row = crate::store::fixtures::row(me, "photos/beach.jpg", &hash_of(bytes));
            row.size = bytes.len() as u64;
            row.have = false;
            files.record(group, &row, true).unwrap();

            Self {
                dir,
                me,
                group,
                group_dir,
                path,
            }
        }

        fn content(&self) -> Content {
            Content::new(self.dir.path().join("files"))
        }

        fn fetch(&self, hash: &str) -> Fetch {
            Fetch::new(
                self.dir.path().join("state.sqlite"),
                self.me,
                self.content(),
                self.group,
                self.group_dir.clone(),
                self.path.clone(),
                hash.to_owned(),
            )
        }

        fn held(&self) -> bool {
            Files::open(&self.dir.path().join("state.sqlite"), self.me)
                .unwrap()
                .get(self.group, &self.path)
                .unwrap()
                .unwrap()
                .have
        }

        fn staged(&self) -> u64 {
            self.content().staged_len(&self.group_dir, &self.path)
        }

        fn committed(&self) -> Option<Vec<u8>> {
            std::fs::read(self.content().locate(&self.group_dir, &self.path)).ok()
        }
    }

    /// Feed `bytes` in chunks the way the stream would, and end it.
    fn feed(fetch: Fetch, size: u64, bytes: &[u8]) -> Result<(), FetchError> {
        let mut receiving = fetch.on_reply(BlobReply::Sending { size })?;
        let mut ended = Ok(());
        for chunk in bytes.chunks(64 * 1024) {
            if let Err(e) = Fetch::on_chunk(&mut receiving, chunk) {
                ended = Err(e);
                break;
            }
        }
        Fetch::on_end(receiving, ended)
    }

    struct Found(bool);

    impl Local for Found {
        fn take(&self, _: GroupId, _: &str, _: &RelPath, _: &str) -> bool {
            self.0
        }
    }

    #[test]
    fn a_download_resumes_from_what_is_staged() {
        let bytes = bytes();
        let node = Fetcher::new(&bytes);
        let hash = hash_of(&bytes);

        let mut first = node.fetch(&hash);
        assert_eq!(first.start().unwrap().unwrap().offset, 0);
        let cut = feed(first, bytes.len() as u64, &bytes[..70_000]);
        assert!(matches!(cut, Err(FetchError::Early { got: 70_000, .. })));

        let mut second = node.fetch(&hash);
        let request = second.start().unwrap().unwrap();
        assert_eq!(request.offset, 70_000, "the request carries what is staged");

        let rest = &bytes[70_000..];
        feed(second, rest.len() as u64, rest).unwrap();
        assert_eq!(node.committed().unwrap(), bytes, "and the file is whole");
        assert!(node.held());
    }

    #[test]
    fn a_wrong_hash_is_final_and_keeps_nothing() {
        let bytes = bytes();
        let node = Fetcher::new(&bytes);

        let mut fetch = node.fetch(&hash_of(b"something else"));
        fetch.start().unwrap();
        let failed = feed(fetch, bytes.len() as u64, &bytes).unwrap_err();

        assert!(matches!(failed, FetchError::WrongContent));
        assert!(failed.is_terminal());
        assert_eq!(node.staged(), 0, "the partial is discarded");
        assert_eq!(node.committed(), None, "nothing is committed");
        assert!(!node.held());
    }

    #[test]
    fn more_than_announced_is_final_and_keeps_what_fitted() {
        let bytes = bytes();
        let node = Fetcher::new(&bytes);

        let mut fetch = node.fetch(&hash_of(&bytes));
        fetch.start().unwrap();
        let announced = 100_000;
        let failed = feed(fetch, announced, &bytes).unwrap_err();

        assert!(matches!(failed, FetchError::Overlong));
        assert!(failed.is_terminal());
        assert_eq!(
            node.staged(),
            64 * 1024,
            "kept up to the last chunk that fitted"
        );
        assert!(!node.held());
    }

    #[test]
    fn a_stream_that_ends_early_is_retryable_and_keeps_its_partial() {
        let bytes = bytes();
        let node = Fetcher::new(&bytes);

        let mut fetch = node.fetch(&hash_of(&bytes));
        fetch.start().unwrap();
        let failed = feed(fetch, bytes.len() as u64, &bytes[..1000]).unwrap_err();

        assert!(matches!(failed, FetchError::Early { got: 1000, .. }));
        assert!(!failed.is_terminal());
        assert_eq!(node.staged(), 1000);
    }

    #[test]
    fn a_stream_that_fails_partway_is_retryable_and_keeps_its_partial() {
        let bytes = bytes();
        let node = Fetcher::new(&bytes);

        let mut fetch = node.fetch(&hash_of(&bytes));
        fetch.start().unwrap();
        let mut receiving = fetch
            .on_reply(BlobReply::Sending {
                size: bytes.len() as u64,
            })
            .unwrap();
        Fetch::on_chunk(&mut receiving, &bytes[..1000]).unwrap();
        let severed = StreamError::Io(io::Error::from(io::ErrorKind::ConnectionReset));
        let failed = Fetch::on_end(receiving, Err(severed.into())).unwrap_err();

        assert!(matches!(failed, FetchError::Stream(_)));
        assert!(!failed.is_terminal());
        assert_eq!(node.staged(), 1000);
    }

    #[test]
    fn an_unavailable_reply_is_final() {
        let bytes = bytes();
        let node = Fetcher::new(&bytes);

        let mut fetch = node.fetch(&hash_of(&bytes));
        fetch.start().unwrap();
        let Err(refused) = fetch.on_reply(BlobReply::Unavailable) else {
            panic!("an unavailable reply cannot start receiving");
        };
        assert!(matches!(refused, FetchError::Unavailable));
        assert!(refused.is_terminal());
    }

    #[test]
    fn bytes_found_locally_are_not_asked_for() {
        let bytes = bytes();
        let node = Fetcher::new(&bytes);

        let mut fetch = node
            .fetch(&hash_of(&bytes))
            .with_local(Arc::new(Found(true)));
        assert!(fetch.start().unwrap().is_none(), "no request goes out");
        assert!(node.held(), "and the row is held");
    }

    #[test]
    fn bytes_not_found_locally_are_asked_for() {
        let bytes = bytes();
        let node = Fetcher::new(&bytes);

        let mut fetch = node
            .fetch(&hash_of(&bytes))
            .with_local(Arc::new(Found(false)));
        let request = fetch.start().unwrap().unwrap();

        assert_eq!(hex::encode(request.hash), hash_of(&bytes));
        assert_eq!(request.path, "photos/beach.jpg");
        assert_eq!(request.offset, 0);
        assert!(!node.held());
    }

    /// The serving side: in-memory stores, with a group shared with one member.
    struct Holder {
        _dir: tempfile::TempDir,
        files: Files,
        groups: Groups,
        content: Content,
        member: PeerId,
        group: GroupId,
        group_dir: String,
        path: RelPath,
        hash: String,
    }

    impl Holder {
        /// A node holding `bytes` at `photos/beach.jpg`, in a group it shares with `member`.
        fn new(bytes: &[u8]) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let key = Keypair::generate_ed25519();
            let me = key.public().to_peer_id();
            let member = Keypair::generate_ed25519().public().to_peer_id();

            let mut groups = Groups::in_memory(me).unwrap();
            let group = groups.create(&key, "holiday", "admin", AT).unwrap();
            groups
                .author(
                    &key,
                    group,
                    Op::Add {
                        peer: member.to_base58(),
                    },
                    AT,
                )
                .unwrap();

            let mut files = Files::in_memory(me).unwrap();
            let group_dir = files.dir_for(group, "holiday").unwrap();
            let content = Content::new(dir.path().join("files"));
            let path = RelPath::parse("photos/beach.jpg").unwrap();

            let src = dir.path().join("incoming");
            std::fs::write(&src, bytes).unwrap();
            let staged = content.stage(&group_dir, &path, &src).unwrap();
            let hash = staged.hash.clone();
            let mut row = crate::store::fixtures::row(me, "photos/beach.jpg", &hash);
            row.size = staged.size;
            content.commit(staged).unwrap();
            files.record(group, &row, true).unwrap();

            Self {
                _dir: dir,
                files,
                groups,
                content,
                member,
                group,
                group_dir,
                path,
                hash,
            }
        }

        fn request(&self, offset: u64) -> BlobRequest {
            let mut hash = [0u8; 32];
            hex::decode_to_slice(&self.hash, &mut hash).unwrap();
            BlobRequest {
                group: self.group,
                path: self.path.to_string(),
                hash,
                offset,
            }
        }

        fn answer(&mut self, peer: PeerId, request: &BlobRequest) -> Answer {
            answer(&mut self.files, &self.groups, &self.content, &peer, request).unwrap()
        }

        fn held(&self) -> bool {
            self.files
                .get(self.group, &self.path)
                .unwrap()
                .unwrap()
                .have
        }
    }

    #[test]
    fn a_requester_outside_the_group_is_refused() {
        let mut node = Holder::new(&bytes());
        let stranger = Keypair::generate_ed25519().public().to_peer_id();
        let request = node.request(0);

        assert!(matches!(
            node.answer(stranger, &request),
            Answer::Unavailable
        ));
    }

    #[test]
    fn a_file_indexed_as_held_but_missing_is_refused_and_corrected() {
        let mut node = Holder::new(&bytes());
        std::fs::remove_file(node.content.locate(&node.group_dir, &node.path)).unwrap();
        let (member, request) = (node.member, node.request(0));

        assert!(matches!(node.answer(member, &request), Answer::Unavailable));
        assert!(
            !node.held(),
            "the row is marked not held, so it is fetched again"
        );
    }

    #[test]
    fn a_hash_other_than_the_row_is_refused() {
        let mut node = Holder::new(&bytes());
        let mut request = node.request(0);
        request.hash = [9u8; 32];
        let member = node.member;

        assert!(matches!(node.answer(member, &request), Answer::Unavailable));
        assert!(node.held(), "nothing about our copy is in doubt");
    }

    #[test]
    fn a_path_that_does_not_parse_is_refused() {
        let mut node = Holder::new(&bytes());
        let mut request = node.request(0);
        request.path = "../outside.jpg".to_owned();
        let member = node.member;

        assert!(matches!(node.answer(member, &request), Answer::Unavailable));
    }

    #[test]
    fn a_held_file_is_sent_from_the_offset_asked_for() {
        let bytes = bytes();
        let mut node = Holder::new(&bytes);
        let (member, request) = (node.member, node.request(70_000));

        let Answer::Send { size, mut file } = node.answer(member, &request) else {
            panic!("a member asking for a held file is sent it");
        };
        assert_eq!(size, bytes.len() as u64 - 70_000);

        let mut sent = Vec::new();
        file.read_to_end(&mut sent).unwrap();
        assert_eq!(sent, &bytes[70_000..]);
    }

    #[test]
    fn a_transfer_may_take_exactly_what_was_announced_and_not_a_byte_more() {
        // Exactly the announced size is the ordinary end of every honest transfer.
        assert!(!overruns(0, 1000, 1000));
        assert!(!overruns(936, 64, 1000));

        // One byte past it is not, however small the overrun.
        assert!(overruns(936, 65, 1000));
        assert!(overruns(1000, 1, 1000));

        // A sender that keeps going cannot wrap the counter into looking acceptable.
        assert!(overruns(u64::MAX - 1, usize::MAX, 1000));
    }

    #[test]
    fn nothing_is_announced_means_nothing_may_arrive() {
        assert!(!overruns(0, 0, 0));
        assert!(overruns(0, 1, 0));
    }
}
