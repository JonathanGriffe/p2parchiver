//! Backing this node's identity up to the companion app, and restoring it from there.

use ac_import::companion::{self, Code};
use ac_import::{Fields, Registered, SourceRow};
use ac_net::config::Paths;
use ac_net::identity::Identity;
use ac_net::{Multiaddr, PeerId, Protocol};
use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The payload's version. A later desktop must still read every version a phone may hold.
pub const VERSION: u64 = 1;

/// What the phone keeps, exactly as it received it.
#[derive(Serialize, Deserialize)]
struct Payload {
    v: u64,
    peer: String,
    /// The protobuf-encoded keypair, the bytes of `identity.key`, in base64. A secret.
    key: String,
    server: String,
    username: String,
}

/// A backup taken back from a phone: enough to enrol as the same node again.
#[derive(Clone)]
pub struct Recovered {
    pub identity: Identity,
    /// The service address the node enrolled with, ending in `/p2p/<server peer id>`.
    pub server: Multiaddr,
    pub username: String,
}

/// By hand, so the key never reaches a log.
impl std::fmt::Debug for Recovered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recovered")
            .field("peer", &self.identity.peer_id())
            .field("server", &self.server)
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

impl Recovered {
    pub fn peer(&self) -> PeerId {
        self.identity.peer_id()
    }
}

/// The payload for this identity, its server and its username, as JSON.
pub fn encode(identity: &Identity, server: &Multiaddr, username: &str) -> Result<String> {
    let key = identity
        .to_protobuf()
        .map_err(|_| anyhow!("this node's key could not be encoded"))?;
    let payload = Payload {
        v: VERSION,
        peer: identity.peer_id().to_base58(),
        key: STANDARD.encode(key),
        server: server.to_string(),
        username: username.to_owned(),
    };
    serde_json::to_string(&payload).context("encoding the backup")
}

/// Read a payload and check it. No error names the key's bytes.
pub fn decode(backup: Value) -> Result<Recovered> {
    let payload: Payload = serde_json::from_value(backup)
        .map_err(|_| anyhow!("the backup is not one this app reads"))?;
    if payload.v != VERSION {
        bail!(
            "the backup is version {}, which this app does not read; update the app",
            payload.v
        );
    }

    let key = STANDARD
        .decode(payload.key.as_bytes())
        .map_err(|_| anyhow!("the backup's key is unreadable"))?;
    let identity =
        Identity::from_protobuf(&key).map_err(|_| anyhow!("the backup's key is unreadable"))?;
    if identity.peer_id().to_base58() != payload.peer {
        bail!("the backup's key does not match the node it names");
    }

    let server: Multiaddr = payload
        .server
        .parse()
        .map_err(|_| anyhow!("the backup's server address is unreadable"))?;
    if !server.iter().any(|p| matches!(p, Protocol::P2p(_))) {
        bail!("the backup's server address does not say which server it is");
    }

    Ok(Recovered {
        identity,
        server,
        username: payload.username,
    })
}

/// What one source made of a backup.
#[derive(Debug)]
pub struct Sent {
    /// The source's name, as the Sources page shows it.
    pub name: String,
    /// `Ok` once it keeps the backup.
    pub result: ac_import::source::Result<()>,
}

impl std::fmt::Display for Sent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.result {
            Ok(()) => write!(f, "{}: backed up", self.name),
            Err(error) => write!(f, "{}: {error}", self.name),
        }
    }
}

/// What became of a backup, one source after another, shown on one line.
#[derive(Debug)]
pub struct Backup(Vec<Sent>);

impl Backup {
    pub fn sent(&self) -> &[Sent] {
        &self.0
    }
}

impl std::fmt::Display for Backup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (at, sent) in self.0.iter().enumerate() {
            if at > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{sent}")?;
        }
        Ok(())
    }
}

/// The configured sources that can take a backup now: their kind has a `BACKUP` hook and
/// they are signed in.
fn takers(paths: &Paths) -> Result<Vec<(SourceRow, &'static Registered)>> {
    let rows = super::import::ledger(paths)?
        .sources()
        .context("reading the configured sources")?;
    Ok(rows
        .into_iter()
        .filter_map(|row| {
            let entry = ac_import::registry::find(&row.source)?;
            (entry.takes_backup() && entry.signed_in(&row.config)).then_some((row, entry))
        })
        .collect())
}

/// Whether a backup has somewhere to go.
pub fn can_back_up(paths: &Paths) -> Result<bool> {
    Ok(!takers(paths)?.is_empty())
}

/// Send this node's identity to every source that can take it, which are the paired phones.
/// Only once the home has enrolled, since a key that never enrolled has nothing to come back
/// to. It succeeds when at least one of them stored it, and fails otherwise.
pub fn backup(paths: &Paths) -> Result<Backup> {
    backup_with(paths, Registered::hand_over)
}

fn backup_with(
    paths: &Paths,
    send: impl Fn(&Registered, &Fields, &str) -> ac_import::source::Result<()>,
) -> Result<Backup> {
    let Some(server) = super::enrolled(paths)? else {
        bail!("this node has not enrolled yet, so there is nothing to back up");
    };
    let Some(statement) = super::enrolment(paths)? else {
        bail!("this node has no attestation yet, so there is nothing to back up");
    };
    let takers = takers(paths)?;
    if takers.is_empty() {
        bail!("no phone is paired to take the backup; pair a phone first");
    }
    let payload = encode(&super::identity(paths)?, &server, &statement.username)?;

    let backup = Backup(
        takers
            .into_iter()
            .map(|(row, entry)| {
                let sent = Sent {
                    name: row.name,
                    result: send(entry, &row.config, &payload),
                };
                tracing::info!(outcome = %sent, "backing up");
                sent
            })
            .collect(),
    );
    match backup.0.iter().any(|sent| sent.result.is_ok()) {
        true => Ok(backup),
        false => Err(anyhow!("{backup}")),
    }
}

/// Show a restore code, and take back the identity the phone that scans it sends. Refused
/// once the home has enrolled, since it already has an identity in use. Writes nothing:
/// enrolling with what it returns is what keeps it. `None` if somebody stopped it.
pub fn restore(paths: &Paths) -> Result<Option<Recovered>> {
    if super::enrolled(paths)?.is_some() {
        bail!("this node has already enrolled, so it keeps the identity it has");
    }
    let recovered = companion::ask(Code::Restore, |mut body, _| {
        let backup = body.get_mut("backup").map(Value::take).unwrap_or_default();
        decode(backup).map_err(|e| format!("{e:#}"))
    })?;
    Ok(recovered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ac_import::SourceError;
    use ac_net::config::Config;
    use ac_net::identity::Keypair;

    const SERVER: &str = "/ip4/203.0.113.7/udp/4001/quic-v1/p2p/12D3KooWDmPLKCjUV7snQBQVod5bNQnDmZ5X4MYNnPx8NM95zxke";

    fn identity() -> Identity {
        Identity::from_protobuf(&Keypair::generate_ed25519().to_protobuf_encoding().unwrap())
            .unwrap()
    }

    fn payload(identity: &Identity) -> serde_json::Value {
        let raw = encode(identity, &SERVER.parse().unwrap(), "alice").unwrap();
        serde_json::from_str(&raw).unwrap()
    }

    #[test]
    fn a_backup_survives_the_round_trip() {
        let mine = identity();
        let back = decode(payload(&mine)).unwrap();

        assert_eq!(back.peer(), mine.peer_id());
        assert_eq!(back.server.to_string(), SERVER);
        assert_eq!(back.username, "alice");
        assert_eq!(
            back.identity.to_protobuf().unwrap(),
            mine.to_protobuf().unwrap(),
            "the very same key"
        );

        let fields = payload(&mine);
        assert_eq!(fields["v"], 1);
        assert_eq!(fields["peer"], mine.peer_id().to_base58());
    }

    #[test]
    fn a_backup_whose_key_is_not_the_peer_it_names_is_refused() {
        let mut fields = payload(&identity());
        fields["peer"] = identity().peer_id().to_base58().into();
        let err = decode(fields).unwrap_err().to_string();
        assert!(err.contains("does not match"), "{err}");
    }

    #[test]
    fn a_backup_of_an_unknown_version_is_refused() {
        let mut fields = payload(&identity());
        fields["v"] = 2.into();
        let err = decode(fields).unwrap_err().to_string();
        assert!(err.contains("version 2"), "{err}");
    }

    #[test]
    fn a_backup_whose_server_is_not_pinned_is_refused() {
        let mut fields = payload(&identity());
        fields["server"] = "/ip4/203.0.113.7/udp/4001/quic-v1".into();
        let err = decode(fields).unwrap_err().to_string();
        assert!(err.contains("which server"), "{err}");
    }

    #[test]
    fn a_broken_key_is_refused_without_being_repeated() {
        for key in ["not base64 at all!", "aGVsbG8="] {
            let mut fields = payload(&identity());
            fields["key"] = key.into();
            let err = format!("{:#}", decode(fields).unwrap_err());
            assert!(err.contains("key is unreadable"), "{err}");
            assert!(!err.contains(key), "{err}");
        }
        assert!(
            decode(Value::Null).is_err(),
            "a restore that carried no backup"
        );
    }

    #[test]
    fn printing_a_restored_backup_does_not_print_its_key() {
        let mine = identity();
        let key = payload(&mine)["key"].as_str().unwrap().to_owned();
        let shown = format!("{:?}", decode(payload(&mine)).unwrap());
        assert!(!shown.contains(&key), "{shown}");
        assert!(shown.contains("alice"), "{shown}");
    }

    #[test]
    fn backup_needs_an_enrolled_home_and_restore_a_fresh_one() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::rooted_at(dir.path());
        let err = backup(&paths).unwrap_err().to_string();
        assert!(err.contains("not enrolled"), "{err}");

        enrol(&paths);
        let err = restore(&paths).unwrap_err().to_string();
        assert!(err.contains("already enrolled"), "{err}");

        let err = backup(&paths).unwrap_err().to_string();
        assert!(err.contains("pair a phone first"), "{err}");
    }

    /// What enrolling leaves on disk: the server in the config and an attestation.
    fn enrol(paths: &Paths) {
        use ac_net::attest;

        let me = super::super::identity(paths).unwrap();
        let attestation = attest::Attestation::issue(
            &Keypair::generate_ed25519(),
            &me.peer_id(),
            "alice",
            attest::now(),
            std::time::Duration::from_secs(3600),
        )
        .unwrap();
        attest::save(&paths.attestation_file(), &attestation).unwrap();
        let config = Config {
            server: Some(SERVER.parse().unwrap()),
            ..Config::default()
        };
        config.save(&paths.config_file()).unwrap();
    }

    fn add(paths: &Paths, name: &str, source: &str, config: Fields) {
        super::super::import::ledger(paths)
            .unwrap()
            .add_source(&SourceRow {
                dir: name.to_lowercase(),
                name: name.to_owned(),
                source: source.to_owned(),
                config,
                added_at: 0,
                scanned_at: 0,
                last_error: None,
                reachable: true,
            })
            .unwrap();
    }

    /// A source of a kind that takes a backup, signed in unless `paired` is false. Every field
    /// holds `name`, so a fake sender can tell the rows apart.
    fn taker(paths: &Paths, name: &str, paired: bool) {
        let entry = ac_import::registry::known()
            .iter()
            .find(|entry| entry.takes_backup())
            .expect("this build has a source that takes a backup");
        let mut config = Fields::new();
        for field in entry.config {
            config.push(field.key, if paired { name } else { "" });
        }
        add(paths, name, entry.name, config);
    }

    /// Each source a backup was handed to, by name, with the payload.
    type Handouts = std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>;

    const AWAY: &str = "could not reach this phone: timed out";
    const PAIR_AGAIN: &str = "this phone is no longer accepting this computer; pair it again";

    /// Records every source a backup was handed to, and answers for each with the failure
    /// `answers` gives it, or as stored.
    fn sending(
        answers: &'static [(&'static str, &'static str)],
    ) -> (
        Handouts,
        impl Fn(&Registered, &Fields, &str) -> ac_import::source::Result<()>,
    ) {
        let sent = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let record = sent.clone();
        let send = move |_: &Registered, config: &Fields, payload: &str| {
            let name = config.iter().next().map(|(_, held)| held.to_owned());
            let name = name.unwrap_or_default();
            record
                .lock()
                .unwrap()
                .push((name.clone(), payload.to_owned()));
            match answers.iter().find(|(whose, _)| *whose == name) {
                Some((_, why)) => Err(SourceError::Failed((*why).to_owned())),
                None => Ok(()),
            }
        };
        (sent, send)
    }

    #[test]
    fn nothing_is_sent_before_enrolment_or_without_a_paired_phone() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::rooted_at(dir.path());
        taker(&paths, "Pixel", true);
        let (sent, send) = sending(&[]);

        let err = backup_with(&paths, &send).unwrap_err().to_string();
        assert!(err.contains("not enrolled"), "{err}");
        assert!(sent.lock().unwrap().is_empty());

        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::rooted_at(dir.path());
        enrol(&paths);
        taker(&paths, "Unpaired", false);
        assert!(!can_back_up(&paths).unwrap());
        let err = backup_with(&paths, &send).unwrap_err().to_string();
        assert!(err.contains("pair a phone first"), "{err}");
        assert!(sent.lock().unwrap().is_empty());
    }

    #[test]
    fn a_source_without_a_backup_hook_is_never_sent_one() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::rooted_at(dir.path());
        enrol(&paths);
        let mut folder = Fields::new();
        folder.push("path", "/home/alice/Pictures");
        add(&paths, "Pictures", "folder", folder);
        let (sent, send) = sending(&[]);

        assert!(!can_back_up(&paths).unwrap());
        let err = backup_with(&paths, &send).unwrap_err().to_string();
        assert!(err.contains("pair a phone first"), "{err}");

        taker(&paths, "Pixel", true);
        assert!(can_back_up(&paths).unwrap());
        let backup = backup_with(&paths, &send).unwrap();
        assert_eq!(backup.sent().len(), 1);
        let sent = sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, "Pixel");
    }

    #[test]
    fn with_two_phones_and_one_away_the_other_takes_it_and_both_are_named() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::rooted_at(dir.path());
        enrol(&paths);
        taker(&paths, "Pixel", true);
        taker(&paths, "iPad", true);
        let (sent, send) = sending(&[("iPad", AWAY)]);

        let backup = backup_with(&paths, &send).unwrap();
        let mut outcome: Vec<_> = backup
            .sent()
            .iter()
            .map(|sent| (sent.name.as_str(), sent.result.is_ok()))
            .collect();
        outcome.sort();
        assert_eq!(outcome, vec![("Pixel", true), ("iPad", false)]);

        let said = backup.to_string();
        assert!(said.contains("Pixel: backed up"), "{said}");
        assert!(said.contains("iPad: could not reach"), "{said}");

        // Both were handed the same payload, the one `encode` makes.
        let sent = sent.lock().unwrap();
        assert_eq!(sent.len(), 2);
        let payload: Value = serde_json::from_str(&sent[0].1).unwrap();
        let me = super::super::identity(&paths).unwrap();
        assert_eq!(payload["peer"], me.peer_id().to_base58());
        assert_eq!(payload["username"], "alice");
        assert_eq!(sent[0].1, sent[1].1);
        assert!(!said.contains(payload["key"].as_str().unwrap()), "{said}");
    }

    #[test]
    fn a_backup_fails_only_when_no_phone_took_it() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::rooted_at(dir.path());
        enrol(&paths);
        taker(&paths, "Pixel", true);
        taker(&paths, "iPad", true);

        let (_, send) = sending(&[("iPad", PAIR_AGAIN)]);
        let some = backup_with(&paths, &send).unwrap().to_string();
        assert!(some.contains("Pixel: backed up"), "{some}");
        assert!(
            some.contains("iPad: this phone is no longer accepting"),
            "{some}"
        );

        let (_, send) = sending(&[("Pixel", AWAY), ("iPad", PAIR_AGAIN)]);
        let none = format!("{:#}", backup_with(&paths, &send).unwrap_err());
        assert!(none.contains("Pixel: could not reach"), "{none}");
        assert!(
            none.contains("iPad: this phone is no longer accepting"),
            "{none}"
        );
        assert!(none.contains("pair it again"), "{none}");
        assert!(!none.contains("backed up"), "{none}");
    }
}
