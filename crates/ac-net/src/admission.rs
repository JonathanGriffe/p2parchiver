use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use libp2p::PeerId;

use crate::attest::{self, Attestation};
use crate::proto::{AttestResponse, PeerAttestResponse};

/// How long a peer has to complete the exchange before it is closed.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, PartialEq)]
pub enum AdmissionAction {
    Send {
        peer: PeerId,
        attestation: Box<Attestation>,
    },
    Renew {
        server: PeerId,
    },
    Close {
        peer: PeerId,
        why: String,
    },
    /// Both halves passed. Emitted exactly once per handshake, this is the signal the app
    /// layer waits on.
    Admitted {
        peer: PeerId,
        username: String,
    },
}

/// What happened to a renewal we asked for.
#[derive(Debug, Clone)]
pub enum Renewal {
    Issued(Box<Attestation>),
    Refused { reason: String },
    Failed { error: String },
}

#[derive(Debug, Clone)]
pub enum AdmissionEvent {
    Connected {
        peer: PeerId,
        now: Instant,
    },
    /// A connection closed. `still_connected` is whether the swarm holds another connection to this peer.
    Disconnected {
        peer: PeerId,
        still_connected: bool,
    },
    Accepted {
        peer: PeerId,
    },
    Rejected {
        peer: PeerId,
        why: String,
    },
    ExchangeFailed {
        peer: PeerId,
        error: String,
    },
    Renewed(Renewal),
    Tick {
        now: Instant,
        at: i64,
        server_connected: bool,
    },
}

/// One peer's progress through the exchange.
#[derive(Debug)]
struct Handshake {
    sent: bool,
    username: Option<String>,
    we_passed: bool,
    /// Whether completion has already been reported.
    /// [`Handshake::complete`] stays true for the life of the entry, so it cannot on its own
    /// tell "just completed" from "completed a while ago"
    announced: bool,
    deadline: Instant,
}

impl Handshake {
    fn new(now: Instant) -> Self {
        Self {
            sent: false,
            username: None,
            we_passed: false,
            announced: false,
            deadline: now + HANDSHAKE_TIMEOUT,
        }
    }

    fn complete(&self) -> bool {
        self.username.is_some() && self.we_passed
    }
}

/// The mutual attestation check, and the credential it is built on.
pub struct Admission {
    path: PathBuf,
    me: PeerId,
    server: Option<PeerId>,
    mine: Option<Attestation>,
    renewing: bool,
    peers: HashMap<PeerId, Handshake>,
}

impl Admission {
    /// Load the cached attestation, discarding one that is no longer usable.
    pub fn load(path: &Path, me: PeerId, server: Option<PeerId>, at: i64) -> Self {
        let path = path.to_path_buf();

        let Some(server) = server else {
            tracing::warn!(
                "this node has not enrolled, so it can verify nobody and can prove nothing \
                 about itself. Every peer connection will be closed. Run `ac join` first."
            );
            return Self {
                path,
                me,
                server: None,
                mine: None,
                renewing: false,
                peers: HashMap::new(),
            };
        };

        let mine = attest::load(&path)
            .unwrap_or_else(|e| {
                tracing::warn!(path = %path.display(), error = %e, "could not read the attestation");
                None
            })
            .filter(|a| match a.verify(&me, &server, at) {
                Ok(statement) => {
                    tracing::info!(
                        username = %statement.username,
                        expires_in_h = (statement.expires_at - at).max(0) / 3600,
                        "loaded this node's attestation"
                    );
                    true
                }
                Err(e) => {
                    tracing::warn!(error = %e, "the stored attestation is unusable; will renew");
                    false
                }
            });

        Self {
            path,
            me,
            server: Some(server),
            mine,
            renewing: false,
            peers: HashMap::new(),
        }
    }

    pub fn server(&self) -> Option<PeerId> {
        self.server
    }

    /// Drive the machine.
    pub fn on(&mut self, event: AdmissionEvent) -> Vec<AdmissionAction> {
        match event {
            AdmissionEvent::Connected { peer, now } => self.connected(peer, now),

            AdmissionEvent::Disconnected {
                peer,
                still_connected,
            } => {
                if !still_connected {
                    self.peers.remove(&peer);
                }
                Vec::new()
            }

            AdmissionEvent::Accepted { peer } => {
                if let Some(handshake) = self.peers.get_mut(&peer) {
                    handshake.we_passed = true;
                }
                self.settle(peer).into_iter().collect()
            }

            AdmissionEvent::Rejected { peer, why } => {
                self.close(peer, format!("they rejected ours: {why}"))
            }

            AdmissionEvent::ExchangeFailed { peer, error } => self.exchange_failed(peer, &error),

            AdmissionEvent::Renewed(renewal) => self.renewed(renewal),

            AdmissionEvent::Tick {
                now,
                at,
                server_connected,
            } => self.tick(now, at, server_connected),
        }
    }

    /// Verify what a peer sent, and say what to answer.
    ///
    /// Total and infallible: exactly one response, always. The daemon holds the
    /// `ResponseChannel` across this call, so no action needs to carry it and a channel can
    /// never be stranded, the same arrangement as `ac_groups::sync::GroupSync::on_request`.
    pub fn on_request(
        &mut self,
        peer: PeerId,
        attestation: &Attestation,
        now: Instant,
        at: i64,
    ) -> (PeerAttestResponse, Vec<AdmissionAction>) {
        let verdict = match self.server {
            Some(server) => attestation
                .verify(&peer, &server, at)
                .map(|statement| statement.username)
                .map_err(|e| e.to_string()),
            // Answered rather than ignored: the peer learns why in one round trip instead of
            // waiting out its own deadline on a connection that will never work.
            None => Err("this node has not enrolled, so it cannot verify anyone".to_owned()),
        };

        match verdict {
            Ok(username) => {
                self.peers
                    .entry(peer)
                    .or_insert_with(|| Handshake::new(now))
                    .username = Some(username);

                // They may have reached us before we had a credential, or before we saw the
                // connection at all; either way this is the moment to send ours.
                let mut actions = self.send_ours(peer);
                actions.extend(self.settle(peer));
                (PeerAttestResponse::Accepted, actions)
            }
            Err(why) => (
                PeerAttestResponse::Rejected(why.clone()),
                self.close(peer, why),
            ),
        }
    }

    /// A peer connected: begin the exchange, unless it is the server.
    fn connected(&mut self, peer: PeerId, now: Instant) -> Vec<AdmissionAction> {
        let Some(server) = self.server else {
            return self.close(peer, "this node has not enrolled with a server".to_owned());
        };
        if peer == server {
            return Vec::new();
        }

        self.peers
            .entry(peer)
            .and_modify(|handshake| {
                handshake.sent = false;
                handshake.deadline = now + HANDSHAKE_TIMEOUT;
            })
            .or_insert_with(|| Handshake::new(now));
        self.send_ours(peer)
    }

    /// Put our attestation on the wire, if we have one and have not already sent it.
    fn send_ours(&mut self, peer: PeerId) -> Vec<AdmissionAction> {
        let Some(mine) = self.mine.clone() else {
            return Vec::new();
        };
        let Some(handshake) = self.peers.get_mut(&peer) else {
            return Vec::new();
        };
        if handshake.sent {
            return Vec::new();
        }
        handshake.sent = true;

        vec![AdmissionAction::Send {
            peer,
            attestation: Box::new(mine),
        }]
    }

    /// Our request to a peer produced no usable answer.
    fn exchange_failed(&mut self, peer: PeerId, error: &str) -> Vec<AdmissionAction> {
        let Some(handshake) = self.peers.get_mut(&peer) else {
            return Vec::new();
        };
        handshake.sent = false;
        tracing::debug!(%peer, error, "attestation exchange failed; will retry until the deadline");
        Vec::new()
    }

    /// Announce a peer once both halves have passed.
    fn settle(&mut self, peer: PeerId) -> Option<AdmissionAction> {
        let handshake = self.peers.get_mut(&peer)?;
        if !handshake.complete() || handshake.announced {
            return None;
        }
        handshake.announced = true;

        let username = handshake.username.clone()?;
        tracing::info!(%peer, %username, "attestation exchange complete");
        Some(AdmissionAction::Admitted { peer, username })
    }

    /// Close a peer that failed the check.
    fn close(&mut self, peer: PeerId, why: String) -> Vec<AdmissionAction> {
        if Some(peer) == self.server {
            return Vec::new();
        }
        self.peers.remove(&peer);
        tracing::warn!(%peer, why, "closing the connection: attestation refused");
        vec![AdmissionAction::Close { peer, why }]
    }

    /// Renew when due, send to anyone still waiting, and close whatever has timed out.
    fn tick(&mut self, now: Instant, at: i64, server_connected: bool) -> Vec<AdmissionAction> {
        let mut actions = Vec::new();

        let due = self.mine.as_ref().is_none_or(|a| a.needs_renewal(at));
        if let Some(server) = self.server
            && due
            && !self.renewing
            && server_connected
        {
            self.renewing = true;
            tracing::info!(%server, "asking for a fresh attestation");
            actions.push(AdmissionAction::Renew { server });
        }

        // Peers that connected before this node had a credential.
        let waiting: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(_, h)| !h.sent)
            .map(|(peer, _)| *peer)
            .collect();
        for peer in waiting {
            actions.extend(self.send_ours(peer));
        }

        let expired: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(_, h)| !h.complete() && now >= h.deadline)
            .map(|(peer, _)| *peer)
            .collect();
        for peer in expired {
            actions.extend(self.close(
                peer,
                "the attestation exchange did not complete in time".to_owned(),
            ));
        }

        actions
    }

    /// Handle the server's answer to a renewal request.
    fn renewed(&mut self, renewal: Renewal) -> Vec<AdmissionAction> {
        self.renewing = false;

        let Some(server) = self.server else {
            return Vec::new();
        };

        match renewal {
            Renewal::Issued(attestation) => {
                let at = attest::now();
                match attestation.verify(&self.me, &server, at) {
                    Ok(statement) => {
                        let mut actions = Vec::new();
                        if let Err(e) = attest::save(&self.path, &attestation) {
                            // Not fatal: the attestation works for this run, and the next start
                            // simply renews again.
                            tracing::warn!(
                                path = %self.path.display(),
                                error = %e,
                                "could not cache the attestation"
                            );
                        }
                        let hours = (statement.expires_at - at).max(0) / 3600;
                        let username = statement.username.clone();
                        self.mine = Some(*attestation);

                        // Anyone whose exchange stalled for want of a credential can proceed.
                        let waiting: Vec<PeerId> = self
                            .peers
                            .iter()
                            .filter(|(_, h)| !h.sent)
                            .map(|(peer, _)| *peer)
                            .collect();
                        for peer in waiting {
                            actions.extend(self.send_ours(peer));
                        }

                        tracing::info!(%username, hours, "attested");
                        actions
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            "the server issued an attestation this node cannot use"
                        );
                        Vec::new()
                    }
                }
            }

            // Logged rather than reported, like `Renewal::Failed` below: nothing a person
            // does about it differs, and the reason string is for whoever reads the log.
            Renewal::Refused { reason } => {
                tracing::warn!(reason, "attestation refused");
                Vec::new()
            }

            Renewal::Failed { error } => {
                tracing::warn!(%error, "could not renew the attestation");
                Vec::new()
            }
        }
    }
}

pub fn renewal_of(response: AttestResponse) -> Renewal {
    match response {
        AttestResponse::Issued(attestation) => Renewal::Issued(Box::new(attestation)),
        AttestResponse::Refused(reason) => Renewal::Refused {
            reason: reason.explain().to_owned(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;
    use std::time::Duration;

    const AT: i64 = 1_700_000_000;

    fn peer() -> PeerId {
        Keypair::generate_ed25519().public().to_peer_id()
    }

    /// A writable path for an [`Admission`]'s attestation cache.
    fn scratch() -> PathBuf {
        static DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

        let dir = DIR.get_or_init(|| tempfile::tempdir().expect("a scratch directory"));
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        dir.path()
            .join(format!("{n}-{}", attest::ATTESTATION_FILENAME))
    }

    /// An [`Admission`] holding no attestation. Enough for anything that does not put one on
    /// the wire.
    fn admission() -> Admission {
        Admission {
            path: scratch(),
            me: peer(),
            server: Some(peer()),
            mine: None,
            renewing: false,
            peers: HashMap::new(),
        }
    }

    /// An [`Admission`] holding a usable attestation, and the server that signed it.
    fn enrolled() -> (Admission, Keypair) {
        let server_key = Keypair::generate_ed25519();
        let me = peer();
        let mine = Attestation::issue(&server_key, &me, "us", AT, Duration::from_secs(86_400))
            .expect("issue");
        let admission = Admission {
            path: scratch(),
            me,
            server: Some(server_key.public().to_peer_id()),
            mine: Some(mine),
            renewing: false,
            peers: HashMap::new(),
        };
        (admission, server_key)
    }

    /// Both halves passed, ready to be announced.
    fn complete_handshake(now: Instant) -> Handshake {
        Handshake {
            username: Some("alice".to_owned()),
            we_passed: true,
            ..Handshake::new(now)
        }
    }

    fn admitted(actions: &[AdmissionAction]) -> Option<PeerId> {
        actions.iter().find_map(|a| match a {
            AdmissionAction::Admitted { peer, .. } => Some(*peer),
            _ => None,
        })
    }

    fn sent_to(actions: &[AdmissionAction]) -> Option<PeerId> {
        actions.iter().find_map(|a| match a {
            AdmissionAction::Send { peer, .. } => Some(*peer),
            _ => None,
        })
    }

    #[test]
    fn a_peer_is_announced_once_however_often_it_attests() {
        // Nothing stops a peer sending a second attestation on the same connection, and each
        // one re-runs the verification path. `complete()` stays true afterwards, so guarding
        // on it alone let the *peer* choose how often it was announced.
        let mut a = admission();
        let p = peer();
        a.peers.insert(p, complete_handshake(Instant::now()));

        assert_eq!(
            a.settle(p),
            Some(AdmissionAction::Admitted {
                peer: p,
                username: "alice".to_owned()
            }),
            "the completing call announces, and says who"
        );
        assert_eq!(a.settle(p), None, "a second attestation must not announce");
        assert_eq!(a.settle(p), None);
    }

    #[test]
    fn an_incomplete_handshake_is_not_announced() {
        // They verified us, we have not verified them. Announcing here would report a peer as
        // verified on one side's say-so.
        let mut a = admission();
        let p = peer();
        a.peers.insert(
            p,
            Handshake {
                we_passed: true,
                ..Handshake::new(Instant::now())
            },
        );

        assert_eq!(a.settle(p), None);
    }

    #[test]
    fn a_reconnecting_peer_is_announced_again() {
        let mut a = admission();
        let p = peer();
        a.peers.insert(p, complete_handshake(Instant::now()));
        assert!(a.settle(p).is_some());

        a.on(AdmissionEvent::Disconnected {
            peer: p,
            still_connected: false,
        });
        a.peers.insert(p, complete_handshake(Instant::now()));

        assert!(
            a.settle(p).is_some(),
            "a fresh handshake announces on its own terms"
        );
    }

    #[test]
    fn an_unknown_peer_settles_to_nothing() {
        let mut a = admission();
        assert_eq!(a.settle(peer()), None);
    }

    #[test]
    fn a_reconnecting_peer_is_sent_our_attestation_again() {
        let (mut a, _server) = enrolled();
        let p = peer();

        assert_eq!(
            sent_to(&a.on(AdmissionEvent::Connected {
                peer: p,
                now: Instant::now(),
            })),
            Some(p),
            "the first connection puts our attestation on the wire"
        );

        // Complete it, exactly as a successful exchange would.
        if let Some(handshake) = a.peers.get_mut(&p) {
            handshake.username = Some("them".to_owned());
            handshake.we_passed = true;
        }
        assert!(admitted(&a.on(AdmissionEvent::Accepted { peer: p })).is_some());

        // No disconnect: the old connection is dead but not yet reaped, so this is what a
        // restarted peer's dial looks like from here.
        assert_eq!(
            sent_to(&a.on(AdmissionEvent::Connected {
                peer: p,
                now: Instant::now(),
            })),
            Some(p),
            "a second connection must be attested too, or the peer times us out"
        );
    }

    #[test]
    fn re_running_the_exchange_does_not_announce_twice() {
        // The other half of the fix: re-sending is cheap, but reporting the peer as newly
        // verified on every connection would not be.
        let (mut a, _server) = enrolled();
        let p = peer();

        a.on(AdmissionEvent::Connected {
            peer: p,
            now: Instant::now(),
        });
        if let Some(handshake) = a.peers.get_mut(&p) {
            handshake.username = Some("them".to_owned());
            handshake.we_passed = true;
        }
        assert!(admitted(&a.on(AdmissionEvent::Accepted { peer: p })).is_some());

        let actions = a.on(AdmissionEvent::Connected {
            peer: p,
            now: Instant::now(),
        });
        assert_eq!(admitted(&actions), None, "already announced, and still is");
    }

    #[test]
    fn a_stalled_exchange_is_closed_when_its_deadline_passes() {
        let (mut a, _server) = enrolled();
        let p = peer();
        let start = Instant::now();
        a.peers.insert(p, Handshake::new(start));

        assert!(
            a.tick(start, AT, true)
                .iter()
                .all(|action| !matches!(action, AdmissionAction::Close { .. })),
            "not yet"
        );

        let actions = a.tick(start + HANDSHAKE_TIMEOUT, AT, true);
        assert!(
            actions.iter().any(|action| matches!(
                action,
                AdmissionAction::Close { peer, .. } if *peer == p
            )),
            "a peer that never completed is closed, not left open and unchecked"
        );
        assert!(!a.peers.contains_key(&p), "and forgotten");
    }

    #[test]
    fn the_server_is_never_closed() {
        let (mut a, server_key) = enrolled();
        let server = server_key.public().to_peer_id();

        assert!(
            a.close(server, "whatever the reason".to_owned()).is_empty(),
            "the server is exempt"
        );
        assert!(
            a.on(AdmissionEvent::Connected {
                peer: server,
                now: Instant::now(),
            })
            .is_empty(),
            "and is not asked to attest"
        );
    }

    #[test]
    fn a_node_that_never_enrolled_closes_every_peer() {
        // It can verify nobody and prove nothing about itself. Leaving a connection open and
        // unchecked would be the worse answer.
        let mut a = admission();
        a.server = None;
        let p = peer();

        let actions = a.on(AdmissionEvent::Connected {
            peer: p,
            now: Instant::now(),
        });
        assert!(matches!(
            actions.as_slice(),
            [AdmissionAction::Close { peer, .. }] if *peer == p
        ));
    }

    #[test]
    fn a_peer_waiting_on_our_credential_is_sent_it_when_one_arrives() {
        // They connected before this node had an attestation. The deadline is already
        // running, so a renewal landing has to unblock them rather than wait for a tick.
        let (donor, server_key) = enrolled();
        let mut a = admission();
        a.server = Some(server_key.public().to_peer_id());
        a.me = donor.me;
        let p = peer();

        assert_eq!(
            sent_to(&a.on(AdmissionEvent::Connected {
                peer: p,
                now: Instant::now(),
            })),
            None,
            "nothing to send yet"
        );

        let issued = Attestation::issue(
            &server_key,
            &a.me,
            "us",
            attest::now(),
            Duration::from_secs(86_400),
        )
        .expect("issue");
        let actions = a.on(AdmissionEvent::Renewed(Renewal::Issued(Box::new(issued))));

        assert_eq!(
            sent_to(&actions),
            Some(p),
            "the waiting peer gets it without another tick"
        );
    }

    #[test]
    fn an_outbound_failure_retries_rather_than_closing_the_peer() {
        let (mut a, _server) = enrolled();
        let p = peer();
        let start = Instant::now();

        assert_eq!(
            sent_to(&a.on(AdmissionEvent::Connected {
                peer: p,
                now: start
            })),
            Some(p)
        );

        let actions = a.on(AdmissionEvent::ExchangeFailed {
            peer: p,
            error: "IO error on outbound stream: connection lost".to_owned(),
        });
        assert!(
            !actions
                .iter()
                .any(|x| matches!(x, AdmissionAction::Close { .. })),
            "a lost stream is not a verdict on the peer"
        );
        assert!(a.peers.contains_key(&p), "and the exchange is still open");

        assert_eq!(
            sent_to(&a.tick(start, AT, true)),
            Some(p),
            "the next tick tries again, on whatever connection is live by then"
        );
    }

    #[test]
    fn a_peer_that_only_ever_fails_is_still_closed_by_the_deadline() {
        // The other half: retrying must not become a way to stay connected forever without
        // ever proving anything.
        let (mut a, _server) = enrolled();
        let p = peer();
        let start = Instant::now();

        a.on(AdmissionEvent::Connected {
            peer: p,
            now: start,
        });
        for _ in 0..3 {
            a.on(AdmissionEvent::ExchangeFailed {
                peer: p,
                error: "connection lost".to_owned(),
            });
        }

        let actions = a.tick(start + HANDSHAKE_TIMEOUT, AT, true);
        assert!(
            actions.iter().any(|x| matches!(
                x,
                AdmissionAction::Close { peer, .. } if *peer == p
            )),
            "the deadline is what closes an unproven peer, and it still does"
        );
    }

    fn closed(actions: &[AdmissionAction]) -> Option<PeerId> {
        actions.iter().find_map(|a| match a {
            AdmissionAction::Close { peer, .. } => Some(*peer),
            _ => None,
        })
    }

    #[test]
    fn a_second_connection_gets_its_own_deadline() {
        let (mut a, _server) = enrolled();
        let p = peer();
        let start = Instant::now();

        a.on(AdmissionEvent::Connected {
            peer: p,
            now: start,
        });
        a.on(AdmissionEvent::Connected {
            peer: p,
            now: start + HANDSHAKE_TIMEOUT - Duration::from_secs(1),
        });

        assert_eq!(
            closed(&a.tick(start + HANDSHAKE_TIMEOUT, AT, true)),
            None,
            "the upgrade inherited the first connection's clock"
        );
    }

    #[test]
    fn a_redial_is_not_closed_by_an_expired_deadline() {
        let (mut a, _server) = enrolled();
        let p = peer();
        let start = Instant::now();

        a.on(AdmissionEvent::Connected {
            peer: p,
            now: start,
        });

        // No `Disconnected`: the transport has not reaped the dead connection yet.
        let redial = start + HANDSHAKE_TIMEOUT + Duration::from_secs(30);
        a.on(AdmissionEvent::Connected {
            peer: p,
            now: redial,
        });

        assert_eq!(
            closed(&a.tick(redial, AT, true)),
            None,
            "a peer that just dialled has not failed anything yet"
        );
    }
}
