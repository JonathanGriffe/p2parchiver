//! Admission: who may stay on a connection, as a state machine.
//!
//! Consumes [`AdmissionEvent`]s and returns [`AdmissionAction`]s. It never sees a `Swarm`, so
//! the whole of the policy here — verification, deadlines, who gets closed, when to renew — is
//! exercisable with no socket and no tokio. That is the point: this code decides who is let in,
//! and it previously could not be tested at all without standing up two real nodes.
//!
//! `ac-node`'s daemon translates in both directions and is the only thing that touches both
//! worlds, exactly as it does for `ac_groups::sync`.
//!
//! # Why both directions
//!
//! Verifying only the peer that dialled would leave the dialer talking to anyone. Both sides
//! send their own attestation and answer the other's, and a peer counts as admitted only when
//! *both* halves have passed. The two halves are tracked separately because they are two
//! independent request-response exchanges that can land in either order.
//!
//! # Why the server is exempt
//!
//! The server does not speak `/ac/peer-attest/1.0.0` — it has no attestation of its own to
//! present, and needs none, since a client pinned its peer id at enrolment and the connection
//! handshake already proved it. Demanding one would close the very connection renewal depends
//! on, and with it the relay reservation and the registry.
//!
//! # The clock is an input
//!
//! Nothing here calls `now()`. `Instant` deadlines and the unix `at` used for verification both
//! arrive on [`AdmissionEvent::Tick`], so a test can drive an expiry without sleeping.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use libp2p::PeerId;

use crate::attest::{self, Attestation};
use crate::proto::{AttestResponse, PeerAttestResponse};

/// How long a peer has to complete the exchange before it is closed.
///
/// Swept on the housekeeping tick, so the real deadline is this plus up to one tick. Sized for
/// a relayed round trip on a slow link, not for a hole punch — nothing here waits on DCUtR,
/// because the exchange runs over whatever connection already exists.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Something worth telling the operator about, for the caller to word.
///
/// A typed enum rather than a formatted string, so tests can assert on it and the binary keeps
/// ownership of the wording — the same split `ac_groups::sync::Notice` uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    /// A fresh attestation was issued and stored.
    Attested { username: String, hours: i64 },
    /// The server declined to issue one.
    RenewalRefused { reason: String },
    /// The server issued one this node cannot use. Its fault, not ours.
    IssuedUnusable { error: String },
    /// The attestation could not be cached. Not fatal: it works for this run.
    NotCached { path: PathBuf, error: String },
    /// This node has never enrolled, so it can neither prove nor verify anything.
    NotEnrolled,
}

/// What the machine wants done. The daemon is the only thing that can do any of it.
#[derive(Debug, Clone, PartialEq)]
pub enum AdmissionAction {
    /// Put our attestation on the wire to this peer.
    Send {
        peer: PeerId,
        attestation: Box<Attestation>,
    },
    /// Ask the server for a fresh attestation.
    Renew { server: PeerId },
    /// Close this peer. It failed the check, or ran out of time.
    Close { peer: PeerId, why: String },
    /// Both halves passed. Emitted exactly once per handshake — this is the signal the app
    /// layer waits on.
    Admitted { peer: PeerId, username: String },
    /// Something to report.
    Note(Notice),
}

/// What happened to a renewal we asked for.
#[derive(Debug, Clone)]
pub enum Renewal {
    Issued(Box<Attestation>),
    Refused { reason: String },
    Failed { error: String },
}

/// Everything the machine reacts to.
#[derive(Debug, Clone)]
pub enum AdmissionEvent {
    /// A connection to this peer was established. `now` starts its deadline.
    Connected { peer: PeerId, now: Instant },
    /// A connection closed. `still_connected` is whether the swarm holds another to this peer.
    Disconnected { peer: PeerId, still_connected: bool },
    /// They accepted the attestation we sent.
    Accepted { peer: PeerId },
    /// They rejected it.
    Rejected { peer: PeerId, why: String },
    /// Our request to them produced no usable answer.
    ExchangeFailed { peer: PeerId, error: String },
    /// The server answered — or failed to answer — a renewal.
    Renewed(Renewal),
    /// The only clock. `now` sweeps deadlines, `at` is unix seconds for verification, and
    /// `server_connected` is asked here rather than of a swarm so this stays testable.
    Tick {
        now: Instant,
        at: i64,
        server_connected: bool,
    },
}

/// One peer's progress through the exchange.
#[derive(Debug)]
struct Handshake {
    /// Whether our attestation has been put on the wire since the last connection opened.
    /// False when the peer connected before this node had one.
    sent: bool,
    /// Their username, set once *their* attestation verified. `Some` is "they passed".
    username: Option<String>,
    /// Whether they accepted ours.
    we_passed: bool,
    /// Whether completion has already been reported.
    ///
    /// [`Handshake::complete`] stays true for the life of the entry, so it cannot on its own
    /// tell "just completed" from "completed a while ago". Nothing stops a peer sending a
    /// second attestation on the same connection, and each one re-runs the verification path
    /// — so without this latch the announcement would repeat as often as the *peer* chose.
    announced: bool,
    /// When to give up and close.
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
    /// Where our attestation is cached between runs.
    path: PathBuf,
    /// This node, for verifying that a renewal really is about us.
    me: PeerId,
    /// The only signer whose attestations mean anything here.
    ///
    /// `None` on a node that has never enrolled. Nothing can be checked without it — not a
    /// peer's attestation and not our own — so every peer connection is closed on sight. That
    /// is the honest reading of "verify before talking": a node that cannot verify does not get
    /// to talk.
    server: Option<PeerId>,
    /// `None` until the server issues one. A node in that state is admitted by nobody.
    mine: Option<Attestation>,
    /// Set while a renewal is in flight, so the tick does not queue a second one.
    renewing: bool,
    /// Per-peer exchange state. An absent entry means the exchange has not started.
    peers: HashMap<PeerId, Handshake>,
}

impl Admission {
    /// Load the cached attestation, discarding one that is no longer usable.
    ///
    /// Verified against this node's own peer id and its server, not merely decoded: a file
    /// copied from another node, or left over from a different server, has to be thrown away
    /// rather than presented and rejected by every peer in turn.
    pub fn load(path: &Path, me: PeerId, server: Option<PeerId>, at: i64) -> (Self, Vec<Notice>) {
        let path = path.to_path_buf();
        let mut notes = Vec::new();

        let Some(server) = server else {
            notes.push(Notice::NotEnrolled);
            return (
                Self {
                    path,
                    me,
                    server: None,
                    mine: None,
                    renewing: false,
                    peers: HashMap::new(),
                },
                notes,
            );
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

        (
            Self {
                path,
                me,
                server: Some(server),
                mine,
                renewing: false,
                peers: HashMap::new(),
            },
            notes,
        )
    }

    /// The server this node trusts, if it has enrolled.
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
    /// never be stranded — the same arrangement as `ac_groups::sync::GroupSync::on_request`.
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
    ///
    /// # Why this always restarts the exchange
    ///
    /// An earlier version skipped a peer whose handshake was already complete, reasoning that a
    /// peer legitimately holds a relayed *and* a direct connection while an upgrade settles and
    /// the second proves nothing new. That is true of an upgrade and wrong of a **restart**: a
    /// peer that dies without closing cleanly leaves a connection the swarm still believes in
    /// for as long as the transport's idle timeout, and when the restarted node dials back, its
    /// brand-new connection was matched against the corpse of the old one. We skipped, never
    /// sent our half, and the peer closed us for timing out — the exchange could not complete
    /// until the dead connection was reaped. It cost a real reconnection every time.
    ///
    /// Nothing can distinguish the two cases from the peer id alone, because in both there is
    /// an existing connection the swarm considers live. So the exchange is simply re-run. The
    /// cost is one extra ~2 KiB message in the upgrade case; `announced` keeps the *result*
    /// from being reported twice, which is the part that ever mattered.
    fn connected(&mut self, peer: PeerId, now: Instant) -> Vec<AdmissionAction> {
        let Some(server) = self.server else {
            // Nothing to check against, and nothing to offer. Closed immediately rather than
            // left to time out, so the peer gets a reason instead of a dead socket.
            return self.close(peer, "this node has not enrolled with a server".to_owned());
        };
        if peer == server {
            return Vec::new();
        }

        // The entry is what `send_ours` writes through, so it has to exist first. Clearing
        // `sent` on an entry that survived is what re-runs the exchange; see above.
        self.peers
            .entry(peer)
            .and_modify(|handshake| handshake.sent = false)
            .or_insert_with(|| Handshake::new(now));
        self.send_ours(peer)
    }

    /// Put our attestation on the wire, if we have one and have not already sent it.
    ///
    /// Yields nothing when this node has no attestation yet. That is not a failure path: the
    /// peer's deadline is already running, so the exchange either completes when a renewal
    /// lands or the connection is closed for not completing.
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
    ///
    /// # Why this retries instead of closing
    ///
    /// It is tempting to read a failed request as "this peer cannot be admitted, and waiting
    /// for the deadline would only delay it". That is wrong whenever more than one connection
    /// to the peer exists, which is routine: a relayed and a direct one while an upgrade
    /// settles, or — the case that bit — a dead connection the transport has not yet reaped
    /// sitting alongside the fresh one a restarted peer just dialled.
    ///
    /// `send_request` addresses a *peer*, not a connection, and libp2p picks. Pick the corpse
    /// and the request dies with `connection lost` through no fault of the peer. Closing on
    /// that then tore down the healthy connection too, because disconnecting is per-peer as
    /// well — so a restart could not recover until the stale connection timed out, and the
    /// peer saw itself refused for something it never did.
    ///
    /// So a failure only clears `sent`, and the next tick tries again. Nothing is weakened:
    /// the deadline still closes a peer that genuinely never completes, which is the check
    /// that was doing the real work all along.
    fn exchange_failed(&mut self, peer: PeerId, error: &str) -> Vec<AdmissionAction> {
        let Some(handshake) = self.peers.get_mut(&peer) else {
            return Vec::new();
        };
        handshake.sent = false;
        tracing::debug!(%peer, error, "attestation exchange failed; will retry until the deadline");
        Vec::new()
    }

    /// Announce a peer once both halves have passed.
    ///
    /// Called from both completion paths, and latches on `announced` so it fires exactly once
    /// per handshake. Completion alone is not enough to decide that: it stays true afterwards,
    /// and a peer may send a second attestation on the same connection, which re-runs the
    /// verification path and calls back in here. Guarding on `complete()` alone let a peer
    /// choose how often it was announced.
    ///
    /// The latch lives on the handshake rather than on the peer, so a genuine reconnection —
    /// where the entry has been dropped — is announced again.
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
        // The server is never subject to this. Closing it would take down renewal, the relay
        // reservation and the registry in one go — and it has already proven itself by holding
        // the key for the peer id pinned at enrolment.
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
            // Unreachable: a request is only ever sent to a known server.
            return Vec::new();
        };

        match renewal {
            Renewal::Issued(attestation) => {
                // Checked before it is stored or presented, so a server that hands out
                // something unusable is caught here rather than as an unexplained refusal from
                // every peer.
                //
                // `at` is the attestation's own issue time rather than a tick's: verifying a
                // just-issued credential against a stale tick would reject it for being from
                // the future on a node whose clock runs slow.
                let at = attest::now();
                match attestation.verify(&self.me, &server, at) {
                    Ok(statement) => {
                        let mut actions = Vec::new();
                        if let Err(e) = attest::save(&self.path, &attestation) {
                            // Not fatal: the attestation works for this run, and the next start
                            // simply renews again.
                            actions.push(AdmissionAction::Note(Notice::NotCached {
                                path: self.path.clone(),
                                error: e.to_string(),
                            }));
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

                        actions.push(AdmissionAction::Note(Notice::Attested { username, hours }));
                        actions
                    }
                    Err(e) => vec![AdmissionAction::Note(Notice::IssuedUnusable {
                        error: e.to_string(),
                    })],
                }
            }

            Renewal::Refused { reason } => {
                vec![AdmissionAction::Note(Notice::RenewalRefused { reason })]
            }

            // The server link has its own reconnect schedule, and this rides on whatever it
            // recovers; `renewing` is already cleared, so the next tick tries again.
            Renewal::Failed { error } => {
                tracing::warn!(%error, "could not renew the attestation");
                Vec::new()
            }
        }
    }
}

/// Turn the server's reply into a [`Renewal`].
///
/// Here rather than in the daemon so that the mapping from wire type to event lives beside the
/// machine that consumes it.
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

    /// An [`Admission`] holding no attestation. Enough for anything that does not put one on
    /// the wire.
    fn admission() -> Admission {
        Admission {
            path: PathBuf::from("attestation.cbor"),
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
            path: PathBuf::from("attestation.cbor"),
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
        // The latch belongs to the handshake, not to the peer. Disconnecting drops the entry,
        // so the next connection is a fresh exchange and genuinely worth reporting — a
        // per-peer latch would silence it forever.
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
        // Regression. A peer that dies without closing cleanly leaves a connection the swarm
        // still believes in until the transport's idle timeout. When it restarts and dials
        // back, the new connection arrives while the corpse of the old one is still counted,
        // so a guard that skipped peers whose handshake was already complete never sent our
        // half — and the peer closed us for timing out. Nothing distinguishes that from a
        // relayed-plus-direct upgrade by peer id alone, so the exchange is simply re-run.
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
        // Closing it would take down renewal, the relay reservation and the registry in one
        // go — and it proved itself by holding the key for the peer id pinned at enrolment.
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
        // Regression. `send_request` addresses a peer, not a connection; with a dead
        // connection still counted alongside a fresh one, libp2p can route our attestation
        // into the corpse and report `connection lost`. Closing on that killed the healthy
        // connection too — a restarted peer could never recover, and saw itself refused for
        // something it had not done.
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
}
