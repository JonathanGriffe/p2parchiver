//! Where the swarm and [`Admission`] meet.
//!
//! The fourth adapter, and the only one that lives down here rather than in `ac-node`. The
//! other three have to be up there because `ac-groups`, `ac-files` and `ac-peers` cannot name a
//! libp2p type at all; admission has no such problem, because the machine it drives is already
//! in this crate and everything it touches — the `attest` and `peer_attest` slots — belongs to
//! [`AcBehaviour`](crate::swarm::AcBehaviour) rather than to the application slot.
//!
//! It owns the same things the other adapters own:
//!
//! - **Turning [`AdmissionAction`]s into swarm calls** — sending our attestation, asking the
//!   server to renew, hanging up on a peer that failed.
//! - **Request correlation**, for both attestation protocols.
//! - **Recording an admitted peer** in the [`Roster`], which is the one output the rest of the
//!   node reads.
//!
//! Nothing is handed back. Everything worth saying about admission is a log line, so it is
//! emitted here where it happens rather than carried up to the binary to be emitted there —
//! which chose no words and formatted nothing differently.

use std::path::Path;
use std::time::Instant;

use libp2p::{PeerId, Swarm, request_response};

use crate::admission::{Admission, AdmissionAction, AdmissionEvent, Renewal, renewal_of};
use crate::authz::PeerAuthorizer;
use crate::proto::{AttestRequest, AttestResponse, PeerAttestRequest, PeerAttestResponse};
use crate::roster::Roster;
use crate::swarm::AcBehaviour;

/// The mutual attestation check, wired to a swarm.
pub struct AdmissionLink {
    admission: Admission,
}

type AcSwarm<A, X> = Swarm<AcBehaviour<A, X>>;

impl AdmissionLink {
    /// Load the cached attestation, discarding one that is no longer usable.
    ///
    /// Says nothing back: what a node with no credential needs told is a warning, and it is
    /// logged where it is discovered.
    pub fn load(path: &Path, me: PeerId, server: Option<PeerId>, at: i64) -> Self {
        Self {
            admission: Admission::load(path, me, server, at),
        }
    }

    /// A connection was established: put our attestation on the wire.
    pub fn connected<A: PeerAuthorizer, X: libp2p::swarm::NetworkBehaviour>(
        &mut self,
        swarm: &mut AcSwarm<A, X>,
        roster: &mut Roster,
        peer: PeerId,
    ) {
        let actions = self.admission.on(AdmissionEvent::Connected {
            peer,
            now: Instant::now(),
        });
        self.dispatch(swarm, roster, actions)
    }

    /// A connection closed.
    ///
    /// `still_connected` is the swarm's answer: a peer holds a relayed *and* a direct
    /// connection while an upgrade settles, so one closing is not the peer leaving.
    pub fn disconnected<A: PeerAuthorizer, X: libp2p::swarm::NetworkBehaviour>(
        &mut self,
        swarm: &mut AcSwarm<A, X>,
        roster: &mut Roster,
        peer: PeerId,
        still_connected: bool,
    ) {
        let actions = self.admission.on(AdmissionEvent::Disconnected {
            peer,
            still_connected,
        });
        self.dispatch(swarm, roster, actions)
    }

    /// Renew when due, re-send to anyone still waiting, and close whatever has timed out.
    ///
    /// `server_connected` is read from the swarm here rather than passed in: there is no
    /// asking the server for a fresh attestation over a connection that does not exist, and
    /// the swarm is the only thing that knows.
    pub fn housekeeping<A: PeerAuthorizer, X: libp2p::swarm::NetworkBehaviour>(
        &mut self,
        swarm: &mut AcSwarm<A, X>,
        roster: &mut Roster,
        at: i64,
    ) {
        let server_connected = self
            .admission
            .server()
            .is_some_and(|server| swarm.is_connected(&server));

        let actions = self.admission.on(AdmissionEvent::Tick {
            now: Instant::now(),
            at,
            server_connected,
        });
        self.dispatch(swarm, roster, actions)
    }

    /// A peer's half of the exchange: their attestation to us, or their verdict on ours.
    pub fn on_peer_attest<A: PeerAuthorizer, X: libp2p::swarm::NetworkBehaviour>(
        &mut self,
        swarm: &mut AcSwarm<A, X>,
        roster: &mut Roster,
        at: i64,
        event: request_response::Event<PeerAttestRequest, PeerAttestResponse>,
    ) {
        let actions = match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    // Answered here, in the same turn, while the channel is still on the stack.
                    // `on_request` is total — always exactly one response — so the channel is
                    // always consumed and can never be stranded.
                    let (response, actions) =
                        self.admission
                            .on_request(peer, &request.attestation, Instant::now(), at);
                    if let Some(behaviour) = swarm.behaviour_mut().peer_attest.as_mut() {
                        // Best effort. A rejected peer is disconnected by the action below,
                        // which can truncate this — the closed connection is the message that
                        // matters, and the reason string is a courtesy to whoever reads both
                        // sides' logs.
                        let _ = behaviour.send_response(channel, response);
                    }
                    actions
                }

                request_response::Message::Response { response, .. } => match response {
                    PeerAttestResponse::Accepted => {
                        self.admission.on(AdmissionEvent::Accepted { peer })
                    }
                    PeerAttestResponse::Rejected(why) => {
                        self.admission.on(AdmissionEvent::Rejected { peer, why })
                    }
                },
            },

            request_response::Event::OutboundFailure { peer, error, .. } => {
                self.admission.on(AdmissionEvent::ExchangeFailed {
                    peer,
                    error: error.to_string(),
                })
            }

            // Their request to us failed mid-flight. Not fatal on its own — their side will
            // retry or time out — so this only stops *us* from having verified them, which the
            // deadline already covers.
            request_response::Event::InboundFailure { peer, error, .. } => {
                tracing::debug!(%peer, %error, "inbound attestation failed");
                Vec::new()
            }

            request_response::Event::ResponseSent { .. } => Vec::new(),
        };

        self.dispatch(swarm, roster, actions)
    }

    /// The server's answer to a renewal we asked for.
    pub fn on_renewal<A: PeerAuthorizer, X: libp2p::swarm::NetworkBehaviour>(
        &mut self,
        swarm: &mut AcSwarm<A, X>,
        roster: &mut Roster,
        event: request_response::Event<AttestRequest, AttestResponse>,
    ) {
        let actions = match event {
            request_response::Event::Message {
                message: request_response::Message::Response { response, .. },
                ..
            } => self
                .admission
                .on(AdmissionEvent::Renewed(renewal_of(response))),

            request_response::Event::OutboundFailure { error, .. } => {
                self.admission.on(AdmissionEvent::Renewed(Renewal::Failed {
                    error: error.to_string(),
                }))
            }

            other => {
                tracing::trace!(?other, "attest event");
                Vec::new()
            }
        };

        self.dispatch(swarm, roster, actions)
    }

    /// Carry out what [`Admission`] asked for.
    fn dispatch<A: PeerAuthorizer, X: libp2p::swarm::NetworkBehaviour>(
        &mut self,
        swarm: &mut AcSwarm<A, X>,
        roster: &mut Roster,
        actions: Vec<AdmissionAction>,
    ) {
        for action in actions {
            match action {
                AdmissionAction::Send { peer, attestation } => {
                    match swarm.behaviour_mut().peer_attest.as_mut() {
                        Some(behaviour) => {
                            behaviour.send_request(
                                &peer,
                                PeerAttestRequest {
                                    attestation: *attestation,
                                },
                            );
                        }
                        // Only a server builds without this protocol, and a server never runs
                        // this loop. Silence here would look exactly like a peer that never
                        // answers, so it is worth a line rather than a shrug.
                        None => tracing::error!(
                            %peer,
                            "asked to attest without the peer-attest protocol mounted"
                        ),
                    }
                }

                AdmissionAction::Renew { server } => match swarm.behaviour_mut().attest.as_mut() {
                    Some(behaviour) => {
                        behaviour.send_request(&server, AttestRequest);
                    }
                    None => tracing::error!(
                        %server,
                        "asked to renew without the attest protocol mounted"
                    ),
                },

                AdmissionAction::Close { peer, why } => {
                    let _ = swarm.disconnect_peer_id(peer);
                    tracing::info!(%peer, %why, "refused");
                }

                // Admitted is not yet usable by the app layer. The roster holds them back until
                // the connection has stopped changing shape — see [`Roster::promote`].
                AdmissionAction::Admitted { peer, username } => {
                    roster.admitted(peer);
                    tracing::info!(%peer, %username, "verified");
                }
            }
        }
    }
}
