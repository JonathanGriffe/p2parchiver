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
                    let (response, actions) =
                        self.admission
                            .on_request(peer, &request.attestation, Instant::now(), at);
                    if let Some(behaviour) = swarm.behaviour_mut().peer_attest.as_mut() {
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

                AdmissionAction::Admitted { peer, username } => {
                    roster.admitted(peer);
                    tracing::info!(%peer, %username, "verified");
                }
            }
        }
    }
}
