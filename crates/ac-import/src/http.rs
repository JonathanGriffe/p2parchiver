//! How long a call may hang before it is given up on.
//!
//! ureq sets no timeouts of its own — every field of its `Timeouts` is `None` bar the wait
//! for a 100-continue — so a host that accepts the connection and then says nothing holds the
//! caller for ever. That caller is a blocking thread, and a blocking thread cannot be
//! cancelled: the node would not shut down either, which is how one silent phone becomes a
//! daemon that will not stop.

use std::time::Duration;

use ureq::config::{Config, ConfigBuilder};
use ureq::typestate::AgentScope;

/// Naming the host.
const RESOLVE: Duration = Duration::from_secs(10);
/// Getting a connection to it.
const CONNECT: Duration = Duration::from_secs(10);
/// Sending the request, its body aside.
const SEND: Duration = Duration::from_secs(30);
/// Waiting for the answer's headers. The one that matters: a host which took the connection
/// and then went quiet is the failure that hangs, and this is what ends it.
const HEADERS: Duration = Duration::from_secs(30);

/// Reading a whole answer that is known to be small.
///
/// Deliberately not among the bounds below. It is a total rather than an idle timeout, so the
/// same number that is generous for a page of JSON would cut off a video that was arriving
/// perfectly well. Asked for by the calls that read JSON, and by no others.
pub const SMALL_BODY: Duration = Duration::from_secs(30);

/// Bound every stage up to the first byte of the answer's body.
pub fn bounded(config: ConfigBuilder<AgentScope>) -> ConfigBuilder<AgentScope> {
    config
        .timeout_resolve(Some(RESOLVE))
        .timeout_connect(Some(CONNECT))
        .timeout_send_request(Some(SEND))
        .timeout_recv_response(Some(HEADERS))
}

/// An agent with those bounds and nothing else said about it.
///
/// One per caller that keeps it, rather than the fresh agent a bare `ureq::get` builds: a
/// scan of a Drive is hundreds of calls to one host, and an agent is what holds the
/// connection open between them.
pub fn agent() -> ureq::Agent {
    ureq::Agent::new_with_config(bounded(Config::builder()).build())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point: what ureq leaves unset is set, and the one that is left unset is left
    /// unset on purpose.
    #[test]
    fn a_bounded_agent_will_not_wait_for_ever() {
        let timeouts = bounded(Config::builder()).build().timeouts();

        assert_eq!(timeouts.connect, Some(CONNECT));
        assert_eq!(timeouts.recv_response, Some(HEADERS));
        assert_eq!(timeouts.resolve, Some(RESOLVE));
        assert_eq!(timeouts.send_request, Some(SEND));

        assert_eq!(
            timeouts.recv_body, None,
            "a body has no total: a video is as long as it is"
        );
    }
}
