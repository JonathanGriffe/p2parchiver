//! The companion app's way in to this node: the listener it answers on, and the codes it scans
//! to pair and to restore a node.

pub(crate) mod listener;

use std::net::IpAddr;
use std::path::Path;
use std::sync::Mutex;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

use serde_json::Value;

use crate::http::encode;
use crate::prompt::{self, Qr};
use crate::source::{Result, SourceError};

/// How long a code is worth scanning for. Long enough to find your phone and unlock it, short
/// enough that one left on a screen is not an open door.
pub(crate) const WAIT: Duration = Duration::from_secs(3 * 60);

/// What to tell someone while a code is up. The QR is the whole instruction, so this only has
/// to say where to look.
pub const SCAN: &str = "scan this with the app on your phone";

/// Who this node is, for the codes that name it. Set on every [`serve`], since the listener
/// outlives a node restarted with a restored key.
static NODE: Mutex<String> = Mutex::new(String::new());

/// A code the companion app scans, and answers with a `POST` to its path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    /// Pair the phone as a source.
    Pair,
    /// Take an identity back from the phone.
    Restore,
}

impl Code {
    /// Its name in `ac://<host>?…`.
    fn host(self) -> &'static str {
        match self {
            Code::Pair => "pair",
            Code::Restore => "restore",
        }
    }

    /// Where the phone posts its answer.
    fn path(self) -> &'static str {
        match self {
            Code::Pair => "/v1/pair",
            Code::Restore => "/v1/restore",
        }
    }

    /// The code a `POST` to `path` answers, if any.
    fn at(path: &str) -> Option<Code> {
        [Code::Pair, Code::Restore]
            .into_iter()
            .find(|code| code.path() == path)
    }

    /// Whether the code carries this node's peer id. A restore has no identity to name yet.
    fn names_node(self) -> bool {
        self != Code::Restore
    }
}

/// Follow this node's id for the codes it shows, and start the listener if it is not up yet.
pub fn serve(state: &Path, node: &str) -> Result<()> {
    *NODE.lock().unwrap_or_else(|e| e.into_inner()) = node.to_owned();
    if listener::listening() {
        return Ok(());
    }
    let port = listener::start(state)?;
    tracing::info!(port, "listening for phones");
    Ok(())
}

/// Show `code`, and wait for the phone that answers it.
///
/// `read` turns that answer, and the address it came from, into what the caller wants, or
/// says why it cannot. It runs once, on the listener's thread, and the phone gets a `204`.
/// `Ok(None)` means somebody stopped it.
pub fn ask<T: Send + 'static>(
    code: Code,
    read: impl FnOnce(Value, IpAddr) -> std::result::Result<T, String> + Send + 'static,
) -> Result<Option<T>> {
    // An answer reaches whichever process holds the listener, which a command run beside a
    // running node does not.
    let Some(serving) = listener::serving() else {
        return Err(SourceError::Failed(
            "there is nowhere for a phone to answer. Use the app, which is where the node \
             listens; from a terminal this works only while the node is stopped."
                .to_owned(),
        ));
    };
    let token = nonce()?;
    let qr = render(&text(code, &serving, &token)?)?;

    let (send, answered) = mpsc::channel();
    listener::open(listener::Open {
        code,
        token,
        answer: Box::new(move |body, from| {
            let read = read(body, from);
            let usable = read.is_ok();
            let _ = send.send(read);
            usable
        }),
    })?;
    prompt::show(Some(qr));
    prompt::stoppable(Some(listener::close));
    tracing::info!(code = code.host(), "waiting for a phone to scan the code");

    let answer = answered.recv_timeout(WAIT);
    // Whatever happened, this code is spent.
    listener::close();
    prompt::stoppable(None);
    prompt::show(None);

    match answer {
        Ok(Ok(value)) => Ok(Some(value)),
        Ok(Err(why)) => Err(SourceError::Failed(why)),
        // The sender went with the code unanswered, which only Stop does.
        Err(RecvTimeoutError::Disconnected) => Ok(None),
        Err(RecvTimeoutError::Timeout) => Err(SourceError::Failed(
            "nothing scanned the code in time".to_owned(),
        )),
    }
}

/// What the phone reads off the screen.
///
/// `a` and `p` get it connected now and need no discovery at all. `i` is what it needs later:
/// the peer id this node already publishes over mDNS, so an address that has moved can be
/// found again without pairing afresh.
fn text(code: Code, serving: &listener::Serving, token: &str) -> Result<String> {
    let node = match code.names_node() {
        true => format!(
            "&i={}",
            encode(&NODE.lock().unwrap_or_else(|e| e.into_inner()))
        ),
        false => String::new(),
    };
    Ok(format!(
        "ac://{}?v=1&a={}&p={}{node}&t={}&f={}&n={}",
        code.host(),
        encode(&address()?),
        serving.port,
        encode(token),
        encode(&serving.fingerprint),
        encode(&serving.name),
    ))
}

/// This machine's address on the network the phone is on.
///
/// Found by asking the routing table which interface would reach the outside, which is the
/// only way to pick one on a machine with several. Nothing is sent: a UDP socket that has
/// been connected has a local address and has put no packet on the wire.
fn address() -> Result<String> {
    let probe = std::net::UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| SourceError::io("a socket to find this machine's address with", e))?;
    probe
        .connect("192.0.2.1:9")
        .map_err(|e| SourceError::io("asking which interface reaches the network", e))?;
    let local = probe
        .local_addr()
        .map_err(|e| SourceError::io("this machine's address", e))?;
    Ok(local.ip().to_string())
}

fn render(payload: &str) -> Result<Qr> {
    let made = qrcode::QrCode::new(payload.as_bytes())
        .map_err(|e| SourceError::Failed(format!("could not make a code: {e}")))?;
    let colours = made.to_colors();
    let size = made.width();

    Ok(Qr {
        size,
        dark: colours
            .iter()
            .map(|colour| *colour == qrcode::Color::Dark)
            .collect(),
    })
}

/// Unguessable, and safe to put in a URL as it is.
fn nonce() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|e| SourceError::Failed(format!("could not draw a random value: {e}")))?;
    Ok(hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wait for a code to be on screen and open, and return its token.
    fn a_code_up() -> String {
        for _ in 0..300 {
            if prompt::showing().is_some()
                && let Some(token) = listener::pending_token()
            {
                return token;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("no code went up");
    }

    #[test]
    fn codes_name_the_node_by_the_id_it_last_served_with() {
        let _one = listener::ONE_LISTENER
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let serving = listener::Serving {
            port: 4433,
            name: "n.node.archiverclient".to_owned(),
            fingerprint: "ab12".to_owned(),
        };

        *NODE.lock().unwrap() = "12D3KooWOld".to_owned();
        let pair = text(Code::Pair, &serving, "tok").unwrap();
        assert!(pair.starts_with("ac://pair?v=1&a="), "{pair}");
        assert!(
            pair.contains("&p=4433&i=12D3KooWOld&t=tok&f=ab12&n="),
            "{pair}"
        );

        *NODE.lock().unwrap() = "12D3KooWNew".to_owned();
        let pair = text(Code::Pair, &serving, "tok").unwrap();
        assert!(pair.contains("&i=12D3KooWNew&"), "follows the key: {pair}");

        let restore = text(Code::Restore, &serving, "tok").unwrap();
        assert!(restore.starts_with("ac://restore?v=1&a="), "{restore}");
        assert!(
            !restore.contains("&i="),
            "no identity to name yet: {restore}"
        );
        assert!(restore.contains("&p=4433&t=tok&f=ab12&n="), "{restore}");
    }

    /// The listener outlives a node restarted with a restored key, so serving again has to
    /// follow the new id without starting a second listener, which `start` would refuse.
    #[test]
    fn serving_again_follows_the_new_id_without_a_second_listener() {
        let _one = listener::ONE_LISTENER
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();

        *NODE.lock().unwrap() = "12D3KooWOld".to_owned();
        listener::pretend_listening(true);
        let served = serve(dir.path(), "12D3KooWRestored");
        listener::pretend_listening(false);

        served.unwrap();
        assert_eq!(*NODE.lock().unwrap(), "12D3KooWRestored");
    }

    #[test]
    fn a_restore_returns_what_its_reader_made_of_the_answer() {
        let _one = listener::ONE_LISTENER
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let port = listener::start_for_test(dir.path()).unwrap();

        let restoring =
            std::thread::spawn(|| ask(Code::Restore, |body, _| Ok(body["backup"].clone())));
        let token = a_code_up();

        let body = serde_json::json!({ "token": token, "backup": { "v": 1, "peer": "p" } });
        let answer =
            listener::post_for_test(dir.path(), port, Code::Restore.path(), &body.to_string());
        assert!(answer.starts_with("HTTP/1.1 204"), "{answer}");
        assert_eq!(
            restoring.join().unwrap().unwrap(),
            Some(body["backup"].clone())
        );
    }

    /// The phone that scanned the code is the only one with its token, so sending again would
    /// send the same thing. The wait ends at once, with the reason.
    #[test]
    fn an_answer_its_reader_refuses_ends_the_wait_with_the_reason() {
        let _one = listener::ONE_LISTENER
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let port = listener::start_for_test(dir.path()).unwrap();

        let restoring = std::thread::spawn(|| {
            ask(Code::Restore, |_, _| {
                Err::<(), _>("update the app".to_owned())
            })
        });
        let token = a_code_up();

        let body = serde_json::json!({ "token": token, "backup": { "v": 9 } }).to_string();
        let answer = listener::post_for_test(dir.path(), port, Code::Restore.path(), &body);
        assert!(answer.starts_with("HTTP/1.1 403"), "{answer}");

        let err = restoring.join().unwrap().unwrap_err().to_string();
        assert_eq!(err, "update the app");
        assert!(listener::pending_token().is_none(), "and the code is spent");
        assert!(prompt::showing().is_none(), "and down");
    }

    #[test]
    fn a_stopped_code_is_not_a_failure() {
        let _one = listener::ONE_LISTENER
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        listener::start_for_test(dir.path()).unwrap();

        let asking = std::thread::spawn(|| ask(Code::Restore, |_, _| Ok(())));
        a_code_up();
        prompt::stop();

        assert_eq!(asking.join().unwrap().unwrap(), None);
        assert!(crate::prompt::showing().is_none(), "the code came down");
    }
}
