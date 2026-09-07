//! The one thing this node serves: a place for a phone to say where it is.
//!
//! Two calls, both tiny, both from a device that has already been paired. It never receives a
//! photograph — the desktop fetches those — so nothing here streams and everything has a hard
//! ceiling on its size.
//!
//! ## Why it speaks TLS
//!
//! What crosses it is a phone's certificate and echoes of the token that reads its camera
//! roll. Over plain HTTP that token would be on the wire for anyone on the wifi. The QR that
//! paired the phone carried this certificate's fingerprint, so the phone verifies it against
//! something it read off a screen: no CA, and no trust-on-first-use prompt either.
//!
//! ## Why the HTTP is written out by hand
//!
//! The alternative was a server crate pinned to a TLS stack three major versions behind the
//! one already here, and two TLS implementations in one binary is two sets of advisories to
//! follow. What is accepted instead is deliberately tiny: a request line, headers, and exactly
//! as many body bytes as `Content-Length` promised. No chunked encoding, no continuation
//! lines, no second request on the same connection. Anything else is a `400` and a closed
//! socket, which is the whole of the parser's error handling.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use crate::source::{Result, SourceError};

/// Nothing here is large. A phone sends a few hundred bytes and anything claiming more is
/// refused before it is read.
const MAX_BODY: usize = 8 * 1024;
const MAX_HEADERS: usize = 64;
const MAX_LINE: usize = 4 * 1024;

/// A connection that has said nothing this long is dropped, so a socket held open by
/// something that is not a phone cannot occupy the thread.
const IDLE: Duration = Duration::from_secs(10);

/// How long a phone counts as here after it last said so.
///
/// The companion app is asked to say hello about once a minute, so this has to leave room for
/// a few of those to go missing: anything near the heartbeat itself would have every phone
/// flickering in and out of reach for no reason but arithmetic. Short enough, still, that a
/// phone taken out of the house stops being scanned well inside the 16-hour cadence.
pub const FRESH: Duration = Duration::from_secs(5 * 60);



/// Where a phone last said it could be found. Written by the listener, read by `reachable`.
static SEEN: OnceLock<Mutex<HashMap<String, Seen>>> = OnceLock::new();

/// Whether anything is listening in this process. What tells `reachable` whether an empty map
/// means "not here" or "nobody was watching".
static LISTENING: AtomicBool = AtomicBool::new(false);

/// What a QR has to carry: where this node is answering, and how to know it is this node.
/// Set once the listener is up, because none of it is known before.
///
/// A lock rather than a `OnceLock` so the last listener raised is the one described. In this
/// process there is only ever one; it is the tests, which raise several, that would otherwise
/// be describing the first one for ever.
static SERVING: Mutex<Option<Serving>> = Mutex::new(None);

/// Whether the pairing that just ended was stopped rather than lapsed. Read once, by the
/// wait it belongs to, while that wait still holds the only claim on the slot.
static STOPPED: AtomicBool = AtomicBool::new(false);

/// The one pairing that may be completed right now, if any.
///
/// One at a time on purpose: two QRs on one screen is not a thing that happens, and a single
/// slot means a phone's answer can only ever belong to the request a person is looking at.
static PENDING: Mutex<Option<Pending>> = Mutex::new(None);

#[derive(Debug, Clone)]
pub struct Serving {
    pub port: u16,
    /// The name the certificate was issued for. Nothing resolves it; it is what a phone
    /// checks the certificate against having been told the address separately.
    pub name: String,
    /// SHA-256 of the certificate, hex. What the QR carries so the very first connection is
    /// verified rather than trusted.
    pub fingerprint: String,
}

/// How a wait ended.
#[derive(Debug)]
pub enum Waited {
    /// A phone scanned the code and answered.
    Paired(Box<Paired>),
    /// Somebody closed the dialog, or pressed Cancel.
    Stopped,
    /// Nobody scanned it in time.
    Expired,
}

struct Pending {
    token: String,
    /// Filled in by the phone that answers, and taken by whoever is waiting.
    answered: std::sync::mpsc::Sender<Paired>,
}

/// What a phone says about itself when it pairs.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Paired {
    /// Stable for this device, and what a source is bound to ever after.
    pub id: String,
    /// What to call it on screen.
    #[serde(default)]
    pub name: String,
    /// Which port it serves its camera roll on.
    pub port: u16,
    /// Its certificate, PEM, which this node pins for every later connection.
    pub cert: String,
    /// Not from the body: where the pairing request came from.
    #[serde(skip)]
    pub address: String,
}

/// Where this node is answering, once it is.
pub fn serving() -> Option<Serving> {
    SERVING.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// One listener at a time, for tests that raise real ones.
///
/// Production has exactly one per process, so nothing guards this there — the guard is in
/// `start`. Tests raise several through `bring_up`, and two at once would have each of them
/// describing the other's certificate.
#[cfg(test)]
pub(crate) static ONE_LISTENER: Mutex<()> = Mutex::new(());

/// Wait for a phone to pair with this token, or give up.
///
/// The token is the one already on screen: a phone that has not seen it cannot answer, which
/// is the whole of what makes an open listener safe to leave running.
///
/// One at a time, and the second caller is refused rather than allowed to replace the first.
/// Two codes on two screens would be one of them silently unanswerable, and whoever was
/// looking at it would have no way to know which.
pub fn expect(token: &str, until: Duration) -> Result<Waited> {
    let (answered, arrives) = std::sync::mpsc::channel();
    {
        let mut pending = PENDING.lock().unwrap_or_else(|e| e.into_inner());
        if pending.is_some() {
            return Err(SourceError::Failed(
                "another phone is being paired right now; finish that one first".to_owned(),
            ));
        }
        STOPPED.store(false, Ordering::SeqCst);
        *pending = Some(Pending {
            token: token.to_owned(),
            answered,
        });
    }

    let waited = match arrives.recv_timeout(until) {
        Ok(paired) => Waited::Paired(Box::new(paired)),
        // Disconnected rather than timed out means the sender went with the pending slot,
        // which is [`cancel`] and nothing else.
        Err(_) if STOPPED.load(Ordering::SeqCst) => Waited::Stopped,
        Err(_) => Waited::Expired,
    };

    // Whatever happened, this token is spent: a second phone cannot answer a QR that has
    // already been used, and one that lapsed must not be answerable later.
    *PENDING.lock().unwrap_or_else(|e| e.into_inner()) = None;
    Ok(waited)
}

/// Stop waiting, now.
///
/// Dropping the pending slot drops the sender with it, so whoever is waiting wakes at once
/// rather than sitting out the rest of its three minutes. Without this, closing the dialog
/// would leave the button that opened it disabled until the wait gave up on its own.
pub fn cancel() {
    STOPPED.store(true, Ordering::SeqCst);
    *PENDING.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// Raise a listener without the once-per-process guard, which a test binary trips after its
/// first listener. Held to one at a time by [`ONE_LISTENER`] instead.
#[cfg(test)]
pub(crate) fn start_for_test(state: &Path) -> Result<u16> {
    bring_up(state, |_, _| None)
}

/// The token a pairing is currently waiting for, if one is. For a test standing in for the
/// camera that would otherwise have read it off the screen.
#[cfg(test)]
pub fn pending_token() -> Option<String> {
    PENDING
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|pending| pending.token.clone())
}

/// A phone answering a QR. `true` when it was the one being waited for.
fn pair(body: &str, from: IpAddr) -> bool {
    let Ok(said) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    let token = said.get("token").and_then(|t| t.as_str()).unwrap_or_default();

    let mut pending = PENDING.lock().unwrap_or_else(|e| e.into_inner());
    let Some(waiting) = pending.as_ref() else {
        return false;
    };
    // Compared whole. A token nobody is waiting for, or the wrong one, is not an error worth
    // explaining to whoever sent it — they are not the person holding the phone.
    if token.is_empty() || token != waiting.token {
        return false;
    }

    let Ok(mut paired) = serde_json::from_str::<Paired>(body) else {
        return false;
    };
    paired.address = format!("{from}:{}", paired.port);

    let sent = waiting.answered.send(paired).is_ok();
    if sent {
        // Spent here as well as in `expect`, so a retry cannot land twice even if the waiter
        // has not woken yet.
        *pending = None;
    }
    sent
}

#[derive(Debug, Clone)]
pub struct Seen {
    /// `host:port`, the host taken from the socket rather than from anything it claimed.
    pub address: String,
    pub at: Instant,
}

fn seen() -> &'static Mutex<HashMap<String, Seen>> {
    SEEN.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Whether this process has a listener up. False in a CLI with no daemon, where the answer to
/// "is that phone there?" has to be found the slow way.
pub fn listening() -> bool {
    LISTENING.load(Ordering::Relaxed)
}

/// Where this device last said it was, if it has said so recently enough to count.
pub fn fresh(device: &str) -> Option<String> {
    let map = seen().lock().unwrap_or_else(|e| e.into_inner());
    map.get(device)
        .filter(|entry| entry.at.elapsed() < FRESH)
        .map(|entry| entry.address.clone())
}

/// Note that a device is here. Public so a test can seed it without a socket.
pub fn note(device: &str, address: &str) {
    let mut map = seen().lock().unwrap_or_else(|e| e.into_inner());
    map.insert(
        device.to_owned(),
        Seen {
            address: address.to_owned(),
            at: Instant::now(),
        },
    );
}

/// What a request turned out to be, once it has been read and understood.
#[derive(Debug, PartialEq, Eq)]
pub enum Asked {
    /// `POST /v1/hello`, with the body.
    Hello(String),
    /// `POST /v1/pair`, with the body. Answered in step 4; refused until then.
    Pair(String),
    /// Understood, and not one of ours.
    Elsewhere,
    /// Not understood at all.
    Malformed(&'static str),
}

/// Start the listener, and answer with the port it got.
///
/// Idempotent by way of [`LISTENING`]: a second call while one is up is a no-op rather than a
/// second socket, because the registry promises at most one start per process and a mistake
/// there should not become two listeners racing for the same map.
pub fn start(state: &Path, on_hello: fn(&str, IpAddr) -> Option<String>) -> Result<u16> {
    if LISTENING.swap(true, Ordering::SeqCst) {
        return Err(SourceError::Failed(
            "the phone listener is already running".to_owned(),
        ));
    }

    let outcome = bring_up(state, on_hello);
    if outcome.is_err() {
        // Undone, or a failure at startup would leave `reachable` believing a listener is
        // watching and answering "not here" for every phone for the life of the process.
        LISTENING.store(false, Ordering::SeqCst);
    }
    outcome
}

fn bring_up(state: &Path, on_hello: fn(&str, IpAddr) -> Option<String>) -> Result<u16> {
    let (cert, key) = certificate(state)?;
    let fingerprint = fingerprint(&cert);
    let tls = Arc::new(server_config(cert, key)?);
    let (listener, port) = bind(state)?;

    *SERVING.lock().unwrap_or_else(|e| e.into_inner()) = Some(Serving {
        port,
        name: name(state)?,
        fingerprint,
    });

    std::thread::Builder::new()
        .name("phone-listener".to_owned())
        .spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    // One at a time and inline: a hello is a few hundred bytes, and a phone
                    // that has to wait behind another phone's hello waits microseconds.
                    Ok(stream) => answer(stream, &tls, on_hello),
                    Err(error) => tracing::debug!(%error, "a phone connection did not open"),
                }
            }
            // Only reached if the listener itself dies, which is not something to be quiet
            // about: nothing will ever be reachable again.
            LISTENING.store(false, Ordering::SeqCst);
            tracing::warn!("the phone listener stopped; phones can no longer announce themselves");
        })
        .map_err(|e| SourceError::io("a thread for the phone listener", e))?;

    Ok(port)
}

/// One connection, from the handshake to the closed socket.
fn answer(stream: TcpStream, tls: &Arc<ServerConfig>, on_hello: fn(&str, IpAddr) -> Option<String>) {
    let from = match stream.peer_addr() {
        Ok(addr) => addr.ip(),
        Err(error) => {
            tracing::debug!(%error, "a phone connection had no address");
            return;
        }
    };
    let _ = stream.set_read_timeout(Some(IDLE));
    let _ = stream.set_write_timeout(Some(IDLE));

    let connection = match ServerConnection::new(Arc::clone(tls)) {
        Ok(connection) => connection,
        Err(error) => {
            tracing::warn!(%error, "could not start TLS for a phone");
            return;
        }
    };
    let mut tls = StreamOwned::new(connection, stream);

    match read(&mut tls) {
        Asked::Hello(body) => match on_hello(&body, from) {
            Some(device) => {
                tracing::debug!(device, %from, "a phone says it is here");
                say(&mut tls, 204, "");
            }
            // Not a phone this node has paired, or a token that has since been replaced.
            None => say(&mut tls, 403, "no"),
        },
        Asked::Pair(body) => match pair(&body, from) {
            true => say(&mut tls, 204, ""),
            // Deliberately the same answer for "no pairing is open", "wrong token" and
            // "unreadable": whoever is asking without the code learns nothing from which.
            false => say(&mut tls, 403, "no"),
        },
        Asked::Elsewhere => say(&mut tls, 404, "no"),
        Asked::Malformed(why) => {
            tracing::debug!(why, %from, "a connection to the phone listener made no sense");
            say(&mut tls, 400, why);
        }
    }

    // Said properly rather than by hanging up. Without it every client sees an unexpected
    // EOF where it should see a finished exchange, and a phone app would be right to treat
    // that as an error worth showing somebody.
    tls.conn.send_close_notify();
    let _ = tls.flush();
}

/// Read one request and say what it was.
///
/// Split from the socket so the grammar can be tested without a handshake: everything this
/// accepts, and everything it refuses, is decided here.
pub fn read(from: &mut impl Read) -> Asked {
    let mut reader = BufReader::new(from);

    let Some(request) = line(&mut reader) else {
        return Asked::Malformed("no request line");
    };
    let mut parts = request.split_whitespace();
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        return Asked::Malformed("not a request line");
    };

    let mut length: Option<usize> = None;
    for _ in 0..MAX_HEADERS {
        let Some(header) = line(&mut reader) else {
            return Asked::Malformed("headers did not end");
        };
        if header.is_empty() {
            break;
        }
        let Some((name, value)) = header.split_once(':') else {
            return Asked::Malformed("a header without a colon");
        };
        let name = name.to_ascii_lowercase();

        // Refused rather than handled: a body arriving in pieces is a whole parser, and no
        // phone needs one to send a few hundred bytes it already knows the length of.
        if name == "transfer-encoding" {
            return Asked::Malformed("chunked bodies are not read here");
        }
        if name == "content-length" {
            match value.trim().parse::<usize>() {
                Ok(n) if n <= MAX_BODY => length = Some(n),
                Ok(_) => return Asked::Malformed("that is too much to send here"),
                Err(_) => return Asked::Malformed("an unreadable content-length"),
            }
        }
    }

    if method != "POST" {
        return Asked::Elsewhere;
    }

    // Exactly what was promised, and no attempt to read past it: there is no second request
    // on this connection, so anything left over is somebody else's problem and not read.
    let mut body = vec![0u8; length.unwrap_or(0)];
    if !body.is_empty() && reader.read_exact(&mut body).is_err() {
        return Asked::Malformed("the body stopped early");
    }
    let Ok(body) = String::from_utf8(body) else {
        return Asked::Malformed("a body that is not text");
    };

    // The path only; a query string on these would mean nothing.
    match target.split('?').next().unwrap_or(target) {
        "/v1/hello" => Asked::Hello(body),
        "/v1/pair" => Asked::Pair(body),
        _ => Asked::Elsewhere,
    }
}

/// One line without its ending, or nothing if it never ended.
fn line(from: &mut impl BufRead) -> Option<String> {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    while out.len() <= MAX_LINE {
        match from.read(&mut byte) {
            Ok(0) => return (!out.is_empty()).then(|| finish(out)),
            Ok(_) if byte[0] == b'\n' => return Some(finish(out)),
            Ok(_) => out.push(byte[0]),
            Err(_) => return None,
        }
    }
    None
}

fn finish(mut raw: Vec<u8>) -> String {
    if raw.last() == Some(&b'\r') {
        raw.pop();
    }
    String::from_utf8_lossy(&raw).into_owned()
}

/// The shortest reply that is still a reply.
fn say(to: &mut impl Write, status: u16, body: &str) {
    let reason = match status {
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Error",
    };
    let _ = write!(
        to,
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = to.flush();
}

/// The port to listen on: the one used last time if it can still be had.
///
/// Kept because the QR told a phone where to come back to and libp2p's record does not carry
/// it. A phone holding a port that has moved cannot reconnect, which is what re-pairing is
/// for — but that should be rare rather than every restart, so the choice is written down.
fn bind(state: &Path) -> Result<(TcpListener, u16)> {
    let file = state.join("phone-port");
    let last: Option<u16> = std::fs::read_to_string(&file)
        .ok()
        .and_then(|raw| raw.trim().parse().ok());

    if let Some(port) = last {
        // Refused rather than worked around. Something already has this node's port — almost
        // always the node itself, in another process — and a second listener on another port
        // would take pairings that die with it while the real one hears nothing. Better to be
        // the node's listener or not to be one at all.
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
            .map_err(|e| SourceError::io(format!("this node's phone port ({port})"), e))?;
        return Ok((listener, port));
    }

    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
        .map_err(|e| SourceError::io("a socket for phones to reach this node on", e))?;
    let port = listener
        .local_addr()
        .map_err(|e| SourceError::io("the port that socket got", e))?
        .port();

    if let Err(error) = std::fs::write(&file, port.to_string()) {
        // Not fatal, but it means the next start picks a different port and strands whatever
        // is paired, so it is worth a line rather than a shrug.
        tracing::warn!(%error, "could not record the phone listener's port");
    }
    Ok((listener, port))
}

/// What a phone checks the certificate against, having read it off a screen.
fn fingerprint(cert: &CertificateDer<'static>) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(cert.as_ref()))
}

/// This node's own certificate, made once and kept.
fn server_config(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig> {
    ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| SourceError::Failed(format!("no usable TLS versions: {e}")))?
        .with_no_client_auth()
        // A phone proves itself with its token, not with a certificate — it has one, but it
        // is what *this* node pins when it connects the other way, not a client credential.
        .with_single_cert(vec![cert], key)
        .map_err(|e| SourceError::Failed(format!("this node's certificate is unusable: {e}")))
}

/// The certificate and key, generated on the first run and read back on every one after.
///
/// DER on disk rather than PEM because nothing here needs to read PEM: rustls wants DER, and
/// the fingerprint a QR carries is over the DER too.
fn certificate(state: &Path) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let cert_file = state.join("phone-cert.der");
    let key_file = state.join("phone-key.der");

    if let (Ok(cert), Ok(key)) = (std::fs::read(&cert_file), std::fs::read(&key_file))
        && let Ok(key) = PrivateKeyDer::try_from(key)
    {
        return Ok((CertificateDer::from(cert), key));
    }

    let made = rcgen::generate_simple_self_signed(vec![name(state)?])
        .map_err(|e| SourceError::Failed(format!("could not make a certificate: {e}")))?;
    let cert = made.cert.der().to_vec();
    let key = made.signing_key.serialize_der();

    let _ = std::fs::create_dir_all(state);
    std::fs::write(&cert_file, &cert)
        .map_err(|e| SourceError::io(cert_file.display().to_string(), e))?;
    write_private(&key_file, &key)?;

    let key = PrivateKeyDer::try_from(key)
        .map_err(|e| SourceError::Failed(format!("the key just made is unusable: {e}")))?;
    Ok((CertificateDer::from(cert), key))
}

/// The name the certificate is for.
///
/// Synthetic and stable: an address would stop matching the first time a lease moved, and
/// this node has no domain. Nothing resolves it — the phone is told the address out of band
/// and only uses this to check the certificate is the one the QR named.
fn name(state: &Path) -> Result<String> {
    let file = state.join("phone-name");
    if let Ok(kept) = std::fs::read_to_string(&file) {
        let kept = kept.trim();
        if !kept.is_empty() {
            return Ok(kept.to_owned());
        }
    }

    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes)
        .map_err(|e| SourceError::Failed(format!("could not draw a random name: {e}")))?;
    let name = format!("{}.node.archiverclient", hex::encode(bytes));

    let _ = std::fs::create_dir_all(state);
    std::fs::write(&file, &name).map_err(|e| SourceError::io(file.display().to_string(), e))?;
    Ok(name)
}

/// Write a private key, readable only by this user where the platform can say so.
fn write_private(at: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(at, bytes).map_err(|e| SourceError::io(at.display().to_string(), e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(at, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| SourceError::io(format!("the permissions on {}", at.display()), e))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asked(raw: &str) -> Asked {
        read(&mut raw.as_bytes())
    }

    #[test]
    fn a_hello_is_read_with_the_body_it_promised() {
        let body = r#"{"token":"tok-1","port":8443}"#;
        let request = format!(
            "POST /v1/hello HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        assert_eq!(asked(&request), Asked::Hello(body.to_owned()));
    }

    /// The grammar is small on purpose, and everything outside it is one answer rather than a
    /// guess. Each of these would be a parser in a general-purpose server.
    #[test]
    fn everything_outside_the_grammar_is_refused_rather_than_guessed_at() {
        for (raw, why) in [
            ("", "no request line"),
            ("nonsense\r\n\r\n", "not a request line"),
            (
                "POST /v1/hello HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
                "chunked bodies are not read here",
            ),
            (
                "POST /v1/hello HTTP/1.1\r\nContent-Length: 99999999\r\n\r\n",
                "that is too much to send here",
            ),
            (
                "POST /v1/hello HTTP/1.1\r\nContent-Length: ten\r\n\r\n",
                "an unreadable content-length",
            ),
            (
                "POST /v1/hello HTTP/1.1\r\nno-colon-here\r\n\r\n",
                "a header without a colon",
            ),
            (
                "POST /v1/hello HTTP/1.1\r\nContent-Length: 20\r\n\r\nshort",
                "the body stopped early",
            ),
        ] {
            assert_eq!(asked(raw), Asked::Malformed(why), "{raw:?}");
        }
    }

    #[test]
    fn anything_that_is_not_one_of_the_two_calls_is_somebody_elses() {
        for raw in [
            "GET /v1/hello HTTP/1.1\r\n\r\n",
            "POST /wp-login.php HTTP/1.1\r\n\r\n",
            "POST / HTTP/1.1\r\n\r\n",
        ] {
            assert_eq!(asked(raw), Asked::Elsewhere, "{raw:?}");
        }
    }

    #[test]
    fn a_query_string_does_not_hide_the_path() {
        assert_eq!(
            asked("POST /v1/hello?x=1 HTTP/1.1\r\n\r\n"),
            Asked::Hello(String::new())
        );
    }

    /// A device is here for a while after it says so, and then it is not. Both halves matter:
    /// the first is what stops one dropped packet counting as a phone leaving the house.
    #[test]
    fn a_phone_is_here_until_it_has_been_quiet_long_enough() {
        note("dev-fresh", "192.168.1.42:8443");
        assert_eq!(fresh("dev-fresh").as_deref(), Some("192.168.1.42:8443"));
        assert!(fresh("dev-never-said").is_none());

        // Reached into rather than waited out: the alternative is a five-minute test.
        let mut map = seen().lock().unwrap();
        if let Some(entry) = map.get_mut("dev-fresh") {
            entry.at = Instant::now() - FRESH - Duration::from_secs(1);
        }
        drop(map);
        assert!(fresh("dev-fresh").is_none(), "quiet for too long is gone");
    }

    /// A floor rather than a value: what matters is that several heartbeats can go missing
    /// without a phone appearing to leave. Shortening this is the change worth catching.
    #[test]
    fn a_phone_stays_reachable_across_a_few_lost_heartbeats() {
        let heartbeat = Duration::from_secs(60);
        assert!(
            FRESH >= heartbeat * 3,
            "a phone saying hello every {heartbeat:?} would flicker with a {FRESH:?} window"
        );
    }

    #[test]
    fn a_certificate_is_made_once_and_then_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let (first, _) = certificate(dir.path()).unwrap();
        let (again, _) = certificate(dir.path()).unwrap();

        assert_eq!(first, again, "a restart is not a new identity");
        assert!(dir.path().join("phone-cert.der").is_file());
        assert!(dir.path().join("phone-key.der").is_file());

        // The name it is for is stable too, or the certificate would stop matching itself.
        let stable = name(dir.path()).unwrap();
        assert_eq!(stable, name(dir.path()).unwrap());
        assert!(stable.ends_with(".node.archiverclient"), "{stable}");
    }

    #[cfg(unix)]
    #[test]
    fn the_private_key_is_not_readable_by_anyone_else() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        certificate(dir.path()).unwrap();

        let mode = std::fs::metadata(dir.path().join("phone-key.der"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "mode {mode:o} lets somebody else read it");
    }

    /// The whole of what a phone does to announce itself, over a real handshake: the node's
    /// own certificate, pinned as the only root, checked against the synthetic name it was
    /// issued for while the socket goes to an address that name does not resolve to.
    ///
    /// That last part is the mechanism the client half will rely on in both directions, and
    /// the reason the certificate names something stable rather than an address.
    #[test]
    fn a_phone_says_hello_over_tls_and_is_heard() {
        use rustls::pki_types::ServerName;
        use rustls::{ClientConfig, ClientConnection, RootCertStore};

        let _one = ONE_LISTENER.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let (cert, _) = certificate(dir.path()).unwrap();
        let issued_for = name(dir.path()).unwrap();

        // Answers every hello, and records what it was handed.
        fn heard(body: &str, from: IpAddr) -> Option<String> {
            note("round-trip", &format!("{from}:9999"));
            (!body.is_empty()).then(|| body.to_owned())
        }
        let port = bring_up(dir.path(), heard).unwrap();

        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        let config = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();

        let server = ServerName::try_from(issued_for).unwrap();
        let connection = ClientConnection::new(Arc::new(config), server).unwrap();
        let socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mut tls = StreamOwned::new(connection, socket);

        let body = r#"{"token":"tok-1","port":8443}"#;
        write!(
            tls,
            "POST /v1/hello HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        tls.flush().unwrap();

        let mut answer = String::new();
        tls.read_to_string(&mut answer).unwrap();
        assert!(answer.starts_with("HTTP/1.1 204"), "{answer}");

        // And it reached the map, keyed by whatever the callback decided this device was.
        assert!(
            fresh("round-trip").is_some_and(|at| at.starts_with("127.0.0.1:")),
            "the address is the socket's, not the body's"
        );
    }

    /// A device this node has never paired gets nothing, and does not land in the map.
    #[test]
    fn a_hello_nobody_recognises_is_refused() {
        let _one = ONE_LISTENER.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        fn nobody(_: &str, _: IpAddr) -> Option<String> {
            None
        }
        let port = bring_up(dir.path(), nobody).unwrap();

        // Plain TCP: the handshake will fail, which is itself the point — there is no way in
        // without the certificate, let alone without a token.
        let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
        // Bounded, because what is being waited for is a reply that is never coming: the
        // server is trying to read a TLS record out of "POST" and will give up in its own
        // time, and this test has no reason to wait out its idle timeout to say so.
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socket.write_all(b"POST /v1/hello HTTP/1.1\r\n\r\n").unwrap();
        let mut answer = String::new();
        let _ = socket.read_to_string(&mut answer);
        assert!(
            !answer.contains("204"),
            "plaintext must not be answered: {answer:?}"
        );
    }

    /// The token on the screen is the whole of what makes an open listener safe: only the
    /// phone that has seen it can pair, only once, and only while somebody is waiting.
    #[test]
    fn only_the_phone_that_scanned_the_code_can_pair_and_only_once() {
        let from: IpAddr = "192.168.1.77".parse().unwrap();
        let body = |token: &str| {
            format!(
                r#"{{"token":"{token}","id":"dev-1","name":"Pixel","port":8443,
                    "cert":"-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----"}}"#
            )
        };

        // Nobody waiting: an answer to a question that was never asked.
        assert!(!pair(&body("anything"), from), "no pairing is open");

        let waiting =
            std::thread::spawn(move || expect("the-token", Duration::from_secs(10)).unwrap());
        // The waiter has to have registered before anything can answer it.
        let mut ready = false;
        for _ in 0..200 {
            if PENDING.lock().unwrap().is_some() {
                ready = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(ready, "the wait never opened");

        assert!(!pair(&body("wrong-token"), from), "a guess is not a scan");
        assert!(!pair("not json", from), "nor is nonsense");
        assert!(pair(&body("the-token"), from), "the one that scanned it");

        let Waited::Paired(paired) = waiting.join().unwrap() else {
            panic!("the wait was answered");
        };
        assert_eq!(paired.id, "dev-1");
        assert_eq!(paired.name, "Pixel");
        assert_eq!(
            paired.address, "192.168.1.77:8443",
            "the host is the socket's and the port is the phone's"
        );
        assert!(paired.cert.contains("BEGIN CERTIFICATE"));

        // Spent. A second phone cannot answer a code that has already been used, and neither
        // can the first one twice.
        assert!(!pair(&body("the-token"), from), "the token was used up");

        // A code nobody scans stops being answerable when the wait gives up, rather than
        // sitting open for whoever finds it later. One test rather than two because there is
        // one slot in this process, and two tests would race for it.
        assert!(
            matches!(
                expect("brief", Duration::from_millis(50)).unwrap(),
                Waited::Expired
            ),
            "nothing scanned it"
        );
        assert!(
            !pair(&body("brief"), from),
            "a lapsed code is not a code"
        );
    }

    /// The port outlives a restart because the QR told a phone where to come back to, and
    /// libp2p's record does not carry it.
    #[test]
    fn the_port_chosen_once_is_the_port_used_again() {
        let dir = tempfile::tempdir().unwrap();

        let (first, port) = bind(dir.path()).unwrap();
        drop(first);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("phone-port"))
                .unwrap()
                .trim(),
            port.to_string()
        );

        let (_again, same) = bind(dir.path()).unwrap();
        assert_eq!(same, port, "a restart comes back where phones expect it");
    }
}
