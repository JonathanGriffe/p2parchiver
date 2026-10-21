//! The one thing this node serves: a place for a phone to say where it is, and to answer a
//! code on screen, to pair, back up or restore.
//!
//! Every call is tiny. It never receives a photograph — the desktop fetches those — so nothing
//! here streams and everything has a hard ceiling on its size.
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

/// The one exchange that may be completed right now, if any: a pairing, a backup or a restore.
///
/// One at a time on purpose: two QRs on one screen is not a thing that happens, and a single
/// slot means a phone's answer can only ever belong to the request a person is looking at.
static PENDING: Mutex<Option<Pending>> = Mutex::new(None);

/// Where a phone answers a code it scanned. Anything else posted is not an exchange.
pub const PAIR: &str = "/v1/pair";
pub const BACKUP: &str = "/v1/backup";
pub const RESTORE: &str = "/v1/restore";
const EXCHANGES: [&str; 3] = [PAIR, BACKUP, RESTORE];

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

/// What a code on screen waits for: a `POST` to `route` carrying `token`.
pub struct Exchange {
    pub route: &'static str,
    pub token: String,
    /// The body of a `200`, or `None` for a `204`. Secret for a backup, so never logged.
    pub reply: Option<String>,
    /// Whether the waiter can use this body. One it refuses leaves the code open.
    pub accepts: Box<dyn Fn(&str) -> bool + Send>,
}

/// A phone's answer to a code: its body, untouched, and where it came from.
#[derive(Debug)]
pub struct Answered {
    pub body: String,
    pub from: IpAddr,
}

/// How a wait ended.
#[derive(Debug)]
pub enum Waited {
    /// A phone scanned the code and answered.
    Answered(Answered),
    /// Somebody closed the dialog, or pressed Cancel.
    Stopped,
    /// Nobody scanned it in time.
    Expired,
}

struct Pending {
    exchange: Exchange,
    /// Filled in by the phone that answers, and taken by whoever is waiting.
    answered: std::sync::mpsc::Sender<Answered>,
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

/// Wait for a phone to answer this exchange, or give up.
///
/// The token is the one already on screen: a phone that has not seen it cannot answer, which
/// is the whole of what makes an open listener safe to leave running.
///
/// One at a time, and the second caller is refused rather than allowed to replace the first.
/// Two codes on two screens would be one of them silently unanswerable, and whoever was
/// looking at it would have no way to know which.
pub fn expect(exchange: Exchange, until: Duration) -> Result<Waited> {
    let (answered, arrives) = std::sync::mpsc::channel();
    {
        let mut pending = PENDING.lock().unwrap_or_else(|e| e.into_inner());
        if pending.is_some() {
            return Err(SourceError::Failed(
                "another code is waiting for a phone right now; finish that one first".to_owned(),
            ));
        }
        STOPPED.store(false, Ordering::SeqCst);
        *pending = Some(Pending { exchange, answered });
    }

    let waited = match arrives.recv_timeout(until) {
        Ok(answered) => Waited::Answered(answered),
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

/// Be the phone: post `body` to `route` over the pinned handshake, and read the answer.
#[cfg(test)]
pub(crate) fn post_for_test(state: &Path, port: u16, route: &str, body: &str) -> String {
    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, ClientConnection, RootCertStore};

    let (cert, _) = certificate(state).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();

    let server = ServerName::try_from(name(state).unwrap()).unwrap();
    let connection = ClientConnection::new(Arc::new(config), server).unwrap();
    let socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut tls = StreamOwned::new(connection, socket);
    write!(
        tls,
        "POST {route} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    tls.flush().unwrap();
    let mut answer = String::new();
    tls.read_to_string(&mut answer).unwrap();
    answer
}

/// The token a pairing is currently waiting for, if one is. For a test standing in for the
/// camera that would otherwise have read it off the screen.
#[cfg(test)]
pub fn pending_token() -> Option<String> {
    PENDING
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|pending| pending.exchange.token.clone())
}

/// A phone answering a QR at `route`. The reply to send when it was the one being waited
/// for: `Some(None)` for a `204`, `Some(Some(body))` for a `200`.
fn exchange(route: &str, body: &str, from: IpAddr) -> Option<Option<String>> {
    let said = serde_json::from_str::<serde_json::Value>(body).ok()?;
    let token = said.get("token").and_then(|t| t.as_str()).unwrap_or_default();

    let mut pending = PENDING.lock().unwrap_or_else(|e| e.into_inner());
    let waiting = pending.as_ref()?;
    // Compared whole. A token nobody is waiting for, or the wrong one, is not an error worth
    // explaining to whoever sent it — they are not the person holding the phone.
    if route != waiting.exchange.route || token.is_empty() || token != waiting.exchange.token {
        return None;
    }
    if !(waiting.exchange.accepts)(body) {
        return None;
    }

    let answered = Answered {
        body: body.to_owned(),
        from,
    };
    waiting.answered.send(answered).ok()?;
    // Spent here as well as in `expect`, so a retry cannot land twice even if the waiter
    // has not woken yet.
    pending.take().map(|spent| spent.exchange.reply)
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
    /// A `POST` answering a code, to one of [`EXCHANGES`], with the body.
    Exchange(&'static str, String),
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
        Asked::Exchange(route, body) => match exchange(route, &body, from) {
            Some(None) => say(&mut tls, 204, ""),
            Some(Some(reply)) => say(&mut tls, 200, &reply),
            // Deliberately the same answer for "no code is open", "wrong token" and
            // "unreadable": whoever is asking without the code learns nothing from which.
            None => say(&mut tls, 403, "no"),
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
    let path = target.split('?').next().unwrap_or(target);
    if path == "/v1/hello" {
        return Asked::Hello(body);
    }
    match EXCHANGES.iter().find(|route| **route == path) {
        Some(route) => Asked::Exchange(route, body),
        None => Asked::Elsewhere,
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
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Error",
    };
    let kind = match status {
        200 => "application/json",
        _ => "text/plain",
    };
    let _ = write!(
        to,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
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

    fn waiting_for(route: &'static str, token: &str, reply: Option<&str>) -> Exchange {
        Exchange {
            route,
            token: token.to_owned(),
            reply: reply.map(str::to_owned),
            accepts: Box::new(|_| true),
        }
    }

    /// Open `exchange` on a thread of its own, and return once it is waiting.
    fn open(exchange: Exchange) -> std::thread::JoinHandle<Waited> {
        let waiting =
            std::thread::spawn(move || expect(exchange, Duration::from_secs(10)).unwrap());
        for _ in 0..200 {
            if PENDING.lock().unwrap_or_else(|e| e.into_inner()).is_some() {
                return waiting;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("the wait never opened");
    }

    fn answered(waiting: std::thread::JoinHandle<Waited>) -> Answered {
        match waiting.join().unwrap() {
            Waited::Answered(answered) => answered,
            other => panic!("the wait was not answered: {other:?}"),
        }
    }

    /// The token on the screen is the whole of what makes an open listener safe: only the
    /// phone that has seen it can answer, only once, and only while somebody is waiting.
    #[test]
    fn only_the_phone_that_scanned_the_code_can_answer_and_only_once() {
        let _one = ONE_LISTENER.lock().unwrap_or_else(|e| e.into_inner());
        let from: IpAddr = "192.168.1.77".parse().unwrap();
        let body = |token: &str| format!(r#"{{"token":"{token}","id":"dev-1","port":8443}}"#);

        // Nobody waiting: an answer to a question that was never asked.
        assert!(exchange(PAIR, &body("anything"), from).is_none());

        let waiting = open(waiting_for(PAIR, "the-token", None));
        assert!(
            exchange(PAIR, &body("wrong-token"), from).is_none(),
            "a guess is not a scan"
        );
        assert!(exchange(PAIR, "not json", from).is_none(), "nor is nonsense");
        assert!(
            exchange(BACKUP, &body("the-token"), from).is_none(),
            "nor the right token at another code's route"
        );
        assert_eq!(exchange(PAIR, &body("the-token"), from), Some(None));

        let answered = answered(waiting);
        assert_eq!(answered.body, body("the-token"), "handed over untouched");
        assert_eq!(answered.from, from, "with where it came from");

        // Spent. A second phone cannot answer a code that has already been used, and neither
        // can the first one twice.
        assert!(
            exchange(PAIR, &body("the-token"), from).is_none(),
            "the token was used up"
        );

        // A code nobody scans stops being answerable when the wait gives up, rather than
        // sitting open for whoever finds it later.
        assert!(
            matches!(
                expect(waiting_for(PAIR, "brief", None), Duration::from_millis(50)).unwrap(),
                Waited::Expired
            ),
            "nothing scanned it"
        );
        assert!(
            exchange(PAIR, &body("brief"), from).is_none(),
            "a lapsed code is not a code"
        );
    }

    #[test]
    fn a_body_the_waiter_refuses_leaves_the_code_open() {
        let _one = ONE_LISTENER.lock().unwrap_or_else(|e| e.into_inner());
        let from: IpAddr = "192.168.1.77".parse().unwrap();
        let waiting = open(Exchange {
            accepts: Box::new(|body| body.contains("good")),
            ..waiting_for(RESTORE, "tok", None)
        });

        assert!(exchange(RESTORE, r#"{"token":"tok","bad":1}"#, from).is_none());
        assert_eq!(
            exchange(RESTORE, r#"{"token":"tok","good":1}"#, from),
            Some(None),
            "the same code still answers a usable body"
        );
        assert_eq!(answered(waiting).body, r#"{"token":"tok","good":1}"#);
    }

    #[test]
    fn only_one_code_is_open_at_a_time() {
        let _one = ONE_LISTENER.lock().unwrap_or_else(|e| e.into_inner());
        let from: IpAddr = "192.168.1.77".parse().unwrap();
        let waiting = open(waiting_for(PAIR, "first", None));

        let second = expect(
            waiting_for(BACKUP, "second", Some("{}")),
            Duration::from_millis(50),
        );
        assert!(second.is_err(), "the first is not replaced");
        assert!(
            exchange(BACKUP, r#"{"token":"second"}"#, from).is_none(),
            "and the second was never answerable"
        );

        cancel();
        assert!(matches!(waiting.join().unwrap(), Waited::Stopped));
    }

    #[test]
    fn a_backup_answers_its_token_once_with_the_reply() {
        let _one = ONE_LISTENER.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let port = start_for_test(dir.path()).unwrap();

        let reply = r#"{"v":1,"peer":"p"}"#;
        let waiting = open(waiting_for(BACKUP, "tok-b", Some(reply)));

        let wrong = post_for_test(dir.path(), port, BACKUP, r#"{"token":"guess"}"#);
        assert!(wrong.starts_with("HTTP/1.1 403"), "{wrong}");
        assert!(!wrong.contains(reply), "a guess gets nothing: {wrong}");

        let right = post_for_test(dir.path(), port, BACKUP, r#"{"token":"tok-b"}"#);
        assert!(right.starts_with("HTTP/1.1 200"), "{right}");
        assert!(right.ends_with(&format!("\r\n\r\n{reply}")), "{right}");
        answered(waiting);

        let again = post_for_test(dir.path(), port, BACKUP, r#"{"token":"tok-b"}"#);
        assert!(again.starts_with("HTTP/1.1 403"), "spent: {again}");
    }

    #[test]
    fn a_restore_hands_its_body_over_untouched() {
        let _one = ONE_LISTENER.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let port = start_for_test(dir.path()).unwrap();

        let waiting = open(waiting_for(RESTORE, "tok-r", None));
        let body = r#"{"token":"tok-r", "backup": {"v":1,  "key":"a2V5"}}"#;
        let answer = post_for_test(dir.path(), port, RESTORE, body);
        assert!(answer.starts_with("HTTP/1.1 204"), "{answer}");
        assert_eq!(answered(waiting).body, body);
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
