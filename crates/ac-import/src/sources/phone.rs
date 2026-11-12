//! A phone on the same wifi, handing over its camera roll.
//!
//! The phone runs the server and this reads from it, which is the same direction every other
//! source runs in: [`Source::scan`] asks what there is, and only what survives the ledger and
//! [`crate::source::is_media`] is ever fetched. A phone that pushed would have to be told what
//! this node already holds, and there is no good place to keep that but here.
//!
//! Intermittent, because a phone is out of the house most of the day. Being absent is not a
//! failure and is not recorded as one: see `reachable`.

use std::io::Write;
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;

use crate::companion::{self, Code, listener};
use crate::http::encode;
use crate::config::{Field, Fields};
use crate::ledger::Ledger;
use crate::registry::{Authorize, HandOver, NodeInfo, Registered, RegisteredSource, Serve};
use crate::source::{
    Checksum, Cursor, Digest, Item, Page, Result, Source, SourceError, SourceType,
};

/// This source's row in the registry.
pub(super) const ENTRY: Registered = Registered::of::<Phone>();

impl RegisteredSource for Phone {
    const NAME: &'static str = "phone";

    /// Only there some of the time, and that is the ordinary state rather than a fault.
    const TYPE: SourceType = SourceType::Intermittent;

    /// Nothing shared. A phone is not an account with a provider this application registered
    /// with; it is one device that agreed to talk to this one node.
    const SETTINGS: &'static [Field] = &[];

    /// All four come from pairing, and `.kept()` keeps every one of them out of every form —
    /// nobody could type a token or a certificate, and being asked to would be worse than not
    /// being asked at all. Together they are also what [`crate::Registered::signed_in`] reads
    /// to decide whether this source still needs pairing, so `AUTH` has to produce the lot.
    const CONFIG: &'static [Field] = &[
        Field::text("device", "Device").optional().kept(),
        Field::secret("token", "Pairing token").optional().kept(),
        Field::secret("cert", "Device certificate").optional().kept(),
        Field::text("address", "Last address").optional().kept(),
    ];

    const AUTH: Option<Authorize> = Some(authorize);

    const WAITING: &'static str = companion::SCAN;

    /// A phone says where it is by checking in with the companion listener, so this hands the
    /// listener what answers it.
    const SERVICE: Option<Serve> = Some(hear_hellos);

    const BACKUP: Option<HandOver> = Some(back_up);

    fn open(config: &Fields, _settings: &Fields) -> Result<Box<dyn Source>> {
        Ok(Box::new(Phone::parse(config)?))
    }
}

/// How many to ask for at once. A page is held whole in memory, and a smaller one gets the
/// first photographs moving sooner.
const PAGE: usize = 200;

/// How long to wait on a phone that is not announcing itself before calling it absent. Only
/// reached with no listener running — a CLI scan with no daemon — where the alternative is
/// having no answer at all.
const PROBE: Duration = Duration::from_secs(1);

/// The ledger, so a hello can be checked against the phones this node has actually paired.
/// A static because the callback the listener takes is a plain function: it is set by the
/// first [`hear_hellos`], before anything can read it, and the home does not change after.
static DB: OnceLock<PathBuf> = OnceLock::new();

/// Answer phones checking in, from the ledger at `node.db`.
fn hear_hellos(node: NodeInfo<'_>) -> Result<()> {
    let _ = DB.set(node.db.to_path_buf());
    listener::hear(arrived);
    Ok(())
}

/// A phone says it is here. Answers with which phone, or nothing if it is not one of ours.
///
/// The address is the socket's, not the body's: a device may say which port it serves on,
/// because only it knows, but where it is coming *from* is not its to assert.
fn arrived(body: &str, from: IpAddr) -> Option<String> {
    let said: Hello = serde_json::from_str(body).ok()?;
    let db = DB.get()?;
    let ledger = Ledger::open(db).ok()?;

    // Whose token is this? Nothing else identifies the caller, and a token that matches no
    // source is a device this node has never paired — or one whose pairing was replaced.
    let row = ledger
        .sources()
        .ok()?
        .into_iter()
        .filter(|row| row.source == Phone::NAME)
        .find(|row| {
            row.config
                .get("token")
                .is_some_and(|token| !token.is_empty() && token == said.token)
        })?;

    let device = row.config.get("device").unwrap_or_default().to_owned();
    let address = format!("{from}:{}", said.port);
    listener::note(&device, &address);

    // Written down as well as remembered, so a scan from a CLI with no daemon still knows
    // where to look. Only on a change: a heartbeat every minute is not a reason to write.
    if row.config.get("address") != Some(address.as_str()) {
        let mut config = Fields::new();
        for (key, value) in row.config.iter() {
            if key != "address" {
                config.push(key, value);
            }
        }
        config.push("address", &address);
        if let Err(error) = ledger.set_source_config(&row.dir, &config) {
            tracing::warn!(%error, device, "could not write down where this phone is");
        }
    }

    Some(device)
}

/// Hand a backup to the phone paired as `config`.
fn back_up(config: &Fields, payload: &str) -> Result<()> {
    Phone::parse(config)?.hand_over(payload)
}

/// Show a code, and wait for the phone that scans it.
///
/// Everything a phone needs is in the code, which is what makes this one action rather than a
/// conversation: where this node is answering now, how to recognise its certificate, and the
/// token it will be asked for ever after. None of that crosses the network to get there — it
/// crosses a room, which is the one channel nothing on the wifi can listen to.
fn authorize(_settings: &Fields) -> Result<Option<Fields>> {
    let Some(paired) = companion::ask(Code::Pair, Paired::read)? else {
        return Ok(None);
    };

    // All four, because `signed_in` reads every one of them: a source missing any would look
    // unpaired and be sent round this loop again on the next add.
    tracing::info!(name = %paired.name, "paired a phone");

    let mut out = Fields::new();
    // The id, not the name it gave. A name is a display string: two phones can share one and
    // renaming one in the app would break the source bound to it. What the user calls this
    // source is the row's own name, which they typed.
    out.push("device", &paired.id)
        .push("token", &paired.token)
        .push("cert", paired.cert.trim())
        .push("address", &paired.address);
    Ok(Some(out))
}

/// What the phone pairs with when it answers a pairing code. No `Debug`, for the token.
#[derive(Deserialize)]
struct Paired {
    /// The code's own token, already checked by the listener. What the phone presents from
    /// now on.
    token: String,
    /// Stable for this device, and what a source is bound to ever after.
    id: String,
    /// What to call it on screen.
    #[serde(default)]
    name: String,
    /// Which port it serves its camera roll on.
    port: u16,
    /// Its certificate, PEM, which this node pins for every later connection.
    cert: String,
    /// Not from the body: where the pairing request came from.
    #[serde(skip)]
    address: String,
}

impl Paired {
    /// A phone's answer to a pairing code, at the address it came from.
    fn read(body: Value, from: IpAddr) -> std::result::Result<Self, String> {
        let mut paired: Paired = serde_json::from_value(body)
            .map_err(|e| format!("the phone's answer is unreadable: {e}"))?;
        paired.address = format!("{from}:{}", paired.port);
        Ok(paired)
    }
}

/// What a phone sends when it announces itself.
#[derive(Debug, Deserialize)]
struct Hello {
    token: String,
    /// Which port it serves its camera roll on. Its own to choose and its own to change.
    port: u16,
}

struct Phone {
    /// Everything before the path, scheme included. One field because it is what changes
    /// between a real phone and the fake one the tests drive.
    base: String,
    /// Pinned to this phone's certificate, and pointed at its address by a resolver of its
    /// own. Built once because building it parses a certificate.
    agent: ureq::Agent,
    /// `host:port`, as last heard. What a probe dials when nothing is listening.
    address: String,
    token: String,
    /// Which phone this is. Carried for the errors, which are read by someone who owns
    /// several and needs to know which one stopped answering.
    device: String,
}

/// Written by hand: the token is the whole of this node's access to somebody's camera roll,
/// and a derived `Debug` would put it in the first log line that mentions a source.
impl std::fmt::Debug for Phone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Phone")
            .field("device", &self.device)
            .field("base", &self.base)
            .field("token", &"…")
            .finish()
    }
}

impl Phone {
    fn parse(config: &Fields) -> Result<Self> {
        config.check(Phone::NAME, Phone::CONFIG)?;

        let token = config.get("token").unwrap_or_default();
        let address = config.get("address").unwrap_or_default();
        if token.is_empty() || address.is_empty() {
            return Err(SourceError::config(
                Phone::NAME,
                "this phone has not been paired; \"Sign in again\" on the Sources tab shows a \
                 code to scan",
            ));
        }

        // Named, not addressed. A certificate cannot name an address that changes with every
        // lease, so the phone's names something stable and this resolves that name to
        // wherever the phone last said it was. See `Fixed`.
        let named = synthetic(config.get("device").unwrap_or_default());
        let port = address.rsplit_once(':').map_or("443", |(_, port)| port);

        Ok(Self {
            agent: pinned(config.get("cert").unwrap_or_default(), address)?,
            base: format!("https://{named}:{port}"),
            address: address.to_owned(),
            token: token.to_owned(),
            device: config.get("device").unwrap_or_default().to_owned(),
        })
    }

    fn request(
        &self,
        path: &str,
        params: &[(&str, &str)],
    ) -> ureq::RequestBuilder<ureq::typestate::WithoutBody> {
        let query: Vec<String> = params
            .iter()
            .map(|(key, value)| format!("{key}={}", encode(value)))
            .collect();

        let url = match query.is_empty() {
            true => format!("{}{path}", self.base),
            false => format!("{}{path}?{}", self.base, query.join("&")),
        };

        self.authed(self.agent.get(url))
    }

    /// Statuses read rather than thrown, with the pairing token as a bearer.
    fn authed<B>(&self, request: ureq::RequestBuilder<B>) -> ureq::RequestBuilder<B> {
        request
            .config()
            // A 404 from a fetch means the photograph has gone, which is an outcome the pump
            // knows what to do with and not an error.
            .http_status_as_error(false)
            .build()
            .header("Authorization", format!("Bearer {}", self.token))
    }

    /// Hand `payload` to this phone with `POST /v1/backup`. The payload is opaque here, and
    /// never logged. Only a `204` means the phone keeps it.
    fn hand_over(&self, payload: &str) -> Result<()> {
        let answer = self
            .authed(self.agent.post(format!("{}/v1/backup", self.base)))
            .content_type("application/json")
            .send(payload);
        match answer.map_err(|e| self.unreachable(e))?.status().as_u16() {
            204 => Ok(()),
            404 => Err(SourceError::Failed(format!(
                "{}'s app cannot take a backup; update it",
                self.who()
            ))),
            other => Err(self.refused(other)),
        }
    }

    /// A call that answers with JSON.
    fn listing(&self, after: Option<&str>) -> Result<Listing> {
        let size = PAGE.to_string();
        let mut params: Vec<(&str, &str)> = vec![("limit", &size)];
        if let Some(after) = after {
            params.push(("after", after));
        }

        let mut response = self
            .request("/v1/items", &params)
            .config()
            // A page of JSON, so the whole of it can be held to a deadline. The fetch below
            // cannot: nothing here knows how long a video ought to take.
            .timeout_recv_body(Some(crate::http::SMALL_BODY))
            .build()
            .call()
            .map_err(|e| self.unreachable(e))?;

        let status = response.status();
        if !status.is_success() {
            return Err(self.refused(status.as_u16()));
        }

        response
            .body_mut()
            .read_json()
            .map_err(|e| SourceError::Failed(format!("{} answered with nonsense: {e}", self.who())))
    }

    /// What to call this phone in something a person reads.
    ///
    /// Deliberately not the device id, which is a string a phone chose for itself. These
    /// errors are shown under the source's own row, which already carries the name somebody
    /// gave it, so saying more here would only be saying it worse.
    fn who(&self) -> &str {
        "this phone"
    }

    fn unreachable(&self, e: ureq::Error) -> SourceError {
        SourceError::Failed(format!("could not reach {}: {e}", self.who()))
    }

    /// A status that is not a success and not a missing file.
    ///
    /// `401` is called out because it is the one a person can act on: the phone still answers,
    /// it has simply stopped accepting this node's token — revoked in the app, or the app
    /// reinstalled — and pairing again is the fix rather than anything about the network.
    fn refused(&self, status: u16) -> SourceError {
        match status {
            401 | 403 => SourceError::Failed(format!(
                "{} is no longer accepting this computer; pair it again",
                self.who()
            )),
            other => SourceError::Failed(format!("{} answered {other}", self.who())),
        }
    }
}

impl Source for Phone {
    fn source_type(&self) -> SourceType {
        Phone::TYPE
    }

    /// Whether this phone is on the network right now.
    ///
    /// Answered from what the listener has heard, which costs a lock and no I/O — this is
    /// asked before every scan, and a scan is asked of every source on a tick.
    ///
    /// With no listener running there is nothing to have heard, so the question is put to the
    /// network instead: a one-second connect to where the phone was last seen. Slower, and
    /// only reached from a CLI with no daemon, where the alternative is refusing to answer.
    fn reachable(&self) -> bool {
        if listener::listening() {
            return listener::fresh(&self.device).is_some();
        }
        knock(&self.address)
    }

    fn scan(&self, from: Option<&Cursor>) -> Result<Page> {
        let listing = self.listing(from.map(String::as_str))?;

        let items = listing
            .items
            .into_iter()
            .map(|entry| Item {
                reference: entry.id,
                folder: entry.folder,
                name: entry.name,
                size: entry.size,
                // A phone knows what it stored, so it can say what the bytes will come to.
                // Optional: without it the transfer is simply unchecked.
                checksum: entry.md5.map(|value| Checksum {
                    algo: Digest::Md5,
                    value,
                }),
            })
            .collect();

        Ok(Page {
            items,
            // Whatever the phone said, carried back to it verbatim next time. What it means
            // is the phone's business; a scan only has to not lose it.
            next: listing.next.filter(|cursor| !cursor.is_empty()),
            skipped: Vec::new(),
        })
    }

    fn fetch(&self, item: &Item, into: &mut dyn Write) -> Result<()> {
        let mut response = self
            .request(&format!("/v1/items/{}/bytes", encode(&item.reference)), &[])
            .call()
            .map_err(|e| self.unreachable(e))?;

        let status = response.status();
        // Deleted from the camera roll between the scan and now, which is ordinary on a
        // device somebody is using. The pump retires the row rather than retrying it.
        if status == 404 || status == 410 {
            return Err(SourceError::Gone {
                reference: item.reference.clone(),
            });
        }
        if !status.is_success() {
            return Err(self.refused(status.as_u16()));
        }

        // Streamed rather than held: these are photographs and video, and the whole point of
        // writing into what the caller handed over is that it never all sits in memory.
        let mut body = response.body_mut().as_reader();
        std::io::copy(&mut body, into)
            .map_err(|e| SourceError::io(format!("the copy of {}", item.name), e))?;
        Ok(())
    }
}

/// One page, in the phone's own words.
#[derive(Debug, Default, Deserialize)]
struct Listing {
    #[serde(default)]
    items: Vec<Entry>,
    /// Absent or null on the last page.
    next: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Entry {
    /// Stable for as long as the photograph is on the phone. Not a filename: two photographs
    /// can share one of those, and a reference has to be the thing that tells them apart.
    id: String,
    name: String,
    /// The album it is in, which is what the Sort tab's bulk actions group by. Empty is the
    /// camera roll itself rather than an error.
    #[serde(default)]
    folder: String,
    size: Option<u64>,
    md5: Option<String>,
}

/// The name a phone's certificate is issued for.
///
/// Synthetic, and derived from the device rather than from where it is: rustls checks a
/// certificate against the host being connected to whatever the roots are, so a certificate
/// naming an address would stop validating the first time a lease moved. Nothing resolves
/// this — [`Fixed`] is what turns it back into an address.
fn synthetic(device: &str) -> String {
    let tame: String = device
        .chars()
        .map(|c| match c.is_ascii_alphanumeric() {
            true => c.to_ascii_lowercase(),
            false => '-',
        })
        .collect();
    format!("{}.phone.archiverclient", tame.trim_matches('-'))
}

/// An agent that trusts this one phone and nothing else, and that sends every request for the
/// synthetic name to where the phone actually is.
fn pinned(cert: &str, address: &str) -> Result<ureq::Agent> {
    if cert.trim().is_empty() {
        return Err(SourceError::config(
            Phone::NAME,
            "this phone has no certificate; pair it again",
        ));
    }
    let cert = ureq::tls::Certificate::from_pem(cert.as_bytes())
        .map_err(|e| SourceError::config(Phone::NAME, format!("its certificate is unreadable: {e}")))?;

    let config = crate::http::bounded(
        ureq::config::Config::builder().tls_config(
            ureq::tls::TlsConfig::builder()
                // The only root. A certificate signed by anybody else — including every
                // public authority — is refused, which is the point of pinning.
                .root_certs(ureq::tls::RootCerts::new_with_certs(&[cert]))
                .build(),
        ),
    )
    .build();

    let to: Vec<std::net::SocketAddr> = address.to_socket_addrs().map(Iterator::collect).map_err(
        |e| SourceError::config(Phone::NAME, format!("{address} is not somewhere to connect: {e}")),
    )?;
    if to.is_empty() {
        return Err(SourceError::config(Phone::NAME, format!("{address} resolves to nowhere")));
    }

    Ok(ureq::Agent::with_parts(
        config,
        ureq::unversioned::transport::DefaultConnector::default(),
        Fixed(to),
    ))
}

/// Sends every name to one address.
///
/// The certificate names the phone and the network names an address, and only this node knows
/// they are the same thing. Nothing here consults DNS: the name is ours and no resolver in the
/// world would answer for it.
#[derive(Debug)]
struct Fixed(Vec<std::net::SocketAddr>);

impl ureq::unversioned::resolver::Resolver for Fixed {
    fn resolve(
        &self,
        _uri: &ureq::http::Uri,
        _config: &ureq::config::Config,
        _timeout: ureq::unversioned::transport::NextTimeout,
    ) -> std::result::Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
        // `from_fn` fills the backing array and leaves the length at nought, so the
        // placeholder is never read. Capped well under the array's own size, because pushing
        // past it panics and a phone resolves to one address or two, never eight.
        const ROOM: usize = 8;

        let mut out = ureq::unversioned::resolver::ResolvedSocketAddrs::from_fn(|_| {
            std::net::SocketAddr::from(([0, 0, 0, 0], 0))
        });
        for addr in self.0.iter().take(ROOM) {
            out.push(*addr);
        }
        Ok(out)
    }
}

/// Whether anything answers at `host:port` within [`PROBE`].
///
/// Deliberately only a connect: a phone that accepts a connection is running its server, and
/// anything more would be a request needing a token this does not have to hand.
fn knock(address: &str) -> bool {
    let Ok(mut candidates) = address.to_socket_addrs() else {
        return false;
    };
    candidates.any(|addr| TcpStream::connect_timeout(&addr, PROBE).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read};
    use std::net::{Ipv4Addr, SocketAddr, TcpListener};
    use std::sync::Arc;
    use std::sync::mpsc::Receiver;

    /// A stand-in for the companion app: serves the calls a phone serves, over plain HTTP,
    /// and hands back what it was asked so a test can check the request as well as the
    /// answer. The same shape `oauth.rs` uses for Google's token endpoint.
    struct FakePhone {
        base: String,
        asked: Receiver<Asked>,
    }

    /// A status, a content type and a body.
    type Answer = (u16, &'static str, &'static [u8]);

    /// One request as the phone received it.
    struct Asked {
        line: String,
        headers: Vec<(String, String)>,
        body: String,
    }

    impl Asked {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        }
    }

    /// Read one request off `stream` and give it `answer`. `None` if no whole request came.
    fn take(stream: &mut (impl Read + Write), (status, kind, body): Answer) -> Option<Asked> {
        let mut reader = BufReader::new(&mut *stream);

        // The request line, then headers to the blank one, then the body.
        let mut line = String::new();
        reader.read_line(&mut line).ok()?;
        let mut headers = Vec::new();
        loop {
            let mut header = String::new();
            reader.read_line(&mut header).ok()?;
            let header = header.trim_end();
            if header.is_empty() {
                break;
            }
            let (key, value) = header.split_once(':')?;
            headers.push((key.trim().to_owned(), value.trim().to_owned()));
        }
        let length = headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
            .map_or(0, |(_, value)| value.parse().unwrap_or(0));
        let mut sent = vec![0u8; length];
        reader.read_exact(&mut sent).ok()?;
        drop(reader);

        let reason = if status == 200 { "OK" } else { "No" };
        write!(
            stream,
            "HTTP/1.1 {status} {reason}\r\nContent-Type: {kind}\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .ok()?;
        stream.write_all(body).ok()?;
        stream.flush().ok()?;
        Some(Asked {
            line: line.trim_end().to_owned(),
            headers,
            body: String::from_utf8(sent).ok()?,
        })
    }

    fn fake(answers: Vec<Answer>) -> FakePhone {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let (send, asked) = std::sync::mpsc::channel();

        std::thread::spawn(move || {
            for answer in answers {
                let (mut stream, _) = listener.accept().unwrap();
                if let Some(request) = take(&mut stream, answer) {
                    let _ = send.send(request);
                }
            }
        });

        FakePhone { base, asked }
    }

    /// The same stand-in over TLS, with its own certificate for `device`, answering one
    /// request. Comes with what pairing would have stored for it.
    fn fake_over_tls(device: &str, answer: Answer) -> (Fields, Receiver<Asked>) {
        use rustls::pki_types::PrivateKeyDer;
        use rustls::{ServerConfig, ServerConnection, StreamOwned};

        let made = rcgen::generate_simple_self_signed(vec![synthetic(device)]).unwrap();
        let key = PrivateKeyDer::try_from(made.signing_key.serialize_der()).unwrap();
        let tls = Arc::new(
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![made.cert.der().clone()], key)
                .unwrap(),
        );
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (send, asked) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let mut stream = StreamOwned::new(ServerConnection::new(tls).unwrap(), socket);
            // A handshake the client walks away from ends here, with nothing asked.
            if let Some(request) = take(&mut stream, answer) {
                let _ = send.send(request);
            }
            stream.conn.send_close_notify();
            let _ = stream.flush();
        });

        let mut config = Fields::new();
        config
            .push("device", device)
            .push("token", "tok-123")
            .push("cert", &made.cert.pem())
            .push("address", &format!("127.0.0.1:{port}"));
        (config, asked)
    }

    /// A port nothing listens on.
    fn nowhere() -> String {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        format!("127.0.0.1:{port}")
    }

    /// `config` with `key` set to `value`.
    fn with(config: &Fields, key: &str, value: &str) -> Fields {
        let mut out = Fields::new();
        for (held, was) in config.iter() {
            out.push(held, if held == key { value } else { was });
        }
        out
    }

    fn phone(at: &FakePhone) -> Phone {
        Phone {
            // Plain, because the fake speaks plain HTTP. What pinning does is asserted
            // against a real handshake in the listener's own tests, not faked here. Bounded
            // like the real one, so a fake that stopped answering fails rather than hangs.
            agent: crate::http::agent(),
            address: at.base.trim_start_matches("http://").to_owned(),
            base: at.base.clone(),
            token: "tok-123".to_owned(),
            device: "Pixel".to_owned(),
        }
    }

    /// A real certificate, because `parse` pins it and a stub is no longer enough to get
    /// past that — which is the point of pinning.
    fn a_certificate() -> String {
        rcgen::generate_simple_self_signed(vec!["pixel.phone.archiverclient".to_owned()])
            .unwrap()
            .cert
            .pem()
    }

    fn paired() -> Fields {
        let mut fields = Fields::new();
        fields
            .push("device", "Pixel")
            .push("token", "tok-123")
            .push("cert", &a_certificate())
            .push("address", "192.168.1.42:8765");
        fields
    }

    #[test]
    fn a_phone_that_has_not_been_paired_says_how_to_pair_it() {
        let err = Phone::parse(&Fields::new()).unwrap_err().to_string();
        assert!(err.contains("not been paired"), "{err}");
        assert!(err.contains("Sign in again"), "and where to do it: {err}");

        // A token with nowhere to send it is no more usable than no token.
        let mut half = Fields::new();
        half.push("token", "tok-123");
        assert!(Phone::parse(&half).is_err());
    }

    /// A phone is addressed by a name its certificate can keep, and reached at an address
    /// that certificate never mentions. That split is what survives a new DHCP lease.
    #[test]
    fn a_phone_is_named_by_its_certificate_and_found_by_its_address() {
        let phone = Phone::parse(&paired()).unwrap();

        assert_eq!(phone.base, "https://pixel.phone.archiverclient:8765");
        assert_eq!(phone.address, "192.168.1.42:8765", "and dialled here");
        assert_eq!(phone.device, "Pixel");
        assert_eq!(phone.source_type(), SourceType::Intermittent);
    }

    /// A phone that took the connection and then went quiet used to hold the thread for ever,
    /// and a blocking thread cannot be cancelled: the node would not shut down either. The
    /// pinned agent has to carry the bounds, whatever else building it has to say.
    #[test]
    fn a_phone_that_goes_quiet_is_given_up_on_rather_than_waited_for() {
        let phone = Phone::parse(&paired()).unwrap();
        let timeouts = phone.agent.config().timeouts();

        assert!(timeouts.connect.is_some(), "dialling a phone that is gone");
        assert!(
            timeouts.recv_response.is_some(),
            "and one that answers the dial and then says nothing"
        );
        assert_eq!(
            timeouts.recv_body, None,
            "but a video is as long as it is, and fetch reads through this agent"
        );
    }

    #[test]
    fn a_name_is_made_from_the_device_and_is_always_a_usable_one() {
        assert_eq!(synthetic("Pixel"), "pixel.phone.archiverclient");
        assert_eq!(
            synthetic("Jonathan's iPhone 15"),
            "jonathan-s-iphone-15.phone.archiverclient"
        );
        assert!(
            !synthetic("--x--").starts_with('-'),
            "a name cannot begin with the separator"
        );
    }

    /// Pinning is the whole of how this node knows it is talking to the right phone, so a
    /// source with no usable certificate is refused rather than opened unpinned.
    #[test]
    fn a_phone_without_a_readable_certificate_is_refused_rather_than_trusted() {
        for cert in ["", "-----BEGIN CERTIFICATE-----", "not a certificate at all"] {
            let mut config = Fields::new();
            config
                .push("device", "Pixel")
                .push("token", "tok-123")
                .push("cert", cert)
                .push("address", "192.168.1.42:8765");

            let err = Phone::parse(&config).unwrap_err().to_string();
            assert!(err.contains("certificate"), "{cert:?}: {err}");
        }
    }

    /// The token is the whole of this node's access to a camera roll.
    #[test]
    fn printing_a_phone_does_not_print_the_way_into_it() {
        let shown = format!("{:?}", Phone::parse(&paired()).unwrap());
        assert!(!shown.contains("tok-123"), "{shown}");
        assert!(shown.contains("Pixel"), "but says which phone: {shown}");
    }

    #[test]
    fn a_scan_reads_what_the_phone_offers_and_carries_its_cursor_back() {
        let at = fake(vec![(
            200,
            "application/json",
            br#"{"items":[
                  {"id":"m-1","name":"IMG_0031.heic","folder":"Camera",
                   "size":4194304,"md5":"9f86d0"},
                  {"id":"m-2","name":"clip.mov","folder":"Camera","size":48000000}
                ],"next":"page-2"}"#,
        )]);
        let page = phone(&at).scan(None).unwrap();

        assert_eq!(page.items.len(), 2);
        let first = &page.items[0];
        assert_eq!(first.reference, "m-1", "the id, because a name is not unique");
        assert_eq!(first.name, "IMG_0031.heic");
        assert_eq!(first.folder, "Camera");
        assert_eq!(first.size, Some(4_194_304));
        assert_eq!(
            first.checksum.as_ref().map(|c| (c.algo, c.value.as_str())),
            Some((Digest::Md5, "9f86d0")),
            "so the bytes can be checked against what was promised"
        );
        assert!(
            page.items[1].checksum.is_none(),
            "a phone that offers no digest is still importable"
        );
        assert_eq!(page.next.as_deref(), Some("page-2"));

        let asked = at.asked.recv().unwrap().line;
        assert!(asked.starts_with("GET /v1/items?"), "{asked}");
        assert!(asked.contains("limit=200"), "{asked}");
        assert!(!asked.contains("after="), "nothing to resume from: {asked}");
    }

    #[test]
    fn a_second_page_asks_from_where_the_last_one_stopped() {
        let at = fake(vec![(200, "application/json", br#"{"items":[],"next":null}"#)]);
        let page = phone(&at).scan(Some(&"page-2".to_owned())).unwrap();

        assert!(page.items.is_empty());
        assert!(page.next.is_none(), "the walk ends rather than looping");

        let asked = at.asked.recv().unwrap().line;
        assert!(asked.contains("after=page-2"), "{asked}");
    }

    /// An empty string is not a cursor. A phone that sends one instead of null would
    /// otherwise have the pump asking for ever.
    #[test]
    fn an_empty_cursor_is_the_end_rather_than_a_place() {
        let at = fake(vec![(200, "application/json", br#"{"items":[],"next":""}"#)]);
        assert!(phone(&at).scan(None).unwrap().next.is_none());
    }

    #[test]
    fn a_page_with_nothing_in_it_at_all_is_read_rather_than_refused() {
        let at = fake(vec![(200, "application/json", b"{}")]);
        let page = phone(&at).scan(None).unwrap();
        assert!(page.items.is_empty() && page.next.is_none());
    }

    #[test]
    fn fetching_writes_the_bytes_into_what_it_was_handed() {
        let at = fake(vec![(200, "image/jpeg", b"these are the bytes")]);
        let item = Item {
            reference: "m-1".to_owned(),
            folder: "Camera".to_owned(),
            name: "a.jpg".to_owned(),
            size: Some(19),
            checksum: None,
        };

        let mut arrived = Vec::new();
        phone(&at).fetch(&item, &mut arrived).unwrap();
        assert_eq!(arrived, b"these are the bytes");

        let asked = at.asked.recv().unwrap().line;
        assert!(asked.starts_with("GET /v1/items/m-1/bytes"), "{asked}");
    }

    /// Ordinary on a device somebody is using: the photograph was there at the scan and
    /// deleted before the fetch. `Gone` is what retires the row instead of retrying it.
    #[test]
    fn a_photograph_deleted_since_the_scan_is_gone_rather_than_broken() {
        for status in [404u16, 410] {
            let at = fake(vec![(status, "text/plain", b"no")]);
            let item = Item {
                reference: "m-9".to_owned(),
                folder: String::new(),
                name: "gone.jpg".to_owned(),
                size: None,
                checksum: None,
            };

            let err = phone(&at).fetch(&item, &mut Vec::new()).unwrap_err();
            assert!(
                matches!(&err, SourceError::Gone { reference } if reference == "m-9"),
                "{status}: {err:?}"
            );
        }
    }

    /// The one failure a person can act on, so it says what to do rather than a number.
    #[test]
    fn a_phone_that_has_stopped_accepting_this_computer_says_to_pair_again() {
        for status in [401u16, 403] {
            let at = fake(vec![(status, "text/plain", b"no")]);
            let err = phone(&at).scan(None).unwrap_err().to_string();
            assert!(err.contains("pair it again"), "{status}: {err}");
            assert!(err.contains("this phone"), "{err}");
        }
    }

    const PAYLOAD: &str =
        r#"{"v":1,"peer":"12D3KooWPeer","key":"c2VjcmV0","server":"/p2p/x","username":"alice"}"#;

    /// A backup handed through the registry's hook, as `ac-node` hands it.
    fn back_up_through_the_registry(config: &Fields) -> Result<()> {
        crate::registry::find(Phone::NAME)
            .unwrap()
            .hand_over(config, PAYLOAD)
    }

    /// The error a backup failed with, checked never to carry the key.
    fn refusal(handed: Result<()>) -> String {
        let said = handed.unwrap_err().to_string();
        assert!(!said.contains("c2VjcmV0"), "{said}");
        said
    }

    #[test]
    fn a_backup_goes_with_the_pairing_token_and_the_payload_unchanged() {
        let at = fake(vec![(204, "text/plain", b"")]);
        phone(&at).hand_over(PAYLOAD).unwrap();

        let asked = at.asked.recv().unwrap();
        assert_eq!(asked.line, "POST /v1/backup HTTP/1.1");
        assert_eq!(asked.header("authorization"), Some("Bearer tok-123"));
        assert_eq!(asked.header("content-type"), Some("application/json"));
        assert_eq!(asked.body, PAYLOAD);
    }

    #[test]
    fn each_answer_says_what_became_of_the_backup() {
        let at = fake(vec![(204, "text/plain", b"")]);
        assert!(phone(&at).hand_over(PAYLOAD).is_ok());

        for (status, says) in [
            (401, "pair it again"),
            (403, "pair it again"),
            (404, "update it"),
            (200, "answered 200"),
            (500, "answered 500"),
        ] {
            let at = fake(vec![(status, "text/plain", b"")]);
            let said = refusal(phone(&at).hand_over(PAYLOAD));
            assert!(said.contains(says), "{status}: {said}");
        }
    }

    #[test]
    fn a_phone_that_does_not_answer_is_away() {
        let address = nowhere();
        let away = Phone {
            agent: crate::http::agent(),
            base: format!("http://{address}"),
            address,
            token: "tok-123".to_owned(),
            device: "Pixel".to_owned(),
        };
        let said = refusal(away.hand_over(PAYLOAD));
        assert!(said.contains("could not reach"), "{said}");
    }

    /// The whole way, through the hook, the pinned agent, the synthetic name and the stored
    /// address.
    #[test]
    fn a_paired_phone_takes_the_backup_over_its_pinned_certificate() {
        let (config, asked) = fake_over_tls("Jonathan's Pixel", (204, "text/plain", b""));
        back_up_through_the_registry(&config).unwrap();

        let asked = asked.recv().unwrap();
        assert_eq!(asked.line, "POST /v1/backup HTTP/1.1");
        assert_eq!(asked.header("authorization"), Some("Bearer tok-123"));
        assert_eq!(asked.body, PAYLOAD);
    }

    /// The key goes only to the certificate this node paired with.
    #[test]
    fn a_phone_with_another_certificate_is_sent_nothing() {
        let (config, asked) = fake_over_tls("Pixel", (204, "text/plain", b""));
        let (impostor, _) = fake_over_tls("Pixel", (204, "text/plain", b""));
        let config = with(&config, "cert", impostor.get("cert").unwrap());

        let said = refusal(back_up_through_the_registry(&config));
        assert!(said.contains("could not reach"), "{said}");
        assert!(
            asked.recv_timeout(Duration::from_secs(1)).is_err(),
            "nothing reached it"
        );
    }

    #[test]
    fn with_two_phones_one_away_the_other_still_takes_it() {
        let (here, asked) = fake_over_tls("Pixel", (204, "text/plain", b""));
        let away = with(&here, "address", &nowhere());

        let said = refusal(back_up_through_the_registry(&away));
        assert!(said.contains("could not reach"), "{said}");
        back_up_through_the_registry(&here).unwrap();
        assert_eq!(asked.recv().unwrap().body, PAYLOAD);
    }

    #[test]
    fn a_phone_that_is_not_paired_is_sent_nothing_and_says_why() {
        let mut config = Fields::new();
        config.push("device", "Pixel").push("token", "tok-123");
        let said = refusal(back_up_through_the_registry(&config));
        assert!(said.contains("has not been paired"), "{said}");
    }

    /// The whole of what a hello does, short of the socket: it says which phone, remembers
    /// where that phone is, and writes the address down so a scan with no daemon running can
    /// still find it. Everything here turns on the token, because nothing else identifies the
    /// caller and a body is free to claim anything.
    #[test]
    fn a_hello_bearing_a_known_token_says_which_phone_and_where() {
        use crate::ledger::SourceRow;

        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("ac.db");
        let ledger = Ledger::open(&db).unwrap();
        ledger
            .add_source(&SourceRow {
                dir: "pixel".to_owned(),
                name: "Pixel".to_owned(),
                source: Phone::NAME.to_owned(),
                config: paired(),
                added_at: 0,
                scanned_at: 0,
                last_error: None,
                reachable: true,
            })
            .unwrap();
        DB.set(db.clone()).expect("only this test sets it");

        let from: IpAddr = "192.168.1.77".parse().unwrap();
        let device = arrived(r#"{"token":"tok-123","port":8443}"#, from);
        assert_eq!(device.as_deref(), Some("Pixel"));

        // Remembered, at the address the socket came from rather than one it claimed.
        assert_eq!(
            listener::fresh("Pixel").as_deref(),
            Some("192.168.1.77:8443")
        );

        // And written down, because `paired()` said 192.168.1.42 and the phone has moved.
        let stored = Ledger::open(&db)
            .unwrap()
            .source("pixel")
            .unwrap()
            .unwrap()
            .config;
        assert_eq!(stored.get("address"), Some("192.168.1.77:8443"));
        assert_eq!(
            stored.get("token"),
            Some("tok-123"),
            "and nothing else was lost rewriting it"
        );
        assert_eq!(stored.get("device"), Some("Pixel"));

        // A token nothing here was paired with is nobody, and changes nothing.
        assert!(arrived(r#"{"token":"not-ours","port":8443}"#, from).is_none());
        assert!(arrived("not json at all", from).is_none());
    }

    /// Pairing, the whole way through, over the handshake a phone would really make.
    ///
    /// What is being checked is that the four fields a source needs come out of it, because
    /// `signed_in` reads every one and a source missing any looks unpaired and gets sent
    /// round again on the next add.
    #[test]
    fn pairing_ends_with_everything_a_source_needs_to_be_paired() {
        let _one = listener::ONE_LISTENER
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path();

        // The node's own listener, exactly as `companion::serve` would raise it.
        let port = listener::start_for_test(state).unwrap();
        let serving = listener::serving().expect("the listener says where it is");
        assert_eq!(serving.port, port);

        // Pairing runs on its own thread, because it blocks until a phone answers.
        let pairing = std::thread::spawn(|| authorize(&Fields::new()));

        // The code is up while it waits, which is what the app photographs.
        let mut shown = None;
        for _ in 0..200 {
            if let Some(qr) = crate::prompt::showing() {
                shown = Some(qr);
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let qr = shown.expect("a code went up");
        assert!(qr.size >= 21, "a real code, not an empty square");

        // Standing in for the camera: the token the code carries, read from where the
        // listener is holding it rather than by decoding pixels.
        let token = listener::pending_token().expect("a pairing is open");

        // Now be the phone. The certificate is pinned from the fingerprint the code carried,
        // and checked against the name it was issued for while the socket goes to localhost.
        let cert = std::fs::read(state.join("phone-cert.der")).unwrap();
        assert_eq!(
            hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&cert)),
            serving.fingerprint,
            "the code names this certificate and no other"
        );

        let mine = rcgen::generate_simple_self_signed(vec!["a-phone".to_owned()]).unwrap();
        let body = serde_json::json!({
            "token": token,
            "id": "device-abc-123",
            "name": "Jonathan's Pixel",
            "port": 8443,
            "cert": mine.cert.pem(),
        })
        .to_string();
        let answer = listener::post_for_test(state, port, "/v1/pair", &body);
        assert!(answer.starts_with("HTTP/1.1 204"), "{answer}");

        let paired = pairing
            .join()
            .unwrap()
            .expect("pairing finished")
            .expect("and was not stopped");

        // The id, not the name: a name is a display string and two phones can share one.
        assert_eq!(paired.get("device"), Some("device-abc-123"));
        assert_eq!(paired.get("token").unwrap_or_default(), token);
        assert!(paired.get("cert").unwrap_or_default().contains("CERTIFICATE"));
        assert!(
            paired.get("address").unwrap_or_default().ends_with(":8443"),
            "the phone's port, at the address it came from"
        );

        // Which is exactly the set that makes a source count as paired, and enough to open.
        let entry = crate::registry::find(Phone::NAME).unwrap();
        assert!(entry.signed_in(&paired), "nothing is left to ask for");
        assert!(Phone::parse(&paired).is_ok(), "and it opens");

        // The code comes down when the wait ends.
        assert!(crate::prompt::showing().is_none());
    }

    /// Closing the dialog has to release the thread at once. It waits three minutes for a
    /// phone, and a button disabled for three minutes after somebody pressed Cancel is a
    /// window that looks broken.
    #[test]
    fn giving_up_on_a_pairing_releases_it_at_once() {
        let _one = listener::ONE_LISTENER
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        listener::start_for_test(dir.path()).unwrap();

        let began = std::time::Instant::now();
        let pairing = std::thread::spawn(|| authorize(&Fields::new()));

        // Wait for it to actually be waiting, so the cancel is not a race.
        let mut up = false;
        for _ in 0..300 {
            if crate::prompt::showing().is_some() {
                up = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(up, "a code went up");

        // What Cancel does.
        crate::prompt::stop();

        let outcome = pairing.join().unwrap();
        let waited = began.elapsed();
        assert!(
            waited < Duration::from_secs(10),
            "it took {waited:?}, so it sat out its own timeout rather than being stopped"
        );
        assert!(waited < companion::WAIT / 2, "and nothing like the full wait");

        assert!(
            outcome.expect("stopped, which is not a failure").is_none(),
            "and nothing was paired"
        );

        // Nothing is left up, and nothing is left listening for an answer.
        assert!(crate::prompt::showing().is_none(), "the code came down");
        assert!(listener::pending_token().is_none(), "and the code is spent");
    }

    /// Nothing about a phone is typed. Every field is issued by pairing, so a form offering
    /// any of them would be a box nobody could fill — and `signed_in` reads exactly this set
    /// to decide whether a source still needs pairing, so all four have to be `.kept()`.
    #[test]
    fn nothing_about_a_phone_is_ever_put_on_a_form() {
        let phone = crate::registry::find(Phone::NAME).expect("this build has a phone source");

        assert_eq!(phone.asked_config().count(), 0, "nothing to type");
        assert_eq!(phone.asked_settings().count(), 0, "and nothing shared");
        assert!(!phone.signed_in(&Fields::new()), "so a fresh one is unpaired");
        assert!(phone.signed_in(&paired()), "and a paired one is not");

        // Two of the four are the whole of the access, and are never read back out.
        for key in ["token", "cert"] {
            let field = Phone::CONFIG.iter().find(|f| f.key == key).unwrap();
            assert_eq!(field.kind, crate::config::FieldKind::Secret, "{key}");
        }
    }

}
