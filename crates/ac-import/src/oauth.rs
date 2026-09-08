//! Signing in to a source that answers to an authorisation server rather than to a password.
//!
//! The flow is the one meant for an application running on the machine of the person using
//! it: send them to the authorisation server in their browser, and have the server send them
//! back to a socket this process is holding open on the loopback address. Nothing but this
//! process can be reached at that address, which is what makes it safe to name as the place
//! to return to, and what makes it work without this application owning a domain.

use std::io::{self, BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use base64::Engine as _;

use crate::source::{Result, SourceError};

/// How long to wait at the socket before giving up on someone finishing in the browser.
const CONSENT_TIMEOUT: Duration = Duration::from_secs(300);

/// Refused rather than read: a browser that opens a connection and says nothing would
/// otherwise hold the request line open for as long as the whole consent window.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Long enough that guessing one is not worth trying, in the alphabet a URL carries whole.
const NONCE_BYTES: usize = 32;

/// How often the wait looks up from the socket to see whether it has been given up on.
const POLL: Duration = Duration::from_millis(100);

/// Set when somebody closes the window this was asking through. Cleared at the start of every
/// flow, so a sign-in given up on does not stop the next one before it begins.
static STOPPED: AtomicBool = AtomicBool::new(false);

/// Stop waiting for the browser. Safe to call when nothing is waiting.
pub fn cancel() {
    STOPPED.store(true, Ordering::SeqCst);
}

/// Where a person is sent, and what is expected back.
pub struct Flow {
    /// Where the browser goes to ask the question.
    pub authorize: &'static str,
    /// Where the code is traded for a token.
    pub token: &'static str,
    /// What is being asked for.
    pub scope: &'static str,
    pub client_id: String,
    pub client_secret: String,
}

/// What a finished sign-in leaves behind.
pub struct Granted {
    /// The lasting half: what is stored, and what every later token is drawn from.
    pub refresh_token: String,
}

/// Says it is there, never what it is. This is the credential itself, and the places a value
/// like this gets printed are exactly the places nobody is watching.
impl std::fmt::Debug for Granted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Granted")
            .field("refresh_token", &"…")
            .finish()
    }
}

impl Flow {
    /// Run the whole thing: open a socket, send them to the browser, wait, and trade the
    /// code that comes back for a token.
    ///
    /// `announce` is handed the URL, so a caller can open a browser at it, print it, or both.
    pub fn run(&self, announce: impl FnOnce(&str)) -> Result<Granted> {
        // Bound before the browser is sent anywhere: the port is part of what it is told to
        // come back to, so it has to be a port already held.
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .map_err(|e| SourceError::io("a socket on the loopback address", e))?;
        let port = listener
            .local_addr()
            .map_err(|e| SourceError::io("the port that socket got", e))?
            .port();
        let redirect = format!("http://127.0.0.1:{port}");

        // Two separate secrets. `state` comes back in the redirect and says the answer belongs
        // to the question this process asked. `verifier` never leaves this process until the
        // code is traded, and says the code is being spent by whoever asked for it — so a code
        // caught in transit is worth nothing on its own.
        STOPPED.store(false, Ordering::SeqCst);
        let state = nonce()?;
        let verifier = nonce()?;
        let challenge = challenge_for(&verifier);

        announce(&self.consent_url(&redirect, &state, &challenge));

        let code = self.wait_for_code(&listener, &state)?;
        self.redeem(&code, &redirect, &verifier)
    }

    /// Where to send the browser.
    fn consent_url(&self, redirect: &str, state: &str, challenge: &str) -> String {
        let query = form(&[
            ("client_id", &self.client_id),
            ("redirect_uri", redirect),
            ("response_type", "code"),
            ("scope", self.scope),
            ("state", state),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
            // Ask for the lasting half, and ask every time. Without both, a second sign-in
            // returns an access token alone and there is nothing to store.
            ("access_type", "offline"),
            ("prompt", "consent"),
        ]);
        format!("{}?{query}", self.authorize)
    }

    /// Sit on the socket until the browser is sent back to it.
    fn wait_for_code(&self, listener: &TcpListener, state: &str) -> Result<String> {
        // Non-blocking, so the wait can be given up on. A blocking `accept` would hold this
        // thread for the whole consent window whatever anybody did to the window that started
        // it, and the button that opened the browser would stay dead until it gave up.
        listener
            .set_nonblocking(true)
            .map_err(|e| SourceError::io("the waiting socket", e))?;
        let deadline = Instant::now() + CONSENT_TIMEOUT;

        // A browser opens connections nobody asked for — a favicon, a speculative preconnect
        // — so one that carries no answer is served and forgotten rather than ending the wait.
        while Instant::now() < deadline {
            if STOPPED.load(Ordering::SeqCst) {
                return Err(SourceError::Failed("signing in was stopped".to_owned()));
            }

            let stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // Nothing yet. Long enough not to spin, short enough that pressing
                    // Cancel feels immediate.
                    std::thread::sleep(POLL);
                    continue;
                }
                Err(e) => return Err(SourceError::io("waiting for the browser", e)),
            };

            // Blocking again for this one exchange: a browser that has connected is about to
            // say something, and reading it in slices would be a parser for no reason.
            let _ = stream.set_nonblocking(false);
            match self.read_answer(stream, state) {
                Ok(Some(code)) => return Ok(code),
                Ok(None) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(SourceError::Failed(
            "nothing came back from the browser in time; the sign-in was not finished".to_owned(),
        ))
    }

    /// One connection: the answer, or nothing if this was not it.
    fn read_answer(&self, stream: TcpStream, state: &str) -> Result<Option<String>> {
        let _ = stream.set_read_timeout(Some(REQUEST_TIMEOUT));
        let mut reader = BufReader::new(&stream);

        let mut line = String::new();
        if reader.read_line(&mut line).is_err() || line.is_empty() {
            return Ok(None);
        }

        // "GET /?code=…&state=… HTTP/1.1"
        let Some(target) = line.split_whitespace().nth(1) else {
            return Ok(None);
        };
        let Some((_, query)) = target.split_once('?') else {
            say(&stream, "Nothing to see here.");
            return Ok(None);
        };

        let answered = |key: &str| {
            query
                .split('&')
                .filter_map(|pair| pair.split_once('='))
                .find(|(k, _)| *k == key)
                .map(|(_, value)| decode(value))
        };

        if let Some(denied) = answered("error") {
            say(&stream, "Sign-in refused. You can close this tab.");
            return Err(SourceError::Failed(format!(
                "the sign-in was refused: {denied}"
            )));
        }

        let (Some(code), Some(came_back)) = (answered("code"), answered("state")) else {
            say(&stream, "Nothing to see here.");
            return Ok(None);
        };

        // Compared before the code is worth anything: a redirect this process did not ask for
        // is somebody else's, whatever it carries.
        if came_back != state {
            say(&stream, "That did not belong to this sign-in.");
            return Err(SourceError::Failed(
                "the browser came back with someone else's sign-in".to_owned(),
            ));
        }

        say(&stream, "Signed in. You can close this tab.");
        Ok(Some(code))
    }

    /// Trade the code for the lasting half.
    fn redeem(&self, code: &str, redirect: &str, verifier: &str) -> Result<Granted> {
        let mut response = crate::http::agent()
            .post(self.token)
            .config()
            .http_status_as_error(false)
            .timeout_recv_body(Some(crate::http::SMALL_BODY))
            .build()
            .send_form([
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("code", code),
                ("code_verifier", verifier),
                ("grant_type", "authorization_code"),
                ("redirect_uri", redirect),
            ])
            .map_err(|e| SourceError::Failed(format!("could not reach {}: {e}", self.token)))?;

        let status = response.status();
        let body: serde_json::Value = response.body_mut().read_json().map_err(|e| {
            SourceError::Failed(format!("{} answered with nonsense: {e}", self.token))
        })?;

        if !status.is_success() {
            return Err(SourceError::Failed(format!(
                "the sign-in was not completed: {}",
                complaint(&body, status.as_u16())
            )));
        }

        match body.get("refresh_token").and_then(|t| t.as_str()) {
            Some(token) => Ok(Granted {
                refresh_token: token.to_owned(),
            }),
            // Reached when consent was remembered from a previous sign-in, which is why the
            // consent URL asks for it again every time.
            None => Err(SourceError::Failed(
                "the sign-in returned no lasting token; revoke this application's access and \
                 try again"
                    .to_owned(),
            )),
        }
    }
}

/// Trade a stored refresh token for a token that can be used now.
///
/// Separate from the flow above because it is the half that runs unattended: a scan hours
/// later needs a live token and there is nobody at the browser to ask.
pub fn refresh(
    token_url: &str,
    client_id: &str,
    client_secret: &str,
    refresh: &str,
) -> Result<(String, Duration)> {
    let mut response = crate::http::agent()
        .post(token_url)
        .config()
        .http_status_as_error(false)
        .timeout_recv_body(Some(crate::http::SMALL_BODY))
        .build()
        .send_form([
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("refresh_token", refresh),
            ("grant_type", "refresh_token"),
        ])
        .map_err(|e| SourceError::Failed(format!("could not reach {token_url}: {e}")))?;

    let status = response.status();
    let body: serde_json::Value = response
        .body_mut()
        .read_json()
        .map_err(|e| SourceError::Failed(format!("{token_url} answered with nonsense: {e}")))?;

    if !status.is_success() {
        return Err(SourceError::Failed(format!(
            "could not renew the sign-in: {}. Signing in again will fix it.",
            // Their sentence already ends; ours follows it.
            complaint(&body, status.as_u16()).trim_end_matches('.')
        )));
    }

    let Some(access) = body.get("access_token").and_then(|t| t.as_str()) else {
        return Err(SourceError::Failed(
            "the renewal carried no token".to_owned(),
        ));
    };
    let lasts = body
        .get("expires_in")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(3600);
    Ok((access.to_owned(), Duration::from_secs(lasts)))
}

/// What the authorisation server said went wrong, in its words where it gave any.
pub fn complaint(body: &serde_json::Value, status: u16) -> String {
    let named = body.get("error").and_then(|e| e.as_str());
    let described = body
        .get("error_description")
        .and_then(|e| e.as_str())
        .or_else(|| body.get("error").and_then(|e| e.get("message"))?.as_str());

    match (named, described) {
        (Some(name), Some(why)) => format!("{name}: {why}"),
        (Some(name), None) => name.to_owned(),
        (None, Some(why)) => why.to_owned(),
        (None, None) => format!("the server answered {status}"),
    }
}

/// The shortest possible reply. A browser is showing this to a person, not parsing it.
fn say(mut stream: &TcpStream, what: &str) {
    let page = format!("<!doctype html><meta charset=utf-8><p>{what}");
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{page}",
        page.len()
    );
    let _ = stream.flush();
}

/// Unguessable, and safe to put in a URL as it is.
fn nonce() -> Result<String> {
    let mut bytes = [0u8; NONCE_BYTES];
    getrandom::fill(&mut bytes)
        .map_err(|e| SourceError::Failed(format!("could not draw a random value: {e}")))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// What is sent in place of the secret, so the secret itself is only ever shown to the
/// authorisation server, and only once the code is already in hand.
fn challenge_for(verifier: &str) -> String {
    use sha2::Digest as _;

    let digest = sha2::Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Percent-encoding, keeping only what every reading of the standard leaves alone.
fn encode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// The reverse, for what comes back in the redirect.
fn decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;

    while at < bytes.len() {
        match bytes[at] {
            b'+' => {
                out.push(b' ');
                at += 1;
            }
            b'%' if at + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[at + 1..at + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        at += 3;
                    }
                    // Not an escape after all, so it is a literal per cent.
                    Err(_) => {
                        out.push(b'%');
                        at += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                at += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_goes_in_a_url_comes_back_out_of_it() {
        for raw in [
            "plain",
            "a b",
            "a/b?c=d&e",
            "sk-Ab_9.~-",
            "café",
            "100%",
            "",
        ] {
            assert_eq!(decode(&encode(raw)), raw, "{raw:?}");
        }
    }

    /// Google's own worked example, so the challenge is checkable against something outside
    /// this file. A wrong one is not rejected until the very last call of the flow.
    #[test]
    fn the_challenge_is_the_verifiers_digest_the_way_the_standard_writes_it() {
        assert_eq!(
            challenge_for("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn two_nonces_are_not_the_same_nonce() {
        let (a, b) = (nonce().unwrap(), nonce().unwrap());
        assert_ne!(a, b);
        assert_eq!(a, encode(&a), "and it survives being put in a URL");
    }

    #[test]
    fn a_consent_url_carries_everything_the_server_is_owed() {
        let flow = Flow {
            authorize: "https://auth.example/authorize",
            token: "https://auth.example/token",
            scope: "https://example/auth/drive.readonly",
            client_id: "an id".to_owned(),
            client_secret: "shh".to_owned(),
        };
        let url = flow.consent_url("http://127.0.0.1:1234", "st-ate", "chall");

        assert!(url.starts_with("https://auth.example/authorize?"));
        for expected in [
            "client_id=an%20id",
            "redirect_uri=http%3A%2F%2F127.0.0.1%3A1234",
            "response_type=code",
            "scope=https%3A%2F%2Fexample%2Fauth%2Fdrive.readonly",
            "state=st-ate",
            "code_challenge=chall",
            "code_challenge_method=S256",
            "access_type=offline",
            "prompt=consent",
        ] {
            assert!(url.contains(expected), "{expected} missing from {url}");
        }
        assert!(
            !url.contains("shh"),
            "the secret is for the token call, never the browser"
        );
    }

    /// A stand-in for the token endpoint. Answers one caller with `body`, and hands back what
    /// it was asked, so a test can check what was sent as well as what came of it.
    fn token_endpoint(
        body: &'static str,
        status: u16,
    ) -> (String, std::sync::mpsc::Receiver<String>) {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let url = format!(
            "http://127.0.0.1:{}/token",
            listener.local_addr().unwrap().port()
        );
        let (send, recv) = std::sync::mpsc::channel();

        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());

            // Headers, then exactly the body they promised.
            let mut length = 0usize;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap_or(0);
                }
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            let mut form = vec![0u8; length];
            std::io::Read::read_exact(&mut reader, &mut form).unwrap();
            let _ = send.send(String::from_utf8_lossy(&form).into_owned());

            let reason = if status == 200 { "OK" } else { "Bad Request" };
            write!(
                stream,
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        (url, recv)
    }

    /// Plays the browser: reads the consent URL, and goes where it says to go.
    fn browser_follows(url: &str) {
        let field = |key: &str| {
            url.split(['?', '&'])
                .filter_map(|pair| pair.split_once('='))
                .find(|(k, _)| *k == key)
                .map(|(_, v)| decode(v))
                .unwrap_or_default()
        };
        let (redirect, state) = (field("redirect_uri"), field("state"));

        std::thread::spawn(move || {
            let _ = ureq::get(format!(
                "{redirect}/?code=the-code&state={}",
                encode(&state)
            ))
            .config()
            .http_status_as_error(false)
            .build()
            .call();
        });
    }

    fn flow(token: String) -> Flow {
        Flow {
            authorize: "http://127.0.0.1:1/authorize",
            token: Box::leak(token.into_boxed_str()),
            scope: "scope",
            client_id: "an-id".to_owned(),
            client_secret: "a-secret".to_owned(),
        }
    }

    /// The whole loop: a socket held open, a browser sent to it, and the code that comes back
    /// traded for the lasting token — with the verifier the challenge was built from.
    #[test]
    fn a_sign_in_goes_out_to_the_browser_and_comes_back_as_a_token() {
        let (url, asked) = token_endpoint(
            r#"{"access_token":"at","refresh_token":"rt-123","expires_in":3599}"#,
            200,
        );

        let granted = flow(url).run(browser_follows).unwrap();
        assert_eq!(granted.refresh_token, "rt-123");

        let form = asked.recv().unwrap();
        assert!(form.contains("code=the-code"), "{form}");
        assert!(form.contains("grant_type=authorization_code"), "{form}");
        assert!(
            form.contains("code_verifier="),
            "PKCE is spent here: {form}"
        );
        assert!(form.contains("redirect_uri=http"), "{form}");
    }

    /// The case that actually happens: consent was remembered, so Google returns an access
    /// token and no lasting one, and there is nothing to store.
    #[test]
    fn a_sign_in_that_returns_nothing_lasting_says_so_rather_than_storing_nothing() {
        let (url, _asked) = token_endpoint(r#"{"access_token":"at","expires_in":3599}"#, 200);

        let err = flow(url).run(browser_follows).unwrap_err();
        assert!(err.to_string().contains("no lasting token"), "{err}");
    }

    /// Closing the window that started a sign-in has to release the thread now, not in five
    /// minutes. A blocking `accept` used to hold it for the whole consent window.
    #[test]
    fn giving_up_on_a_sign_in_releases_it_at_once() {
        let (url, _asked) = token_endpoint("{}", 200);

        let began = std::time::Instant::now();
        let waiting = std::thread::spawn(move || {
            flow(url).run(|_| {
                // Nobody is going to the browser. Given up on from the other thread instead.
            })
        });

        std::thread::sleep(Duration::from_millis(200));
        cancel();

        let err = waiting.join().unwrap().unwrap_err().to_string();
        let waited = began.elapsed();

        assert!(err.contains("stopped"), "said plainly: {err}");
        assert!(
            waited < Duration::from_secs(10),
            "it took {waited:?}, so it sat out the whole consent window"
        );
        assert!(waited < CONSENT_TIMEOUT / 2);
    }

    #[test]
    fn a_refusal_at_the_token_endpoint_is_repeated_in_its_own_words() {
        let (url, _asked) = token_endpoint(
            r#"{"error":"invalid_grant","error_description":"Bad code."}"#,
            400,
        );

        let err = flow(url).run(browser_follows).unwrap_err();
        assert!(err.to_string().contains("invalid_grant"), "{err}");
        assert!(err.to_string().contains("Bad code."), "{err}");
    }

    /// The redirect is a URL anything on this machine could hit. What makes an answer this
    /// process's own is the state it carries, so one carrying the wrong state is refused.
    #[test]
    fn a_redirect_from_someone_elses_sign_in_is_refused() {
        let (url, _asked) = token_endpoint("{}", 200);

        let err = flow(url)
            .run(|consent| {
                let redirect = consent
                    .split(['?', '&'])
                    .filter_map(|pair| pair.split_once('='))
                    .find(|(k, _)| *k == "redirect_uri")
                    .map(|(_, v)| decode(v))
                    .unwrap_or_default();

                std::thread::spawn(move || {
                    let _ = ureq::get(format!("{redirect}/?code=stolen&state=not-the-one"))
                        .config()
                        .http_status_as_error(false)
                        .build()
                        .call();
                });
            })
            .unwrap_err();

        assert!(err.to_string().contains("someone else's"), "{err}");
    }

    #[test]
    fn the_servers_own_words_are_what_gets_repeated() {
        let named = serde_json::json!({"error": "invalid_grant"});
        assert_eq!(complaint(&named, 400), "invalid_grant");

        let described = serde_json::json!({
            "error": "invalid_grant",
            "error_description": "Token has been expired or revoked."
        });
        assert_eq!(
            complaint(&described, 400),
            "invalid_grant: Token has been expired or revoked."
        );

        // Drive's own errors are shaped differently from the token endpoint's.
        let nested = serde_json::json!({"error": {"message": "File not found: abc."}});
        assert_eq!(complaint(&nested, 404), "File not found: abc.");

        assert_eq!(
            complaint(&serde_json::json!({}), 503),
            "the server answered 503"
        );
    }
}
