//! Google Drive.
//!
//! Drive is a graph rather than a tree — a file names its parents, and folders are files with
//! a particular type — so a scan walks it a folder at a time, breadth first, carrying where it
//! had got to in the cursor. One call to [`Source::scan`] is one request to Drive: the pump
//! keeps asking while a cursor comes back, and pausing between pages costs nothing.
//!
//! Files that Drive made rather than stored — Docs, Sheets, Slides — have no original bytes,
//! only renderings generated per request. They are listed as skipped rather than exported: an
//! export has no stable hash, so it could be neither deduplicated nor checked against what it
//! was promised to be, which is most of what this crate does with a file.

use std::io::Write;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::config::{Field, Fields};
use crate::oauth::{self, Flow};
use crate::registry::{Authorize, Registered, RegisteredSource};
use crate::source::{
    Checksum, Cursor, Digest, Item, Page, Result, Source, SourceError, SourceType,
};

/// This source's row in the registry.
pub(super) const ENTRY: Registered = Registered::of::<Drive>();

impl RegisteredSource for Drive {
    const NAME: &'static str = "drive";

    /// Remote rather than intermittent: Drive is either reachable or the network is down, and
    /// a scan that fails says so on its own.
    const TYPE: SourceType = SourceType::Remote;

    /// Shared by every Drive source, because these are this application's own credentials
    /// rather than anybody's account: they are what lets it ask Google for consent at all.
    /// Adding a second Drive does not mean registering with Google twice.
    const SETTINGS: &'static [Field] = &[
        Field::text("client_id", "OAuth client id"),
        Field::secret("client_secret", "OAuth client secret"),
    ];

    /// Per source, because *whose* Drive is what one differs from the next by.
    ///
    /// The token lives here rather than beside the credentials so that two sources can be two
    /// accounts. Nobody types it — signing in is what produces it — so it is declared and
    /// never asked for: it needs somewhere to be stored, and `signed_in` needs something to
    /// look at.
    const CONFIG: &'static [Field] = &[
        Field::text("folder", "Folder in Drive").optional(),
        Field::secret("refresh_token", "Refresh token")
            .optional()
            .kept(),
    ];

    const AUTH: Option<Authorize> = Some(authorize);

    /// Where to look while the sign-in is out at Google.
    const WAITING: &'static str = "finish signing in, in your browser";

    fn open(config: &Fields, settings: &Fields) -> Result<Box<dyn Source>> {
        Ok(Box::new(Drive::parse(config, settings)?))
    }
}

const CONSENT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN: &str = "https://oauth2.googleapis.com/token";
const API: &str = "https://www.googleapis.com/drive/v3";

/// Reading is all this does. Asking for less than full access is the difference between an
/// import and something that could delete the thing it is importing.
const SCOPE: &str = "https://www.googleapis.com/auth/drive.readonly";

/// How many entries to ask for at once. Well under Drive's own ceiling: a page is held in
/// memory whole, and a smaller one gets the first files moving sooner.
const PAGE: usize = 200;

/// Everything Drive made rather than stored shares this prefix.
const NATIVE: &str = "application/vnd.google-apps.";
const IS_FOLDER: &str = "application/vnd.google-apps.folder";
const IS_SHORTCUT: &str = "application/vnd.google-apps.shortcut";

/// Renewed this much before it lapses, so a token cannot go stale between being checked and
/// being used.
const EARLY: Duration = Duration::from_secs(60);

/// The name Drive answers to for the top of someone's own Drive.
const TOP: &str = "root";

/// Send someone to Google, and keep what comes back.
fn authorize(settings: &Fields) -> Result<Fields> {
    let flow = Flow {
        authorize: CONSENT,
        token: TOKEN,
        scope: SCOPE,
        client_id: required(settings, "client_id")?,
        client_secret: required(settings, "client_secret")?,
    };

    // So closing the window that started this actually stops it, rather than leaving the
    // button dead until the consent window runs out.
    crate::registry::stoppable(Some(oauth::cancel));
    let waited = flow.run(|url| {
        // Said three ways, because the one thing worse than this failing is it failing
        // silently: a window with no console shows nothing, and someone watching a spinner
        // for five minutes deserves somewhere to look.
        println!("Opening your browser to sign in to Google Drive.");
        println!("If nothing opens, go to:\n\n{url}\n");
        tracing::info!(%url, "waiting for a Google Drive sign-in in the browser");
        browse(url);
    });

    // Held rather than asked, so this runs whichever way the sign-in went. Saying a sign-in
    // is waiting when none is makes `stop` do something where it promises to do nothing.
    crate::registry::stoppable(None);
    let granted = waited?;

    let mut out = Fields::new();
    out.push("refresh_token", &granted.refresh_token);
    Ok(out)
}

struct Drive {
    client_id: String,
    client_secret: String,
    refresh_token: String,
    /// The folder to import, as a path within the Drive. Empty for all of it.
    folder: String,
    /// The token in hand and when it lapses. Behind a lock because a source is asked to scan
    /// and to fetch through a shared reference.
    token: Mutex<Option<(String, Instant)>>,
    /// The id `folder` resolved to, kept once found: it costs a request per path segment.
    top: Mutex<Option<String>>,
    /// Bounded, so a call cannot hang for ever, and kept, so a scan's hundreds of calls to
    /// the one host can share a connection.
    agent: ureq::Agent,
}

/// Written out by hand because two of its fields are the whole of someone's access to their
/// Drive, and a derived one would put them in the first log line that mentions a source.
impl std::fmt::Debug for Drive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Drive")
            .field("client_id", &self.client_id)
            .field("client_secret", &"…")
            .field("refresh_token", &"…")
            .field("folder", &self.folder)
            .finish_non_exhaustive()
    }
}

impl Drive {
    fn parse(config: &Fields, settings: &Fields) -> Result<Self> {
        config.check(Drive::NAME, Drive::CONFIG)?;
        settings.check(Drive::NAME, Drive::SETTINGS)?;

        let refresh_token = config.get("refresh_token").unwrap_or_default();
        if refresh_token.is_empty() {
            return Err(SourceError::config(
                Drive::NAME,
                "this source has not been signed in to; \"Sign in again\" on the Sources tab \
                 does it, or `ac import auth <source>`",
            ));
        }

        Ok(Self {
            client_id: required(settings, "client_id")?,
            client_secret: required(settings, "client_secret")?,
            refresh_token: refresh_token.to_owned(),
            folder: config.get("folder").unwrap_or_default().trim_matches('/').to_owned(),
            token: Mutex::new(None),
            top: Mutex::new(None),
            agent: crate::http::agent(),
        })
    }

    /// A token that can be used now, renewed if the one in hand is spent.
    fn access(&self) -> Result<String> {
        let mut held = self.token.lock().unwrap_or_else(|e| e.into_inner());

        if let Some((token, until)) = held.as_ref()
            && Instant::now() + EARLY < *until
        {
            return Ok(token.clone());
        }

        let (token, lasts) = oauth::refresh(
            TOKEN,
            &self.client_id,
            &self.client_secret,
            &self.refresh_token,
        )?;
        *held = Some((token.clone(), Instant::now() + lasts));
        Ok(token)
    }

    /// The id of the folder a scan starts at.
    fn top(&self) -> Result<String> {
        let mut known = self.top.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(id) = known.as_ref() {
            return Ok(id.clone());
        }

        let mut at = TOP.to_owned();
        for part in self.folder.split('/').filter(|part| !part.is_empty()) {
            at = self.child_folder(&at, part)?;
        }
        *known = Some(at.clone());
        Ok(at)
    }

    /// One step down a folder path.
    fn child_folder(&self, parent: &str, name: &str) -> Result<String> {
        let query = format!(
            "name = '{}' and '{}' in parents and mimeType = '{IS_FOLDER}' and trashed = false",
            escape(name),
            escape(parent),
        );
        let found: Listing = self.get(
            &format!("{API}/files"),
            &[
                ("q", &query),
                ("fields", "files(id)"),
                ("pageSize", "1"),
                ("supportsAllDrives", "true"),
                ("includeItemsFromAllDrives", "true"),
            ],
        )?;

        match found.files.into_iter().next() {
            Some(entry) => Ok(entry.id),
            None => Err(SourceError::Failed(format!(
                "there is no folder called {name:?} in {:?}",
                match self.folder.is_empty() {
                    true => "your Drive",
                    false => self.folder.as_str(),
                }
            ))),
        }
    }

    /// One page of one folder.
    fn listing(&self, folder: &str, page: Option<&str>) -> Result<Listing> {
        let query = format!("'{}' in parents and trashed = false", escape(folder));
        let size = PAGE.to_string();
        let mut params: Vec<(&str, &str)> = vec![
            ("q", &query),
            (
                "fields",
                "nextPageToken,files(id,name,mimeType,size,md5Checksum)",
            ),
            ("pageSize", &size),
            // Folders first, so a scan reaches the whole shape of a Drive sooner.
            ("orderBy", "folder,name"),
            ("supportsAllDrives", "true"),
            ("includeItemsFromAllDrives", "true"),
        ];
        if let Some(token) = page {
            params.push(("pageToken", token));
        }
        self.get(&format!("{API}/files"), &params)
    }

    /// A call that answers with JSON.
    fn get<T: for<'de> Deserialize<'de>>(&self, url: &str, params: &[(&str, &str)]) -> Result<T> {
        let mut response = self
            .request(url, params)?
            .config()
            // JSON, so the whole answer can be held to a deadline. `fetch` reads a file
            // through the same builder and deliberately does not.
            .timeout_recv_body(Some(crate::http::SMALL_BODY))
            .build()
            .call()
            .map_err(|e| SourceError::Failed(format!("could not reach Google Drive: {e}")))?;

        let status = response.status();
        if !status.is_success() {
            let complaint = response
                .body_mut()
                .read_json::<serde_json::Value>()
                .ok()
                .map_or_else(
                    || format!("Drive answered {status}"),
                    |body| oauth::complaint(&body, status.as_u16()),
                );
            return Err(SourceError::Failed(complaint));
        }

        response
            .body_mut()
            .read_json()
            .map_err(|e| SourceError::Failed(format!("Drive answered with nonsense: {e}")))
    }

    fn request(
        &self,
        url: &str,
        params: &[(&str, &str)],
    ) -> Result<ureq::RequestBuilder<ureq::typestate::WithoutBody>> {
        let token = self.access()?;
        let query: Vec<String> = params
            .iter()
            .map(|(key, value)| format!("{key}={}", encode(value)))
            .collect();

        Ok(self
            .agent
            .get(format!("{url}?{}", query.join("&")))
            .config()
            .http_status_as_error(false)
            .build()
            .header("Authorization", format!("Bearer {token}")))
    }
}

impl Source for Drive {
    fn source_type(&self) -> SourceType {
        Self::TYPE
    }

    fn scan(&self, from: Option<&Cursor>) -> Result<Page> {
        let mut spot = match from {
            Some(raw) => Spot::decode(raw)?,
            None => Spot::start(self.top()?),
        };

        // Where the last page ended a folder and there was nothing after it.
        let Some(here) = spot.at.clone().or_else(|| spot.pending.pop()) else {
            return Ok(Page::default());
        };

        let listing = self.listing(&here.id, spot.page.as_deref())?;
        walk(here, listing, &mut spot)
    }

    fn fetch(&self, item: &Item, into: &mut dyn Write) -> Result<()> {
        let mut response = self
            .request(
                &format!("{API}/files/{}", item.reference),
                &[("alt", "media"), ("supportsAllDrives", "true")],
            )?
            .call()
            .map_err(|e| SourceError::Failed(format!("could not fetch {}: {e}", item.name)))?;

        let status = response.status();
        if status == 404 || status == 410 {
            return Err(SourceError::Gone {
                reference: item.reference.clone(),
            });
        }
        if !status.is_success() {
            let complaint = response
                .body_mut()
                .read_json::<serde_json::Value>()
                .ok()
                .map_or_else(
                    || format!("Drive answered {status}"),
                    |body| oauth::complaint(&body, status.as_u16()),
                );
            return Err(SourceError::Failed(format!(
                "could not fetch {}: {complaint}",
                item.name
            )));
        }

        // Streamed rather than held: these are photos and video, and the whole point of
        // writing into what the caller handed over is that it never all sits in memory.
        let mut body = response.body_mut().as_reader();
        std::io::copy(&mut body, into)
            .map_err(|e| SourceError::io(format!("the copy of {}", item.name), e))?;
        Ok(())
    }
}

/// What one page of one folder adds to the scan, and where that leaves it.
///
/// Apart from the request that produced the listing, because this is the whole of the walk:
/// which entries are files, which are folders still owed, and whether there is anything left
/// to come back for. A cursor that says there is more when there is not would have the pump
/// asking for ever.
fn walk(here: Place, listing: Listing, spot: &mut Spot) -> Result<Page> {
    let mut page = Page::default();

    for entry in listing.files {
        let path = join(&here.path, &entry.name);
        match entry.kind() {
            Kind::Folder => spot.pending.push(Place { id: entry.id, path }),
            Kind::Native(what) => page
                .skipped
                .push(format!("skipping {path} ({what} has no original bytes)")),
            Kind::Shortcut => page
                .skipped
                .push(format!("skipping {path} (a shortcut to somewhere else)")),
            Kind::File => page.items.push(Item {
                reference: entry.id,
                folder: here.path.clone(),
                name: entry.name,
                size: entry.size.as_deref().and_then(|size| size.parse().ok()),
                // Drive publishes one for anything it merely stored, which is exactly the
                // set of things reaching this arm.
                checksum: entry.md5_checksum.map(|value| Checksum {
                    algo: Digest::Md5,
                    value,
                }),
            }),
        }
    }

    // Either there is more of this folder, or it is done and the next one is owed.
    match listing.next_page_token {
        Some(token) => {
            spot.at = Some(here);
            spot.page = Some(token);
        }
        None => {
            spot.at = None;
            spot.page = None;
        }
    }

    page.next = match spot.at.is_some() || !spot.pending.is_empty() {
        true => Some(spot.encode()?),
        false => None,
    };
    Ok(page)
}

/// How far a scan has got, carried in the cursor between calls.
///
/// Drive gives out a token for the next page of one listing, which is enough to finish a
/// folder and nothing more. The rest of this is the walk itself: the folders found but not
/// yet opened, so a scan can be put down after any page and picked up later.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Spot {
    /// Found and still owed, deepest last.
    pending: Vec<Place>,
    /// The folder being read, while there is more of it.
    at: Option<Place>,
    /// Where in that folder's listing.
    page: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Place {
    id: String,
    /// Where it sits within the source, which is what the bulk actions group by.
    path: String,
}

impl Spot {
    fn start(id: String) -> Self {
        Self {
            at: Some(Place {
                id,
                path: String::new(),
            }),
            ..Self::default()
        }
    }

    fn encode(&self) -> Result<Cursor> {
        serde_json::to_string(self)
            .map_err(|e| SourceError::Failed(format!("could not write down where the scan got to: {e}")))
    }

    fn decode(raw: &str) -> Result<Self> {
        serde_json::from_str(raw)
            .map_err(|e| SourceError::Failed(format!("could not read where the scan got to: {e}")))
    }
}

/// One entry of a listing, in Drive's own words.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    id: String,
    name: String,
    mime_type: String,
    /// A string, because Drive counts bytes past what a JSON number is trusted to hold.
    size: Option<String>,
    md5_checksum: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Listing {
    #[serde(default)]
    files: Vec<Entry>,
    next_page_token: Option<String>,
}

enum Kind {
    Folder,
    Shortcut,
    /// Made by Drive rather than stored by it, named the way a person would say it.
    Native(&'static str),
    File,
}

impl Entry {
    fn kind(&self) -> Kind {
        match self.mime_type.as_str() {
            IS_FOLDER => Kind::Folder,
            IS_SHORTCUT => Kind::Shortcut,
            other if other.starts_with(NATIVE) => Kind::Native(match other {
                "application/vnd.google-apps.document" => "a Google Doc",
                "application/vnd.google-apps.spreadsheet" => "a Google Sheet",
                "application/vnd.google-apps.presentation" => "a Google Slides deck",
                "application/vnd.google-apps.drawing" => "a Google Drawing",
                "application/vnd.google-apps.form" => "a Google Form",
                _ => "a file Drive made",
            }),
            _ => Kind::File,
        }
    }
}

fn required(settings: &Fields, key: &'static str) -> Result<String> {
    match settings.get(key).filter(|value| !value.is_empty()) {
        Some(value) => Ok(value.to_owned()),
        None => Err(SourceError::config(Drive::NAME, format!("{key} is required"))),
    }
}

fn join(folder: &str, name: &str) -> String {
    match folder.is_empty() {
        true => name.to_owned(),
        false => format!("{folder}/{name}"),
    }
}

/// Drive's query language quotes with a single quote and escapes with a backslash. A name
/// carrying either would otherwise end the string early and change what was asked.
fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "\\'")
}

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

/// Hand a URL to whatever the desktop opens them with. Best effort on purpose: the URL is
/// printed too, and a machine with no browser is a normal place to be running this.
fn browse(url: &str) {
    let opener = match () {
        _ if cfg!(target_os = "linux") => "xdg-open",
        _ if cfg!(target_os = "macos") => "open",
        _ if cfg!(target_os = "windows") => "explorer",
        _ => return,
    };
    let _ = std::process::Command::new(opener)
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The application's own credentials, shared by every Drive source.
    fn settings() -> Fields {
        let mut fields = Fields::new();
        fields.push("client_id", "an-id").push("client_secret", "a-secret");
        fields
    }

    /// One source's own: which Drive, and whose.
    fn signed_in() -> Fields {
        let mut fields = Fields::new();
        fields.push("refresh_token", "a-token");
        fields
    }

    #[test]
    fn a_drive_nobody_has_signed_in_to_says_how_to_sign_in() {
        let err = Drive::parse(&Fields::new(), &settings())
            .unwrap_err()
            .to_string();
        assert!(err.contains("signed in"), "{err}");
        // Both ways in, because this reaches a window and a terminal alike.
        assert!(err.contains("Sign in again"), "{err}");
        assert!(err.contains("ac import auth"), "{err}");
    }

    /// Anything holding a live credential gets printed sooner or later — a trace, a panic,
    /// an error being formatted for a log — and this one holds two.
    #[test]
    fn printing_a_drive_does_not_print_the_way_into_it() {
        let drive = Drive::parse(&signed_in(), &settings()).unwrap();
        let shown = format!("{drive:?}");

        assert!(!shown.contains("a-secret"), "{shown}");
        assert!(!shown.contains("a-token"), "{shown}");
        assert!(shown.contains("an-id"), "the id is not a secret: {shown}");
    }

    /// A scan runs on a blocking thread, and a blocking thread cannot be cancelled: a call
    /// that hangs for ever is a node that will not shut down.
    #[test]
    fn a_drive_that_stops_answering_is_given_up_on_rather_than_waited_for() {
        let drive = Drive::parse(&signed_in(), &settings()).unwrap();
        let timeouts = drive.agent.config().timeouts();

        assert!(timeouts.connect.is_some());
        assert!(timeouts.recv_response.is_some());
        assert_eq!(
            timeouts.recv_body, None,
            "a file is as long as it is; only the JSON calls ask for a body deadline"
        );
    }

    #[test]
    fn the_folder_is_optional_and_means_the_whole_drive_when_left_out() {
        let drive = Drive::parse(&signed_in(), &settings()).unwrap();
        assert_eq!(drive.folder, "");

        let mut config = signed_in();
        config.push("folder", "/Photos/2024/");
        let narrowed = Drive::parse(&config, &settings()).unwrap();
        assert_eq!(narrowed.folder, "Photos/2024", "the slashes are ours to add");
    }

    /// A name is not a literal: Drive reads the query as a language, and an apostrophe in a
    /// folder name would otherwise end the string and turn the rest into syntax.
    #[test]
    fn a_name_with_a_quote_in_it_cannot_change_the_question() {
        assert_eq!(escape("Ana's photos"), "Ana\\'s photos");
        assert_eq!(escape("back\\slash"), "back\\\\slash");
        assert_eq!(escape("plain"), "plain");
    }

    #[test]
    fn what_drive_made_is_told_apart_from_what_it_was_given() {
        let entry = |mime: &str| Entry {
            id: "id".to_owned(),
            name: "n".to_owned(),
            mime_type: mime.to_owned(),
            size: None,
            md5_checksum: None,
        };

        assert!(matches!(entry(IS_FOLDER).kind(), Kind::Folder));
        assert!(matches!(entry(IS_SHORTCUT).kind(), Kind::Shortcut));
        assert!(matches!(entry("image/jpeg").kind(), Kind::File));
        assert!(matches!(entry("video/mp4").kind(), Kind::File));
        assert!(matches!(entry("application/pdf").kind(), Kind::File));

        let Kind::Native(what) = entry("application/vnd.google-apps.document").kind() else {
            panic!("a Doc has no bytes of its own");
        };
        assert_eq!(what, "a Google Doc");
        assert!(matches!(
            entry("application/vnd.google-apps.jam").kind(),
            Kind::Native(_)
        ));
    }

    /// The cursor is the whole of what a scan carries between calls: everything it has found
    /// and not yet opened has to survive the round trip, or the walk would forget a branch.
    #[test]
    fn where_a_scan_got_to_survives_being_written_down() {
        let spot = Spot {
            pending: vec![
                Place {
                    id: "a".to_owned(),
                    path: "DCIM".to_owned(),
                },
                Place {
                    id: "b".to_owned(),
                    path: "DCIM/2024".to_owned(),
                },
            ],
            at: Some(Place {
                id: "c".to_owned(),
                path: String::new(),
            }),
            page: Some("token".to_owned()),
        };

        let back = Spot::decode(&spot.encode().unwrap()).unwrap();
        assert_eq!(back.pending.len(), 2);
        assert_eq!(back.pending[1].path, "DCIM/2024");
        assert_eq!(back.at.map(|at| at.id).as_deref(), Some("c"));
        assert_eq!(back.page.as_deref(), Some("token"));
    }

    #[test]
    fn a_fresh_scan_starts_at_the_folder_it_was_pointed_at() {
        let spot = Spot::start("some-id".to_owned());
        assert_eq!(spot.at.as_ref().map(|at| at.id.as_str()), Some("some-id"));
        assert_eq!(
            spot.at.as_ref().map(|at| at.path.as_str()),
            Some(""),
            "the top of a source is not a folder within it"
        );
        assert!(spot.pending.is_empty());
    }

    #[test]
    fn a_path_within_the_source_reads_the_way_it_would_be_typed() {
        assert_eq!(join("", "a.jpg"), "a.jpg");
        assert_eq!(join("DCIM", "a.jpg"), "DCIM/a.jpg");
        assert_eq!(join("DCIM/2024", "a.jpg"), "DCIM/2024/a.jpg");
    }

    fn file(id: &str, name: &str) -> Entry {
        Entry {
            id: id.to_owned(),
            name: name.to_owned(),
            mime_type: "image/jpeg".to_owned(),
            size: Some("1024".to_owned()),
            md5_checksum: Some("d41d8c".to_owned()),
        }
    }

    fn folder(id: &str, name: &str) -> Entry {
        Entry {
            id: id.to_owned(),
            name: name.to_owned(),
            mime_type: IS_FOLDER.to_owned(),
            size: None,
            md5_checksum: None,
        }
    }

    fn listing(files: Vec<Entry>, next: Option<&str>) -> Listing {
        Listing {
            files,
            next_page_token: next.map(str::to_owned),
        }
    }

    fn at(id: &str, path: &str) -> Place {
        Place {
            id: id.to_owned(),
            path: path.to_owned(),
        }
    }

    #[test]
    fn a_file_carries_what_drive_already_knew_about_it() {
        let mut spot = Spot::start("root".to_owned());
        let page = walk(at("root", ""), listing(vec![file("f1", "a.jpg")], None), &mut spot).unwrap();

        assert_eq!(page.items.len(), 1);
        let item = &page.items[0];
        assert_eq!(item.reference, "f1", "the id, because a name is not unique");
        assert_eq!(item.name, "a.jpg");
        assert_eq!(item.folder, "", "the top of the source is not a folder in it");
        assert_eq!(item.size, Some(1024));
        assert_eq!(
            item.checksum.as_ref().map(|c| (c.algo, c.value.as_str())),
            Some((Digest::Md5, "d41d8c")),
            "so the bytes can be checked against what was promised"
        );
        assert!(page.next.is_none(), "one folder, one page, nothing left");
    }

    #[test]
    fn a_folder_is_kept_for_later_rather_than_descended_into_now() {
        let mut spot = Spot::start("root".to_owned());
        let page = walk(
            at("root", ""),
            listing(vec![folder("d1", "DCIM"), file("f1", "a.jpg")], None),
            &mut spot,
        )
        .unwrap();

        assert_eq!(page.items.len(), 1, "the folder is not a file");
        assert_eq!(spot.pending.len(), 1);
        assert_eq!(spot.pending[0].path, "DCIM");
        assert!(spot.at.is_none(), "this folder is finished");
        assert!(page.next.is_some(), "but the scan is not");
    }

    #[test]
    fn a_folder_with_more_pages_is_stayed_in() {
        let mut spot = Spot::start("root".to_owned());
        let page = walk(
            at("root", ""),
            listing(vec![file("f1", "a.jpg")], Some("page-2")),
            &mut spot,
        )
        .unwrap();

        assert_eq!(spot.at.as_ref().map(|p| p.id.as_str()), Some("root"));
        assert_eq!(spot.page.as_deref(), Some("page-2"));
        assert!(page.next.is_some());
    }

    /// The property the pump depends on: a scan that keeps handing back a cursor never ends.
    /// Driven here the way the pump drives it, over a Drive shaped like a small photo library.
    #[test]
    fn a_whole_walk_reaches_every_folder_and_then_stops() {
        // root: a.jpg + DCIM/ + Docs/ ; DCIM: two pages ; Docs: a native doc only.
        let pages: Vec<Listing> = vec![
            listing(
                vec![folder("d1", "DCIM"), folder("d2", "Docs"), file("f1", "a.jpg")],
                None,
            ),
            listing(vec![file("f2", "b.jpg")], Some("more")),
            listing(vec![file("f3", "c.jpg"), folder("d3", "2024")], None),
            listing(
                vec![Entry {
                    id: "g1".to_owned(),
                    name: "Notes".to_owned(),
                    mime_type: "application/vnd.google-apps.document".to_owned(),
                    size: None,
                    md5_checksum: None,
                }],
                None,
            ),
            listing(vec![file("f4", "d.jpg")], None),
        ];

        let mut spot = Spot::start("root".to_owned());
        let mut cursor: Option<Cursor> = None;
        let (mut found, mut skipped, mut rounds) = (Vec::new(), Vec::new(), 0);

        for listing in pages {
            if rounds > 0 {
                let raw = cursor.clone().expect("the walk said there was more");
                spot = Spot::decode(&raw).unwrap();
            }
            let here = spot.at.clone().or_else(|| spot.pending.pop()).unwrap();

            let page = walk(here, listing, &mut spot).unwrap();
            found.extend(page.items.iter().map(|i| i.name.clone()));
            skipped.extend(page.skipped);
            cursor = page.next;
            rounds += 1;
        }

        assert!(cursor.is_none(), "the walk ends rather than looping");
        found.sort();
        assert_eq!(found, ["a.jpg", "b.jpg", "c.jpg", "d.jpg"]);
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].contains("Google Doc"), "{:?}", skipped[0]);
    }

    /// Where a file sits is what the bulk actions group by, so it has to be the path down
    /// from the top of the source rather than the name of the one folder it is in.
    #[test]
    fn a_file_deep_in_the_tree_is_filed_under_the_whole_path_to_it() {
        let mut spot = Spot {
            pending: vec![at("d3", "DCIM/2024")],
            at: None,
            page: None,
        };
        let here = spot.pending.pop().unwrap();
        let page = walk(here, listing(vec![file("f9", "e.jpg")], None), &mut spot).unwrap();

        assert_eq!(page.items[0].folder, "DCIM/2024");
        assert!(page.next.is_none());
    }

    /// Drive's own field names, so a rename on their side is caught here rather than as an
    /// import that quietly finds nothing.
    #[test]
    fn a_listing_is_read_the_way_drive_writes_it() {
        let listing: Listing = serde_json::from_str(
            r#"{
                "nextPageToken": "more",
                "files": [
                    {"id": "1", "name": "a.jpg", "mimeType": "image/jpeg",
                     "size": "2097152", "md5Checksum": "abc123"},
                    {"id": "2", "name": "Trip", "mimeType": "application/vnd.google-apps.folder"}
                ]
            }"#,
        )
        .unwrap();

        assert_eq!(listing.next_page_token.as_deref(), Some("more"));
        assert_eq!(listing.files.len(), 2);
        assert_eq!(listing.files[0].size.as_deref(), Some("2097152"));
        assert_eq!(listing.files[0].md5_checksum.as_deref(), Some("abc123"));
        assert!(listing.files[1].size.is_none(), "a folder is not a size");

        // An empty Drive answers without the key at all.
        let empty: Listing = serde_json::from_str("{}").unwrap();
        assert!(empty.files.is_empty() && empty.next_page_token.is_none());
    }
}
