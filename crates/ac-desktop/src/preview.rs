use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use slint::{ComponentHandle, Weak};

use crate::ui::MainWindow;

/// One behind, the one on screen, one ahead. Both the prefetch distance and the cache cap,
/// deliberately one number: a cache smaller than the window would evict exactly what the
/// worker just fetched.
pub const PREVIEW_WINDOW: usize = 3;

/// The longest side a cached preview may have. A 100-megapixel photo decoded to RGBA is
/// 400MB of memory for something shown at about a thousand pixels.
const PREVIEW_MAX: u32 = 1400;

/// What a route's tool gets before it is killed. A tool that hangs must not wedge the
/// worker, which would take every later preview with it.
const TOOL_TIMEOUT: Duration = Duration::from_secs(20);

/// How often a running tool is looked in on.
const POLL: Duration = Duration::from_millis(50);

/// How a file becomes a picture. Chosen by extension, which is all that is known before
/// anything is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// What the `image` crate reads itself.
    BuiltIn,
    /// A first frame, pulled with ffmpeg. iPhones shoot HEVC in `.mov` and Android H.264
    /// in `.mp4`, and one route covers the lot.
    Video,
    Heic,
    /// Every RAW embeds a full-size JPEG, so nothing here decodes RAW itself.
    Raw,
}

/// Which route a name takes, or none at all. Pure, and tested as one.
pub fn route_for(name: &str) -> Option<Route> {
    let ext = Path::new(name).extension()?.to_str()?.to_ascii_lowercase();
    Some(match ext.as_str() {
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "tif" | "tiff" | "webp" => Route::BuiltIn,
        "mov" | "mp4" | "avi" | "mkv" | "webm" | "3gp" | "avif" => Route::Video,
        "heic" | "heif" => Route::Heic,
        "cr2" | "cr3" | "nef" | "arw" | "dng" | "raf" | "orf" => Route::Raw,
        _ => return None,
    })
}

/// Which routes this machine can actually take, settled once at startup. A missing tool
/// degrades the tab rather than breaking it, which is a designed state and not an error.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tools {
    pub ffmpeg: bool,
    /// Whichever of the two is here, since macOS ships one and Linux the other.
    pub heif: Option<&'static str>,
}

pub fn detect() -> Tools {
    Tools {
        ffmpeg: on_path("ffmpeg"),
        heif: ["heif-convert", "sips"]
            .into_iter()
            .find(|tool| on_path(tool)),
    }
}

impl Tools {
    pub fn can(&self, route: Route) -> bool {
        match route {
            // Neither needs anything installed: one is decoded in this binary, and the
            // other is a JPEG this binary goes and finds.
            Route::BuiltIn | Route::Raw => true,
            Route::Video => self.ffmpeg,
            Route::Heic => self.heif.is_some(),
        }
    }
}

fn on_path(tool: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join(tool).is_file()))
}

/// The previews on disk, newest last. Keyed by content hash, so an entry is unambiguous and
/// outlives a restart.
pub struct Cache {
    dir: PathBuf,
    recent: Mutex<VecDeque<String>>,
}

impl Cache {
    pub fn at(dir: PathBuf) -> Self {
        let _ = std::fs::create_dir_all(&dir);
        Self {
            dir,
            recent: Mutex::new(VecDeque::new()),
        }
    }

    pub fn path(&self, hash: &str) -> PathBuf {
        self.dir.join(format!("{hash}.png"))
    }

    pub fn has(&self, hash: &str) -> bool {
        self.path(hash).is_file()
    }

    /// Say this one was just wanted, and drop whatever falls out of the window. Bounding it
    /// by the window is what saves it needing a size budget of its own.
    pub fn touch(&self, hash: &str) {
        let mut recent = match self.recent.lock() {
            Ok(recent) => recent,
            Err(poisoned) => poisoned.into_inner(),
        };

        recent.retain(|seen| seen != hash);
        recent.push_back(hash.to_owned());
        while recent.len() > PREVIEW_WINDOW {
            if let Some(evicted) = recent.pop_front() {
                let _ = std::fs::remove_file(self.path(&evicted));
            }
        }
    }
}

/// One file to turn into a preview, and the window to tell when it is there.
struct Job {
    hash: String,
    path: PathBuf,
    show: Option<Weak<MainWindow>>,
}

/// The worker, its cache, and what this machine can decode.
pub struct Previews {
    cache: Arc<Cache>,
    tools: Tools,
    want: Sender<Job>,
    /// Previews actually produced. Read only by the test that proves the window is not
    /// re-fetched as it is stepped through, which is the whole reason it is counted.
    #[allow(dead_code)]
    made: Arc<AtomicUsize>,
}

/// The one worker for the process. It owns a thread and a directory, so there is no sense
/// in a second.
pub fn previews() -> &'static Previews {
    static PREVIEWS: OnceLock<Previews> = OnceLock::new();
    PREVIEWS.get_or_init(|| Previews::start(cache_dir(), detect()))
}

fn cache_dir() -> PathBuf {
    // Derived data, so it goes where the OS puts derived data — never under the storage
    // root, which was just taught to count `.unsorted` against the content budget.
    directories::ProjectDirs::from("", "", "archiverclient")
        .map(|dirs| dirs.cache_dir().join("previews"))
        .unwrap_or_else(std::env::temp_dir)
}

impl Previews {
    pub fn start(dir: PathBuf, tools: Tools) -> Self {
        let cache = Arc::new(Cache::at(dir));
        let made = Arc::new(AtomicUsize::new(0));
        let (want, jobs) = channel::<Job>();

        std::thread::spawn({
            let (cache, made) = (Arc::clone(&cache), Arc::clone(&made));
            move || {
                // Off the event loop by construction: an ffmpeg run is far too slow to do
                // anywhere a frame is waiting on it.
                while let Ok(job) = jobs.recv() {
                    work(&cache, tools, &made, job);
                }
            }
        });

        Self {
            cache,
            tools,
            want,
            made,
        }
    }

    #[cfg(test)]
    pub fn made(&self) -> usize {
        self.made.load(Ordering::Relaxed)
    }

    /// The preview for what is on screen. Already cached, it is handed over now; otherwise
    /// the tile stands until the worker has it.
    pub fn show(&self, window: &MainWindow, hash: &str, path: &Path) {
        if hash.is_empty() {
            window.set_sort_preview(Default::default());
            return;
        }

        if self.cache.has(hash) {
            self.cache.touch(hash);
            window.set_sort_preview(load(&self.cache.path(hash)));
            return;
        }

        window.set_sort_preview(Default::default());
        self.enqueue(hash, path, Some(window.as_weak()));
    }

    /// Fetch one the reader has not asked for yet, so stepping either way is instant.
    pub fn prefetch(&self, hash: &str, path: &Path) {
        if hash.is_empty() || self.cache.has(hash) {
            return;
        }
        self.enqueue(hash, path, None);
    }

    fn enqueue(&self, hash: &str, path: &Path, show: Option<Weak<MainWindow>>) {
        if !self.wanted(path) {
            return;
        }
        let _ = self.want.send(Job {
            hash: hash.to_owned(),
            path: path.to_owned(),
            show,
        });
    }

    /// Whether this file has a route at all, and whether this machine can take it. Both
    /// answers mean the tile, and neither is worth waking the worker for.
    fn wanted(&self, path: &Path) -> bool {
        let name = path.file_name().and_then(|name| name.to_str());
        name.and_then(route_for)
            .is_some_and(|route| self.tools.can(route))
    }
}

fn work(cache: &Cache, tools: Tools, made: &AtomicUsize, job: Job) {
    // Asked for twice while it sat in the queue, or fetched as a neighbour and then
    // stepped onto. Either way it is here, and running the tool again buys nothing.
    if !cache.has(&job.hash) {
        // Built beside the entry and renamed into place, so `has` is never true of a file
        // still being written: a reader that caught one mid-write would be handed half a
        // picture, which is the same rule `Content::commit` follows for content itself.
        let dest = cache.path(&job.hash);
        let building = dest.with_extension("part");

        if let Err(error) = produce(tools, &job.path, &building) {
            tracing::debug!(file = %job.path.display(), error = %format!("{error:#}"), "no preview");
            let _ = std::fs::remove_file(&building);
            return;
        }
        if let Err(error) = std::fs::rename(&building, &dest) {
            tracing::debug!(file = %job.path.display(), %error, "could not put the preview in place");
            let _ = std::fs::remove_file(&building);
            return;
        }
        made.fetch_add(1, Ordering::Relaxed);
    }
    cache.touch(&job.hash);

    let Some(window) = job.show else {
        return;
    };
    let at = cache.path(&job.hash);
    let hash = job.hash;
    let _ = window.upgrade_in_event_loop(move |window| {
        // It may have been stepped past while the tool ran, and the file on screen now
        // owns the preview.
        if window.get_sort_hash() == hash.as_str() {
            window.set_sort_preview(load(&at));
        }
    });
}

fn load(path: &Path) -> slint::Image {
    slint::Image::load_from_path(path).unwrap_or_default()
}

/// Turn one file into a capped, right-way-up preview.
fn produce(tools: Tools, src: &Path, dest: &Path) -> Result<()> {
    let name = src
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let route = route_for(name).with_context(|| format!("nothing previews {name}"))?;
    if !tools.can(route) {
        bail!("no tool installed for {route:?}");
    }

    match route {
        Route::BuiltIn => shrink(src, dest),
        // The three that need a tool all produce an ordinary picture first, and then take
        // the same path a jpeg does — so capping and orientation are written once.
        _ => {
            let extracted = dest.with_extension("extracted");
            let outcome = extract(tools, route, src, &extracted).and_then(|()| {
                shrink(&extracted, dest).with_context(|| format!("reading what {route:?} made"))
            });
            let _ = std::fs::remove_file(&extracted);
            outcome
        }
    }
}

/// Get *a* picture out of a file the `image` crate cannot open on its own.
fn extract(tools: Tools, route: Route, src: &Path, dest: &Path) -> Result<()> {
    let mut command = match route {
        Route::Video => {
            let mut command = std::process::Command::new("ffmpeg");
            command
                .arg("-y")
                .arg("-i")
                .arg(src)
                .args(["-frames:v", "1"])
                .arg("-f")
                .arg("image2")
                .arg(dest);
            command
        }
        Route::Heic => match tools.heif {
            Some("sips") => {
                let mut command = std::process::Command::new("sips");
                command
                    .args(["-s", "format", "jpeg"])
                    .arg(src)
                    .arg("--out")
                    .arg(dest);
                command
            }
            _ => {
                let mut command = std::process::Command::new("heif-convert");
                command.arg(src).arg(dest);
                command
            }
        },
        // Handled here rather than by a tool: see `embedded`.
        Route::Raw => return embedded(src, dest),
        Route::BuiltIn => bail!("the built-in route needs no tool"),
    };

    run(&mut command)?;
    match std::fs::metadata(dest).map(|meta| meta.len()).unwrap_or(0) {
        0 => bail!("{route:?} produced nothing"),
        _ => Ok(()),
    }
}

/// A RAW bigger than this is not read
const MAX_RAW: u64 = 256 * 1024 * 1024;

/// Below this, a JPEG inside a RAW is the little thumbnail rather than the preview.
const MIN_PREVIEW: u32 = 160;

/// The biggest usable JPEG inside a RAW, written out as it was found.
fn embedded(src: &Path, dest: &Path) -> Result<()> {
    let size = std::fs::metadata(src)
        .with_context(|| format!("reading {}", src.display()))?
        .len();
    if size > MAX_RAW {
        bail!("{} is too big to look inside", src.display());
    }

    let bytes = std::fs::read(src).with_context(|| format!("reading {}", src.display()))?;
    let mut found = jpegs(&bytes);
    found.sort_by_key(|range| std::cmp::Reverse(range.len()));

    for range in found {
        let candidate = &bytes[range];
        let Ok(reader) = image::ImageReader::new(std::io::Cursor::new(candidate))
            .with_guessed_format()
            .map(|reader| reader.into_dimensions())
        else {
            continue;
        };
        let Ok((width, height)) = reader else {
            continue;
        };
        if width < MIN_PREVIEW && height < MIN_PREVIEW {
            continue;
        }

        return std::fs::write(dest, candidate)
            .with_context(|| format!("writing {}", dest.display()));
    }
    bail!(
        "produced nothing: no preview is embedded in {}",
        src.display()
    )
}

/// Every complete JPEG in `bytes`, as byte ranges.
fn jpegs(bytes: &[u8]) -> Vec<std::ops::Range<usize>> {
    let mut out = Vec::new();
    let mut at = 0usize;

    while at + 3 < bytes.len() {
        if bytes[at] == 0xFF && bytes[at + 1] == 0xD8 && bytes[at + 2] == 0xFF {
            if let Some(end) = ends_at(bytes, at) {
                out.push(at..end);
                at = end;
                continue;
            }
        }
        at += 1;
    }
    out
}

/// Where the JPEG starting at `from` ends, or `None` if it never does.
fn ends_at(bytes: &[u8], from: usize) -> Option<usize> {
    let mut at = from + 2;

    loop {
        // Segments are allowed to be padded with fill bytes before their marker.
        while *bytes.get(at)? == 0xFF && *bytes.get(at + 1)? == 0xFF {
            at += 1;
        }
        if *bytes.get(at)? != 0xFF {
            return None;
        }
        let marker = *bytes.get(at + 1)?;
        at += 2;

        match marker {
            // The end.
            0xD9 => return Some(at),
            // Standalone: no length, nothing to skip.
            0x01 | 0xD0..=0xD7 => {}
            // The image data itself, which is not a segment: it runs until the next marker
            // that is not a stuffed 0xFF00 or a restart.
            0xDA => {
                at += length(bytes, at)?;
                loop {
                    while *bytes.get(at)? != 0xFF {
                        at += 1;
                    }
                    match *bytes.get(at + 1)? {
                        0x00 | 0xFF => at += 2,
                        0xD0..=0xD7 => at += 2,
                        _ => break,
                    }
                }
            }
            _ => at += length(bytes, at)?,
        }
    }
}

/// A segment's length, which counts its own two bytes.
fn length(bytes: &[u8], at: usize) -> Option<usize> {
    let len = u16::from_be_bytes([*bytes.get(at)?, *bytes.get(at + 1)?]) as usize;
    (len >= 2).then_some(len)
}

/// Run a tool, and kill it if it will not finish. A hung ffmpeg would otherwise take every
/// later preview with it.
fn run(command: &mut std::process::Command) -> Result<()> {
    let mut child = command
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("running {:?}", command.get_program()))?;

    let waited = std::time::Instant::now();
    loop {
        match child.try_wait()? {
            Some(status) if status.success() => return Ok(()),
            Some(status) => bail!("{:?} gave up: {status}", command.get_program()),
            None => {}
        }
        if waited.elapsed() > TOOL_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            bail!("{:?} took too long", command.get_program());
        }
        std::thread::sleep(POLL);
    }
}

/// Decode, turn the right way up, cap, and write the preview.
fn shrink(src: &Path, dest: &Path) -> Result<()> {
    let reader = image::ImageReader::open(src)
        .with_context(|| format!("opening {}", src.display()))?
        .with_guessed_format()
        .with_context(|| format!("reading {}", src.display()))?;

    let mut decoder = reader
        .into_decoder()
        .with_context(|| format!("decoding {}", src.display()))?;
    let orientation = image::ImageDecoder::orientation(&mut decoder)
        .unwrap_or(image::metadata::Orientation::NoTransforms);

    let mut picture = image::DynamicImage::from_decoder(decoder)
        .with_context(|| format!("decoding {}", src.display()))?;
    picture.apply_orientation(orientation);

    // Bounded by construction, including for the formats slint could have loaded itself.
    if picture.width() > PREVIEW_MAX || picture.height() > PREVIEW_MAX {
        picture = picture.thumbnail(PREVIEW_MAX, PREVIEW_MAX);
    }

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    picture
        .save_with_format(dest, image::ImageFormat::Png)
        .with_context(|| format!("writing {}", dest.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    /// A picture of a known size, written where the tests can point at it.
    fn picture(at: &Path, width: u32, height: u32) {
        let buffer = image::RgbImage::from_fn(width, height, |x, y| {
            image::Rgb([(x % 256) as u8, (y % 256) as u8, 128])
        });
        image::DynamicImage::ImageRgb8(buffer).save(at).unwrap();
    }

    #[test]
    fn a_name_takes_the_route_its_format_needs() {
        assert_eq!(route_for("IMG_1.JPG"), Some(Route::BuiltIn));
        assert_eq!(route_for("a/b/holiday.png"), Some(Route::BuiltIn));
        // An iPhone shoots this and an Android that, and one route covers both.
        assert_eq!(route_for("IMG_2.mov"), Some(Route::Video));
        assert_eq!(route_for("VID_3.mp4"), Some(Route::Video));
        assert_eq!(route_for("IMG_4.HEIC"), Some(Route::Heic));
        assert_eq!(route_for("DSC_5.NEF"), Some(Route::Raw));

        // A document from a Drive folder gets the tile, and this does not grow a renderer.
        assert_eq!(route_for("notes.pdf"), None);
        assert_eq!(route_for("no-extension"), None);
    }

    #[test]
    fn a_route_whose_tool_is_missing_is_one_this_machine_cannot_take() {
        let bare = Tools::default();
        assert!(bare.can(Route::BuiltIn), "decoding needs nothing installed");
        assert!(
            bare.can(Route::Raw),
            "and neither does finding an embedded jpeg"
        );
        assert!(!bare.can(Route::Video));
        assert!(!bare.can(Route::Heic));

        let equipped = Tools {
            ffmpeg: true,
            heif: Some("heif-convert"),
        };
        assert!(equipped.can(Route::Video) && equipped.can(Route::Heic));
    }

    #[test]
    fn a_huge_picture_comes_out_inside_the_cap() {
        let tmp = tmp();
        let src = tmp.path().join("big.png");
        let dest = tmp.path().join("small.png");
        picture(&src, PREVIEW_MAX * 2, PREVIEW_MAX);

        shrink(&src, &dest).unwrap();

        let made = image::image_dimensions(&dest).unwrap();
        assert!(
            made.0 <= PREVIEW_MAX && made.1 <= PREVIEW_MAX,
            "a preview is bounded by construction, not by what it was given: {made:?}"
        );
        assert!(made.0 > made.1, "and keeps its shape");
    }

    #[test]
    fn a_picture_already_inside_the_cap_is_left_at_its_own_size() {
        let tmp = tmp();
        let src = tmp.path().join("small.png");
        let dest = tmp.path().join("preview.png");
        picture(&src, 64, 48);

        shrink(&src, &dest).unwrap();
        assert_eq!(image::image_dimensions(&dest).unwrap(), (64, 48));
    }

    /// A jpeg carrying the tag a phone writes for a portrait shot held sideways.
    fn rotated(at: &Path, width: u32, height: u32) {
        let plain = at.with_extension("plain.jpg");
        picture(&plain, width, height);
        let body = std::fs::read(&plain).unwrap();

        // APP1: "Exif\0\0", then a little-endian TIFF header and one IFD entry saying
        // Orientation = 6, which is "rotate this a quarter turn".
        let mut exif: Vec<u8> = Vec::new();
        exif.extend(b"Exif\0\0");
        exif.extend(b"II\x2a\x00\x08\x00\x00\x00");
        exif.extend([0x01, 0x00]);
        exif.extend([0x12, 0x01, 0x03, 0x00]);
        exif.extend([0x01, 0x00, 0x00, 0x00]);
        exif.extend([0x06, 0x00, 0x00, 0x00]);
        exif.extend([0x00, 0x00, 0x00, 0x00]);

        let mut out: Vec<u8> = Vec::new();
        out.extend(&body[..2]); // SOI
        out.extend([0xff, 0xe1]);
        out.extend(((exif.len() + 2) as u16).to_be_bytes());
        out.extend(&exif);
        out.extend(&body[2..]);
        std::fs::write(at, out).unwrap();
    }

    #[test]
    fn a_portrait_photo_comes_out_the_right_way_up() {
        let tmp = tmp();
        let src = tmp.path().join("portrait.jpg");
        let dest = tmp.path().join("preview.png");
        // Stored landscape, tagged as needing a quarter turn: what a phone actually writes.
        rotated(&src, 200, 100);

        shrink(&src, &dest).unwrap();

        assert_eq!(
            image::image_dimensions(&dest).unwrap(),
            (100, 200),
            "the tag was applied, so it is taller than it is wide"
        );
    }

    #[test]
    fn the_cache_keeps_the_window_and_nothing_more() {
        let tmp = tmp();
        let cache = Cache::at(tmp.path().join("previews"));

        for at in 0..PREVIEW_WINDOW + 2 {
            let hash = format!("hash-{at}");
            std::fs::write(cache.path(&hash), b"a preview").unwrap();
            cache.touch(&hash);
        }

        assert!(!cache.has("hash-0"), "the oldest was evicted");
        assert!(!cache.has("hash-1"));
        for at in 2..PREVIEW_WINDOW + 2 {
            assert!(
                cache.has(&format!("hash-{at}")),
                "{at} should still be here"
            );
        }
    }

    #[test]
    fn stepping_back_onto_something_still_in_the_window_keeps_it() {
        let tmp = tmp();
        let cache = Cache::at(tmp.path().join("previews"));

        for hash in ["a", "b", "c"] {
            std::fs::write(cache.path(hash), b"x").unwrap();
            cache.touch(hash);
        }
        // Step back onto the first, which is what the window exists to make instant.
        cache.touch("a");

        std::fs::write(cache.path("d"), b"x").unwrap();
        cache.touch("d");

        assert!(cache.has("a"), "the one just looked at survived");
        assert!(!cache.has("b"), "the least recently wanted went instead");
    }

    #[test]
    fn a_file_with_no_route_is_never_handed_to_the_worker() {
        let tmp = tmp();
        let previews = Previews::start(tmp.path().join("previews"), Tools::default());

        assert!(!previews.wanted(Path::new("/somewhere/notes.pdf")));
        // A route this machine cannot take is the same answer, and for the same reason:
        // the tile is a designed state.
        assert!(!previews.wanted(Path::new("/somewhere/IMG_1.mov")));
        assert!(previews.wanted(Path::new("/somewhere/IMG_1.jpg")));
    }

    #[test]
    fn a_missing_tool_is_a_tile_rather_than_a_failure() {
        let tmp = tmp();
        let src = tmp.path().join("clip.mov");
        std::fs::write(&src, b"not really a video").unwrap();

        let error = produce(Tools::default(), &src, &tmp.path().join("out.png")).unwrap_err();
        assert!(
            error.to_string().contains("no tool"),
            "it says which route it cannot take: {error}"
        );
    }

    #[test]
    fn a_preview_is_made_once_however_often_it_is_asked_for() {
        let tmp = tmp();
        let src = tmp.path().join("a.png");
        picture(&src, 32, 32);

        let previews = Previews::start(tmp.path().join("previews"), detect());
        for _ in 0..4 {
            previews.prefetch("abc123", &src);
        }

        // The worker is a thread, so wait for it rather than racing it.
        for _ in 0..100 {
            if previews.cache.has("abc123") {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        assert!(previews.cache.has("abc123"));
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(
            previews.made(),
            1,
            "asking again for one already cached spawns nothing"
        );
    }

    /// A stand-in for a RAW: a container with a little thumbnail and a big preview inside
    /// it, which is the shape every one of them has.
    fn raw_with(at: &Path, embedded: &[(u32, u32)]) {
        let mut out: Vec<u8> = Vec::new();
        out.extend(b"II\x2a\x00\x08\x00\x00\x00");
        out.extend([0xFF, 0xD8, 0xFF, 0x11, 0x22, 0x33]);
        out.extend([0u8; 64]);

        for (width, height) in embedded {
            let mut jpeg: Vec<u8> = Vec::new();
            image::DynamicImage::ImageRgb8(image::RgbImage::from_fn(*width, *height, |x, y| {
                image::Rgb([(x % 256) as u8, (y % 256) as u8, 200])
            }))
            .write_to(
                &mut std::io::Cursor::new(&mut jpeg),
                image::ImageFormat::Jpeg,
            )
            .unwrap();

            out.extend(&jpeg);
            out.extend([0u8; 32]);
        }
        std::fs::write(at, out).unwrap();
    }

    #[test]
    fn a_raw_gives_up_the_biggest_jpeg_it_carries() {
        let tmp = tmp();
        let src = tmp.path().join("DSC_0001.NEF");
        let dest = tmp.path().join("preview.png");
        // The thumbnail every RAW has, and the preview worth showing.
        raw_with(&src, &[(160, 120), (1024, 768)]);

        produce(Tools::default(), &src, &dest).unwrap();

        assert_eq!(
            image::image_dimensions(&dest).unwrap(),
            (1024, 768),
            "the preview, not the thumbnail beside it"
        );
    }

    #[test]
    fn bytes_that_merely_look_like_a_jpeg_are_walked_past() {
        let noise = [0xFFu8, 0xD8, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55];
        assert!(jpegs(&noise).is_empty());

        let tmp = tmp();
        let src = tmp.path().join("sensor.cr2");
        std::fs::write(&src, [noise.as_slice(), &[7u8; 512]].concat()).unwrap();

        let error = produce(Tools::default(), &src, &tmp.path().join("out.png")).unwrap_err();
        assert!(
            format!("{error:#}").contains("no preview is embedded"),
            "and what comes of that is a tile: {error:#}"
        );
    }

    #[test]
    fn a_jpeg_is_found_whole_rather_than_to_the_first_end_marker() {
        let tmp = tmp();
        let src = tmp.path().join("one.arw");
        raw_with(&src, &[(320, 240)]);

        let bytes = std::fs::read(&src).unwrap();
        let found = jpegs(&bytes);

        assert_eq!(found.len(), 1, "one jpeg, found once: {found:?}");
        // What was found is exactly a jpeg, start to end, and decodes on its own.
        let carved = &bytes[found[0].clone()];
        assert_eq!(&carved[..2], &[0xFF, 0xD8]);
        assert_eq!(&carved[carved.len() - 2..], &[0xFF, 0xD9]);
        assert_eq!(
            image::load_from_memory(carved).unwrap().width(),
            320,
            "carved cleanly out of the middle of the file"
        );
    }

    #[test]
    fn a_raw_too_big_to_hold_in_memory_is_refused_before_it_is_read() {
        let tmp = tmp();
        let src = tmp.path().join("huge.dng");
        std::fs::File::create(&src)
            .unwrap()
            .set_len(MAX_RAW + 1)
            .unwrap();

        let error = embedded(&src, &tmp.path().join("out.jpg")).unwrap_err();
        assert!(
            format!("{error:#}").contains("too big to look inside"),
            "refused on its size rather than after allocating it: {error:#}"
        );
    }
}

#[cfg(test)]
mod through_the_window {
    use super::*;
    use crate::ui::MainWindow;

    #[test]
    fn a_photo_becomes_the_image_the_tab_shows() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("beach.jpg");
        image::DynamicImage::ImageRgb8(image::RgbImage::from_fn(2000, 1500, |x, y| {
            image::Rgb([(x % 256) as u8, (y % 256) as u8, 90])
        }))
        .save(&src)
        .unwrap();

        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().unwrap();
        let previews = Previews::start(tmp.path().join("cache"), detect());

        // Nothing cached yet, so the tab holds the tile and the worker is set going.
        previews.show(&window, "beach-hash", &src);
        assert_eq!(
            window.get_sort_preview().size().width,
            0,
            "the tile stands until there is something to show"
        );

        for _ in 0..200 {
            if previews.cache.has("beach-hash") {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(
            previews.cache.has("beach-hash"),
            "the worker never finished"
        );

        // Asked for again, as the next poll does: now it is there.
        previews.show(&window, "beach-hash", &src);
        let shown = window.get_sort_preview().size();
        assert!(
            shown.width > 0 && shown.height > 0,
            "a real image: {shown:?}"
        );
        assert!(
            shown.width <= PREVIEW_MAX && shown.height <= PREVIEW_MAX,
            "and a capped one, from a 2000x1500 original: {shown:?}"
        );
    }
}
