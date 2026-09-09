use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use slint::{ComponentHandle, Weak};

use crate::ui::MainWindow;

pub const PREVIEW_WINDOW: usize = 3;

const PREVIEW_MAX: u32 = 1400;

const TOOL_TIMEOUT: Duration = Duration::from_secs(20);

/// How often a running tool is looked in on.
const POLL: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// What the `image` crate reads itself.
    BuiltIn,
    /// A first frame, pulled with ffmpeg. iPhones shoot HEVC in `.mov` and Android H.264
    /// in `.mp4`, and one route covers the lot.
    Video,
    /// Decoded in this process. What an iPhone shoots by default.
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

const BUNDLED: &str = "ac-ffmpeg";

const OVERRIDE: &str = "AC_FFMPEG";

/// Which routes this machine can actually take, settled once at startup.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tools {
    pub ffmpeg: Option<PathBuf>,
}

pub fn detect() -> Tools {
    Tools { ffmpeg: ffmpeg() }
}

/// The copy this app shipped with, or one named outright.
fn ffmpeg() -> Option<PathBuf> {
    beside_us(BUNDLED).or_else(|| named(std::env::var_os(OVERRIDE)))
}

/// Split out from the variable it reads so a test can hand it one: in edition 2024 the
/// environment is not something a test may set.
fn named(value: Option<std::ffi::OsString>) -> Option<PathBuf> {
    let named = PathBuf::from(value?);
    named.is_file().then_some(named)
}

/// A binary installed alongside this one
fn beside_us(name: &str) -> Option<PathBuf> {
    let here = std::env::current_exe().ok()?;
    beside_us_in(here.parent()?, name)
}

/// Split out so a test can point at a directory it made: the real one is wherever this
/// process was launched from, which no test can move.
fn beside_us_in(dir: &Path, name: &str) -> Option<PathBuf> {
    let candidate = dir.join(exe_name(name));
    candidate.is_file().then_some(candidate)
}

fn exe_name(name: &str) -> String {
    match cfg!(windows) {
        true => format!("{name}.exe"),
        false => name.to_owned(),
    }
}

impl Tools {
    pub fn can(&self, route: Route) -> bool {
        match route {
            Route::BuiltIn | Route::Heic | Route::Raw => true,
            Route::Video => self.ffmpeg.is_some(),
        }
    }
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
    /// Where to hand the pixels back. Always set, even when nothing is waiting on them: a
    /// preview fetched ahead is decoded ahead too, which is the whole point of fetching it.
    show: Weak<MainWindow>,
    /// Whether this is the one on screen, or one being got ready either side of it.
    wanted_now: bool,
}

/// A decoded preview on its way to the window. Raw pixels rather than a `slint::Image`,
/// because that is not `Send` — and because building one from a buffer is a copy, where
/// building one from a file is a decode.
struct Decoded {
    width: u32,
    height: u32,
    rgba: Vec<u8>,
}

/// The worker, its cache, and what this machine can decode.
pub struct Previews {
    cache: Arc<Cache>,
    tools: Tools,
    want: Sender<Job>,
    /// Previews actually produced
    #[allow(dead_code)]
    made: Arc<AtomicUsize>,
}

/// Which pending job to work next: the one on screen if any is waiting on a preview, else
/// whatever has waited longest.
fn next_up(pending: &VecDeque<Job>) -> usize {
    pending
        .iter()
        .position(|job| job.wanted_now)
        .unwrap_or_default()
}

/// The one worker for the process. It owns a thread and a directory, so there is no sense
/// in a second.
pub fn previews() -> &'static Previews {
    static PREVIEWS: OnceLock<Previews> = OnceLock::new();
    PREVIEWS.get_or_init(|| Previews::start(cache_dir(), detect()))
}

fn cache_dir() -> PathBuf {
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
            let mine = tools.clone();
            move || {
                // Off the event loop by construction: an ffmpeg run is far too slow to do
                // anywhere a frame is waiting on it.
                //
                // Taken out of order on purpose: the file on screen is the only preview
                // anyone is waiting on, and stepping quickly queues a prefetch either side
                // of every file passed through. Strictly first-in, the visible one would
                // wait behind them — up to a tool timeout each.
                let mut pending: VecDeque<Job> = VecDeque::new();
                loop {
                    if pending.is_empty() {
                        match jobs.recv() {
                            Ok(job) => pending.push_back(job),
                            Err(_) => break,
                        }
                    }
                    pending.extend(jobs.try_iter());

                    let Some(job) = pending.remove(next_up(&pending)) else {
                        break;
                    };
                    work(&cache, &mine, &made, job);
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

    /// The preview for what is on screen.
    ///
    /// Decoded already, it is handed over now and costs nothing. Otherwise the tile stands
    /// until the worker has it — decoding here is what used to make stepping stutter, and
    /// it is the one piece of the work that was still being done on the event loop.
    pub fn show(&self, window: &MainWindow, hash: &str, path: &Path) {
        if hash.is_empty() {
            window.set_sort_preview(Default::default());
            return;
        }

        if let Some(ready) = decoded(hash) {
            window.set_sort_preview(ready);
            self.cache.touch(hash);
            return;
        }

        window.set_sort_preview(Default::default());
        self.enqueue(hash, path, window, true);
    }

    /// Get one ready that has not been asked for yet, so stepping either way is instant.
    /// Fetched *and* decoded: leaving the decode until it is stepped onto would put the
    /// slow half back where it was.
    pub fn prefetch(&self, window: &MainWindow, hash: &str, path: &Path) {
        if hash.is_empty() || decoded(hash).is_some() {
            return;
        }
        self.enqueue(hash, path, window, false);
    }

    fn enqueue(&self, hash: &str, path: &Path, window: &MainWindow, wanted_now: bool) {
        if !self.wanted(path) {
            return;
        }
        let _ = self.want.send(Job {
            hash: hash.to_owned(),
            path: path.to_owned(),
            show: window.as_weak(),
            wanted_now,
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

fn work(cache: &Cache, tools: &Tools, made: &AtomicUsize, job: Job) {
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

    // Decoded here rather than where it is shown. This is the part that was left on the
    // event loop, and at a capped preview's size it is milliseconds every step.
    let Some(pixels) = decode(&cache.path(&job.hash)) else {
        return;
    };

    let (hash, wanted_now) = (job.hash, job.wanted_now);
    let _ = job.show.upgrade_in_event_loop(move |window| {
        let image = image_from(&pixels);
        remember(&hash, image.clone());

        // It may have been stepped past while the tool ran, and whatever is on screen now
        // owns the preview. Kept either way: stepping back to it is then free.
        if wanted_now && window.get_sort_hash() == hash.as_str() {
            window.set_sort_preview(image);
        }
    });
}

/// Read a cached preview into plain pixels, off the event loop.
fn decode(at: &Path) -> Option<Decoded> {
    let picture = image::ImageReader::open(at).ok()?.decode().ok()?;
    let rgba = picture.to_rgba8();
    Some(Decoded {
        width: rgba.width(),
        height: rgba.height(),
        rgba: rgba.into_raw(),
    })
}

/// The same pixels as a slint image. A copy, which is what makes it cheap enough to do
/// where a frame is waiting.
fn image_from(pixels: &Decoded) -> slint::Image {
    let buffer = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(
        &pixels.rgba,
        pixels.width,
        pixels.height,
    );
    slint::Image::from_rgba8(buffer)
}

// The previews already decoded, on the thread that draws them. A `slint::Image` is neither
// `Send` nor `Sync`, so it cannot live beside the worker — and this is the one thread that
// ever reads it.
thread_local! {
    static READY: std::cell::RefCell<VecDeque<(String, slint::Image)>> =
        const { std::cell::RefCell::new(VecDeque::new()) };
}

fn decoded(hash: &str) -> Option<slint::Image> {
    READY.with_borrow(|ready| {
        ready
            .iter()
            .find(|(seen, _)| seen == hash)
            .map(|(_, image)| image.clone())
    })
}

/// Keep it, and drop whatever falls out of the window — the same bound the files on disk
/// are held to, so the two cannot disagree about what is ready.
fn remember(hash: &str, image: slint::Image) {
    READY.with_borrow_mut(|ready| {
        ready.retain(|(seen, _)| seen != hash);
        ready.push_back((hash.to_owned(), image));
        while ready.len() > PREVIEW_WINDOW {
            ready.pop_front();
        }
    });
}

/// Turn one file into a capped, right-way-up preview.
fn produce(tools: &Tools, src: &Path, dest: &Path) -> Result<()> {
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
        Route::Heic => heic(src, dest),
        Route::Video | Route::Raw => {
            let extracted = dest.with_extension("extracted");
            let outcome = extract(tools, route, src, &extracted).and_then(|()| {
                shrink(&extracted, dest).with_context(|| format!("reading what {route:?} made"))
            });
            let _ = std::fs::remove_file(&extracted);
            outcome
        }
    }
}

/// Decode a HEIC in this process, which is what an iPhone shoots by default
fn heic(src: &Path, dest: &Path) -> Result<()> {
    let decoded = heif_oxide::decode_file(src)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .with_context(|| format!("decoding {}", src.display()))?;

    let picture = image::RgbaImage::from_raw(decoded.width, decoded.height, decoded.to_rgba8())
        .with_context(|| format!("{} decoded to fewer pixels than it declared", src.display()))?;
    store(image::DynamicImage::ImageRgba8(picture), dest)
}

/// Get *a* picture out of a file the `image` crate cannot open on its own.
fn extract(tools: &Tools, route: Route, src: &Path, dest: &Path) -> Result<()> {
    let mut command = match route {
        Route::Video => {
            let Some(ffmpeg) = &tools.ffmpeg else {
                bail!("no ffmpeg to take the video route with");
            };
            let mut command = std::process::Command::new(ffmpeg);
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
        Route::Heic => bail!("heic is decoded in this process, not by a tool"),
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
    store(picture, dest)
}

fn store(mut picture: image::DynamicImage, dest: &Path) -> Result<()> {
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

    /// The ffmpeg a test may use: whatever an installed copy would find, or the one the
    /// vendoring script fetched, which sits beside this crate rather than beside the test
    /// binary. `None` only when neither exists, and then the video tests say nothing.
    fn ffmpeg_for_test() -> Option<PathBuf> {
        if let Some(found) = ffmpeg() {
            return Some(found);
        }
        let vendored = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("vendor")
            .join(exe_name(&format!("{BUNDLED}-{}", env!("TEST_TARGET"))));
        vendored.is_file().then_some(vendored)
    }

    /// The build has to leave ffmpeg where the running binary looks for it, which is beside
    /// itself — and not merely in `vendor/`, which is where only a test would think to look.
    ///
    /// This is the gap that made every video show a placeholder while the tests were green:
    /// they fell back to the vendored copy through [`ffmpeg_for_test`], so the one thing that
    /// was broken — the copy the app itself would find — was the one thing nothing checked.
    /// Stepping quickly queues a prefetch either side of every file passed through, so the
    /// one on screen has to be taken out of turn or it waits behind them — a tool timeout
    /// each, for something nobody is looking at yet.
    #[test]
    fn the_preview_on_screen_is_taken_before_the_ones_fetched_ahead() {
        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().unwrap();
        let job = |hash: &str, wanted_now| Job {
            hash: hash.to_owned(),
            path: PathBuf::from(hash),
            show: window.as_weak(),
            wanted_now,
        };

        let mut pending: VecDeque<Job> = VecDeque::new();
        pending.push_back(job("ahead", false));
        pending.push_back(job("behind", false));
        assert_eq!(
            next_up(&pending),
            0,
            "nothing on screen waiting, so the oldest"
        );

        pending.push_back(job("on-screen", true));
        assert_eq!(
            pending[next_up(&pending)].hash,
            "on-screen",
            "it goes first however long the others have been queued"
        );
    }

    #[test]
    fn the_build_leaves_ffmpeg_where_the_binary_will_look_for_it() {
        let vendored = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("vendor")
            .join(exe_name(&format!("{BUNDLED}-{}", env!("TEST_TARGET"))));
        if !vendored.is_file() {
            // Nobody has vendored for this target; there is nothing to have placed.
            return;
        }

        // A test binary lives in `<target>/<profile>/deps`, one below the binary itself.
        let here = std::env::current_exe().unwrap();
        let beside = here.parent().and_then(Path::parent).unwrap();

        let placed = beside.join(exe_name(BUNDLED));
        assert!(
            placed.is_file(),
            "{} is vendored but was not put at {}: every video would be a placeholder",
            vendored.display(),
            placed.display()
        );
        assert_eq!(
            std::fs::metadata(&placed).unwrap().len(),
            std::fs::metadata(&vendored).unwrap().len(),
            "the copy beside the binary is not the one that was vendored"
        );
    }

    /// A picture of a known size, written where the tests can point at it.
    fn picture(at: &Path, width: u32, height: u32) {
        let buffer = image::RgbImage::from_fn(width, height, |x, y| {
            image::Rgb([(x % 256) as u8, (y % 256) as u8, 128])
        });
        image::DynamicImage::ImageRgb8(buffer).save(at).unwrap();
    }

    /// Stepping used to stutter because the last piece of the work — turning the cached
    /// file into an image — was still done where the frame was drawn. It is done on the
    /// worker now, and what reaches the window is pixels it only has to copy.
    #[test]
    fn a_preview_already_decoded_costs_nothing_to_show() {
        let tmp = tmp();
        let at = tmp.path().join("cached.png");
        picture(&at, 1400, 1050);

        // What the worker does, off the event loop.
        let pixels = decode(&at).expect("it did not decode");
        assert_eq!((pixels.width, pixels.height), (1400, 1050));
        assert_eq!(pixels.rgba.len(), 1400 * 1050 * 4, "four bytes a pixel");

        i_slint_backend_testing::init_no_event_loop();
        remember("ready", image_from(&pixels));

        // What the window does: nothing but take the one already made.
        let held = decoded("ready").expect("it was not kept");
        assert_eq!(held.size().width, 1400);

        // Bounded by the same window the files on disk are, so the two cannot disagree
        // about what is ready.
        for at in 0..PREVIEW_WINDOW + 1 {
            remember(&format!("other-{at}"), image_from(&pixels));
        }
        assert!(decoded("ready").is_none(), "it fell out of the window");
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
        // Three of the four are answered inside this binary, so a machine with nothing
        // installed still previews a photo, an iPhone photo and a RAW.
        let bare = Tools::default();
        assert!(bare.can(Route::BuiltIn), "decoding needs nothing installed");
        assert!(bare.can(Route::Heic), "nor does an iPhone photo");
        assert!(bare.can(Route::Raw), "nor finding the jpeg a RAW embeds");

        // Video is the one left, and the only thing `Tools` still answers for.
        assert!(!bare.can(Route::Video));
        let shipped = Tools {
            ffmpeg: Some(PathBuf::from("/opt/archiverclient/ac-ffmpeg")),
        };
        assert!(shipped.can(Route::Video));
    }

    #[test]
    fn the_shipped_ffmpeg_is_preferred_over_whatever_the_machine_has() {
        let tmp = tmp();
        let installed = tmp.path().join("bin");
        std::fs::create_dir_all(&installed).unwrap();

        // Nothing shipped yet, so nothing beside us to find.
        assert_eq!(beside_us_in(&installed, BUNDLED), None);

        // The name is deliberately not `ffmpeg`: these land beside the system's own, and
        // taking that name would collide with it.
        let shipped = installed.join(exe_name(BUNDLED));
        std::fs::write(&shipped, b"#!/bin/sh\n").unwrap();
        assert_eq!(beside_us_in(&installed, BUNDLED), Some(shipped));
        assert_ne!(exe_name(BUNDLED), "ffmpeg", "it must not take that name");
    }

    /// The only way to reach an ffmpeg this app did not ship: named outright, never found
    /// by searching. A build from source has no bundled copy, and this is what it uses.
    #[test]
    fn an_ffmpeg_this_app_did_not_ship_has_to_be_named_outright() {
        let tmp = tmp();
        let tool = tmp.path().join(exe_name("my-own-ffmpeg"));
        std::fs::write(&tool, b"#!/bin/sh\n").unwrap();

        assert_eq!(named(Some(tool.clone().into())), Some(tool));
        // A name that is not there is no answer, rather than a path that will fail later.
        assert_eq!(named(Some(tmp.path().join("gone").into())), None);
        assert_eq!(named(None), None);
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
    fn something_that_is_not_a_heic_is_refused_by_the_decoder() {
        let tmp = tmp();
        let src = tmp.path().join("IMG_0001.HEIC");
        std::fs::write(&src, b"ftypheic but nothing behind it").unwrap();

        assert!(
            Tools::default().can(Route::Heic),
            "the route is always available now, so nothing gates this"
        );
        let error = produce(&Tools::default(), &src, &tmp.path().join("out.png")).unwrap_err();
        assert!(
            format!("{error:#}").contains("decoding"),
            "the decoder was reached and said no: {error:#}"
        );
    }

    /// The video route, driven end to end against a real clip.
    #[test]
    fn a_video_previews_from_its_first_frame() {
        let Some(ffmpeg) = ffmpeg_for_test() else {
            return;
        };
        let tools = Tools {
            ffmpeg: Some(ffmpeg.clone()),
        };

        let tmp = tmp();
        let clip = tmp.path().join("holiday.mp4");
        let made = std::process::Command::new(&ffmpeg)
            .args(["-hide_banner", "-loglevel", "error"])
            .args([
                "-f",
                "lavfi",
                "-i",
                "testsrc=size=640x480:rate=10:duration=1",
            ])
            .args(["-c:v", "mpeg4", "-pix_fmt", "yuv420p", "-y"])
            .arg(&clip)
            .status();
        if !made.is_ok_and(|status| status.success()) {
            return;
        }

        let dest = tmp.path().join("preview.png");
        produce(&tools, &clip, &dest).unwrap();

        let shown = image::image_dimensions(&dest).unwrap();
        assert_eq!(shown, (640, 480), "the first frame, at its own size");
    }

    #[test]
    fn an_avif_still_previews_like_any_other_picture() {
        let Some(ffmpeg) = ffmpeg_for_test() else {
            return;
        };
        let tools = Tools {
            ffmpeg: Some(ffmpeg.clone()),
        };

        let tmp = tmp();
        let picture = tmp.path().join("web.avif");
        let made = std::process::Command::new(&ffmpeg)
            .args(["-hide_banner", "-loglevel", "error"])
            .args([
                "-f",
                "lavfi",
                "-i",
                "testsrc=size=320x240:duration=1:rate=1",
            ])
            .args(["-frames:v", "1", "-c:v", "libaom-av1", "-y"])
            .arg(&picture)
            .status();
        if !made.is_ok_and(|status| status.success()) {
            return;
        }

        assert_eq!(route_for("web.avif"), Some(Route::Video));
        let dest = tmp.path().join("preview.png");
        produce(&tools, &picture, &dest).unwrap();

        assert_eq!(image::image_dimensions(&dest).unwrap(), (320, 240));
    }

    #[test]
    fn a_missing_tool_is_a_tile_rather_than_a_failure() {
        let tmp = tmp();
        let src = tmp.path().join("clip.mov");
        std::fs::write(&src, b"not really a video").unwrap();

        let error = produce(&Tools::default(), &src, &tmp.path().join("out.png")).unwrap_err();
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

        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().unwrap();
        let previews = Previews::start(tmp.path().join("previews"), detect());
        for _ in 0..4 {
            previews.prefetch(&window, "abc123", &src);
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

        produce(&Tools::default(), &src, &dest).unwrap();

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

        let error = produce(&Tools::default(), &src, &tmp.path().join("out.png")).unwrap_err();
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

        // What the worker does once the file is cached, and what the event loop then does
        // with that. Driven here rather than awaited: the hop between the two is
        // `upgrade_in_event_loop`, and no event loop runs under a test.
        let pixels = decode(&previews.cache.path("beach-hash")).expect("it did not decode");
        remember("beach-hash", image_from(&pixels));

        // Asked for again, as the next poll does: now it costs nothing.
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
