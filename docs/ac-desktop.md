# ac-desktop

The desktop app, built as the `ac-desktop` binary: a Slint window and a tray icon, in one binary that also runs a full node. It runs the `ac-node` daemon on a background thread, and its pages do what the `ac` CLI does, through the same operations: groups, peers, files, sorting imported photos, import sources, settings and enrolment. It depends on `ac-node`, on `ac-net` for the node's paths and config, and on `ac-import` for the fields its source forms are built from, and nothing builds on it. It is packaged as ArchiverClient, with the `ac` CLI and a bundled `ac-ffmpeg` installed beside it.

Paths below are relative to `crates/ac-desktop/`.

## Features

- **Startup**: the flags, the node lock, and wiring up every page in `src/main.rs`.
- **Node**: the daemon on its own thread, which can be restarted, in `src/node.rs`.
- **Reading and acting**: the poller that refreshes the page on screen, and the helpers that run actions off the UI thread, in `src/work.rs`, with the state both share in `src/selection.rs`.
- **Pages**: Status in `src/view.rs`, Groups in `src/groups.rs`, Peers in `src/peers.rs`, Files in `src/files.rs`, Sort in `src/sort.rs`, Sources in `src/sources.rs`, and Settings and enrolment in `src/settings.rs`, laid out in `ui/`.
- **Previews**: the Sort page's previews of photos, RAW files and videos in `src/preview.rs`.
- **Tray**: the tray icon on Linux and Windows in `src/tray/`, with the icon drawn in code in `src/tray/icon.rs`.
- **Logs**: the log files in `src/log.rs`.
- **File manager**: opening a file or folder, or showing a file in its folder, in `src/shell.rs`.
- **Build**: `build.rs` compiles the Slint UI and puts the bundled ffmpeg beside development builds.

## Design

### Threads

- The main thread runs the window's event loop. With `--headless` there is no window, and the daemon runs on the main thread instead, logging to stderr.
- The daemon runs on its own `ac-node` thread with its own tokio runtime. Stopping it waits for the thread to end, so restarting the node never runs on the event loop.
- One poller thread reads what the page on screen shows, each action runs on a thread of its own, and one worker makes previews.

### Reading

The window reaches the daemon only through the node's home: every read and every action goes through `ac-node`'s operations, and the daemon's status is the snapshot it publishes in `state.sqlite`.
- The poller reads every 2 s, since the daemon only publishes every 5 s, and reads at once after an action or a switch of page. Several actions finishing during one read cost one extra read between them.
- It reads only what the page on screen needs: rebuilding the file list on every step of the Sort page would cost more than the step itself.
- While the window is hidden in the tray, nothing is read.
- The Settings fields are loaded at startup and after each save, never polled, so a refresh cannot overwrite what someone is typing.

### Acting

A button runs its action on a new thread, with the page's buttons disabled meanwhile, then shows the outcome and has the poller read again at once. One message line is shared by every page. A successful action usually says nothing, since the change on screen already says it, so the line is kept for failures and for what the screen does not show, and it clears after 5 s.

Adding a source does not disable the rest of the app, since a sign-in can wait on a browser for minutes, and closing its dialog cancels the sign-in.

### Sort page

The Sort page steps through the imported files waiting to be sorted, one at a time, to file each into a group and folder or delete it, alone or with the rest of its folder.
- **Undo.** The last 5 actions can be undone. Deleting only marks the file, and its bytes are removed once the deletion falls off the list, or when the node next starts. Deleting a whole folder can be undone, but clears the list first, since holding several folders' bytes for undo would take too much disk. Filing a whole folder cannot be undone, since undoing a filing takes the file back out of its group, which its members see as a removal.
- **Previews.** The route is chosen by extension. Common image formats are decoded directly, HEIC is decoded in-process, a RAW file gives its largest embedded JPEG of at least 160 px (files over 256 MB are skipped), and a video, or an `.avif`, gives its first frame through ffmpeg. Anything else shows a placeholder.
- **Preview worker.** Previews are made off the UI thread, capped at 1400 px, turned upright, and cached as PNG by content hash. The worker does the file on screen first and prepares the next and previous ones so stepping is instant, and stops a tool after 20 s. The cache on disk and the decoded previews in memory both keep the last 3.
- **ffmpeg** is only looked for beside the app, as `ac-ffmpeg`, or where `AC_FFMPEG` points, never on the `PATH`. The name avoids clashing with a system `ffmpeg` installed in the same directory.

### Names and groups

- A name this node chose for someone is shown as it is. A name they chose for themselves is shown with a `~ ` prefix, since nothing verifies it. Without a name, nothing is shown rather than the start of a peer id, which is the same for every node.
- A group this node has left disappears at once, without waiting for the admin to remove it.
- For a group this node administers, Leave forgets the group instead, since an admin cannot leave.

### Window and enrolment

Closing the window hides it to the tray while there is one. Without a tray, including on Linux when the tray host goes away, closing quits. `--background` starts in the tray without a window, for starting at login.

A node that has not enrolled shows the enrol dialog at startup. Enrolling stops the node, joins, and starts the node again whatever the outcome, so a refusal never leaves it stopped.

### Layout

- The window is at least 880 px wide, and a test checks that every button, drop-down, text field and checkbox on every page fits at that width. Button labels never contain paths, since a button cannot shorten its text.
- Rust formats every string, and the `.slint` files only lay text out.
- Colours and sizes live in `ui/theme.slint`, and colour is never the only signal: a word always goes with it.
- The window uses Slint's software renderer, so the workspace optimises dependencies even in debug builds. Otherwise drawing the Sort page's preview would take noticeably long on every step.

## On-disk files

- `logs/ac-desktop.<date>.log` in the node's home: one file per day, keeping the last 7.
- `previews/<hash>.png` in the platform's cache directory, such as `~/.cache/archiverclient/` on Linux: the Sort page's previews, keeping the last 3.
- The node's home itself, `--home`, `AC_HOME` or the same per-OS directory as `ac`, belongs to `ac-node`.

## Database

None of its own. It reads and writes the node's `state.sqlite` only through `ac-node`'s operations.
