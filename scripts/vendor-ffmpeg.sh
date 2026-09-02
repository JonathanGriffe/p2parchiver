#!/usr/bin/env bash
# Usage: scripts/vendor-ffmpeg.sh <target-triple>
set -euo pipefail

TRIPLE="${1:?usage: vendor-ffmpeg.sh <target-triple>}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR="$HERE/crates/ac-desktop/vendor"

RELEASE="autobuild-2026-09-02-13-13"
BUILD="ffmpeg-n9.0.1-11-ge47273f4d9"
BASE="https://github.com/BtbN/FFmpeg-Builds/releases/download/$RELEASE"

case "$TRIPLE" in
  x86_64-unknown-linux-gnu)
    ARCHIVE="$BUILD-linux64-lgpl-9.0.tar.xz"
    SHA256="bce5103c29b51d4b6937de78a01fa39f6a30e22201bf85fbf74b0a13b662c0ff"
    BINARY="ffmpeg"
    ;;
  x86_64-pc-windows-msvc)
    ARCHIVE="$BUILD-win64-lgpl-9.0.zip"
    SHA256="14ce996102bcaccdc8de62e404dd96c9e6eb4c7ae28a25eb3537817f1e4d60fd"
    BINARY="ffmpeg.exe"
    ;;
  *)
    echo "no ffmpeg pinned for $TRIPLE" >&2
    echo "add one above, with its sha256, rather than letting the build go without." >&2
    exit 1
    ;;
esac

DEST="$VENDOR/ac-ffmpeg-$TRIPLE"
case "$TRIPLE" in *windows*) DEST="$DEST.exe" ;; esac

if [ -f "$DEST" ]; then
  echo "already vendored: $DEST"
  exit 0
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$VENDOR"

echo "fetching $ARCHIVE"
curl -fsSL --retry 3 -o "$WORK/$ARCHIVE" "$BASE/$ARCHIVE"

echo "$SHA256  $WORK/$ARCHIVE" | sha256sum -c - >/dev/null || {
  echo "ffmpeg did not match its pinned hash; refusing to package it." >&2
  echo "if the pin was updated deliberately, change SHA256 above in the same commit." >&2
  exit 1
}

# Git Bash on the Windows runner has tar but not always unzip, so python stands in for it.
case "$ARCHIVE" in
  *.tar.xz)
    tar -xf "$WORK/$ARCHIVE" -C "$WORK"
    ;;
  *.zip)
    if command -v unzip >/dev/null; then
      unzip -q "$WORK/$ARCHIVE" -d "$WORK"
    else
      python -c "import sys,zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" \
        "$WORK/$ARCHIVE" "$WORK"
    fi
    ;;
esac

# Only the one binary travels. ffprobe and ffplay are most of the archive and nothing here
# ever runs them.
found="$(find "$WORK" -type f -name "$BINARY" | head -1)"
[ -n "$found" ] || { echo "no $BINARY inside $ARCHIVE" >&2; exit 1; }
cp "$found" "$DEST"
chmod 755 "$DEST"

# LGPL asks that the licence travel with the binary. It is packaged as a resource, so an
# installed copy carries it rather than pointing at a repository.
licence="$(find "$WORK" -type f -iname "LICENSE*" | head -1)"
[ -n "$licence" ] || { echo "no licence inside $ARCHIVE" >&2; exit 1; }
{
  cat "$licence"
  echo
  echo "---"
  echo "This is an unmodified LGPL build of FFmpeg $BUILD, from"
  echo "$BASE/$ARCHIVE"
  echo "Its source is available from https://github.com/BtbN/FFmpeg-Builds and https://ffmpeg.org."
} > "$VENDOR/FFMPEG-LICENSE"

echo "vendored $(basename "$DEST") ($(du -h "$DEST" | cut -f1))"
