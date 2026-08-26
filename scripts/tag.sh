#!/usr/bin/env bash
#
# Decide this push's version from the commits since the last release, tag it, and hand the
# result to the workflow.
#
# The same scheme as `clockdata` and `beatguessr`, so a version means the same thing across
# the three repositories that deploy into `beatguessr-infra`: bare `MAJOR.MINOR.PATCH`, no
# `v` prefix, bumped from conventional commit subjects.
#
#   BREAKING CHANGE   major
#   feat:             minor
#   anything else     patch
#

set -euo pipefail

git fetch --tags --quiet

# Anchored on both ends and with the dots escaped, so `1.2.3` matches and `1.2.3-rc1`,
# `v1.2.3` and `1x2x3` do not. The unescaped version of this pattern is why a stray tag can
# quietly become the base version everything is counted from.
readonly SEMVER='^[0-9]+\.[0-9]+\.[0-9]+$'

# Re-runs must not fail. A workflow replayed against a commit that is already released has
# nothing to decide: the tag exists, `git tag` would refuse it, and the honest answer is the
# version this commit already has.
ALREADY=$(git tag --points-at HEAD | grep -E "$SEMVER" | sort -V | tail -n1 || true)
if [[ -n "$ALREADY" ]]; then
    echo "HEAD is already released as $ALREADY; reusing it"
    echo "VERSION=$ALREADY" >> "$GITHUB_ENV"
    echo "version=$ALREADY" >> "$GITHUB_OUTPUT"
    exit 0
fi

LAST_BASE_TAG=$(git tag --list | grep -E "$SEMVER" | sort -V | tail -n1 || true)

if [[ -z "$LAST_BASE_TAG" ]]; then
    # The first release. Counting from 0.0.0 over the whole history means the bump rules
    # decide the opening version like any other, rather than it being picked by hand: a
    # history containing a `feat:` opens at 0.1.0.
    #
    echo "No release tags yet; counting from 0.0.0 over the whole history"
    MAJOR=0 MINOR=0 PATCH=0
    RANGE=HEAD
else
    IFS='.' read -r MAJOR MINOR PATCH <<< "$LAST_BASE_TAG"
    RANGE="${LAST_BASE_TAG}..HEAD"
fi

echo "Current base version: $MAJOR.$MINOR.$PATCH"

COMMITS=$(git log "$RANGE" --format=%B)

echo "Commits since that version:"
git log "$RANGE" --oneline

BUMP=patch
if grep -q "BREAKING CHANGE" <<< "$COMMITS"; then
    BUMP=major
elif grep -qE "^feat(\(.+\))?!?:" <<< "$COMMITS"; then
    BUMP=minor
fi

echo "Determined bump: $BUMP"

case "$BUMP" in
    major) MAJOR=$((MAJOR + 1)); MINOR=0; PATCH=0 ;;
    minor) MINOR=$((MINOR + 1)); PATCH=0 ;;
    patch) PATCH=$((PATCH + 1)) ;;
esac

NEW_TAG="${MAJOR}.${MINOR}.${PATCH}"
echo "Next tag: $NEW_TAG"

git tag "$NEW_TAG"
git push origin "$NEW_TAG"

echo "VERSION=$NEW_TAG" >> "$GITHUB_ENV"
echo "version=$NEW_TAG" >> "$GITHUB_OUTPUT"
