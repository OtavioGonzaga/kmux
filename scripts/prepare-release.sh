#!/usr/bin/env bash
set -euo pipefail

root="$(pwd)"
date="$(date -u +%F)"
if [[ ${1:-} == "--root" ]]; then
  root="$2"
  shift 2
fi
if [[ ${1:-} == "--date" ]]; then
  date="$2"
  shift 2
fi
version="${1:?usage: prepare-release.sh [--root PATH] [--date YYYY-MM-DD] VERSION}"

if [[ ! "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+\.)*[0-9A-Za-z-]+)?$ ]]; then
  printf '%s\n' "prepare-release: version must be SemVer without a v prefix or build metadata" >&2
  exit 1
fi

cargo_toml="$root/Cargo.toml"
cargo_lock="$root/Cargo.lock"
changelog="$root/CHANGELOG.md"
current="$(awk '
  /^\[package\]$/ { package = 1; next }
  /^\[/ { package = 0 }
  package && /^version = / { gsub(/"/, "", $3); print $3; exit }
' "$cargo_toml")"

if [[ -z "$current" ]]; then
  printf '%s\n' "prepare-release: could not read [package].version" >&2
  exit 1
fi

version_key() {
  local value="$1" core pre major minor patch
  core="${value%%-*}"
  pre="${value#"$core"}"
  IFS=. read -r major minor patch <<< "$core"
  printf '%08d.%08d.%08d.%s' "$major" "$minor" "$patch" "${pre:--zzzz}"
}

if [[ "$(version_key "$version")" < "$(version_key "$current")" ]]; then
  printf '%s\n' "prepare-release: release version is lower than current version $current" >&2
  exit 1
fi
if git -C "$root" rev-parse -q --verify "refs/tags/v$version" >/dev/null; then
  printf '%s\n' "prepare-release: tag v$version already exists; use release recovery instead" >&2
  exit 1
fi
if ! grep -Fq '## [Unreleased]' "$changelog"; then
  printf '%s\n' "prepare-release: CHANGELOG.md has no [Unreleased] section" >&2
  exit 1
fi
if grep -Fq "## [$version]" "$changelog"; then
  printf '%s\n' "prepare-release: CHANGELOG.md already contains $version" >&2
  exit 1
fi

body="$(awk '
  /^## \[Unreleased\]$/ { active = 1; next }
  active && /^## \[/ { exit }
  active { print }
' "$changelog")"
if ! grep -Eq '^- +[^[:space:]]' <<< "$body"; then
  printf '%s\n' "prepare-release: CHANGELOG.md [Unreleased] has no changes" >&2
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
awk -v version="$version" -v date="$date" '
  /^## \[Unreleased\]$/ { print; print ""; print "## [" version "] - " date; next }
  { print }
' "$changelog" > "$tmp/CHANGELOG.md"
mv "$tmp/CHANGELOG.md" "$changelog"

if [[ "$version" != "$current" ]]; then
  awk -v version="$version" '
    /^\[package\]$/ { package = 1 }
    /^\[/ && $0 != "[package]" { package = 0 }
    package && /^version = / { print "version = \"" version "\""; package = 2; next }
    { print }
  ' "$cargo_toml" > "$tmp/Cargo.toml"
  awk -v version="$version" '
    /^\[\[package\]\]$/ { root = 0 }
    /^name = "ssh-kmux"$/ { root = 1 }
    root && /^version = / { print "version = \"" version "\""; root = 2; next }
    { print }
  ' "$cargo_lock" > "$tmp/Cargo.lock"
  mv "$tmp/Cargo.toml" "$cargo_toml"
  mv "$tmp/Cargo.lock" "$cargo_lock"
fi
