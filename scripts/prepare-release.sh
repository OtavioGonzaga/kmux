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
if [[ "$version" == *-* ]]; then
  IFS=. read -r -a prerelease_ids <<< "${version#*-}"
  for identifier in "${prerelease_ids[@]}"; do
    if [[ "$identifier" =~ ^0[0-9]+$ ]]; then
      printf '%s\n' "prepare-release: numeric prerelease identifiers cannot have leading zeroes" >&2
      exit 1
    fi
  done
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

semver_less() {
  local left="$1" right="$2" left_core right_core left_pre right_pre
  left_core="${left%%-*}"
  right_core="${right%%-*}"
  left_pre="${left#"$left_core"}"
  right_pre="${right#"$right_core"}"
  local -a left_parts right_parts left_ids right_ids
  IFS=. read -r -a left_parts <<< "$left_core"; IFS=. read -r -a right_parts <<< "$right_core"
  for index in 0 1 2; do
    ((10#${left_parts[index]} < 10#${right_parts[index]})) && return 0
    ((10#${left_parts[index]} > 10#${right_parts[index]})) && return 1
  done
  [[ -z "$left_pre" && -n "$right_pre" ]] && return 1
  [[ -n "$left_pre" && -z "$right_pre" ]] && return 0
  [[ -z "$left_pre" ]] && return 1
  IFS=. read -r -a left_ids <<< "${left_pre#-}"; IFS=. read -r -a right_ids <<< "${right_pre#-}"
  for ((index=0; index<${#left_ids[@]} && index<${#right_ids[@]}; index++)); do
    [[ ${left_ids[index]} == "${right_ids[index]}" ]] && continue
    if [[ ${left_ids[index]} =~ ^[0-9]+$ && ${right_ids[index]} =~ ^[0-9]+$ ]]; then
      ((10#${left_ids[index]} < 10#${right_ids[index]})) && return 0 || return 1
    fi
    [[ ${left_ids[index]} =~ ^[0-9]+$ && ! ${right_ids[index]} =~ ^[0-9]+$ ]] && return 0
    [[ ! ${left_ids[index]} =~ ^[0-9]+$ && ${right_ids[index]} =~ ^[0-9]+$ ]] && return 1
    [[ ${left_ids[index]} < ${right_ids[index]} ]] && return 0 || return 1
  done
  ((${#left_ids[@]} < ${#right_ids[@]}))
}

if semver_less "$version" "$current"; then
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
