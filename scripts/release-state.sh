#!/usr/bin/env bash
set -euo pipefail

root="$(pwd)"
main_ref="origin/main"
crate_state="unknown"
github_release_state="unknown"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root) root="$2"; shift 2 ;;
    --main-ref) main_ref="$2"; shift 2 ;;
    --crate-state) crate_state="$2"; shift 2 ;;
    --github-release-state) github_release_state="$2"; shift 2 ;;
    *) break ;;
  esac
done

version="${1:?usage: release-state.sh [--root PATH] [--main-ref REF] [--crate-state STATE] [--github-release-state STATE] VERSION}"
tag="v$version"

if [[ ! "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+\.)*[0-9A-Za-z-]+)?$ ]]; then
  printf 'release-state: version must be SemVer without a v prefix or build metadata\n' >&2
  exit 1
fi
if [[ "$version" == *-* ]]; then
  IFS=. read -r -a prerelease_ids <<< "${version#*-}"
  for identifier in "${prerelease_ids[@]}"; do
    [[ ! "$identifier" =~ ^0[0-9]+$ ]] || {
      printf 'release-state: numeric prerelease identifiers cannot have leading zeroes\n' >&2
      exit 1
    }
  done
fi

case "$crate_state" in absent|published|unknown) ;; *) exit 2 ;; esac
case "$github_release_state" in absent|draft|published|unknown) ;; *) exit 2 ;; esac

release_commit=""
while IFS= read -r candidate; do
  [[ "$(git -C "$root" log -1 --format=%s "$candidate")" == "chore(release): v$version" ]] || continue
  cargo_version="$(git -C "$root" show "$candidate:Cargo.toml" | awk '
    /^\[package\]$/ { package = 1; next }
    /^\[/ { package = 0 }
    package && /^version = / { gsub(/"/, "", $3); print $3; exit }
  ')"
  [[ "$cargo_version" == "$version" ]] || continue
  git -C "$root" show "$candidate:CHANGELOG.md" | grep -Fq "## [$version]" || continue
  git -C "$root" merge-base --is-ancestor "$candidate" "$main_ref" || continue
  release_commit="$candidate"
  break
done < <(git -C "$root" rev-list "$main_ref")

tag_state="missing"
if git -C "$root" rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
  [[ "$(git -C "$root" cat-file -t "refs/tags/$tag")" == tag ]] || {
    printf 'release-state: %s is not an annotated tag\n' "$tag" >&2
    exit 1
  }
  [[ -n "$release_commit" ]] || {
    printf 'release-state: %s exists but no matching release commit is reachable from %s\n' "$tag" "$main_ref" >&2
    exit 1
  }
  [[ "$(git -C "$root" rev-parse "$tag^{}")" == "$release_commit" ]] || {
    printf 'release-state: %s does not point to release commit %s\n' "$tag" "$release_commit" >&2
    exit 1
  }
  tag_state="correct"
fi

if [[ -z "$release_commit" ]]; then
  recovery_action="prepare"
elif [[ "$crate_state" == published && "$tag_state" == missing ]]; then
  recovery_action="create-tag"
elif [[ "$github_release_state" == published ]]; then
  recovery_action="verify-public-release"
elif [[ "$github_release_state" == draft ]]; then
  recovery_action="publish-draft"
elif [[ "$crate_state" == published ]]; then
  recovery_action="create-release"
else
  recovery_action="build-and-publish"
fi

printf 'release_commit_sha=%s\n' "$release_commit"
printf 'prepared=%s\n' "$([[ -n "$release_commit" ]] && printf true || printf false)"
printf 'tag_state=%s\n' "$tag_state"
printf 'crate_state=%s\n' "$crate_state"
printf 'github_release_state=%s\n' "$github_release_state"
printf 'recovery_action=%s\n' "$recovery_action"
