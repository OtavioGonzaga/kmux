#!/usr/bin/env bash
set -euo pipefail

upstream=false
if [[ ${1:-} == "--upstream" ]]; then
  upstream=true
  shift
fi
version="${1:?usage: debian-version.sh [--upstream] SEMVER}"

if [[ "$version" == *-* ]]; then
  debian_upstream="${version%%-*}~${version#*-}"
else
  debian_upstream="$version"
fi

if "$upstream"; then
  printf '%s\n' "$debian_upstream"
else
  printf '%s-1\n' "$debian_upstream"
fi
