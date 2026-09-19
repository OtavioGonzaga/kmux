#!/usr/bin/env bash
set -euo pipefail

version="${1:?usage: extract-release-notes.sh VERSION [CHANGELOG.md]}"
changelog="${2:-CHANGELOG.md}"
if ! grep -Fq "## [$version]" "$changelog"; then
  printf '%s\n' "extract-release-notes: CHANGELOG.md has no $version section" >&2
  exit 1
fi
awk -v heading="## [$version]" '
  $0 ~ "^" heading { active = 1; next }
  active && /^## \[/ { exit }
  active { print }
' "$changelog"
