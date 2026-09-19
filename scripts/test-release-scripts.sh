#!/usr/bin/env bash
set -euo pipefail

root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
cat > "$root/Cargo.toml" <<'EOF'
[package]
name = "ssh-kmux"
version = "0.1.0"
EOF
cat > "$root/Cargo.lock" <<'EOF'
version = 4

[[package]]
name = "ssh-kmux"
version = "0.1.0"
EOF
cat > "$root/CHANGELOG.md" <<'EOF'
# Changelog

## [Unreleased]

### Added

- Change
EOF
git -C "$root" init --quiet
git -C "$root" config user.email test@example.invalid
git -C "$root" config user.name Test
git -C "$root" add .
git -C "$root" commit --quiet -m initial

grep -Fq 'version = "0.2.0"' "$root/Cargo.toml"
grep -Fq '## [0.2.0] - 2026-09-19' "$root/CHANGELOG.md"

if scripts/prepare-release.sh --root "$root" 0.1.0; then exit 1; fi
if scripts/prepare-release.sh --root "$root" v0.3.0; then exit 1; fi
git -C "$root" tag v0.2.1
if scripts/prepare-release.sh --root "$root" 0.2.1; then exit 1; fi
