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

bash scripts/prepare-release.sh --root "$root" --date 2026-09-19 0.2.0
grep -Fq 'version = "0.2.0"' "$root/Cargo.toml"
grep -Fq '## [0.2.0] - 2026-09-19' "$root/CHANGELOG.md"
test "$(bash scripts/extract-release-notes.sh 0.2.0 "$root/CHANGELOG.md")" = $'\n### Added\n\n- Change'

test "$(bash scripts/debian-version.sh 0.1.0)" = "0.1.0-1"
test "$(bash scripts/debian-version.sh 0.2.0-beta.1)" = "0.2.0~beta.1-1"
test "$(bash scripts/debian-version.sh 1.0.0-rc.2)" = "1.0.0~rc.2-1"
dpkg --compare-versions '0.2.0~beta.1-1' lt '0.2.0-1'
dpkg --compare-versions '0.2.0~beta.1-1' lt '0.2.0~beta.2-1'
dpkg --compare-versions '0.2.0~beta.2-1' lt '0.2.0~rc.1-1'

if bash scripts/prepare-release.sh --root "$root" 0.1.0; then exit 1; fi
if bash scripts/prepare-release.sh --root "$root" v0.3.0; then exit 1; fi
if bash scripts/prepare-release.sh --root "$root" 1.0.0-alpha.01; then exit 1; fi
git -C "$root" tag v0.2.1
if bash scripts/prepare-release.sh --root "$root" 0.2.1; then exit 1; fi

sed -i 's/0.2.0/1.0.0-beta.2/g' "$root/Cargo.toml" "$root/Cargo.lock"
cat > "$root/CHANGELOG.md" <<'EOF'
## [Unreleased]

### Added

- Prerelease change
EOF
bash scripts/prepare-release.sh --root "$root" 1.0.0-beta.10
grep -Fq 'version = "1.0.0-beta.10"' "$root/Cargo.toml"
