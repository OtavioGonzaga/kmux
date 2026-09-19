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

test "$(bash scripts/release-state.sh --root "$root" --main-ref HEAD 0.3.0 | grep '^prepared=')" = 'prepared=false'
test "$(bash scripts/release-state.sh --root "$root" --main-ref HEAD 0.3.0 | grep '^recovery_action=')" = 'recovery_action=prepare'
git -C "$root" add Cargo.toml Cargo.lock CHANGELOG.md
git -C "$root" commit --quiet -m 'chore(release): v0.2.0'
release_sha="$(git -C "$root" rev-parse HEAD)"
state="$(bash scripts/release-state.sh --root "$root" --main-ref HEAD --crate-state absent --github-release-state absent 0.2.0)"
grep -Fxq "release_commit_sha=$release_sha" <<< "$state"
grep -Fxq 'prepared=true' <<< "$state"
grep -Fxq 'tag_state=missing' <<< "$state"
grep -Fxq 'recovery_action=build-and-publish' <<< "$state"
state="$(bash scripts/release-state.sh --root "$root" --main-ref HEAD --crate-state published --github-release-state absent 0.2.0)"
grep -Fxq 'recovery_action=create-tag' <<< "$state"
git -C "$root" tag --annotate v0.2.0 --message 'Release v0.2.0'
state="$(bash scripts/release-state.sh --root "$root" --main-ref HEAD --crate-state published --github-release-state absent 0.2.0)"
grep -Fxq 'recovery_action=create-release' <<< "$state"
state="$(bash scripts/release-state.sh --root "$root" --main-ref HEAD --crate-state published --github-release-state draft 0.2.0)"
grep -Fxq 'tag_state=correct' <<< "$state"
grep -Fxq 'crate_state=published' <<< "$state"
grep -Fxq 'github_release_state=draft' <<< "$state"
grep -Fxq 'recovery_action=publish-draft' <<< "$state"
state="$(bash scripts/release-state.sh --root "$root" --main-ref HEAD --crate-state published --github-release-state published 0.2.0)"
grep -Fxq 'github_release_state=published' <<< "$state"
grep -Fxq 'recovery_action=verify-public-release' <<< "$state"
git -C "$root" tag --annotate v0.3.0 "$release_sha" --message 'Release v0.3.0'
sed -i 's/0.2.0/0.3.0/g' "$root/Cargo.toml" "$root/Cargo.lock" "$root/CHANGELOG.md"
git -C "$root" add Cargo.toml Cargo.lock CHANGELOG.md
git -C "$root" commit --quiet -m 'chore(release): v0.3.0'
if bash scripts/release-state.sh --root "$root" --main-ref HEAD 0.3.0; then exit 1; fi

test "$(bash scripts/debian-version.sh 0.1.0)" = "0.1.0-1"
test "$(bash scripts/debian-version.sh 0.2.0-beta.1)" = "0.2.0~beta.1-1"
test "$(bash scripts/debian-version.sh 1.0.0-rc.2)" = "1.0.0~rc.2-1"
dpkg --compare-versions '0.2.0~beta.1-1' lt '0.2.0-1'
dpkg --compare-versions '0.2.0~beta.1-1' lt '0.2.0~beta.2-1'
dpkg --compare-versions '0.2.0~beta.2-1' lt '0.2.0~rc.1-1'

if bash scripts/prepare-release.sh --root "$root" 0.1.0; then exit 1; fi
if bash scripts/prepare-release.sh --root "$root" v0.3.0; then exit 1; fi
if bash scripts/prepare-release.sh --root "$root" 1.0.0-alpha.01; then exit 1; fi
git -C "$root" tag v0.3.1
if bash scripts/prepare-release.sh --root "$root" 0.3.1; then exit 1; fi

sed -i 's/0.2.0/1.0.0-beta.2/g' "$root/Cargo.toml" "$root/Cargo.lock"
cat > "$root/CHANGELOG.md" <<'EOF'
## [Unreleased]

### Added

- Prerelease change
EOF
bash scripts/prepare-release.sh --root "$root" 1.0.0-beta.10
grep -Fq 'version = "1.0.0-beta.10"' "$root/Cargo.toml"
