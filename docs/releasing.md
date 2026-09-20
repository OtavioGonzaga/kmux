# Releasing

Releases are SemVer versions created from `main` by the `Create Release` GitHub Actions workflow. This document describes the established pipeline; do not modify release artifacts manually after publication.

## Before Starting

1. Target `main` with all changes.
2. Add notable user-facing changes to `CHANGELOG.md` under `Unreleased`.
3. Ensure the package version and changelog are ready for the requested SemVer version.
4. Run the checks from CI, including formatting, Clippy, tests, docs, audit, and `cargo publish --dry-run --locked`.

## Workflow

The manually dispatched workflow accepts a SemVer value without `v` or build metadata. It verifies that the run starts at current `origin/main`, runs CI, creates the release commit, and builds static MUSL binaries for `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` with Rust 1.89.0.

It creates architecture-matched Debian packages, validates package contents and checksums, performs the crates.io publish flow in the protected `release` environment, creates an annotated `vVERSION` tag, and publishes the GitHub Release. Release assets include tarballs, `.deb` packages, per-asset checksums, and `SHA256SUMS`.

## Recovery And Immutability

The release scripts record and inspect release state so reruns can distinguish preparation from publication. Once a crate version, tag, or GitHub Release is published, treat it as immutable. Publish a corrective SemVer release rather than rewriting a published release. See `scripts/release-state.sh`, `scripts/prepare-release.sh`, and `CONTRIBUTING.md` for maintainer procedures.
