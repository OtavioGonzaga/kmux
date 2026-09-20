# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

## [Unreleased]

### Changed

- Allow filtered command execution without scopes through `kmux [FILTERS] -- COMMAND...`.
- Add reusable key filters for scopes, comments, aliases, fingerprints, tags, and agents.
- Allow configured keys without scopes while preserving filtered SSH-agent isolation.

## [0.1.0] - 2026-09-19

### Added

- MIT licensing, contributor guidance, and release documentation.
- Automated release infrastructure for crates.io, Linux tarballs, and Debian packages.
- Core domain model for SSH identities, fingerprints, agents, scopes, and key catalogs.
- Deterministic exact-or-descendant scope matching with validation and unit tests.
- Read-only configuration loading for YAML, JSON, and TOML with static validation.
- Unix-socket upstream SSH agent identity discovery with bounded protocol framing.
- Filtered proxy policy that blocks unselected signatures and mutable or unknown operations.
- Runtime upstream diagnostics through `kmux doctor`.
- Candidate resolution with interactive selection and non-interactive ambiguity errors.
- Public identity import snippets through `kmux import agent`.
- Structured JSON logging controlled by `KMUX_LOG` or `RUST_LOG`.
- Signal-aware `exec` cleanup and proxy, CLI, and OpenSSH integration coverage.
- GitHub Actions validation for formatting, Clippy, and tests on Linux.

### Changed

- CI validates documentation, publishable package metadata, and RustSec advisories.
- Replace the deprecated YAML parser with `serde-saphyr` and enforce strict YAML configuration parsing and a 1 MiB file limit.
- Added usage, configuration, and security documentation for the pre-release CLI.
- Version reusable agent skills alongside project instructions and prompts.
- Split CLI parsing and command orchestration into focused functional modules.
- Only query upstream agents referenced by the requested scope.
- Include derived parent scopes in `kmux scopes` and improve import alias suggestions from public comments.
- Track active proxy connections so shutdown closes downstream and upstream workers before socket removal.
- Harden proxy shutdown for stalled upstream responses, use private runtime-directory fallbacks, and forward child signals through safe Rust APIs.
- Use bounded `serde-saphyr` parsing, per-execution runtime directories, and structurally validate `session-bind@openssh.com` requests before forwarding.
- Sanitize untrusted SSH-agent comments in terminal selection output and validate generated import snippets in every supported format.
