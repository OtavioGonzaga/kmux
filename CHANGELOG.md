# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

## [Unreleased]

### Added

- Core domain model for SSH identities, fingerprints, agents, scopes, and key catalogs.
- Deterministic exact-or-descendant scope matching with validation and unit tests.
- Read-only configuration loading for YAML, JSON, and TOML with static validation.
- Unix-socket upstream SSH agent identity discovery with bounded protocol framing.

### Changed

- Version reusable agent skills alongside project instructions and prompts.
