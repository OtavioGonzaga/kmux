#![warn(missing_docs)]

//! Core types for building filtered SSH Agent workflows.
//!
//! The `kmux` binary resolves configured public identities, then exposes a
//! filtered SSH Agent proxy to one child process. Private keys remain in the
//! upstream agent. Applications can use this crate to model agents, catalogs,
//! configuration, hierarchical scopes, selection, and the proxy itself.
//!
//! - [`agent`] communicates with Unix-socket upstream agents.
//! - [`catalog`] stores configured public identities and queries them.
//! - [`config`] loads, validates, and atomically writes configuration.
//! - [`management`] provides administrative operations and per-agent inspection.
//! - [`proxy`] serves a filtered SSH Agent.
//! - [`scope`] models hierarchical scopes.
//! - [`selection`] resolves configured identities available upstream.

/// Types for naming and communicating with upstream SSH agents.
pub mod agent;
/// Configured public identities and static catalog queries.
pub mod catalog;
/// Configuration discovery, validation, and atomic persistence.
pub mod config;
/// Reusable administration and upstream-agent inspection APIs.
pub mod management;
/// The filtered SSH Agent proxy.
pub mod proxy;
/// Hierarchical key-selection scopes.
pub mod scope;
/// Identity availability resolution and interactive selection.
pub mod selection;
