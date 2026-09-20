//! Public-identity catalog entries and reusable static filters.

mod key;
mod query;

/// Key-entry types and validation errors.
pub use key::{Fingerprint, FingerprintError, Identity, KeyAlias, KeyAliasError, KeyEntry};
/// Catalog query types and validation errors.
pub use query::{KeyCatalog, KeyCatalogError, KeyQuery, QueryError, QueryMatch};
