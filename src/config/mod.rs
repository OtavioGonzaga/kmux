//! Configuration discovery, schema validation, and atomic persistence.

mod schema;

/// Configuration model, format selection, and persistence APIs.
pub use schema::{Config, ConfigDocument, ConfigError, ConfigFormat, ConfigPath, ConfigStore};
