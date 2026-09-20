//! Public-key fingerprints and configured catalog entries.

use crate::agent::AgentName;
use crate::scope::ScopePath;
use base64::Engine;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
/// A canonical OpenSSH SHA-256 public-key fingerprint.
pub struct Fingerprint(String);

impl Fingerprint {
    /// Computes the canonical fingerprint for an SSH public-key blob.
    pub fn from_public_key_blob(key_blob: &[u8]) -> Self {
        let digest = Sha256::digest(key_blob);
        Self(format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
        ))
    }

    /// Returns the canonical `SHA256:` representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Fingerprint {
    type Err = FingerprintError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let Some(encoded) = value.strip_prefix("SHA256:") else {
            return Err(FingerprintError::UnsupportedFormat);
        };

        if encoded.len() != 43 || !encoded.bytes().all(is_base64_character) {
            return Err(FingerprintError::InvalidDigest);
        }

        let final_value = base64_value(*encoded.as_bytes().last().unwrap());
        if !final_value.is_multiple_of(4) {
            return Err(FingerprintError::InvalidDigest);
        }

        Ok(Self(value.to_owned()))
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// A fingerprint parse error.
pub enum FingerprintError {
    /// The fingerprint did not use the `SHA256:` prefix.
    UnsupportedFormat,
    /// The SHA-256 digest was not canonical base64.
    InvalidDigest,
}

impl fmt::Display for FingerprintError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedFormat => {
                formatter.write_str("fingerprints must use the SHA256: prefix")
            }
            Self::InvalidDigest => {
                formatter.write_str("fingerprints must contain a canonical SHA-256 base64 digest")
            }
        }
    }
}

impl std::error::Error for FingerprintError {}

#[derive(Clone, Debug, Eq, PartialEq)]
/// A public identity returned by an upstream SSH Agent.
pub struct Identity {
    /// Raw SSH public-key blob used by the Agent protocol.
    pub key_blob: Vec<u8>,
    /// Fingerprint derived from `key_blob`.
    pub fingerprint: Fingerprint,
    /// Optional upstream-provided comment; treat it as untrusted text.
    pub comment: Option<String>,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
/// A normalized alias for a configured public key.
pub struct KeyAlias(String);

impl KeyAlias {
    /// Validates and lowercases a key alias.
    pub fn new(value: impl AsRef<str>) -> Result<Self, KeyAliasError> {
        let value = value.as_ref();
        if !is_name(value) {
            return Err(KeyAliasError::Invalid);
        }

        Ok(Self(value.to_ascii_lowercase()))
    }

    /// Returns the normalized alias.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyAlias {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// A key-alias validation error.
pub enum KeyAliasError {
    /// The alias is empty or contains unsupported characters.
    Invalid,
}

impl fmt::Display for KeyAliasError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("key aliases must use letters, numbers, '.', '_' or '-'")
    }
}

impl std::error::Error for KeyAliasError {}

#[derive(Clone, Debug, Eq, PartialEq)]
/// A configured public identity and its local metadata.
pub struct KeyEntry {
    alias: KeyAlias,
    fingerprint: Fingerprint,
    agent: AgentName,
    scopes: BTreeSet<ScopePath>,
    tags: BTreeMap<String, String>,
    comment: Option<String>,
}

impl KeyEntry {
    /// Creates an entry with sorted, deduplicated scopes and no comment.
    pub fn new(
        alias: KeyAlias,
        fingerprint: Fingerprint,
        agent: AgentName,
        scopes: impl IntoIterator<Item = ScopePath>,
        tags: BTreeMap<String, String>,
    ) -> Self {
        let scopes = scopes.into_iter().collect::<BTreeSet<_>>();
        Self {
            alias,
            fingerprint,
            agent,
            scopes,
            tags,
            comment: None,
        }
    }

    /// Attaches non-empty local comment metadata to this entry.
    pub fn with_comment(mut self, comment: Option<String>) -> Self {
        self.comment = comment.filter(|comment| !comment.is_empty());
        self
    }

    /// Returns the entry alias.
    pub fn alias(&self) -> &KeyAlias {
        &self.alias
    }

    /// Returns the configured public-key fingerprint.
    pub fn fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }

    /// Returns the upstream agent responsible for signing.
    pub fn agent(&self) -> &AgentName {
        &self.agent
    }

    /// Returns the configured hierarchical scopes.
    pub fn scopes(&self) -> &BTreeSet<ScopePath> {
        &self.scopes
    }

    /// Returns the local tag metadata.
    pub fn tags(&self) -> &BTreeMap<String, String> {
        &self.tags
    }

    /// Returns the persisted local comment, if one exists.
    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }
}

fn is_base64_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/')
}

fn base64_value(byte: u8) -> u8 {
    match byte {
        b'A'..=b'Z' => byte - b'A',
        b'a'..=b'z' => byte - b'a' + 26,
        b'0'..=b'9' => byte - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => unreachable!("base64 input was validated"),
    }
}

fn is_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::{Fingerprint, KeyAlias};
    use std::str::FromStr;

    const FINGERPRINT: &str = "SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+Y";

    #[test]
    fn accepts_canonical_sha256_fingerprints() {
        let fingerprint = Fingerprint::from_str(FINGERPRINT).unwrap();

        assert_eq!(fingerprint.as_str(), FINGERPRINT);
    }

    #[test]
    fn rejects_malformed_fingerprints() {
        for value in [
            "MD5:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+Y",
            "SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8",
            "SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8++",
            "SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+Z",
        ] {
            assert!(
                Fingerprint::from_str(value).is_err(),
                "{value} should be invalid"
            );
        }
    }

    #[test]
    fn aliases_are_normalized() {
        let alias = KeyAlias::new("Company-Debian-2").unwrap();

        assert_eq!(alias.as_str(), "company-debian-2");
    }
}
