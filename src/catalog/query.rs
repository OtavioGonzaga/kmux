//! Static matching for configured public-key entries.

use super::{Fingerprint, KeyAlias, KeyEntry};
use crate::agent::AgentName;
use crate::scope::ScopePath;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
/// A validated set of AND-combined catalog filters.
pub struct KeyQuery {
    scope: Option<ScopePath>,
    comment: Option<String>,
    key: Option<KeyAlias>,
    fingerprint: Option<String>,
    tags: Vec<(String, String)>,
    agent: Option<AgentName>,
}

impl KeyQuery {
    /// Builds a query from CLI-shaped optional values.
    pub fn from_values(
        scope: Option<String>,
        comment: Option<String>,
        key: Option<String>,
        fingerprint: Option<String>,
        tags: impl IntoIterator<Item = String>,
        agent: Option<String>,
    ) -> Result<Self, QueryError> {
        let scope = scope
            .map(|scope| ScopePath::from_str(&scope).map_err(QueryError::Scope))
            .transpose()?;
        let key = key
            .map(|key| KeyAlias::new(key).map_err(QueryError::Key))
            .transpose()?;
        let fingerprint = fingerprint
            .map(|fingerprint| validate_fingerprint_prefix(&fingerprint))
            .transpose()?;
        let agent = agent
            .map(|agent| AgentName::new(agent).map_err(QueryError::Agent))
            .transpose()?;
        let tags = tags
            .into_iter()
            .map(parse_tag)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            scope,
            comment,
            key,
            fingerprint,
            tags,
            agent,
        })
    }

    /// Returns the requested agent filter, if any.
    pub fn agent(&self) -> Option<&AgentName> {
        self.agent.as_ref()
    }

    /// Returns the matched scope when `entry` satisfies every filter.
    pub fn matches_entry(&self, entry: &KeyEntry) -> Option<Option<ScopePath>> {
        let matched_scope = match &self.scope {
            Some(scope) => entry
                .scopes()
                .iter()
                .find(|configured| scope.is_prefix_of(configured))
                .cloned()
                .map(Some)?,
            None => None,
        };
        if self.key.as_ref().is_some_and(|key| key != entry.alias())
            || self
                .fingerprint
                .as_ref()
                .is_some_and(|prefix| !fingerprint_matches(entry.fingerprint(), prefix))
            || self
                .agent
                .as_ref()
                .is_some_and(|agent| agent != entry.agent())
            || self
                .tags
                .iter()
                .any(|(key, value)| entry.tags().get(key) != Some(value))
            || self.comment.as_ref().is_some_and(|needle| {
                !entry
                    .comment()
                    .is_some_and(|comment| comment.to_lowercase().contains(&needle.to_lowercase()))
            })
        {
            return None;
        }
        Some(matched_scope)
    }
}

impl fmt::Display for KeyQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut filters = Vec::new();
        if let Some(scope) = &self.scope {
            filters.push(format!("scope: {scope}"));
        }
        if let Some(comment) = &self.comment {
            filters.push(format!("comment: {comment}"));
        }
        if let Some(key) = &self.key {
            filters.push(format!("key: {key}"));
        }
        if let Some(fingerprint) = &self.fingerprint {
            filters.push(format!("fingerprint: {fingerprint}"));
        }
        if let Some(agent) = &self.agent {
            filters.push(format!("agent: {agent}"));
        }
        filters.extend(
            self.tags
                .iter()
                .map(|(key, value)| format!("tag: {key}={value}")),
        );
        if filters.is_empty() {
            formatter.write_str("all configured identities")
        } else {
            formatter.write_str(&filters.join(", "))
        }
    }
}

fn validate_fingerprint_prefix(value: &str) -> Result<String, QueryError> {
    let value = value.strip_prefix("SHA256:").unwrap_or(value);
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
    {
        return Err(QueryError::FingerprintPrefix);
    }
    Ok(value.to_owned())
}

fn fingerprint_matches(fingerprint: &Fingerprint, prefix: &str) -> bool {
    fingerprint
        .as_str()
        .strip_prefix("SHA256:")
        .is_some_and(|value| value.starts_with(prefix))
}

fn parse_tag(value: String) -> Result<(String, String), QueryError> {
    let Some((key, tag_value)) = value.split_once('=') else {
        return Err(QueryError::Tag(value));
    };
    if key.is_empty() || tag_value.is_empty() {
        return Err(QueryError::Tag(value));
    }
    Ok((key.to_owned(), tag_value.to_owned()))
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// An invalid catalog-query input.
pub enum QueryError {
    /// The scope filter was invalid.
    Scope(crate::scope::ScopePathError),
    /// The alias filter was invalid.
    Key(super::KeyAliasError),
    /// The agent filter was invalid.
    Agent(crate::agent::AgentNameError),
    /// The fingerprint prefix contained unsupported characters.
    FingerprintPrefix,
    /// A tag was not non-empty `KEY=VALUE` syntax.
    Tag(String),
}

impl fmt::Display for QueryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scope(error) => error.fmt(formatter),
            Self::Key(error) => error.fmt(formatter),
            Self::Agent(error) => error.fmt(formatter),
            Self::FingerprintPrefix => {
                formatter.write_str("fingerprint prefixes must use SHA-256 base64 characters")
            }
            Self::Tag(tag) => write!(
                formatter,
                "tags must use non-empty KEY=VALUE syntax: '{tag}'"
            ),
        }
    }
}

impl std::error::Error for QueryError {}

#[derive(Clone, Debug)]
/// A catalog entry and the scope that caused it to match.
pub struct QueryMatch<'a> {
    /// The matching configured entry.
    pub entry: &'a KeyEntry,
    /// The matching configured scope for a scope query.
    pub matched_scope: Option<ScopePath>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
/// A validated collection of unique configured public identities.
pub struct KeyCatalog {
    entries: BTreeMap<KeyAlias, KeyEntry>,
    fingerprints: BTreeSet<Fingerprint>,
}

impl KeyCatalog {
    /// Creates a catalog, rejecting duplicate aliases and fingerprints.
    pub fn from_entries(
        entries: impl IntoIterator<Item = KeyEntry>,
    ) -> Result<Self, KeyCatalogError> {
        let mut catalog = Self::default();
        for entry in entries {
            catalog.insert(entry)?;
        }
        Ok(catalog)
    }

    /// Inserts an entry, rejecting duplicate aliases and fingerprints.
    pub fn insert(&mut self, entry: KeyEntry) -> Result<(), KeyCatalogError> {
        if self.entries.contains_key(entry.alias()) {
            return Err(KeyCatalogError::DuplicateAlias(entry.alias().clone()));
        }
        if self.fingerprints.contains(entry.fingerprint()) {
            return Err(KeyCatalogError::DuplicateFingerprint(
                entry.fingerprint().clone(),
            ));
        }
        self.fingerprints.insert(entry.fingerprint().clone());
        self.entries.insert(entry.alias().clone(), entry);
        Ok(())
    }

    /// Finds an entry by normalized alias.
    pub fn get(&self, alias: &KeyAlias) -> Option<&KeyEntry> {
        self.entries.get(alias)
    }
    /// Iterates entries in alias order.
    pub fn entries(&self) -> impl Iterator<Item = &KeyEntry> {
        self.entries.values()
    }

    /// Applies a query without communicating with an upstream agent.
    pub fn query_static(&self, query: &KeyQuery) -> Vec<QueryMatch<'_>> {
        self.entries
            .values()
            .filter_map(|entry| {
                query.matches_entry(entry).map(|matched_scope| QueryMatch {
                    entry,
                    matched_scope,
                })
            })
            .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// A duplicate-value error while building a catalog.
pub enum KeyCatalogError {
    /// An alias was already present.
    DuplicateAlias(KeyAlias),
    /// A fingerprint was already present.
    DuplicateFingerprint(Fingerprint),
}

impl fmt::Display for KeyCatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateAlias(alias) => write!(formatter, "duplicate key alias '{alias}'"),
            Self::DuplicateFingerprint(fingerprint) => {
                write!(formatter, "duplicate fingerprint '{fingerprint}'")
            }
        }
    }
}
impl std::error::Error for KeyCatalogError {}

#[cfg(test)]
mod tests {
    use super::{KeyCatalog, KeyQuery};
    use crate::agent::AgentName;
    use crate::catalog::{Fingerprint, KeyAlias, KeyEntry};
    use crate::scope::ScopePath;
    use std::str::FromStr;

    const A: &str = "SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+Y";
    const B: &str = "SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+A";
    fn entry(alias: &str, fingerprint: &str, scopes: &[&str], tags: &[(&str, &str)]) -> KeyEntry {
        KeyEntry::new(
            KeyAlias::new(alias).unwrap(),
            Fingerprint::from_str(fingerprint).unwrap(),
            AgentName::new("bitwarden").unwrap(),
            scopes
                .iter()
                .map(|scope| ScopePath::from_str(scope).unwrap()),
            tags.iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect(),
        )
    }
    fn query(
        scope: Option<&str>,
        key: Option<&str>,
        fingerprint: Option<&str>,
        tags: &[&str],
    ) -> KeyQuery {
        KeyQuery::from_values(
            scope.map(str::to_owned),
            None,
            key.map(str::to_owned),
            fingerprint.map(str::to_owned),
            tags.iter().map(|tag| (*tag).to_owned()),
            None,
        )
        .unwrap()
    }
    #[test]
    fn filters_static_fields_and_preserves_scope_semantics() {
        let catalog = KeyCatalog::from_entries([
            entry("root", A, &["company"], &[]),
            entry(
                "postgres",
                B,
                &["company/postgres/production"],
                &[("provider", "aws"), ("environment", "production")],
            ),
            entry("unscoped", A, &[], &[]),
        ])
        .unwrap_err();
        assert!(matches!(
            catalog,
            super::KeyCatalogError::DuplicateFingerprint(_)
        ));
        let catalog = KeyCatalog::from_entries([
            entry("root", A, &["company"], &[]),
            entry(
                "postgres",
                B,
                &["company/postgres/production"],
                &[("provider", "aws"), ("environment", "production")],
            ),
        ])
        .unwrap();
        assert_eq!(
            catalog
                .query_static(&query(Some("company/postgres"), None, None, &[]))
                .len(),
            1
        );
        assert!(
            catalog
                .query_static(&query(
                    Some("company/postgres/production/x"),
                    None,
                    None,
                    &[]
                ))
                .is_empty()
        );
        assert_eq!(
            catalog
                .query_static(&query(None, Some("postgres"), Some("ZZZZ"), &[]))
                .len(),
            0
        );
        assert_eq!(
            catalog
                .query_static(&query(
                    None,
                    Some("postgres"),
                    Some("Wda9mr6okK7"),
                    &["provider=aws", "environment=production"]
                ))
                .len(),
            1
        );
        assert_eq!(
            catalog.query_static(&query(None, None, Some(B), &[])).len(),
            1
        );
        let wrong_agent =
            KeyQuery::from_values(None, None, None, None, [], Some("other-agent".to_owned()))
                .unwrap();
        assert!(catalog.query_static(&wrong_agent).is_empty());
    }
    #[test]
    fn accepts_unscoped_entries_and_rejects_bad_tags() {
        let catalog = KeyCatalog::from_entries([entry("unscoped", A, &[], &[])]).unwrap();
        assert_eq!(catalog.query_static(&KeyQuery::default()).len(), 1);
        assert!(
            catalog
                .query_static(&query(Some("company"), None, None, &[]))
                .is_empty()
        );
        for tag in ["invalid", "=value", "key="] {
            assert!(KeyQuery::from_values(None, None, None, None, [tag.to_owned()], None).is_err());
        }
    }

    #[test]
    fn rejects_invalid_filter_values() {
        for (scope, fingerprint, agent) in [
            (Some("company//production"), None, None),
            (None, Some("not-a-fingerprint"), None),
            (None, None, Some("invalid agent")),
        ] {
            assert!(
                KeyQuery::from_values(
                    scope.map(str::to_owned),
                    None,
                    None,
                    fingerprint.map(str::to_owned),
                    [],
                    agent.map(str::to_owned),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn repeated_tags_use_and_semantics() {
        let catalog =
            KeyCatalog::from_entries([entry("aws", B, &[], &[("provider", "aws")])]).unwrap();
        let query = KeyQuery::from_values(
            None,
            None,
            None,
            None,
            ["provider=aws".to_owned(), "provider=gcp".to_owned()],
            None,
        )
        .unwrap();
        assert!(catalog.query_static(&query).is_empty());
    }
}
