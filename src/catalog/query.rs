use super::{Fingerprint, KeyAlias, KeyEntry};
use crate::scope::ScopePath;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeQuery {
    scope: ScopePath,
}

impl ScopeQuery {
    pub fn new(scope: ScopePath) -> Self {
        Self { scope }
    }

    pub fn scope(&self) -> &ScopePath {
        &self.scope
    }

    fn matches(&self, entry: &KeyEntry) -> bool {
        entry
            .scopes()
            .iter()
            .any(|entry_scope| self.scope.is_prefix_of(entry_scope))
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct KeyCatalog {
    entries: BTreeMap<KeyAlias, KeyEntry>,
    fingerprints: BTreeSet<Fingerprint>,
}

impl KeyCatalog {
    pub fn from_entries(
        entries: impl IntoIterator<Item = KeyEntry>,
    ) -> Result<Self, KeyCatalogError> {
        let mut catalog = Self::default();
        for entry in entries {
            catalog.insert(entry)?;
        }
        Ok(catalog)
    }

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

    pub fn get(&self, alias: &KeyAlias) -> Option<&KeyEntry> {
        self.entries.get(alias)
    }

    pub fn query(&self, query: &ScopeQuery) -> Vec<&KeyEntry> {
        self.entries
            .values()
            .filter(|entry| query.matches(entry))
            .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyCatalogError {
    DuplicateAlias(KeyAlias),
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
    use super::{KeyCatalog, ScopeQuery};
    use crate::agent::AgentName;
    use crate::catalog::{Fingerprint, KeyAlias, KeyEntry};
    use crate::scope::ScopePath;
    use std::collections::BTreeMap;
    use std::str::FromStr;

    const FINGERPRINT_A: &str = "SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+Y";
    const FINGERPRINT_B: &str = "SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+A";

    fn entry(alias: &str, fingerprint: &str, scopes: &[&str]) -> KeyEntry {
        KeyEntry::new(
            KeyAlias::new(alias).unwrap(),
            Fingerprint::from_str(fingerprint).unwrap(),
            AgentName::new("bitwarden").unwrap(),
            scopes
                .iter()
                .map(|scope| ScopePath::from_str(scope).unwrap()),
            BTreeMap::new(),
        )
        .unwrap()
    }

    #[test]
    fn a_scope_query_matches_only_the_scope_and_its_descendants() {
        let catalog = KeyCatalog::from_entries([
            entry("hogix-root", FINGERPRINT_A, &["hogix"]),
            entry("postgres", FINGERPRINT_B, &["hogix/postgres/production"]),
        ])
        .unwrap();
        let query = ScopeQuery::new(ScopePath::from_str("hogix/postgres").unwrap());

        let aliases = catalog
            .query(&query)
            .into_iter()
            .map(|entry| entry.alias().as_str())
            .collect::<Vec<_>>();

        assert_eq!(aliases, ["postgres"]);
    }

    #[test]
    fn a_parent_scope_query_includes_descendants_in_alias_order() {
        let catalog = KeyCatalog::from_entries([
            entry("zebra", FINGERPRINT_A, &["hogix/postgres"]),
            entry("alpha", FINGERPRINT_B, &["hogix/api"]),
        ])
        .unwrap();
        let query = ScopeQuery::new(ScopePath::from_str("hogix").unwrap());

        let aliases = catalog
            .query(&query)
            .into_iter()
            .map(|entry| entry.alias().as_str())
            .collect::<Vec<_>>();

        assert_eq!(aliases, ["alpha", "zebra"]);
    }

    #[test]
    fn catalog_rejects_duplicate_aliases_and_fingerprints() {
        let duplicate_alias = KeyCatalog::from_entries([
            entry("same", FINGERPRINT_A, &["hogix"]),
            entry("same", FINGERPRINT_B, &["personal"]),
        ]);
        let duplicate_fingerprint = KeyCatalog::from_entries([
            entry("first", FINGERPRINT_A, &["hogix"]),
            entry("second", FINGERPRINT_A, &["personal"]),
        ]);

        assert!(duplicate_alias.is_err());
        assert!(duplicate_fingerprint.is_err());
    }

    #[test]
    fn catalog_returns_no_match_for_unrelated_scope() {
        let catalog =
            KeyCatalog::from_entries([entry("hogix", FINGERPRINT_A, &["hogix"])]).unwrap();
        let query = ScopeQuery::new(ScopePath::from_str("personal").unwrap());

        assert!(catalog.query(&query).is_empty());
    }
}
