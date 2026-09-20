//! Validated slash-separated scope paths.

use std::fmt;
use std::str::FromStr;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
/// One normalized component of a [`ScopePath`].
pub struct ScopeSegment(String);

impl ScopeSegment {
    /// Validates and lowercases a scope segment.
    pub fn new(value: impl AsRef<str>) -> Result<Self, ScopePathError> {
        let value = value.as_ref();
        if value.is_empty() {
            return Err(ScopePathError::EmptySegment);
        }
        if !value.bytes().all(is_segment_character) {
            return Err(ScopePathError::InvalidSegment(value.to_owned()));
        }

        Ok(Self(value.to_ascii_lowercase()))
    }

    /// Returns the normalized segment.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ScopeSegment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
/// A normalized hierarchical scope path.
pub struct ScopePath(Vec<ScopeSegment>);

impl ScopePath {
    /// Returns ordered scope segments.
    pub fn segments(&self) -> &[ScopeSegment] {
        &self.0
    }

    /// Returns true when `self` is the same scope as `other` or an ancestor of it.
    pub fn is_prefix_of(&self, other: &Self) -> bool {
        self.0.len() <= other.0.len()
            && self
                .0
                .iter()
                .zip(&other.0)
                .all(|(left, right)| left == right)
    }

    /// Iterates this scope's ancestors from root to itself.
    pub fn ancestors(&self) -> impl Iterator<Item = Self> + '_ {
        (1..=self.0.len()).map(|length| Self(self.0[..length].to_vec()))
    }
}

impl FromStr for ScopePath {
    type Err = ScopePathError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty() {
            return Err(ScopePathError::EmptyPath);
        }

        value
            .split('/')
            .map(ScopeSegment::new)
            .collect::<Result<Vec<_>, _>>()
            .map(Self)
    }
}

impl fmt::Display for ScopePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, segment) in self.0.iter().enumerate() {
            if index > 0 {
                formatter.write_str("/")?;
            }
            segment.fmt(formatter)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// A scope-path validation error.
pub enum ScopePathError {
    /// The whole path was empty.
    EmptyPath,
    /// A slash produced an empty path segment.
    EmptySegment,
    /// A segment contained unsupported characters.
    InvalidSegment(String),
}

impl fmt::Display for ScopePathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPath => formatter.write_str("scope paths cannot be empty"),
            Self::EmptySegment => formatter.write_str("scope paths cannot contain empty segments"),
            Self::InvalidSegment(segment) => write!(
                formatter,
                "scope segment '{segment}' must use letters, numbers, '.', '_' or '-'"
            ),
        }
    }
}

impl std::error::Error for ScopePathError {}

fn is_segment_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
}

#[cfg(test)]
mod tests {
    use super::ScopePath;
    use std::str::FromStr;

    #[test]
    fn paths_are_normalized_to_lowercase() {
        let path = ScopePath::from_str("Company/Postgres-Walg/Production").unwrap();

        assert_eq!(path.to_string(), "company/postgres-walg/production");
    }

    #[test]
    fn paths_reject_empty_or_invalid_segments() {
        for value in [
            "",
            "/company",
            "company/",
            "company//production",
            "company/post gres",
        ] {
            assert!(
                ScopePath::from_str(value).is_err(),
                "{value} should be invalid"
            );
        }
    }

    #[test]
    fn ancestor_matching_includes_the_same_path() {
        let parent = ScopePath::from_str("company").unwrap();
        let child = ScopePath::from_str("company/postgres").unwrap();

        assert!(parent.is_prefix_of(&parent));
        assert!(parent.is_prefix_of(&child));
        assert!(!child.is_prefix_of(&parent));
    }

    #[test]
    fn ancestors_are_returned_from_root_to_self() {
        let scope = ScopePath::from_str("company/postgres/production").unwrap();
        let ancestors = scope
            .ancestors()
            .map(|scope| scope.to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            ancestors,
            ["company", "company/postgres", "company/postgres/production"]
        );
    }
}
