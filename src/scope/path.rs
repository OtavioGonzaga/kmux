use std::fmt;
use std::str::FromStr;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ScopeSegment(String);

impl ScopeSegment {
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
pub struct ScopePath(Vec<ScopeSegment>);

impl ScopePath {
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
pub enum ScopePathError {
    EmptyPath,
    EmptySegment,
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
        let path = ScopePath::from_str("Hogix/Postgres-Walg/Production").unwrap();

        assert_eq!(path.to_string(), "hogix/postgres-walg/production");
    }

    #[test]
    fn paths_reject_empty_or_invalid_segments() {
        for value in [
            "",
            "/hogix",
            "hogix/",
            "hogix//production",
            "hogix/post gres",
        ] {
            assert!(
                ScopePath::from_str(value).is_err(),
                "{value} should be invalid"
            );
        }
    }

    #[test]
    fn ancestor_matching_includes_the_same_path() {
        let parent = ScopePath::from_str("hogix").unwrap();
        let child = ScopePath::from_str("hogix/postgres").unwrap();

        assert!(parent.is_prefix_of(&parent));
        assert!(parent.is_prefix_of(&child));
        assert!(!child.is_prefix_of(&parent));
    }
}
