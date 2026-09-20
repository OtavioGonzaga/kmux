//! Upstream SSH Agent definitions and Unix-socket communication.

use std::fmt;
use std::path::{Path, PathBuf};

mod unix;

/// Unix-socket upstream-agent APIs and their errors.
pub use unix::{AgentError, UnixSocketAgent, UpstreamAgent};
pub(crate) use unix::{read_frame, write_frame};

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
/// A normalized name for a configured upstream agent.
///
/// ```
/// use kmux::agent::AgentName;
///
/// assert_eq!(AgentName::new("Work_Agent").unwrap().as_str(), "work_agent");
/// ```
pub struct AgentName(String);

impl AgentName {
    /// Validates and lowercases an agent name.
    pub fn new(value: impl AsRef<str>) -> Result<Self, AgentNameError> {
        let value = value.as_ref();
        if !is_name(value) {
            return Err(AgentNameError::Invalid);
        }

        Ok(Self(value.to_ascii_lowercase()))
    }

    /// Returns the normalized agent name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AgentName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// An invalid agent-name error.
pub enum AgentNameError {
    /// The name is empty or contains unsupported characters.
    Invalid,
}

impl fmt::Display for AgentNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("agent names must use letters, numbers, '.', '_' or '-'")
    }
}

impl std::error::Error for AgentNameError {}

#[derive(Clone, Debug, Eq, PartialEq)]
/// A configured Unix-socket upstream agent.
pub struct AgentDefinition {
    name: AgentName,
    socket: PathBuf,
}

impl AgentDefinition {
    /// Creates a definition whose socket path is absolute.
    pub fn new(name: AgentName, socket: impl Into<PathBuf>) -> Result<Self, AgentDefinitionError> {
        let socket = socket.into();
        if !socket.is_absolute() {
            return Err(AgentDefinitionError::SocketMustBeAbsolute);
        }

        Ok(Self { name, socket })
    }

    /// Returns the normalized configured name.
    pub fn name(&self) -> &AgentName {
        &self.name
    }

    /// Returns the Unix socket path.
    pub fn socket(&self) -> &Path {
        &self.socket
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// An invalid agent-definition error.
pub enum AgentDefinitionError {
    /// The configured socket is relative.
    SocketMustBeAbsolute,
}

impl fmt::Display for AgentDefinitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("agent socket paths must be absolute")
    }
}

impl std::error::Error for AgentDefinitionError {}

fn is_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::{AgentDefinition, AgentName};

    #[test]
    fn agent_names_are_normalized() {
        let name = AgentName::new("BitWarden").unwrap();

        assert_eq!(name.as_str(), "bitwarden");
    }

    #[test]
    fn agent_sockets_must_be_absolute() {
        let name = AgentName::new("bitwarden").unwrap();

        assert!(AgentDefinition::new(name, "agent.sock").is_err());
    }
}
