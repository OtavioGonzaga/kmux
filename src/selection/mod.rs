use crate::agent::{UnixSocketAgent, UpstreamAgent};
use crate::catalog::{Identity, KeyEntry, ScopeQuery};
use crate::config::Config;
use crate::scope::ScopePath;
use inquire::Select;
use std::collections::BTreeMap;
use std::fmt;
use std::io::{IsTerminal, stdin, stdout};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Candidate {
    pub entry: KeyEntry,
    pub identity: Identity,
}

impl fmt::Display for Candidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({})",
            self.entry.alias(),
            self.identity.comment.as_deref().unwrap_or("no comment")
        )
    }
}

pub fn resolve(config: &Config, scope: ScopePath) -> Result<Vec<Candidate>, SelectionError> {
    let query = ScopeQuery::new(scope);
    let mut available = BTreeMap::new();
    for (name, definition) in config.agents() {
        let agent = UnixSocketAgent::new(definition.socket().to_owned());
        available.insert(name.clone(), agent.identities()?);
    }
    Ok(resolve_available(
        config.catalog().query(&query),
        &available,
    ))
}

pub fn resolve_available(
    entries: Vec<&KeyEntry>,
    available: &BTreeMap<crate::agent::AgentName, Vec<Identity>>,
) -> Vec<Candidate> {
    entries
        .into_iter()
        .filter_map(|entry| {
            available
                .get(entry.agent())?
                .iter()
                .find(|identity| identity.fingerprint == *entry.fingerprint())
                .cloned()
                .map(|identity| Candidate {
                    entry: entry.clone(),
                    identity,
                })
        })
        .collect()
}

pub fn choose(candidates: Vec<Candidate>) -> Result<Candidate, SelectionError> {
    match candidates.len() {
        0 => Err(SelectionError::NoCandidates),
        1 => Ok(candidates.into_iter().next().unwrap()),
        _ if !stdin().is_terminal() || !stdout().is_terminal() => Err(SelectionError::Ambiguous(
            candidates
                .into_iter()
                .map(|candidate| candidate.to_string())
                .collect(),
        )),
        _ => Select::new("Select identity", candidates)
            .prompt()
            .map_err(|error| SelectionError::Prompt(error.to_string())),
    }
}

#[derive(Debug)]
pub enum SelectionError {
    Agent(crate::agent::AgentError),
    NoCandidates,
    Ambiguous(Vec<String>),
    Prompt(String),
}
impl From<crate::agent::AgentError> for SelectionError {
    fn from(value: crate::agent::AgentError) -> Self {
        Self::Agent(value)
    }
}
impl fmt::Display for SelectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Agent(error) => error.fmt(f),
            Self::NoCandidates => f.write_str("no configured identities match the requested scope"),
            Self::Ambiguous(candidates) => write!(
                f,
                "multiple identities match; use an interactive terminal: {}",
                candidates.join(", ")
            ),
            Self::Prompt(error) => write!(f, "identity selection failed: {error}"),
        }
    }
}
impl std::error::Error for SelectionError {}
