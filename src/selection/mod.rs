use crate::agent::{UnixSocketAgent, UpstreamAgent};
use crate::catalog::{Identity, KeyEntry, ScopeQuery};
use crate::config::Config;
use crate::scope::ScopePath;
use inquire::Select;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{IsTerminal, stdin};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Candidate {
    pub entry: KeyEntry,
    pub identity: Identity,
    pub matched_scope: ScopePath,
}

impl fmt::Display for Candidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} - {} - {}",
            self.entry.alias(),
            self.matched_scope,
            self.identity.comment.as_deref().unwrap_or("no comment")
        )
    }
}

pub fn resolve(config: &Config, scope: ScopePath) -> Result<Vec<Candidate>, SelectionError> {
    let query = ScopeQuery::new(scope);
    let entries = config.catalog().query(&query);
    let required_agents = entries
        .iter()
        .map(|entry| entry.agent())
        .collect::<BTreeSet<_>>();
    let mut available = BTreeMap::new();
    for name in required_agents {
        let definition = config
            .agents()
            .get(name)
            .ok_or_else(|| SelectionError::MissingAgent(name.clone()))?;
        let agent = UnixSocketAgent::new(definition.socket().to_owned());
        available.insert(name.clone(), agent.identities()?);
    }
    Ok(resolve_available(entries, &available, &query))
}

pub fn resolve_available(
    entries: Vec<&KeyEntry>,
    available: &BTreeMap<crate::agent::AgentName, Vec<Identity>>,
    query: &ScopeQuery,
) -> Vec<Candidate> {
    entries
        .into_iter()
        .filter_map(|entry| {
            let matched_scope = query.matching_scope(entry)?;
            available
                .get(entry.agent())?
                .iter()
                .find(|identity| identity.fingerprint == *entry.fingerprint())
                .cloned()
                .map(|identity| Candidate {
                    entry: entry.clone(),
                    identity,
                    matched_scope,
                })
        })
        .collect()
}

pub fn choose(candidates: Vec<Candidate>) -> Result<Candidate, SelectionError> {
    choose_with(candidates, &InquireCandidateChooser)
}

pub trait CandidateChooser {
    fn choose(&self, candidates: Vec<Candidate>) -> Result<Candidate, SelectionError>;
}

pub struct InquireCandidateChooser;

impl CandidateChooser for InquireCandidateChooser {
    fn choose(&self, candidates: Vec<Candidate>) -> Result<Candidate, SelectionError> {
        Select::new("Select identity", candidates)
            .prompt()
            .map_err(|error| SelectionError::Prompt(error.to_string()))
    }
}

pub fn choose_with(
    candidates: Vec<Candidate>,
    chooser: &dyn CandidateChooser,
) -> Result<Candidate, SelectionError> {
    choose_with_mode(candidates, stdin().is_terminal(), chooser)
}

pub fn choose_with_mode(
    candidates: Vec<Candidate>,
    interactive: bool,
    chooser: &dyn CandidateChooser,
) -> Result<Candidate, SelectionError> {
    match candidates.len() {
        0 => Err(SelectionError::NoCandidates),
        1 => Ok(candidates.into_iter().next().unwrap()),
        _ if !interactive => Err(SelectionError::Ambiguous(
            candidates
                .into_iter()
                .map(|candidate| candidate.to_string())
                .collect(),
        )),
        _ => chooser.choose(candidates),
    }
}

#[derive(Debug)]
pub enum SelectionError {
    Agent(crate::agent::AgentError),
    NoCandidates,
    Ambiguous(Vec<String>),
    Prompt(String),
    MissingAgent(crate::agent::AgentName),
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
            Self::MissingAgent(agent) => write!(f, "configured agent '{agent}' is missing"),
        }
    }
}
impl std::error::Error for SelectionError {}

#[cfg(test)]
mod tests {
    use super::{Candidate, CandidateChooser, SelectionError, choose_with_mode, resolve};
    use crate::agent::{AgentDefinition, AgentName, read_frame, write_frame};
    use crate::catalog::{Fingerprint, Identity, KeyAlias, KeyCatalog, KeyEntry};
    use crate::config::Config;
    use crate::scope::ScopePath;
    use std::collections::BTreeMap;
    use std::io;
    use std::os::unix::net::UnixListener;
    use std::str::FromStr;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn resolution_does_not_contact_unrelated_agents() {
        let work = AgentName::new("work").unwrap();
        let old = AgentName::new("old-agent").unwrap();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let work_socket =
            std::env::temp_dir().join(format!("kmux-work-{}-{unique}.sock", std::process::id()));
        let old_socket =
            std::env::temp_dir().join(format!("kmux-old-{}-{unique}.sock", std::process::id()));
        let work_listener = UnixListener::bind(&work_socket).unwrap();
        let old_listener = UnixListener::bind(&old_socket).unwrap();
        old_listener.set_nonblocking(true).unwrap();
        let key_blob = b"work-public-key".to_vec();
        let fingerprint = Fingerprint::from_public_key_blob(&key_blob);
        let worker = thread::spawn(move || {
            let (mut stream, _) = work_listener.accept().unwrap();
            assert_eq!(read_frame(&mut stream).unwrap(), [11]);
            let mut response = vec![12];
            response.extend_from_slice(&1_u32.to_be_bytes());
            response.extend_from_slice(&(key_blob.len() as u32).to_be_bytes());
            response.extend_from_slice(&key_blob);
            response.extend_from_slice(&0_u32.to_be_bytes());
            write_frame(&mut stream, &response).unwrap();
        });
        let entry = KeyEntry::new(
            KeyAlias::new("work-key").unwrap(),
            fingerprint,
            work.clone(),
            [ScopePath::from_str("work/production").unwrap()],
            BTreeMap::new(),
        )
        .unwrap();
        let config = Config::from_parts(
            BTreeMap::from([
                (
                    work.clone(),
                    AgentDefinition::new(work, &work_socket).unwrap(),
                ),
                (old.clone(), AgentDefinition::new(old, &old_socket).unwrap()),
            ]),
            KeyCatalog::from_entries([entry]).unwrap(),
        )
        .unwrap();
        assert_eq!(
            resolve(&config, ScopePath::from_str("work").unwrap())
                .unwrap()
                .len(),
            1
        );
        worker.join().unwrap();
        assert!(
            matches!(old_listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
        let _ = std::fs::remove_file(work_socket);
        let _ = std::fs::remove_file(old_socket);
    }

    struct FakeChooser(std::cell::Cell<usize>);
    impl CandidateChooser for FakeChooser {
        fn choose(&self, candidates: Vec<Candidate>) -> Result<Candidate, SelectionError> {
            self.0.set(self.0.get() + 1);
            Ok(candidates.into_iter().next().unwrap())
        }
    }

    #[test]
    fn selection_mode_and_chooser_invocation_are_correct() {
        let chooser = FakeChooser(std::cell::Cell::new(0));
        assert!(matches!(
            choose_with_mode(Vec::new(), true, &chooser),
            Err(SelectionError::NoCandidates)
        ));
        let candidate = candidate("hogix/production", "personal/server");
        assert!(candidate.to_string().contains("hogix/production"));
        assert!(!candidate.to_string().contains("personal/server"));
        assert_eq!(
            choose_with_mode(vec![candidate.clone()], false, &chooser).unwrap(),
            candidate
        );
        assert_eq!(chooser.0.get(), 0);
        assert!(matches!(
            choose_with_mode(vec![candidate.clone(), candidate.clone()], false, &chooser),
            Err(SelectionError::Ambiguous(_))
        ));
        assert_eq!(
            choose_with_mode(vec![candidate.clone(), candidate], true, &chooser)
                .unwrap()
                .matched_scope
                .to_string(),
            "hogix/production"
        );
        assert_eq!(chooser.0.get(), 1);
    }

    fn candidate(matched_scope: &str, other_scope: &str) -> Candidate {
        let agent = AgentName::new("agent").unwrap();
        let entry = KeyEntry::new(
            KeyAlias::new("key").unwrap(),
            Fingerprint::from_public_key_blob(b"key"),
            agent,
            [
                ScopePath::from_str(other_scope).unwrap(),
                ScopePath::from_str(matched_scope).unwrap(),
            ],
            BTreeMap::new(),
        )
        .unwrap();
        Candidate {
            entry,
            identity: Identity {
                key_blob: b"key".to_vec(),
                fingerprint: Fingerprint::from_public_key_blob(b"key"),
                comment: None,
            },
            matched_scope: ScopePath::from_str(matched_scope).unwrap(),
        }
    }
}
