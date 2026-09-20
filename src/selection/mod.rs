use crate::agent::{UnixSocketAgent, UpstreamAgent};
use crate::catalog::{Identity, KeyEntry, KeyQuery, QueryMatch};
use crate::config::Config;
use inquire::Select;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{IsTerminal, stdin};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Candidate {
    pub entry: KeyEntry,
    pub identity: Identity,
    pub matched_scope: Option<crate::scope::ScopePath>,
}

impl fmt::Display for Candidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scope = match &self.matched_scope {
            Some(scope) => scope.to_string(),
            None if self.entry.scopes().is_empty() => "unscoped".to_owned(),
            None => format!(
                "scopes: {}",
                self.entry
                    .scopes()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        };
        write!(
            f,
            "{} - {} - {}",
            self.entry.alias(),
            scope,
            self.entry
                .comment()
                .map(sanitize_comment)
                .unwrap_or_else(|| "no comment".to_owned())
        )
    }
}

const MAX_DISPLAY_COMMENT_CHARS: usize = 200;

fn sanitize_comment(comment: &str) -> String {
    let mut sanitized = String::with_capacity(comment.len().min(MAX_DISPLAY_COMMENT_CHARS));
    for character in comment.chars().take(MAX_DISPLAY_COMMENT_CHARS) {
        sanitized.push(if character.is_control() {
            ' '
        } else {
            character
        });
    }
    if comment.chars().nth(MAX_DISPLAY_COMMENT_CHARS).is_some() {
        sanitized.push_str("...");
    }
    sanitized
}

pub fn resolve(config: &Config, query: &KeyQuery) -> Result<Vec<Candidate>, SelectionError> {
    validate_agent(config, query)?;
    let entries = config.catalog().query_static(query);
    let required_agents = entries
        .iter()
        .map(|entry| entry.entry.agent())
        .collect::<BTreeSet<_>>();
    let mut available = BTreeMap::new();
    for name in required_agents {
        let definition = config
            .agents()
            .get(name)
            .ok_or_else(|| SelectionError::MissingAgent(name.clone()))?;
        available.insert(
            name.clone(),
            UnixSocketAgent::new(definition.socket().to_owned()).identities()?,
        );
    }
    Ok(resolve_available(entries, &available))
}

pub fn validate_agent(config: &Config, query: &KeyQuery) -> Result<(), SelectionError> {
    if let Some(agent) = query.agent()
        && !config.agents().contains_key(agent)
    {
        return Err(SelectionError::UnknownAgent(agent.clone()));
    }
    Ok(())
}

pub fn resolve_available(
    entries: Vec<QueryMatch<'_>>,
    available: &BTreeMap<crate::agent::AgentName, Vec<Identity>>,
) -> Vec<Candidate> {
    entries
        .into_iter()
        .filter_map(|matched| {
            available
                .get(matched.entry.agent())?
                .iter()
                .find(|identity| identity.fingerprint == *matched.entry.fingerprint())
                .cloned()
                .map(|identity| Candidate {
                    entry: matched.entry.clone(),
                    identity,
                    matched_scope: matched.matched_scope,
                })
        })
        .collect()
}

pub fn choose(query: &KeyQuery, candidates: Vec<Candidate>) -> Result<Candidate, SelectionError> {
    choose_with(query, candidates, &InquireCandidateChooser)
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
    query: &KeyQuery,
    candidates: Vec<Candidate>,
    chooser: &dyn CandidateChooser,
) -> Result<Candidate, SelectionError> {
    choose_with_mode(query, candidates, stdin().is_terminal(), chooser)
}

pub fn choose_with_mode(
    query: &KeyQuery,
    candidates: Vec<Candidate>,
    interactive: bool,
    chooser: &dyn CandidateChooser,
) -> Result<Candidate, SelectionError> {
    match candidates.len() {
        0 => Err(SelectionError::NoCandidates(Box::new(query.clone()))),
        1 => Ok(candidates.into_iter().next().unwrap()),
        _ if !interactive => Err(SelectionError::Ambiguous(
            Box::new(query.clone()),
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
    NoCandidates(Box<KeyQuery>),
    Ambiguous(Box<KeyQuery>, Vec<String>),
    Prompt(String),
    MissingAgent(crate::agent::AgentName),
    UnknownAgent(crate::agent::AgentName),
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
            Self::NoCandidates(query) => write!(f, "no identities matched: {query}"),
            Self::Ambiguous(query, candidates) => write!(
                f,
                "multiple identities matched ({query}); run interactively to select one or add filters: {}",
                candidates.join(", ")
            ),
            Self::Prompt(error) => write!(f, "identity selection failed: {error}"),
            Self::MissingAgent(agent) => write!(f, "configured agent '{agent}' is missing"),
            Self::UnknownAgent(agent) => write!(f, "unknown configured agent '{agent}'"),
        }
    }
}
impl std::error::Error for SelectionError {}

#[cfg(test)]
mod tests {
    use super::{
        Candidate, CandidateChooser, SelectionError, choose_with_mode, resolve, resolve_available,
        sanitize_comment,
    };
    use crate::agent::{AgentDefinition, AgentName, read_frame, write_frame};
    use crate::catalog::{Fingerprint, Identity, KeyAlias, KeyCatalog, KeyEntry, KeyQuery};
    use crate::config::Config;
    use std::collections::BTreeMap;
    use std::io;
    use std::os::unix::net::UnixListener;
    use std::str::FromStr;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn query() -> KeyQuery {
        KeyQuery::default()
    }
    fn candidate() -> Candidate {
        Candidate {
            entry: KeyEntry::new(
                KeyAlias::new("key").unwrap(),
                Fingerprint::from_public_key_blob(b"key"),
                AgentName::new("agent").unwrap(),
                [],
                BTreeMap::new(),
            ),
            identity: Identity {
                key_blob: b"key".to_vec(),
                fingerprint: Fingerprint::from_public_key_blob(b"key"),
                comment: None,
            },
            matched_scope: None,
        }
    }
    struct FakeChooser;
    impl CandidateChooser for FakeChooser {
        fn choose(&self, candidates: Vec<Candidate>) -> Result<Candidate, SelectionError> {
            Ok(candidates.into_iter().next().unwrap())
        }
    }
    #[test]
    fn selection_never_chooses_ambiguous_candidates_without_a_terminal() {
        let candidate = candidate();
        assert!(matches!(
            choose_with_mode(&query(), Vec::new(), true, &FakeChooser),
            Err(SelectionError::NoCandidates(_))
        ));
        assert!(matches!(
            choose_with_mode(
                &query(),
                vec![candidate.clone(), candidate],
                false,
                &FakeChooser
            ),
            Err(SelectionError::Ambiguous(_, _))
        ));
    }

    struct RecordingChooser(std::cell::Cell<bool>);
    impl CandidateChooser for RecordingChooser {
        fn choose(&self, _: Vec<Candidate>) -> Result<Candidate, SelectionError> {
            self.0.set(true);
            unreachable!("a single candidate must not invoke the chooser")
        }
    }

    #[test]
    fn selection_returns_a_single_candidate_without_invoking_the_chooser() {
        let chooser = RecordingChooser(std::cell::Cell::new(false));
        assert!(choose_with_mode(&query(), vec![candidate()], true, &chooser).is_ok());
        assert!(!chooser.0.get());
    }
    #[test]
    fn unscoped_candidates_and_unicode_comments_are_displayed_safely() {
        assert_eq!(candidate().to_string(), "key - unscoped - no comment");
        assert_eq!(
            sanitize_comment("chave de produção\n"),
            "chave de produção "
        );
    }

    #[test]
    fn candidates_only_display_a_matched_scope_when_one_was_requested() {
        let mut candidate = candidate();
        candidate.entry = KeyEntry::new(
            KeyAlias::new("key").unwrap(),
            Fingerprint::from_public_key_blob(b"key"),
            AgentName::new("agent").unwrap(),
            [
                "hogix/production".parse().unwrap(),
                "backup".parse().unwrap(),
            ],
            BTreeMap::new(),
        );
        assert_eq!(
            candidate.to_string(),
            "key - scopes: backup,hogix/production - no comment"
        );
        candidate.matched_scope = Some("hogix/production".parse().unwrap());
        assert_eq!(candidate.to_string(), "key - hogix/production - no comment");
    }

    #[test]
    fn candidate_display_prefers_persisted_comment() {
        let mut candidate = candidate();
        candidate.entry = candidate
            .entry
            .with_comment(Some("Persisted deployment key".to_owned()));
        candidate.identity.comment = Some("different upstream comment".to_owned());
        assert_eq!(
            candidate.to_string(),
            "key - unscoped - Persisted deployment key"
        );
    }

    #[test]
    fn comment_filter_does_not_contact_agents_eliminated_by_static_filters() {
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
        let work = AgentName::new("work").unwrap();
        let old = AgentName::new("old").unwrap();
        let entry = KeyEntry::new(
            KeyAlias::new("work-key").unwrap(),
            fingerprint,
            work.clone(),
            ["work/production".parse().unwrap()],
            BTreeMap::new(),
        )
        .with_comment(Some("work deployment".to_owned()));
        let old_entry = KeyEntry::new(
            KeyAlias::new("old-key").unwrap(),
            Fingerprint::from_public_key_blob(b"old-public-key"),
            old.clone(),
            [],
            BTreeMap::new(),
        )
        .with_comment(Some("old deployment".to_owned()));
        let config = Config::from_parts(
            BTreeMap::from([
                (
                    work.clone(),
                    AgentDefinition::new(work, &work_socket).unwrap(),
                ),
                (old.clone(), AgentDefinition::new(old, &old_socket).unwrap()),
            ]),
            KeyCatalog::from_entries([entry, old_entry]).unwrap(),
        )
        .unwrap();
        let query =
            KeyQuery::from_values(None, Some("WORK".to_owned()), None, None, [], None).unwrap();
        assert_eq!(resolve(&config, &query).unwrap().len(), 1);
        worker.join().unwrap();
        assert!(
            matches!(old_listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
        let _ = std::fs::remove_file(work_socket);
        let _ = std::fs::remove_file(old_socket);
    }

    #[test]
    fn comment_filter_is_case_insensitive_and_matches_persisted_metadata() {
        let entry = KeyEntry::new(
            KeyAlias::new("deploy").unwrap(),
            Fingerprint::from_public_key_blob(b"key"),
            AgentName::new("agent").unwrap(),
            [],
            BTreeMap::new(),
        )
        .with_comment(Some("chave de produção".to_owned()));
        let catalog = KeyCatalog::from_entries([entry]).unwrap();
        let query =
            KeyQuery::from_values(None, Some("PRODUÇÃO".to_owned()), None, None, [], None).unwrap();
        let available = BTreeMap::from([(
            AgentName::new("agent").unwrap(),
            vec![Identity {
                key_blob: b"key".to_vec(),
                fingerprint: Fingerprint::from_public_key_blob(b"key"),
                comment: Some("different upstream comment".to_owned()),
            }],
        )]);
        assert_eq!(
            resolve_available(catalog.query_static(&query), &available).len(),
            1
        );
    }

    #[test]
    fn fingerprint_prefixes_remain_ambiguous_when_multiple_identities_match() {
        let first =
            Fingerprint::from_str("SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+Y").unwrap();
        let second =
            Fingerprint::from_str("SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+A").unwrap();
        let entries = KeyCatalog::from_entries([
            KeyEntry::new(
                KeyAlias::new("first").unwrap(),
                first.clone(),
                AgentName::new("agent").unwrap(),
                [],
                BTreeMap::new(),
            ),
            KeyEntry::new(
                KeyAlias::new("second").unwrap(),
                second.clone(),
                AgentName::new("agent").unwrap(),
                [],
                BTreeMap::new(),
            ),
        ])
        .unwrap();
        let prefix = &first.as_str()[7..18];
        let query =
            KeyQuery::from_values(None, None, None, Some(prefix.to_owned()), [], None).unwrap();
        let available = BTreeMap::from([(
            AgentName::new("agent").unwrap(),
            vec![
                Identity {
                    key_blob: b"first".to_vec(),
                    fingerprint: first,
                    comment: None,
                },
                Identity {
                    key_blob: b"second".to_vec(),
                    fingerprint: second,
                    comment: None,
                },
            ],
        )]);
        let candidates = resolve_available(entries.query_static(&query), &available);

        assert!(matches!(
            choose_with_mode(&query, candidates, false, &FakeChooser),
            Err(SelectionError::Ambiguous(_, _))
        ));
    }
}
