//! Resolution of configured keys against identities available upstream.
//!
//! Static catalog filters are applied before upstream agents are contacted.
//! Call `resolve_for_execution` to apply kmux's execution policy.

use crate::agent::{UnixSocketAgent, UpstreamAgent};
use crate::catalog::{Identity, KeyEntry, KeyQuery, QueryMatch};
use crate::config::Config;
use inquire::{MultiSelect, Select};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{IsTerminal, stdin};

#[derive(Clone, Debug, Eq, PartialEq)]
/// A configured key paired with an available upstream public identity.
pub struct Candidate {
    /// The configured catalog entry.
    pub entry: KeyEntry,
    /// The matching identity currently advertised by the upstream agent.
    pub identity: Identity,
    /// The configured scope that matched the query, if one was requested.
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

/// Resolves static matches against the public identities currently upstream.
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

/// Resolves matches from exactly one upstream agent for filtered execution.
///
/// This fails before contacting an upstream agent when static matches span
/// multiple agents, because a filtered proxy can delegate identities from only
/// one upstream agent at a time.
pub fn resolve_single_agent(
    config: &Config,
    query: &KeyQuery,
) -> Result<Vec<Candidate>, SelectionError> {
    validate_agent(config, query)?;
    let entries = config.catalog().query_static(query);
    let agents = entries
        .iter()
        .map(|matched| matched.entry.agent().clone())
        .collect::<BTreeSet<_>>();
    let agent = match agents.len() {
        0 => return Err(SelectionError::NoCandidates(Box::new(query.clone()))),
        1 => agents.into_iter().next().unwrap(),
        _ => return Err(SelectionError::MultipleAgents(agents)),
    };
    let definition = config
        .agents()
        .get(&agent)
        .ok_or_else(|| SelectionError::MissingAgent(agent.clone()))?;
    let available = BTreeMap::from([(
        agent,
        UnixSocketAgent::new(definition.socket().to_owned()).identities()?,
    )]);
    let candidates = resolve_available(entries, &available);
    if candidates.is_empty() {
        return Err(SelectionError::NoCandidates(Box::new(query.clone())));
    }
    Ok(candidates)
}

/// Resolves the identities authorized for one command execution.
///
/// Explicit filters authorize every match unless `select` requests an
/// interactive subset. Unfiltered execution requires an interactive selection
/// when more than one identity or upstream agent is available.
pub fn resolve_for_execution(
    config: &Config,
    query: &KeyQuery,
    has_filters: bool,
    select: bool,
) -> Result<Vec<Candidate>, SelectionError> {
    resolve_for_execution_with(
        config,
        query,
        has_filters,
        select,
        stdin().is_terminal(),
        &InquireAgentChooser,
        &InquireCandidateSelector,
    )
}

fn resolve_for_execution_with(
    config: &Config,
    query: &KeyQuery,
    has_filters: bool,
    select: bool,
    interactive: bool,
    agent_chooser: &dyn AgentChooser,
    candidate_selector: &dyn CandidateSelector,
) -> Result<Vec<Candidate>, SelectionError> {
    validate_agent(config, query)?;
    let entries = config.catalog().query_static(query);
    if entries.is_empty() {
        return Err(SelectionError::NoCandidates(Box::new(query.clone())));
    }
    let agents = entries
        .iter()
        .map(|matched| matched.entry.agent().clone())
        .collect::<BTreeSet<_>>();
    let agent = if agents.len() == 1 {
        agents.into_iter().next().unwrap()
    } else if has_filters && !select {
        return Err(SelectionError::MultipleAgents(agents));
    } else {
        choose_agent_with_mode(agents, interactive, agent_chooser)?
    };
    let definition = config
        .agents()
        .get(&agent)
        .ok_or_else(|| SelectionError::MissingAgent(agent.clone()))?;
    let available = BTreeMap::from([(
        agent.clone(),
        UnixSocketAgent::new(definition.socket().to_owned()).identities()?,
    )]);
    let candidates = resolve_available(
        entries
            .into_iter()
            .filter(|matched| matched.entry.agent() == &agent)
            .collect(),
        &available,
    );
    if has_filters && !select {
        if candidates.is_empty() {
            return Err(SelectionError::NoCandidates(Box::new(query.clone())));
        }
        Ok(candidates)
    } else {
        select_with_mode(query, candidates, interactive, candidate_selector)
    }
}

/// Verifies that an agent query names an agent present in configuration.
pub fn validate_agent(config: &Config, query: &KeyQuery) -> Result<(), SelectionError> {
    if let Some(agent) = query.agent()
        && !config.agents().contains_key(agent)
    {
        return Err(SelectionError::UnknownAgent(agent.clone()));
    }
    Ok(())
}

/// Intersects static query matches with identities collected from each agent.
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

/// Chooses a candidate using the controlling terminal when necessary.
pub fn choose(query: &KeyQuery, candidates: Vec<Candidate>) -> Result<Candidate, SelectionError> {
    choose_with(query, candidates, &InquireCandidateChooser)
}

/// An interactive policy for selecting one candidate among several.
pub trait CandidateChooser {
    /// Selects exactly one candidate or returns a selection error.
    fn choose(&self, candidates: Vec<Candidate>) -> Result<Candidate, SelectionError>;
}
/// The standard terminal chooser implemented with `inquire`.
pub struct InquireCandidateChooser;
impl CandidateChooser for InquireCandidateChooser {
    fn choose(&self, candidates: Vec<Candidate>) -> Result<Candidate, SelectionError> {
        Select::new("Select identity", candidates)
            .prompt()
            .map_err(|error| SelectionError::Prompt(error.to_string()))
    }
}

/// An interactive policy for selecting a subset of candidates.
pub trait CandidateSelector {
    /// Selects zero or more candidates from the available options.
    fn select(&self, candidates: Vec<Candidate>) -> Result<Vec<Candidate>, SelectionError>;
}

/// The standard terminal multi-selector implemented with `inquire`.
pub struct InquireCandidateSelector;
impl CandidateSelector for InquireCandidateSelector {
    fn select(&self, candidates: Vec<Candidate>) -> Result<Vec<Candidate>, SelectionError> {
        MultiSelect::new("Select SSH identities", candidates)
            .prompt()
            .map_err(|error| SelectionError::Prompt(error.to_string()))
    }
}

trait AgentChooser {
    fn choose(
        &self,
        agents: Vec<crate::agent::AgentName>,
    ) -> Result<crate::agent::AgentName, SelectionError>;
}

struct InquireAgentChooser;
impl AgentChooser for InquireAgentChooser {
    fn choose(
        &self,
        agents: Vec<crate::agent::AgentName>,
    ) -> Result<crate::agent::AgentName, SelectionError> {
        Select::new("Select upstream agent", agents)
            .prompt()
            .map_err(|error| SelectionError::Prompt(error.to_string()))
    }
}

fn choose_agent_with_mode(
    agents: BTreeSet<crate::agent::AgentName>,
    interactive: bool,
    chooser: &dyn AgentChooser,
) -> Result<crate::agent::AgentName, SelectionError> {
    match agents.len() {
        0 => unreachable!("an execution query must have at least one matching agent"),
        1 => Ok(agents.into_iter().next().unwrap()),
        _ if !interactive => Err(SelectionError::AmbiguousAgents(agents)),
        _ => chooser.choose(agents.into_iter().collect()),
    }
}

/// Applies selection behavior with a caller-provided chooser.
pub fn choose_with(
    query: &KeyQuery,
    candidates: Vec<Candidate>,
    chooser: &dyn CandidateChooser,
) -> Result<Candidate, SelectionError> {
    choose_with_mode(query, candidates, stdin().is_terminal(), chooser)
}

/// Applies selection behavior using an explicit interactive-mode flag.
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

/// Selects multiple candidates using the controlling terminal when necessary.
pub fn select(
    query: &KeyQuery,
    candidates: Vec<Candidate>,
) -> Result<Vec<Candidate>, SelectionError> {
    select_with_mode(
        query,
        candidates,
        stdin().is_terminal(),
        &InquireCandidateSelector,
    )
}

/// Applies multi-selection behavior using an explicit interactive-mode flag.
pub fn select_with_mode(
    query: &KeyQuery,
    candidates: Vec<Candidate>,
    interactive: bool,
    selector: &dyn CandidateSelector,
) -> Result<Vec<Candidate>, SelectionError> {
    match candidates.len() {
        0 => Err(SelectionError::NoCandidates(Box::new(query.clone()))),
        1 => Ok(candidates),
        _ if !interactive => Err(SelectionError::Ambiguous(
            Box::new(query.clone()),
            candidates
                .into_iter()
                .map(|candidate| candidate.to_string())
                .collect(),
        )),
        _ => {
            let selected = selector.select(candidates.clone())?;
            if selected.is_empty() {
                Err(SelectionError::EmptySelection)
            } else if selected
                .iter()
                .any(|candidate| !candidates.contains(candidate))
            {
                Err(SelectionError::InvalidSelection)
            } else {
                Ok(selected)
            }
        }
    }
}

#[derive(Debug)]
/// Failure while resolving or choosing a configured identity.
pub enum SelectionError {
    /// Upstream-agent communication failed.
    Agent(crate::agent::AgentError),
    /// No configured identities satisfied the query and availability check.
    NoCandidates(Box<KeyQuery>),
    /// Multiple candidates matched without a usable interactive terminal.
    Ambiguous(Box<KeyQuery>, Vec<String>),
    /// The interactive chooser failed.
    Prompt(String),
    /// The interactive selector confirmed no identities.
    EmptySelection,
    /// The interactive selector returned an identity it was not offered.
    InvalidSelection,
    /// A catalog entry referenced an agent absent from the configuration.
    MissingAgent(crate::agent::AgentName),
    /// The query named an agent absent from the configuration.
    UnknownAgent(crate::agent::AgentName),
    /// Static matches belong to more than one upstream agent.
    MultipleAgents(BTreeSet<crate::agent::AgentName>),
    /// Multiple upstream agents require an interactive choice.
    AmbiguousAgents(BTreeSet<crate::agent::AgentName>),
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
            Self::EmptySelection => f.write_str("no identities selected"),
            Self::InvalidSelection => f.write_str("selected identity was not offered"),
            Self::MissingAgent(agent) => write!(f, "configured agent '{agent}' is missing"),
            Self::UnknownAgent(agent) => write!(f, "unknown configured agent '{agent}'"),
            Self::MultipleAgents(agents) => write!(
                f,
                "matched identities span multiple upstream agents: {}; add --agent to select one upstream agent",
                agents
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::AmbiguousAgents(agents) => write!(
                f,
                "multiple upstream agents matched; run interactively to select one or add --agent: {}",
                agents
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
}
impl std::error::Error for SelectionError {}

#[cfg(test)]
mod tests {
    use super::{
        AgentChooser, Candidate, CandidateChooser, CandidateSelector, SelectionError,
        choose_agent_with_mode, choose_with_mode, resolve, resolve_available,
        resolve_for_execution_with, resolve_single_agent, sanitize_comment, select_with_mode,
    };
    use crate::agent::{AgentDefinition, AgentName, read_frame, write_frame};
    use crate::catalog::{Fingerprint, Identity, KeyAlias, KeyCatalog, KeyEntry, KeyQuery};
    use crate::config::Config;
    use std::collections::{BTreeMap, BTreeSet};
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

    struct RecordingSelector {
        called: std::cell::Cell<bool>,
        selected: Vec<Candidate>,
    }
    impl CandidateSelector for RecordingSelector {
        fn select(&self, _: Vec<Candidate>) -> Result<Vec<Candidate>, SelectionError> {
            self.called.set(true);
            Ok(self.selected.clone())
        }
    }

    #[test]
    fn multi_selection_uses_the_selector_and_rejects_empty_choices() {
        let first = candidate();
        let second = candidate();
        let selector = RecordingSelector {
            called: std::cell::Cell::new(false),
            selected: vec![first.clone()],
        };
        assert_eq!(
            select_with_mode(
                &query(),
                vec![first.clone(), second.clone()],
                true,
                &selector
            )
            .unwrap(),
            vec![first.clone()]
        );
        assert!(selector.called.get());

        let empty = RecordingSelector {
            called: std::cell::Cell::new(false),
            selected: Vec::new(),
        };
        assert!(matches!(
            select_with_mode(&query(), vec![first, second], true, &empty),
            Err(SelectionError::EmptySelection)
        ));
        assert!(empty.called.get());

        let mut invalid_candidate = candidate();
        invalid_candidate.identity.key_blob = b"not-offered".to_vec();
        let invalid = RecordingSelector {
            called: std::cell::Cell::new(false),
            selected: vec![invalid_candidate],
        };
        assert!(matches!(
            select_with_mode(&query(), vec![candidate(), candidate()], true, &invalid),
            Err(SelectionError::InvalidSelection)
        ));
    }

    #[test]
    fn multi_selection_requires_a_terminal_and_skips_single_candidates() {
        let candidate = candidate();
        let selector = RecordingSelector {
            called: std::cell::Cell::new(false),
            selected: Vec::new(),
        };
        assert!(matches!(
            select_with_mode(
                &query(),
                vec![candidate.clone(), candidate.clone()],
                false,
                &selector
            ),
            Err(SelectionError::Ambiguous(_, _))
        ));
        assert!(!selector.called.get());
        assert_eq!(
            select_with_mode(&query(), vec![candidate.clone()], true, &selector).unwrap(),
            [candidate]
        );
        assert!(!selector.called.get());
    }

    struct FakeAgentChooser;
    impl AgentChooser for FakeAgentChooser {
        fn choose(&self, agents: Vec<AgentName>) -> Result<AgentName, SelectionError> {
            Ok(agents.into_iter().next().unwrap())
        }
    }

    struct FirstCandidateSelector(std::cell::Cell<bool>);
    impl CandidateSelector for FirstCandidateSelector {
        fn select(&self, candidates: Vec<Candidate>) -> Result<Vec<Candidate>, SelectionError> {
            self.0.set(true);
            Ok(vec![candidates.into_iter().next().unwrap()])
        }
    }

    #[test]
    fn multiple_agents_require_an_interactive_choice() {
        let agents = BTreeSet::from([
            AgentName::new("primary").unwrap(),
            AgentName::new("secondary").unwrap(),
        ]);
        assert!(matches!(
            choose_agent_with_mode(agents.clone(), false, &FakeAgentChooser),
            Err(SelectionError::AmbiguousAgents(_))
        ));
        assert_eq!(
            choose_agent_with_mode(agents, true, &FakeAgentChooser).unwrap(),
            AgentName::new("primary").unwrap()
        );
    }

    #[test]
    fn execution_selects_an_agent_before_contacting_upstreams() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let primary_socket = std::env::temp_dir().join(format!("kmux-primary-{unique}.sock"));
        let secondary_socket = std::env::temp_dir().join(format!("kmux-secondary-{unique}.sock"));
        let primary_listener = UnixListener::bind(&primary_socket).unwrap();
        let secondary_listener = UnixListener::bind(&secondary_socket).unwrap();
        secondary_listener.set_nonblocking(true).unwrap();
        let primary_blob = b"primary-public-key".to_vec();
        let worker_blob = primary_blob.clone();
        let worker = thread::spawn(move || {
            let (mut stream, _) = primary_listener.accept().unwrap();
            assert_eq!(read_frame(&mut stream).unwrap(), [11]);
            let mut response = vec![12];
            response.extend_from_slice(&1_u32.to_be_bytes());
            response.extend_from_slice(&(worker_blob.len() as u32).to_be_bytes());
            response.extend_from_slice(&worker_blob);
            response.extend_from_slice(&0_u32.to_be_bytes());
            write_frame(&mut stream, &response).unwrap();
        });
        let primary = AgentName::new("primary").unwrap();
        let secondary = AgentName::new("secondary").unwrap();
        let config = Config::from_parts(
            BTreeMap::from([
                (
                    primary.clone(),
                    AgentDefinition::new(primary.clone(), &primary_socket).unwrap(),
                ),
                (
                    secondary.clone(),
                    AgentDefinition::new(secondary.clone(), &secondary_socket).unwrap(),
                ),
            ]),
            KeyCatalog::from_entries([
                KeyEntry::new(
                    KeyAlias::new("primary-key").unwrap(),
                    Fingerprint::from_public_key_blob(&primary_blob),
                    primary,
                    [],
                    BTreeMap::new(),
                ),
                KeyEntry::new(
                    KeyAlias::new("secondary-key").unwrap(),
                    Fingerprint::from_public_key_blob(b"secondary-public-key"),
                    secondary,
                    [],
                    BTreeMap::new(),
                ),
            ])
            .unwrap(),
        )
        .unwrap();
        let selector = FirstCandidateSelector(std::cell::Cell::new(false));

        assert_eq!(
            resolve_for_execution_with(
                &config,
                &query(),
                false,
                false,
                true,
                &FakeAgentChooser,
                &selector,
            )
            .unwrap()
            .len(),
            1
        );
        assert!(!selector.0.get());
        worker.join().unwrap();
        assert!(
            matches!(secondary_listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
        let _ = std::fs::remove_file(primary_socket);
        let _ = std::fs::remove_file(secondary_socket);
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
    fn filtered_resolution_rejects_multiple_agents_before_connecting() {
        let primary = AgentName::new("primary").unwrap();
        let secondary = AgentName::new("secondary").unwrap();
        let config = Config::from_parts(
            BTreeMap::from([
                (
                    primary.clone(),
                    AgentDefinition::new(primary.clone(), "/tmp/kmux-primary.sock").unwrap(),
                ),
                (
                    secondary.clone(),
                    AgentDefinition::new(secondary.clone(), "/tmp/kmux-secondary.sock").unwrap(),
                ),
            ]),
            KeyCatalog::from_entries([
                KeyEntry::new(
                    KeyAlias::new("primary-key").unwrap(),
                    Fingerprint::from_public_key_blob(b"primary-key"),
                    primary.clone(),
                    ["personal".parse().unwrap()],
                    BTreeMap::new(),
                ),
                KeyEntry::new(
                    KeyAlias::new("secondary-key").unwrap(),
                    Fingerprint::from_public_key_blob(b"secondary-key"),
                    secondary.clone(),
                    ["personal".parse().unwrap()],
                    BTreeMap::new(),
                ),
            ])
            .unwrap(),
        )
        .unwrap();
        let query =
            KeyQuery::from_values(Some("personal".to_owned()), None, None, None, [], None).unwrap();

        assert!(matches!(
            resolve_single_agent(&config, &query),
            Err(SelectionError::MultipleAgents(agents)) if agents == BTreeSet::from([primary, secondary])
        ));
    }

    #[test]
    fn agent_filter_limits_filtered_resolution_to_one_upstream() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let socket = std::env::temp_dir().join(format!("kmux-primary-{unique}.sock"));
        let listener = UnixListener::bind(&socket).unwrap();
        let key_blob = b"primary-public-key".to_vec();
        let worker_blob = key_blob.clone();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            assert_eq!(read_frame(&mut stream).unwrap(), [11]);
            let mut response = vec![12];
            response.extend_from_slice(&1_u32.to_be_bytes());
            response.extend_from_slice(&(worker_blob.len() as u32).to_be_bytes());
            response.extend_from_slice(&worker_blob);
            response.extend_from_slice(&0_u32.to_be_bytes());
            write_frame(&mut stream, &response).unwrap();
        });
        let primary = AgentName::new("primary").unwrap();
        let secondary = AgentName::new("secondary").unwrap();
        let config = Config::from_parts(
            BTreeMap::from([
                (
                    primary.clone(),
                    AgentDefinition::new(primary.clone(), &socket).unwrap(),
                ),
                (
                    secondary.clone(),
                    AgentDefinition::new(secondary.clone(), "/tmp/kmux-secondary.sock").unwrap(),
                ),
            ]),
            KeyCatalog::from_entries([
                KeyEntry::new(
                    KeyAlias::new("primary-key").unwrap(),
                    Fingerprint::from_public_key_blob(&key_blob),
                    primary,
                    ["personal".parse().unwrap()],
                    BTreeMap::new(),
                ),
                KeyEntry::new(
                    KeyAlias::new("secondary-key").unwrap(),
                    Fingerprint::from_public_key_blob(b"secondary-public-key"),
                    secondary,
                    ["personal".parse().unwrap()],
                    BTreeMap::new(),
                ),
            ])
            .unwrap(),
        )
        .unwrap();
        let query = KeyQuery::from_values(
            Some("personal".to_owned()),
            None,
            None,
            None,
            [],
            Some("primary".to_owned()),
        )
        .unwrap();

        assert_eq!(resolve_single_agent(&config, &query).unwrap().len(), 1);
        worker.join().unwrap();
        let _ = std::fs::remove_file(socket);
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
