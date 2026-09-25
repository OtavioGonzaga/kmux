//! Reusable administrative operations for configured agents and keys.
//!
//! These operations mutate configuration transactionally and do not perform terminal I/O.

use crate::agent::{AgentError, AgentName, UnixSocketAgent};
use crate::catalog::{Identity, KeyAlias, KeyEntry};
use crate::config::{Config, ConfigError, ConfigSnapshot, ConfigStore};
use crate::scope::ScopePath;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Runtime inspection result for one configured upstream agent.
#[derive(Debug)]
pub struct AgentInspection {
    /// Normalized configured agent name.
    pub name: AgentName,
    /// Configured Unix socket path.
    pub socket: PathBuf,
    /// Outcome of querying this agent.
    pub status: AgentStatus,
}

/// Outcome of an individual upstream-agent query.
#[derive(Debug)]
pub enum AgentStatus {
    /// Agent responded successfully with its advertised public identities.
    Available(Vec<Identity>),
    /// Agent could not be reached or communication failed.
    Unavailable(AgentError),
    /// Agent responded with an invalid or unexpected protocol message.
    ProtocolError(AgentError),
    /// Connecting or communicating with the agent exceeded the configured timeout.
    TimedOut,
}

/// Inspects every configured agent independently, returning partial results.
///
/// `timeout` bounds the socket connection and each blocking read/write operation. A failed or
/// timed-out agent is represented in its own result and does not stop other queries.
pub fn inspect_agents(config: &Config, timeout: Duration) -> Vec<AgentInspection> {
    config
        .agents()
        .values()
        .map(|definition| {
            let status = if timeout.is_zero() {
                AgentStatus::TimedOut
            } else {
                match UnixSocketAgent::new(definition.socket().to_owned())
                    .identities_with_timeout(Some(timeout))
                {
                    Ok(identities) => AgentStatus::Available(identities),
                    Err(error @ AgentError::UnexpectedResponse)
                    | Err(error @ AgentError::MalformedResponse) => {
                        AgentStatus::ProtocolError(error)
                    }
                    Err(AgentError::Io(error))
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                        ) =>
                    {
                        AgentStatus::TimedOut
                    }
                    Err(AgentError::Connect(error))
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                        ) =>
                    {
                        AgentStatus::TimedOut
                    }
                    Err(error) => AgentStatus::Unavailable(error),
                }
            };
            AgentInspection {
                name: definition.name().clone(),
                socket: definition.socket().to_owned(),
                status,
            }
        })
        .collect()
}

/// Request to add a Unix-socket agent to a configuration.
pub struct AddAgentRequest {
    /// Validated agent name.
    pub name: AgentName,
    /// Absolute path to the SSH agent socket.
    pub socket: PathBuf,
}

/// Request to change an existing agent's socket path.
pub struct UpdateAgentRequest {
    /// Agent whose socket will be updated.
    pub name: AgentName,
    /// New absolute socket path.
    pub socket: PathBuf,
}

/// Request to add a configured public key entry.
pub struct AddKeyRequest {
    /// Validated key entry to add.
    pub entry: KeyEntry,
}

/// Request to replace metadata on an existing key.
pub struct UpdateKeyMetadataRequest {
    /// Alias of the configured key.
    pub alias: KeyAlias,
    /// Complete replacement scope list; an empty list clears scopes.
    pub scopes: Vec<ScopePath>,
    /// Complete replacement tag map; an empty map clears tags.
    pub tags: BTreeMap<String, String>,
    /// Replacement comment; `None` or an empty string clears the existing comment.
    pub comment: Option<String>,
}

/// Adds an agent using the shared configuration mutation rules.
pub fn add_agent(path: &Path, request: AddAgentRequest) -> Result<(), ConfigError> {
    ConfigStore::update(path, move |document| {
        document.add_agent(request.name, request.socket)
    })
}

/// Removes an agent, failing if configured keys still refer to it.
pub fn remove_agent(path: &Path, name: AgentName) -> Result<(), ConfigError> {
    ConfigStore::update(path, move |document| document.remove_agent(&name))
}

/// Updates an existing agent's socket path.
pub fn update_agent_socket(path: &Path, request: UpdateAgentRequest) -> Result<(), ConfigError> {
    ConfigStore::update(path, move |document| {
        document.update_agent_socket(&request.name, request.socket)
    })
}

/// Adds a key entry using the shared configuration mutation rules.
pub fn add_key(path: &Path, request: AddKeyRequest) -> Result<(), ConfigError> {
    ConfigStore::update(path, move |document| document.add_key(request.entry))
}

/// Removes a configured key by alias.
pub fn remove_key(path: &Path, alias: KeyAlias) -> Result<(), ConfigError> {
    ConfigStore::update(path, move |document| document.remove_key(&alias))
}

/// Replaces a key's scopes, tags, and comment without changing its identity or agent.
pub fn update_key_metadata(
    path: &Path,
    request: UpdateKeyMetadataRequest,
) -> Result<(), ConfigError> {
    ConfigStore::update(path, move |document| {
        document.update_key_metadata(
            &request.alias,
            request.scopes,
            request.tags,
            request.comment,
        )
    })
}

/// Updates key metadata only if the configuration still matches a previously loaded snapshot.
///
/// Use this when replacement metadata was derived from a configuration read earlier. Any
/// intervening change causes a conflict rather than silently overwriting that change.
pub fn update_key_metadata_if_unchanged(
    path: &Path,
    snapshot: &ConfigSnapshot,
    request: UpdateKeyMetadataRequest,
) -> Result<(), ConfigError> {
    let mut document = snapshot.document().clone();
    document.update_key_metadata(
        &request.alias,
        request.scopes,
        request.tags,
        request.comment,
    )?;
    ConfigStore::save_if_unchanged(path, snapshot, &document)
}

#[cfg(test)]
mod tests {
    use super::{
        AddAgentRequest, AddKeyRequest, AgentStatus, UpdateAgentRequest, UpdateKeyMetadataRequest,
        add_agent, add_key, inspect_agents, remove_agent, remove_key, update_agent_socket,
        update_key_metadata, update_key_metadata_if_unchanged,
    };
    use crate::agent::AgentName;
    use crate::catalog::{Fingerprint, KeyAlias, KeyEntry};
    use crate::config::{Config, ConfigDocument, ConfigError, ConfigStore};
    use crate::scope::ScopePath;
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    const FINGERPRINT: &str = "SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+Y";
    static TEMPORARY_PATH_ID: AtomicU64 = AtomicU64::new(0);

    fn temporary_directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "kmux-management-{}-{}",
            std::process::id(),
            TEMPORARY_PATH_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn manages_agents_and_keys_through_the_public_api() {
        let directory = temporary_directory();
        let path = directory.join("config.toml");
        ConfigStore::save(&path, &ConfigDocument::empty()).unwrap();
        let agent = AgentName::new("work").unwrap();
        add_agent(
            &path,
            AddAgentRequest {
                name: agent.clone(),
                socket: "/tmp/old.sock".into(),
            },
        )
        .unwrap();
        update_agent_socket(
            &path,
            UpdateAgentRequest {
                name: agent.clone(),
                socket: "/tmp/new.sock".into(),
            },
        )
        .unwrap();
        assert_eq!(
            Config::load(&path)
                .unwrap()
                .agents()
                .get(&agent)
                .unwrap()
                .socket(),
            std::path::Path::new("/tmp/new.sock")
        );
        let alias = KeyAlias::new("deploy").unwrap();
        add_key(
            &path,
            AddKeyRequest {
                entry: KeyEntry::new(
                    alias.clone(),
                    Fingerprint::from_str(FINGERPRINT).unwrap(),
                    agent.clone(),
                    [],
                    BTreeMap::new(),
                ),
            },
        )
        .unwrap();
        assert!(remove_agent(&path, agent.clone()).is_err());
        remove_key(&path, alias).unwrap();
        remove_agent(&path, agent).unwrap();

        assert!(Config::load(&path).unwrap().agents().is_empty());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn socket_update_preserves_toml_comment_and_key_formatting() {
        let directory = temporary_directory();
        let path = directory.join("config.toml");
        fs::write(
            &path,
            "version = 1\n\n[agents.work]\ntype   = 'unix'\nsocket = '/tmp/old.sock' # Local agent socket\n",
        )
        .unwrap();

        update_agent_socket(
            &path,
            UpdateAgentRequest {
                name: AgentName::new("work").unwrap(),
                socket: "/tmp/new.sock".into(),
            },
        )
        .unwrap();

        let output = fs::read_to_string(&path).unwrap();
        assert!(output.contains("type   = 'unix'"));
        assert!(output.contains("socket = \"/tmp/new.sock\" # Local agent socket"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn metadata_update_preserves_toml_comments_and_unrelated_content() {
        let directory = temporary_directory();
        let path = directory.join("config.toml");
        fs::write(
            &path,
            format!(
                "version = 1\n\n[agents.work]\ntype = 'unix'\nsocket = '/tmp/work.sock'\n\n[keys.deploy]\nfingerprint = '{FINGERPRINT}'\nagent = 'work'\n# Scope explanation\nscopes = ['old'] # Keep this inline note\ncomment = 'old comment'\n\n[keys.deploy.tags]\n# Provider explanation\nprovider = 'old' # Keep this provider note\nregion = 'west'\n\n[keys.other]\nfingerprint = 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'\nagent = 'work'\n"
            ),
        )
        .unwrap();

        update_key_metadata(
            &path,
            UpdateKeyMetadataRequest {
                alias: KeyAlias::new("deploy").unwrap(),
                scopes: vec![
                    ScopePath::from_str("company/production").unwrap(),
                    ScopePath::from_str("company/staging").unwrap(),
                ],
                tags: BTreeMap::from([
                    ("provider".to_owned(), "aws".to_owned()),
                    ("source".to_owned(), "vault".to_owned()),
                ]),
                comment: Some("updated comment".to_owned()),
            },
        )
        .unwrap();

        let output = fs::read_to_string(&path).unwrap();
        for preserved in [
            "# Scope explanation\nscopes = [\"company/production\", \"company/staging\"] # Keep this inline note",
            "# Provider explanation\nprovider = \"aws\" # Keep this provider note",
            "[keys.other]\nfingerprint = 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'\nagent = 'work'",
        ] {
            assert!(
                output.contains(preserved),
                "missing preserved text: {preserved}"
            );
        }
        assert!(output.contains("comment = \"updated comment\""));
        assert!(!output.contains("region = 'west'"));
        let config = Config::load(&path).unwrap();
        let entry = config.catalog().entries().next().unwrap();
        assert_eq!(entry.alias().as_str(), "deploy");
        assert_eq!(entry.fingerprint().to_string(), FINGERPRINT);
        assert_eq!(entry.agent().as_str(), "work");
        assert_eq!(
            entry
                .scopes()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["company/production", "company/staging"]
        );
        assert_eq!(entry.comment(), Some("updated comment"));
        assert_eq!(
            entry.tags().get("provider").map(String::as_str),
            Some("aws")
        );
        assert_eq!(
            entry.tags().get("source").map(String::as_str),
            Some("vault")
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn tag_only_update_preserves_multiline_scope_array_verbatim() {
        let directory = temporary_directory();
        let path = directory.join("config.toml");
        fs::write(
            &path,
            format!(
                "version = 1\n\n[agents.work]\ntype = 'unix'\nsocket = '/tmp/work.sock'\n\n[keys.deploy]\nfingerprint = '{FINGERPRINT}'\nagent = 'work'\nscopes = [\n  'company/production', # Production environment\n  'personal',           # Personal use\n]\ncomment = 'keep single quotes'\n\n[keys.deploy.tags]\nprovider = 'old'\n"
            ),
        )
        .unwrap();
        let before = fs::read_to_string(&path).unwrap();
        let scopes_before = before
            .split("scopes = [")
            .nth(1)
            .unwrap()
            .split("]\n")
            .next()
            .unwrap()
            .to_owned();

        update_key_metadata(
            &path,
            UpdateKeyMetadataRequest {
                alias: KeyAlias::new("deploy").unwrap(),
                scopes: vec![
                    ScopePath::from_str("company/production").unwrap(),
                    ScopePath::from_str("personal").unwrap(),
                ],
                tags: BTreeMap::from([("provider".to_owned(), "new".to_owned())]),
                comment: Some("keep single quotes".to_owned()),
            },
        )
        .unwrap();

        let after = fs::read_to_string(&path).unwrap();
        let scopes_after = after
            .split("scopes = [")
            .nth(1)
            .unwrap()
            .split("]\n")
            .next()
            .unwrap();
        assert_eq!(scopes_after, scopes_before);
        assert!(after.contains("comment = 'keep single quotes'"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn versioned_metadata_update_rejects_stale_snapshot() {
        let directory = temporary_directory();
        let path = directory.join("config.toml");
        fs::write(
            &path,
            format!(
                "version = 1\n\n[agents.work]\ntype = 'unix'\nsocket = '/tmp/work.sock'\n\n[keys.deploy]\nfingerprint = '{FINGERPRINT}'\nagent = 'work'\nscopes = ['old']\n\n[keys.deploy.tags]\nprovider = 'old'\n"
            ),
        )
        .unwrap();
        let stale = ConfigStore::load_versioned(&path).unwrap();
        update_key_metadata(
            &path,
            UpdateKeyMetadataRequest {
                alias: KeyAlias::new("deploy").unwrap(),
                scopes: vec![ScopePath::from_str("new/scope").unwrap()],
                tags: BTreeMap::from([("provider".to_owned(), "old".to_owned())]),
                comment: None,
            },
        )
        .unwrap();

        let result = update_key_metadata_if_unchanged(
            &path,
            &stale,
            UpdateKeyMetadataRequest {
                alias: KeyAlias::new("deploy").unwrap(),
                scopes: vec![ScopePath::from_str("old").unwrap()],
                tags: BTreeMap::from([("provider".to_owned(), "new".to_owned())]),
                comment: None,
            },
        );
        assert!(matches!(result, Err(ConfigError::Conflict(_))));
        let entry = Config::load(&path)
            .unwrap()
            .catalog()
            .entries()
            .next()
            .unwrap()
            .clone();
        assert_eq!(
            entry.scopes().iter().next().unwrap().to_string(),
            "new/scope"
        );
        assert_eq!(
            entry.tags().get("provider").map(String::as_str),
            Some("old")
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn agent_inspection_returns_independent_partial_results() {
        let directory = temporary_directory();
        let config_path = directory.join("config.toml");
        ConfigStore::save(&config_path, &ConfigDocument::empty()).unwrap();

        let available_socket = directory.join("available.sock");
        let available_listener = UnixListener::bind(&available_socket).unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = available_listener.accept().unwrap();
            let mut request = [0; 5];
            stream.read_exact(&mut request).unwrap();
            stream.write_all(&[0, 0, 0, 5, 12, 0, 0, 0, 0]).unwrap();
        });

        let slow_socket = directory.join("slow.sock");
        let slow_listener = UnixListener::bind(&slow_socket).unwrap();
        std::thread::spawn(move || {
            let (_stream, _) = slow_listener.accept().unwrap();
            std::thread::sleep(Duration::from_millis(150));
        });

        let protocol_socket = directory.join("protocol.sock");
        let protocol_listener = UnixListener::bind(&protocol_socket).unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = protocol_listener.accept().unwrap();
            let mut request = [0; 5];
            stream.read_exact(&mut request).unwrap();
            stream.write_all(&[0, 0, 0, 1, 5]).unwrap();
        });

        for (name, socket) in [
            ("available", available_socket),
            ("slow", slow_socket),
            ("protocol", protocol_socket),
            ("missing", directory.join("missing.sock")),
        ] {
            add_agent(
                &config_path,
                AddAgentRequest {
                    name: AgentName::new(name).unwrap(),
                    socket,
                },
            )
            .unwrap();
        }
        let config = Config::load(&config_path).unwrap();
        let results = inspect_agents(&config, Duration::from_millis(30));

        assert_eq!(results.len(), 4);
        let by_name = results
            .iter()
            .map(|result| (result.name.as_str(), &result.status))
            .collect::<BTreeMap<_, _>>();
        assert!(matches!(by_name["available"], AgentStatus::Available(ids) if ids.is_empty()));
        assert!(matches!(by_name["slow"], AgentStatus::TimedOut));
        assert!(matches!(by_name["protocol"], AgentStatus::ProtocolError(_)));
        assert!(matches!(by_name["missing"], AgentStatus::Unavailable(_)));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn metadata_update_clears_fields_and_keeps_inline_tables_valid() {
        let directory = temporary_directory();
        let path = directory.join("config.toml");
        fs::write(
            &path,
            format!(
                "version = 1\nagents = {{ work = {{ type = 'unix', socket = '/tmp/work.sock' }} }}\nkeys = {{ deploy = {{ fingerprint = '{FINGERPRINT}', agent = 'work', scopes = ['old'], tags = {{ provider = 'old' }}, comment = 'old' }} }}\n"
            ),
        )
        .unwrap();

        update_key_metadata(
            &path,
            UpdateKeyMetadataRequest {
                alias: KeyAlias::new("deploy").unwrap(),
                scopes: Vec::new(),
                tags: BTreeMap::new(),
                comment: Some(String::new()),
            },
        )
        .unwrap();

        let output = fs::read_to_string(&path).unwrap();
        assert!(output.contains("agents = { work = {"));
        assert!(output.contains("keys = { deploy = {"));
        assert!(!output.contains("scopes"));
        assert!(!output.contains("tags"));
        assert!(!output.contains("comment"));
        let entry = Config::load(&path)
            .unwrap()
            .catalog()
            .entries()
            .next()
            .unwrap()
            .clone();
        assert!(entry.scopes().is_empty());
        assert!(entry.tags().is_empty());
        assert_eq!(entry.comment(), None);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn metadata_update_adds_fields_to_existing_inline_key_table() {
        let directory = temporary_directory();
        let path = directory.join("config.toml");
        fs::write(
            &path,
            format!(
                "version = 1\nagents = {{ work = {{ type = 'unix', socket = '/tmp/work.sock' }} }}\nkeys = {{ deploy = {{ fingerprint = '{FINGERPRINT}', agent = 'work' }} }}\n"
            ),
        )
        .unwrap();

        update_key_metadata(
            &path,
            UpdateKeyMetadataRequest {
                alias: KeyAlias::new("deploy").unwrap(),
                scopes: vec![ScopePath::from_str("company/production").unwrap()],
                tags: BTreeMap::from([("provider".to_owned(), "aws".to_owned())]),
                comment: Some("production key".to_owned()),
            },
        )
        .unwrap();

        let config = Config::load(&path).unwrap();
        let entry = config.catalog().entries().next().unwrap();
        assert_eq!(entry.comment(), Some("production key"));
        assert_eq!(
            entry.tags().get("provider").map(String::as_str),
            Some("aws")
        );
        assert_eq!(
            entry.scopes().iter().next().unwrap().to_string(),
            "company/production"
        );
        fs::remove_dir_all(directory).unwrap();
    }
}
