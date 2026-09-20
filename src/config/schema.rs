use crate::agent::{AgentDefinition, AgentName};
use crate::catalog::{Fingerprint, KeyAlias, KeyCatalog, KeyEntry};
use crate::scope::ScopePath;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::str::FromStr;

const CONFIG_ENV: &str = "KMUX_CONFIG";
const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_YAML_DOCUMENTS: usize = 1;
const MAX_YAML_DEPTH: usize = 128;
const MAX_YAML_EVENTS: usize = 100_000;
const MAX_YAML_NODES: usize = 50_000;
const MAX_YAML_ANCHORS: usize = 1_024;
const MAX_YAML_ALIASES: usize = 4_096;
const MAX_YAML_ALIAS_REPLAY_EVENTS: usize = 100_000;
const MAX_YAML_ALIAS_REPLAY_DEPTH: usize = 64;
const MAX_YAML_ALIAS_EXPANSIONS_PER_ANCHOR: usize = 256;
const SUPPORTED_VERSION: u32 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    agents: BTreeMap<AgentName, AgentDefinition>,
    catalog: KeyCatalog,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let decoder: &dyn ConfigDecoder =
            match path.extension().and_then(|extension| extension.to_str()) {
                Some("yaml" | "yml") => &YamlConfigDecoder,
                Some("json") => &JsonConfigDecoder,
                Some("toml") => &TomlConfigDecoder,
                _ => return Err(ConfigError::UnsupportedFormat(path.to_owned())),
            };
        let content = read_config(path)?;
        Self::from_schema(decoder.decode(&content)?)
    }

    pub fn discover(explicit: Option<&Path>) -> Result<ConfigPath, ConfigError> {
        if let Some(path) = explicit {
            return Ok(ConfigPath(path.to_owned()));
        }
        if let Some(path) = env::var_os(CONFIG_ENV) {
            return Ok(ConfigPath(PathBuf::from(path)));
        }

        let config_home = env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
            .ok_or(ConfigError::ConfigHomeUnavailable)?;
        let directory = config_home.join("kmux");
        Self::discover_in(directory)
    }

    fn discover_in(directory: PathBuf) -> Result<ConfigPath, ConfigError> {
        let candidates = ["config.yaml", "config.yml", "config.json", "config.toml"]
            .into_iter()
            .map(|name| directory.join(name))
            .filter(|path| path.is_file())
            .collect::<Vec<_>>();

        match candidates.as_slice() {
            [] => Err(ConfigError::ConfigNotFound(directory)),
            [path] => Ok(ConfigPath(path.clone())),
            _ => Err(ConfigError::AmbiguousConfig(candidates)),
        }
    }

    pub fn agents(&self) -> &BTreeMap<AgentName, AgentDefinition> {
        &self.agents
    }

    pub fn catalog(&self) -> &KeyCatalog {
        &self.catalog
    }

    pub(crate) fn from_parts(
        agents: BTreeMap<AgentName, AgentDefinition>,
        catalog: KeyCatalog,
    ) -> Result<Self, ConfigError> {
        for (name, definition) in &agents {
            if name != definition.name() {
                return Err(ConfigError::Validation(format!(
                    "agent map key '{name}' does not match its definition"
                )));
            }
        }
        for entry in catalog.entries() {
            if !agents.contains_key(entry.agent()) {
                return Err(ConfigError::UnknownAgent(entry.agent().clone()));
            }
        }

        Ok(Self { agents, catalog })
    }

    fn from_schema(schema: ConfigSchema) -> Result<Self, ConfigError> {
        if schema.version != SUPPORTED_VERSION {
            return Err(ConfigError::UnsupportedVersion(schema.version));
        }

        let mut agents = BTreeMap::new();
        for (name, definition) in schema.agents {
            let name = AgentName::new(name)
                .map_err(|source| ConfigError::Validation(source.to_string()))?;
            let AgentSchema { kind, socket } = definition;
            let agent = match kind {
                AgentKind::Unix => AgentDefinition::new(name.clone(), socket),
            }
            .map_err(|source| ConfigError::Validation(source.to_string()))?;
            if agents.insert(name.clone(), agent).is_some() {
                return Err(ConfigError::DuplicateAgent(name));
            }
        }

        let mut entries = Vec::new();
        for (alias, key) in schema.keys {
            let agent = AgentName::new(key.agent)
                .map_err(|source| ConfigError::Validation(source.to_string()))?;
            if !agents.contains_key(&agent) {
                return Err(ConfigError::UnknownAgent(agent));
            }
            let alias = KeyAlias::new(alias)
                .map_err(|source| ConfigError::Validation(source.to_string()))?;
            let fingerprint = Fingerprint::from_str(&key.fingerprint)
                .map_err(|source| ConfigError::Validation(source.to_string()))?;
            let scopes = key
                .scopes
                .iter()
                .map(|scope| ScopePath::from_str(scope))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|source| ConfigError::Validation(source.to_string()))?;
            let entry = KeyEntry::new(alias, fingerprint, agent, scopes, key.tags);
            entries.push(entry);
        }

        let catalog = KeyCatalog::from_entries(entries)
            .map_err(|source| ConfigError::Validation(source.to_string()))?;
        Self::from_parts(agents, catalog)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigPath(PathBuf);

impl ConfigPath {
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    TooLarge {
        path: PathBuf,
        limit: usize,
    },
    Parse(String),
    UnsupportedFormat(PathBuf),
    ConfigHomeUnavailable,
    ConfigNotFound(PathBuf),
    AmbiguousConfig(Vec<PathBuf>),
    UnsupportedVersion(u32),
    DuplicateAgent(AgentName),
    UnknownAgent(AgentName),
    Validation(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => {
                write!(formatter, "could not read '{}': {source}", path.display())
            }
            Self::TooLarge { path, limit } => write!(
                formatter,
                "configuration file '{}' exceeds the {limit}-byte limit",
                path.display()
            ),
            Self::Parse(source) => write!(formatter, "invalid configuration: {source}"),
            Self::UnsupportedFormat(path) => {
                write!(formatter, "unsupported config format: '{}'", path.display())
            }
            Self::ConfigHomeUnavailable => {
                formatter.write_str("could not determine the config directory")
            }
            Self::ConfigNotFound(path) => {
                write!(formatter, "no config found in '{}'", path.display())
            }
            Self::AmbiguousConfig(paths) => write!(
                formatter,
                "multiple config files found: {}",
                paths
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported config version {version}")
            }
            Self::DuplicateAgent(agent) => write!(
                formatter,
                "duplicate agent name '{agent}' after normalization"
            ),
            Self::UnknownAgent(agent) => {
                write!(formatter, "key references unknown agent '{agent}'")
            }
            Self::Validation(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            _ => None,
        }
    }
}

trait ConfigDecoder {
    fn decode(&self, source: &str) -> Result<ConfigSchema, ConfigError>;
}

struct YamlConfigDecoder;
struct JsonConfigDecoder;
struct TomlConfigDecoder;

impl ConfigDecoder for YamlConfigDecoder {
    fn decode(&self, source: &str) -> Result<ConfigSchema, ConfigError> {
        let options = serde_saphyr::options! {
            budget: serde_saphyr::budget! {
                max_documents: MAX_YAML_DOCUMENTS,
                max_depth: MAX_YAML_DEPTH,
                max_events: MAX_YAML_EVENTS,
                max_nodes: MAX_YAML_NODES,
                max_anchors: MAX_YAML_ANCHORS,
                max_aliases: MAX_YAML_ALIASES,
                max_recorded_anchor_events: MAX_YAML_ALIAS_REPLAY_EVENTS,
                max_recorded_anchor_bytes: MAX_CONFIG_BYTES,
                max_total_scalar_bytes: MAX_CONFIG_BYTES,
            },
            emit_comments: false,
            duplicate_keys: serde_saphyr::DuplicateKeyPolicy::Error,
            merge_keys: serde_saphyr::MergeKeyPolicy::Error,
            alias_limits: serde_saphyr::alias_limits! {
                max_total_replayed_events: MAX_YAML_ALIAS_REPLAY_EVENTS,
                max_replay_stack_depth: MAX_YAML_ALIAS_REPLAY_DEPTH,
                max_alias_expansions_per_anchor: MAX_YAML_ALIAS_EXPANSIONS_PER_ANCHOR,
            },
        };
        let mut documents: Vec<ConfigSchema> =
            serde_saphyr::from_multiple_with_options(source, options)
                .map_err(|error| ConfigError::Parse(error.to_string()))?;
        match documents.len() {
            1 => Ok(documents.remove(0)),
            _ => Err(ConfigError::Parse(
                "configuration must contain exactly one YAML document".to_owned(),
            )),
        }
    }
}

impl ConfigDecoder for JsonConfigDecoder {
    fn decode(&self, source: &str) -> Result<ConfigSchema, ConfigError> {
        serde_json::from_str(source).map_err(|error| ConfigError::Parse(error.to_string()))
    }
}

impl ConfigDecoder for TomlConfigDecoder {
    fn decode(&self, source: &str) -> Result<ConfigSchema, ConfigError> {
        toml::from_str(source).map_err(|error| ConfigError::Parse(error.to_string()))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigSchema {
    version: u32,
    #[serde(default)]
    agents: BTreeMap<String, AgentSchema>,
    #[serde(default)]
    keys: BTreeMap<String, KeySchema>,
}

fn read_config(path: &Path) -> Result<String, ConfigError> {
    let mut file = File::open(path).map_err(|source| ConfigError::Read {
        path: path.to_owned(),
        source,
    })?;
    let mut content = Vec::with_capacity(MAX_CONFIG_BYTES.min(8192));
    file.by_ref()
        .take((MAX_CONFIG_BYTES + 1) as u64)
        .read_to_end(&mut content)
        .map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
    if content.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::TooLarge {
            path: path.to_owned(),
            limit: MAX_CONFIG_BYTES,
        });
    }

    String::from_utf8(content).map_err(|source| ConfigError::Read {
        path: path.to_owned(),
        source: io::Error::new(io::ErrorKind::InvalidData, source),
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentSchema {
    #[serde(rename = "type")]
    kind: AgentKind,
    socket: PathBuf,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum AgentKind {
    Unix,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeySchema {
    fingerprint: String,
    agent: String,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    tags: BTreeMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::{Config, ConfigError, MAX_CONFIG_BYTES, MAX_YAML_ALIASES};
    use crate::agent::{AgentDefinition, AgentName};
    use crate::catalog::{Fingerprint, KeyAlias, KeyCatalog, KeyEntry};
    use crate::scope::ScopePath;
    use std::collections::BTreeMap;
    use std::fs;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMPORARY_PATH_ID: AtomicU64 = AtomicU64::new(0);

    const FINGERPRINT: &str = "SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+Y";

    fn config(format: &str) -> String {
        match format {
            "yaml" => format!(
                "version: 1\nagents:\n  bitwarden:\n    type: unix\n    socket: /run/user/1000/agent.sock\nkeys:\n  deploy:\n    fingerprint: {FINGERPRINT}\n    agent: bitwarden\n    scopes: [company/production]\n"
            ),
            "json" => format!(
                r#"{{"version":1,"agents":{{"bitwarden":{{"type":"unix","socket":"/run/user/1000/agent.sock"}}}},"keys":{{"deploy":{{"fingerprint":"{FINGERPRINT}","agent":"bitwarden","scopes":["company/production"]}}}}}}"#
            ),
            "toml" => format!(
                "version = 1\n[agents.bitwarden]\ntype = \"unix\"\nsocket = \"/run/user/1000/agent.sock\"\n[keys.deploy]\nfingerprint = \"{FINGERPRINT}\"\nagent = \"bitwarden\"\nscopes = [\"company/production\"]\n"
            ),
            _ => unreachable!(),
        }
    }

    fn write_config(extension: &str, content: &str) -> std::path::PathBuf {
        let unique = TEMPORARY_PATH_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "kmux-config-{}-{unique}.{extension}",
            std::process::id()
        ));
        fs::write(&path, content).unwrap();
        path
    }

    fn temporary_directory() -> std::path::PathBuf {
        let unique = TEMPORARY_PATH_ID.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("kmux-config-{}-{unique}", std::process::id()));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn loads_the_same_schema_from_every_supported_format() {
        for extension in ["yaml", "json", "toml"] {
            let path = write_config(extension, &config(extension));
            let loaded = Config::load(&path).unwrap();
            fs::remove_file(path).unwrap();

            assert_eq!(loaded.agents().len(), 1);
            assert_eq!(
                loaded
                    .catalog()
                    .query_static(
                        &crate::catalog::KeyQuery::from_values(
                            Some("company".to_owned()),
                            None,
                            None,
                            None,
                            [],
                            None,
                        )
                        .unwrap()
                    )
                    .len(),
                1
            );
        }
    }

    #[test]
    fn rejects_unknown_fields_and_unknown_agents() {
        let unknown_field = write_config("yaml", "version: 1\nunknown: true\n");
        let unknown_agent = write_config(
            "yaml",
            &format!(
                "version: 1\nkeys:\n  deploy:\n    fingerprint: {FINGERPRINT}\n    agent: missing\n    scopes: [company]\n"
            ),
        );

        assert!(matches!(
            Config::load(&unknown_field),
            Err(ConfigError::Parse(_))
        ));
        assert!(matches!(
            Config::load(&unknown_agent),
            Err(ConfigError::UnknownAgent(_))
        ));
        fs::remove_file(unknown_field).unwrap();
        fs::remove_file(unknown_agent).unwrap();
    }

    #[test]
    fn rejects_invalid_yaml_syntax_and_types() {
        let syntax = write_config("yaml", "version: [1\n");
        let types = write_config("yaml", "version: one\n");

        assert!(matches!(Config::load(&syntax), Err(ConfigError::Parse(_))));
        assert!(matches!(Config::load(&types), Err(ConfigError::Parse(_))));
        fs::remove_file(syntax).unwrap();
        fs::remove_file(types).unwrap();
    }

    #[test]
    fn rejects_duplicate_keys_and_multiple_documents() {
        let duplicate = write_config("yaml", "version: 1\nversion: 1\n");
        let multiple = write_config("yaml", "version: 1\n---\nversion: 1\n");

        assert!(matches!(
            Config::load(&duplicate),
            Err(ConfigError::Parse(_))
        ));
        assert!(matches!(
            Config::load(&multiple),
            Err(ConfigError::Parse(_))
        ));
        fs::remove_file(duplicate).unwrap();
        fs::remove_file(multiple).unwrap();
    }

    #[test]
    fn resolves_yaml_anchors_and_aliases() {
        let path = write_config(
            "yaml",
            &format!(
                "version: 1\nagents:\n  &primary primary:\n    type: unix\n    socket: /run/user/1000/agent.sock\nkeys:\n  deploy:\n    fingerprint: {FINGERPRINT}\n    agent: *primary\n    scopes: [company/production]\n"
            ),
        );

        assert!(Config::load(&path).is_ok());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_yaml_that_exceeds_alias_budget() {
        let mut source = String::from("version: 1\nanchor: &anchor value\n");
        for index in 0..=MAX_YAML_ALIASES {
            source.push_str(&format!("alias-{index}: *anchor\n"));
        }
        let path = write_config("yaml", &source);

        let error = Config::load(&path).unwrap_err();
        assert!(matches!(error, ConfigError::Parse(ref message) if message.contains("alias")));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn discovers_config_yml() {
        let directory = temporary_directory();
        let path = directory.join("config.yml");
        fs::write(&path, config("yaml")).unwrap();

        assert_eq!(
            Config::discover_in(directory.clone()).unwrap().as_path(),
            path
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_ambiguous_config_yaml_and_yml() {
        let directory = temporary_directory();
        fs::write(directory.join("config.yaml"), config("yaml")).unwrap();
        fs::write(directory.join("config.yml"), config("yaml")).unwrap();
        assert!(matches!(
            Config::discover_in(directory.clone()),
            Err(ConfigError::AmbiguousConfig(_))
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_files_larger_than_one_mebibyte() {
        let valid = format!("version: 1\n#{}", " ".repeat(MAX_CONFIG_BYTES - 12));
        let within_limit = write_config("yaml", &valid);
        let path = write_config("yaml", &" ".repeat(MAX_CONFIG_BYTES + 1));

        assert!(Config::load(&within_limit).is_ok());
        assert!(matches!(
            Config::load(&path),
            Err(ConfigError::TooLarge {
                limit: MAX_CONFIG_BYTES,
                ..
            })
        ));
        fs::remove_file(within_limit).unwrap();
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn from_parts_rejects_catalog_entries_for_missing_agents() {
        let missing = AgentName::new("missing").unwrap();
        let entry = KeyEntry::new(
            KeyAlias::new("deploy").unwrap(),
            Fingerprint::from_str(FINGERPRINT).unwrap(),
            missing,
            [ScopePath::from_str("company/production").unwrap()],
            BTreeMap::new(),
        );

        assert!(matches!(
            Config::from_parts(BTreeMap::new(), KeyCatalog::from_entries([entry]).unwrap()),
            Err(ConfigError::UnknownAgent(_))
        ));
    }

    #[test]
    fn from_parts_rejects_mismatched_agent_keys() {
        let key = AgentName::new("primary").unwrap();
        let definition =
            AgentDefinition::new(AgentName::new("secondary").unwrap(), "/tmp/agent.sock").unwrap();

        assert!(matches!(
            Config::from_parts(BTreeMap::from([(key, definition)]), KeyCatalog::default()),
            Err(ConfigError::Validation(_))
        ));
    }

    #[test]
    fn rejects_agent_names_that_collide_after_normalization() {
        let path = write_config(
            "yaml",
            "version: 1\nagents:\n  Work:\n    type: unix\n    socket: /tmp/work.sock\n  work:\n    type: unix\n    socket: /tmp/other.sock\n",
        );
        assert!(matches!(
            Config::load(&path),
            Err(super::ConfigError::DuplicateAgent(_))
        ));
        fs::remove_file(path).unwrap();
    }
}
