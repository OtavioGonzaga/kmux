use crate::agent::{AgentDefinition, AgentName};
use crate::catalog::{Fingerprint, KeyAlias, KeyCatalog, KeyEntry};
use crate::scope::ScopePath;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

const CONFIG_ENV: &str = "KMUX_CONFIG";
const SUPPORTED_VERSION: u32 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    agents: BTreeMap<AgentName, AgentDefinition>,
    catalog: KeyCatalog,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        let schema = match path.extension().and_then(|extension| extension.to_str()) {
            Some("yaml" | "yml") => serde_yaml::from_str(&content)
                .map_err(|source| ConfigError::Parse(source.to_string()))?,
            Some("json") => serde_json::from_str(&content)
                .map_err(|source| ConfigError::Parse(source.to_string()))?,
            Some("toml") => {
                toml::from_str(&content).map_err(|source| ConfigError::Parse(source.to_string()))?
            }
            _ => return Err(ConfigError::UnsupportedFormat(path.to_owned())),
        };

        Self::from_schema(schema)
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
        let candidates = ["config.yaml", "config.json", "config.toml"]
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
            agents.insert(name, agent);
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
            let entry = KeyEntry::new(alias, fingerprint, agent, scopes, key.tags)
                .map_err(|source| ConfigError::Validation(source.to_string()))?;
            entries.push(entry);
        }

        let catalog = KeyCatalog::from_entries(entries)
            .map_err(|source| ConfigError::Validation(source.to_string()))?;
        Ok(Self { agents, catalog })
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
    Parse(String),
    UnsupportedFormat(PathBuf),
    ConfigHomeUnavailable,
    ConfigNotFound(PathBuf),
    AmbiguousConfig(Vec<PathBuf>),
    UnsupportedVersion(u32),
    UnknownAgent(AgentName),
    Validation(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => {
                write!(formatter, "could not read '{}': {source}", path.display())
            }
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigSchema {
    version: u32,
    #[serde(default)]
    agents: BTreeMap<String, AgentSchema>,
    #[serde(default)]
    keys: BTreeMap<String, KeySchema>,
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
    scopes: Vec<String>,
    #[serde(default)]
    tags: BTreeMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::Config;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

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
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("kmux-config-{unique}.{extension}"));
        fs::write(&path, content).unwrap();
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
                    .query(&crate::catalog::ScopeQuery::new("company".parse().unwrap()))
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

        assert!(Config::load(&unknown_field).is_err());
        assert!(Config::load(&unknown_agent).is_err());
        fs::remove_file(unknown_field).unwrap();
        fs::remove_file(unknown_agent).unwrap();
    }
}
