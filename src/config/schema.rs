use crate::agent::{AgentDefinition, AgentName};
use crate::catalog::{Fingerprint, KeyAlias, KeyCatalog, KeyEntry};
use crate::scope::ScopePath;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tempfile::NamedTempFile;

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
        ConfigStore::load(path)?.validate()
    }

    pub fn discover(explicit: Option<&Path>) -> Result<ConfigPath, ConfigError> {
        ConfigStore::discover(explicit)
    }

    fn from_document(document: ConfigDocument) -> Result<Self, ConfigError> {
        if document.version != SUPPORTED_VERSION {
            return Err(ConfigError::UnsupportedVersion(document.version));
        }

        let mut agents = BTreeMap::new();
        for (name, definition) in document.agents {
            let name = AgentName::new(name)
                .map_err(|source| ConfigError::Validation(source.to_string()))?;
            let AgentDocument { kind, socket } = definition;
            let agent = match kind {
                AgentKind::Unix => AgentDefinition::new(name.clone(), socket),
            }
            .map_err(|source| ConfigError::Validation(source.to_string()))?;
            if agents.insert(name.clone(), agent).is_some() {
                return Err(ConfigError::DuplicateAgent(name));
            }
        }

        let mut entries = Vec::new();
        for (alias, key) in document.keys {
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
            if key
                .tags
                .iter()
                .any(|(name, value)| name.is_empty() || value.is_empty())
            {
                return Err(ConfigError::Validation(
                    "tags must use non-empty KEY=VALUE syntax".to_owned(),
                ));
            }
            entries.push(KeyEntry::new(alias, fingerprint, agent, scopes, key.tags));
        }

        let catalog = KeyCatalog::from_entries(entries)
            .map_err(|source| ConfigError::Validation(source.to_string()))?;
        Self::from_parts(agents, catalog)
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

    pub fn agents(&self) -> &BTreeMap<AgentName, AgentDefinition> {
        &self.agents
    }

    pub fn catalog(&self) -> &KeyCatalog {
        &self.catalog
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigFormat {
    Toml,
    Yaml,
    Json,
}

impl ConfigFormat {
    pub fn from_path(path: &Path) -> Result<Self, ConfigError> {
        match path.extension().and_then(|extension| extension.to_str()) {
            Some("toml") => Ok(Self::Toml),
            Some("yaml" | "yml") => Ok(Self::Yaml),
            Some("json") => Ok(Self::Json),
            _ => Err(ConfigError::UnsupportedFormat(path.to_owned())),
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Self::Toml => "toml",
            Self::Yaml => "yaml",
            Self::Json => "json",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigDocument {
    version: u32,
    #[serde(default)]
    agents: BTreeMap<String, AgentDocument>,
    #[serde(default)]
    keys: BTreeMap<String, KeyDocument>,
}

impl ConfigDocument {
    pub fn empty() -> Self {
        Self {
            version: SUPPORTED_VERSION,
            agents: BTreeMap::new(),
            keys: BTreeMap::new(),
        }
    }

    pub fn validate(&self) -> Result<Config, ConfigError> {
        Config::from_document(self.clone())
    }

    pub fn add_agent(&mut self, name: AgentName, socket: PathBuf) -> Result<(), ConfigError> {
        if self.agents.keys().any(|existing| {
            AgentName::new(existing).expect("loaded configuration has valid agent names") == name
        }) {
            return Err(ConfigError::DuplicateAgent(name));
        }
        let mut candidate = self.clone();
        candidate.agents.insert(
            name.to_string(),
            AgentDocument {
                kind: AgentKind::Unix,
                socket,
            },
        );
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    pub fn remove_agent(&mut self, name: &AgentName) -> Result<(), ConfigError> {
        let dependents = self
            .keys
            .iter()
            .filter_map(|(alias, key)| {
                (AgentName::new(&key.agent).ok().as_ref() == Some(name)).then_some(alias.clone())
            })
            .collect::<Vec<_>>();
        if !dependents.is_empty() {
            return Err(ConfigError::AgentInUse(name.clone(), dependents));
        }
        let key = self
            .agents
            .keys()
            .find(|existing| AgentName::new(existing).ok().as_ref() == Some(name))
            .cloned()
            .ok_or_else(|| ConfigError::UnknownAgent(name.clone()))?;
        let mut candidate = self.clone();
        candidate.agents.remove(&key);
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    pub fn add_key(&mut self, entry: KeyEntry) -> Result<(), ConfigError> {
        if self.keys.keys().any(|existing| {
            KeyAlias::new(existing).expect("loaded configuration has valid key aliases")
                == *entry.alias()
        }) {
            return Err(ConfigError::Validation(format!(
                "duplicate key alias '{}'",
                entry.alias()
            )));
        }
        let mut candidate = self.clone();
        candidate.keys.insert(
            entry.alias().to_string(),
            KeyDocument {
                fingerprint: entry.fingerprint().to_string(),
                agent: entry.agent().to_string(),
                scopes: entry.scopes().iter().map(ToString::to_string).collect(),
                tags: entry.tags().clone(),
            },
        );
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    pub fn remove_key(&mut self, alias: &KeyAlias) -> Result<(), ConfigError> {
        let key = self
            .keys
            .keys()
            .find(|existing| KeyAlias::new(existing).ok().as_ref() == Some(alias))
            .cloned()
            .ok_or_else(|| ConfigError::UnknownKey(alias.clone()))?;
        let mut candidate = self.clone();
        candidate.keys.remove(&key);
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }
}

pub struct ConfigStore;

impl ConfigStore {
    pub fn explicit_path(explicit: Option<&Path>) -> Option<PathBuf> {
        explicit
            .map(Path::to_owned)
            .or_else(|| env::var_os(CONFIG_ENV).map(PathBuf::from))
    }

    pub fn default_path() -> Result<PathBuf, ConfigError> {
        let config_home = env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
            .ok_or(ConfigError::ConfigHomeUnavailable)?;
        Ok(config_home.join("kmux").join("config.toml"))
    }

    pub fn load(path: &Path) -> Result<ConfigDocument, ConfigError> {
        let decoder: &dyn ConfigDecoder = match ConfigFormat::from_path(path)? {
            ConfigFormat::Yaml => &YamlConfigDecoder,
            ConfigFormat::Json => &JsonConfigDecoder,
            ConfigFormat::Toml => &TomlConfigDecoder,
        };
        let document = decoder.decode(&read_config(path)?)?;
        document.validate()?;
        Ok(document)
    }

    pub fn save(path: &Path, document: &ConfigDocument) -> Result<(), ConfigError> {
        document.validate()?;
        let output = match ConfigFormat::from_path(path)? {
            ConfigFormat::Toml => toml::to_string_pretty(document)
                .map_err(|error| ConfigError::Serialize(error.to_string()))?,
            ConfigFormat::Yaml => serde_saphyr::to_string(document)
                .map_err(|error| ConfigError::Serialize(error.to_string()))?,
            ConfigFormat::Json => serde_json::to_string_pretty(document)
                .map_err(|error| ConfigError::Serialize(error.to_string()))?,
        };
        if output.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge {
                path: path.to_owned(),
                limit: MAX_CONFIG_BYTES,
            });
        }
        let parent = path.parent().ok_or_else(|| ConfigError::Write {
            path: path.to_owned(),
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "configuration path has no parent",
            ),
        })?;
        fs::create_dir_all(parent).map_err(|source| ConfigError::Write {
            path: parent.to_owned(),
            source,
        })?;
        let mut temporary = NamedTempFile::new_in(parent).map_err(|source| ConfigError::Write {
            path: parent.to_owned(),
            source,
        })?;
        temporary
            .as_file_mut()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|source| ConfigError::Write {
                path: temporary.path().to_owned(),
                source,
            })?;
        use std::io::Write;
        temporary
            .write_all(output.as_bytes())
            .map_err(|source| ConfigError::Write {
                path: temporary.path().to_owned(),
                source,
            })?;
        temporary
            .as_file()
            .sync_all()
            .map_err(|source| ConfigError::Write {
                path: temporary.path().to_owned(),
                source,
            })?;
        temporary
            .persist(path)
            .map_err(|error| ConfigError::Write {
                path: path.to_owned(),
                source: error.error,
            })?;
        Ok(())
    }

    pub fn discover(explicit: Option<&Path>) -> Result<ConfigPath, ConfigError> {
        if let Some(path) = Self::explicit_path(explicit) {
            return Ok(ConfigPath(path));
        }

        let directory = Self::default_path()?
            .parent()
            .expect("default config path has a parent")
            .to_owned();
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
    AgentInUse(AgentName, Vec<String>),
    UnknownKey(KeyAlias),
    Serialize(String),
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
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
                write!(formatter, "unknown agent '{agent}'")
            }
            Self::AgentInUse(agent, aliases) => write!(
                formatter,
                "cannot remove agent '{agent}' because it is used by: {}",
                aliases.join(", ")
            ),
            Self::UnknownKey(alias) => write!(formatter, "unknown key '{alias}'"),
            Self::Serialize(error) => {
                write!(formatter, "could not serialize configuration: {error}")
            }
            Self::Write { path, source } => {
                write!(formatter, "could not write '{}': {source}", path.display())
            }
            Self::Validation(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read { source, .. } | Self::Write { source, .. } => Some(source),
            _ => None,
        }
    }
}

trait ConfigDecoder {
    fn decode(&self, source: &str) -> Result<ConfigDocument, ConfigError>;
}

struct YamlConfigDecoder;
struct JsonConfigDecoder;
struct TomlConfigDecoder;

impl ConfigDecoder for YamlConfigDecoder {
    fn decode(&self, source: &str) -> Result<ConfigDocument, ConfigError> {
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
        let mut documents: Vec<ConfigDocument> =
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
    fn decode(&self, source: &str) -> Result<ConfigDocument, ConfigError> {
        serde_json::from_str(source).map_err(|error| ConfigError::Parse(error.to_string()))
    }
}

impl ConfigDecoder for TomlConfigDecoder {
    fn decode(&self, source: &str) -> Result<ConfigDocument, ConfigError> {
        toml::from_str(source).map_err(|error| ConfigError::Parse(error.to_string()))
    }
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentDocument {
    #[serde(rename = "type")]
    kind: AgentKind,
    socket: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum AgentKind {
    Unix,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyDocument {
    fingerprint: String,
    agent: String,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    tags: BTreeMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::{
        AgentDocument, AgentKind, Config, ConfigDocument, ConfigError, ConfigStore, KeyDocument,
        MAX_CONFIG_BYTES, MAX_YAML_ALIASES, SUPPORTED_VERSION,
    };
    use crate::agent::{AgentDefinition, AgentName};
    use crate::catalog::{Fingerprint, KeyAlias, KeyCatalog, KeyEntry};
    use crate::scope::ScopePath;
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
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
        let expected_path = write_config("toml", &config("toml"));
        let expected = Config::load(&expected_path).unwrap();
        fs::remove_file(expected_path).unwrap();
        for (extension, format) in [
            ("toml", "toml"),
            ("yaml", "yaml"),
            ("yml", "yaml"),
            ("json", "json"),
        ] {
            let path = write_config(extension, &config(format));
            let loaded = Config::load(&path).unwrap();
            fs::remove_file(path).unwrap();

            assert_eq!(loaded, expected);
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
            ConfigStore::discover_in(directory.clone())
                .unwrap()
                .as_path(),
            path
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_ambiguous_config_formats_without_a_default_precedence() {
        for names in [
            ["config.yaml", "config.yml"],
            ["config.toml", "config.yaml"],
        ] {
            let directory = temporary_directory();
            for name in names {
                fs::write(directory.join(name), "version: 1\n").unwrap();
            }
            assert!(matches!(
                ConfigStore::discover_in(directory.clone()),
                Err(ConfigError::AmbiguousConfig(_))
            ));
            fs::remove_dir_all(directory).unwrap();
        }
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

    #[test]
    fn store_round_trips_empty_documents_in_every_writable_format() {
        let directory = temporary_directory();
        for extension in ["toml", "yaml", "json"] {
            let path = directory.join(format!("config.{extension}"));
            ConfigStore::save(&path, &ConfigDocument::empty()).unwrap();
            assert!(ConfigStore::load(&path).unwrap().validate().is_ok());
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(directory).unwrap();
    }

    fn populated_document() -> ConfigDocument {
        ConfigDocument {
            version: SUPPORTED_VERSION,
            agents: BTreeMap::from([(
                "work".to_owned(),
                AgentDocument {
                    kind: AgentKind::Unix,
                    socket: "/tmp/work.sock".into(),
                },
            )]),
            keys: BTreeMap::from([(
                "deploy".to_owned(),
                KeyDocument {
                    fingerprint: FINGERPRINT.to_owned(),
                    agent: "work".to_owned(),
                    scopes: vec!["company/production".to_owned()],
                    tags: BTreeMap::from([("provider".to_owned(), "aws".to_owned())]),
                },
            )]),
        }
    }

    #[test]
    fn store_round_trips_populated_documents_in_every_supported_format() {
        let directory = temporary_directory();
        for extension in ["toml", "yaml", "yml", "json"] {
            let path = directory.join(format!("config.{extension}"));
            ConfigStore::save(&path, &populated_document()).unwrap();
            let config = ConfigStore::load(&path).unwrap().validate().unwrap();
            assert_eq!(config.agents().len(), 1);
            let entry = config.catalog().entries().next().unwrap();
            assert_eq!(entry.scopes().len(), 1);
            assert_eq!(
                entry.tags().get("provider").map(String::as_str),
                Some("aws")
            );
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn store_preserves_existing_file_when_document_validation_fails() {
        let directory = temporary_directory();
        let path = directory.join("config.toml");
        let original = "version = 1\n";
        fs::write(&path, original).unwrap();
        let document = ConfigDocument {
            version: SUPPORTED_VERSION,
            agents: BTreeMap::from([(
                "agent".to_owned(),
                AgentDocument {
                    kind: AgentKind::Unix,
                    socket: "relative.sock".into(),
                },
            )]),
            keys: BTreeMap::new(),
        };
        assert!(ConfigStore::save(&path, &document).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn store_creates_missing_directories_and_replaces_the_target_atomically() {
        let directory = temporary_directory();
        let path = directory.join("missing").join("config.toml");
        ConfigStore::save(&path, &ConfigDocument::empty()).unwrap();
        let original_inode = fs::metadata(&path).unwrap().ino();
        ConfigStore::save(&path, &ConfigDocument::empty()).unwrap();
        assert_ne!(fs::metadata(&path).unwrap().ino(), original_inode);
        assert!(
            ConfigStore::save(&directory.join("config.ini"), &ConfigDocument::empty()).is_err()
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn store_rejects_oversized_serialized_documents_without_touching_the_target() {
        let directory = temporary_directory();
        let path = directory.join("config.toml");
        let original = "version = 1\n";
        fs::write(&path, original).unwrap();
        let mut document = populated_document();
        document
            .keys
            .get_mut("deploy")
            .unwrap()
            .tags
            .insert("note".to_owned(), "x".repeat(MAX_CONFIG_BYTES));
        assert!(matches!(
            ConfigStore::save(&path, &document),
            Err(ConfigError::TooLarge { .. })
        ));
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        fs::remove_dir_all(directory).unwrap();
    }
}
