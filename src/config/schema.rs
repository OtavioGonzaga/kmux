//! The serialized configuration schema and its filesystem store.

use crate::agent::{AgentDefinition, AgentName};
use crate::catalog::{Fingerprint, KeyAlias, KeyCatalog, KeyEntry};
use crate::scope::ScopePath;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tempfile::NamedTempFile;
use toml_edit::{Array, DocumentMut, Item, Table, TableLike, value};

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
/// Validated runtime configuration containing agents and a key catalog.
pub struct Config {
    agents: BTreeMap<AgentName, AgentDefinition>,
    catalog: KeyCatalog,
}

impl Config {
    /// Loads, parses, and validates the document at `path`.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        ConfigStore::load(path)?.validate()
    }

    /// Discovers a configuration path from an explicit path, environment, or XDG defaults.
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
            entries.push(
                KeyEntry::new(alias, fingerprint, agent, scopes, key.tags)
                    .with_comment(key.comment),
            );
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

    /// Returns configured upstream agents keyed by normalized name.
    pub fn agents(&self) -> &BTreeMap<AgentName, AgentDefinition> {
        &self.agents
    }

    /// Returns the validated catalog of configured public identities.
    pub fn catalog(&self) -> &KeyCatalog {
        &self.catalog
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// A supported serialized configuration format.
pub enum ConfigFormat {
    /// TOML configuration.
    Toml,
    /// YAML or YML configuration.
    Yaml,
    /// JSON configuration.
    Json,
}

impl ConfigFormat {
    /// Infers a supported format from `path`'s extension.
    pub fn from_path(path: &Path) -> Result<Self, ConfigError> {
        match path.extension().and_then(|extension| extension.to_str()) {
            Some("toml") => Ok(Self::Toml),
            Some("yaml" | "yml") => Ok(Self::Yaml),
            Some("json") => Ok(Self::Json),
            _ => Err(ConfigError::UnsupportedFormat(path.to_owned())),
        }
    }

    /// Returns this format's canonical file extension.
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
/// Mutable serialized configuration that can be validated or persisted.
pub struct ConfigDocument {
    version: u32,
    #[serde(default)]
    agents: BTreeMap<String, AgentDocument>,
    #[serde(default)]
    keys: BTreeMap<String, KeyDocument>,
    #[serde(skip)]
    toml: Option<DocumentMut>,
}

impl ConfigDocument {
    /// Creates an empty version-1 configuration document.
    pub fn empty() -> Self {
        Self {
            version: SUPPORTED_VERSION,
            agents: BTreeMap::new(),
            keys: BTreeMap::new(),
            toml: None,
        }
    }

    /// Validates this document and returns its runtime representation.
    pub fn validate(&self) -> Result<Config, ConfigError> {
        Config::from_document(self.clone())
    }

    fn normalized(mut self) -> Self {
        for key in self.keys.values_mut() {
            key.comment = key.comment.take().filter(|comment| !comment.is_empty());
        }
        self
    }

    /// Adds an agent after validating the resulting document.
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
        candidate = candidate.normalized();
        candidate.validate()?;
        candidate.insert_toml_agent(&name)?;
        *self = candidate;
        Ok(())
    }

    /// Removes an agent that is not referenced by any configured key.
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
        candidate = candidate.normalized();
        candidate.validate()?;
        candidate.remove_toml_agent(&key)?;
        *self = candidate;
        Ok(())
    }

    /// Updates an agent's socket after validating the resulting document.
    pub fn update_agent_socket(
        &mut self,
        name: &AgentName,
        socket: PathBuf,
    ) -> Result<(), ConfigError> {
        let key = self
            .agents
            .keys()
            .find(|existing| AgentName::new(existing).ok().as_ref() == Some(name))
            .cloned()
            .ok_or_else(|| ConfigError::UnknownAgent(name.clone()))?;
        let mut candidate = self.clone();
        candidate
            .agents
            .get_mut(&key)
            .expect("agent key was found")
            .socket = socket.clone();
        candidate.validate()?;
        candidate.update_toml_agent_socket(&key, &socket)?;
        *self = candidate;
        Ok(())
    }

    /// Adds a key entry after validating the resulting document.
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
                comment: entry.comment().map(str::to_owned),
            },
        );
        candidate = candidate.normalized();
        candidate.validate()?;
        candidate.insert_toml_key(entry.alias().as_str())?;
        *self = candidate;
        Ok(())
    }

    /// Removes a configured key by alias.
    pub fn remove_key(&mut self, alias: &KeyAlias) -> Result<(), ConfigError> {
        let key = self
            .keys
            .keys()
            .find(|existing| KeyAlias::new(existing).ok().as_ref() == Some(alias))
            .cloned()
            .ok_or_else(|| ConfigError::UnknownKey(alias.clone()))?;
        let mut candidate = self.clone();
        candidate.keys.remove(&key);
        candidate = candidate.normalized();
        candidate.validate()?;
        candidate.remove_toml_key(&key)?;
        *self = candidate;
        Ok(())
    }

    /// Replaces a key's scopes, tags, and comment without changing its identity or agent.
    pub fn update_key_metadata(
        &mut self,
        alias: &KeyAlias,
        scopes: Vec<ScopePath>,
        tags: BTreeMap<String, String>,
        comment: Option<String>,
    ) -> Result<(), ConfigError> {
        let key = self
            .keys
            .keys()
            .find(|existing| KeyAlias::new(existing).ok().as_ref() == Some(alias))
            .cloned()
            .ok_or_else(|| ConfigError::UnknownKey(alias.clone()))?;
        let existing = self.keys.get(&key).expect("key alias was found");
        let scopes_changed =
            existing.scopes != scopes.iter().map(ToString::to_string).collect::<Vec<_>>();
        let tags_changed = existing.tags != tags;
        let comment_changed = existing.comment != comment;
        let mut candidate = self.clone();
        let key_document = candidate.keys.get_mut(&key).expect("key alias was found");
        key_document.scopes = scopes.iter().map(ToString::to_string).collect();
        key_document.tags = tags.clone();
        key_document.comment = comment.clone();
        candidate = candidate.normalized();
        candidate.validate()?;
        let normalized_comment = candidate
            .keys
            .get(&key)
            .expect("key alias was found")
            .comment
            .clone();
        candidate.update_toml_key_metadata(
            &key,
            &scopes,
            &tags,
            normalized_comment.as_deref(),
            (
                scopes_changed,
                tags_changed,
                comment_changed || comment.as_deref().is_some_and(str::is_empty),
            ),
        )?;
        *self = candidate;
        Ok(())
    }

    fn matches_serialized(&self, other: &Self) -> bool {
        self.version == other.version && self.agents == other.agents && self.keys == other.keys
    }

    fn is_unchanged_from(&self, other: &Self) -> bool {
        self.matches_serialized(other)
            && self.toml.as_ref().map(ToString::to_string)
                == other.toml.as_ref().map(ToString::to_string)
    }

    fn insert_toml_agent(&mut self, name: &AgentName) -> Result<(), ConfigError> {
        let Some(document) = self.toml.as_mut() else {
            return Ok(());
        };
        let agent = self
            .agents
            .get(name.as_str())
            .expect("added agent is present in the candidate document");
        let agents = toml_root_table(document, "agents")?;
        let mut item = Table::new();
        item.insert("type", value("unix"));
        item.insert("socket", value(agent.socket.to_string_lossy().as_ref()));
        agents.insert(name.as_str(), Item::Table(item));
        Ok(())
    }

    fn remove_toml_agent(&mut self, name: &str) -> Result<(), ConfigError> {
        let Some(document) = self.toml.as_mut() else {
            return Ok(());
        };
        let agents = toml_root_table(document, "agents")?;
        agents.remove(name).ok_or_else(|| {
            ConfigError::Serialize(format!(
                "could not find agent '{name}' in the TOML document"
            ))
        })?;
        Ok(())
    }

    fn update_toml_agent_socket(&mut self, name: &str, socket: &Path) -> Result<(), ConfigError> {
        let Some(document) = self.toml.as_mut() else {
            return Ok(());
        };
        let agents = toml_root_table(document, "agents")?;
        let agent = agents
            .get_mut(name)
            .and_then(Item::as_table_like_mut)
            .ok_or_else(|| {
                ConfigError::Serialize(format!(
                    "could not find agent '{name}' as a TOML table to update"
                ))
            })?;
        set_toml_field(
            agent,
            "socket",
            Some(value(socket.to_string_lossy().as_ref())),
        )
    }

    fn insert_toml_key(&mut self, alias: &str) -> Result<(), ConfigError> {
        let Some(document) = self.toml.as_mut() else {
            return Ok(());
        };
        let key = self
            .keys
            .get(alias)
            .expect("added key is present in the candidate document");
        let keys = toml_root_table(document, "keys")?;
        let mut item = Table::new();
        item.insert("fingerprint", value(&key.fingerprint));
        item.insert("agent", value(&key.agent));
        if !key.scopes.is_empty() {
            let mut scopes = Array::new();
            for scope in &key.scopes {
                scopes.push(scope);
            }
            item.insert("scopes", Item::Value(scopes.into()));
        }
        if let Some(comment) = &key.comment {
            item.insert("comment", value(comment));
        }
        if !key.tags.is_empty() {
            let mut tags = Table::new();
            for (name, tag_value) in &key.tags {
                tags.insert(name, value(tag_value));
            }
            item.insert("tags", Item::Table(tags));
        }
        keys.insert(alias, Item::Table(item));
        Ok(())
    }

    fn remove_toml_key(&mut self, alias: &str) -> Result<(), ConfigError> {
        let Some(document) = self.toml.as_mut() else {
            return Ok(());
        };
        let keys = toml_root_table(document, "keys")?;
        keys.remove(alias).ok_or_else(|| {
            ConfigError::Serialize(format!("could not find key '{alias}' in the TOML document"))
        })?;
        Ok(())
    }

    fn update_toml_key_metadata(
        &mut self,
        alias: &str,
        scopes: &[ScopePath],
        tags: &BTreeMap<String, String>,
        comment: Option<&str>,
        changed: (bool, bool, bool),
    ) -> Result<(), ConfigError> {
        let (scopes_changed, tags_changed, comment_changed) = changed;
        let Some(document) = self.toml.as_mut() else {
            return Ok(());
        };
        let keys = toml_root_table(document, "keys")?;
        let key = keys
            .get_mut(alias)
            .and_then(Item::as_table_like_mut)
            .ok_or_else(|| {
                ConfigError::Serialize(format!(
                    "could not find key '{alias}' as a TOML table to update"
                ))
            })?;

        if scopes_changed {
            let scopes_item = if scopes.is_empty() {
                None
            } else {
                let mut array = Array::new();
                for scope in scopes {
                    array.push(scope.to_string());
                }
                Some(Item::Value(array.into()))
            };
            set_toml_field(key, "scopes", scopes_item)?;
        }
        if comment_changed {
            set_toml_field(key, "comment", comment.map(value))?;
        }

        if tags_changed && tags.is_empty() {
            key.remove("tags");
        } else if tags_changed {
            let tags_table = key
                .entry("tags")
                .or_insert_with(|| Item::Table(Table::new()))
                .as_table_like_mut()
                .ok_or_else(|| {
                    ConfigError::Serialize(format!(
                        "TOML field 'keys.{alias}.tags' must be a table to update it"
                    ))
                })?;
            let old_names = tags_table
                .iter()
                .map(|(name, _)| name.to_owned())
                .collect::<Vec<_>>();
            for name in old_names {
                if !tags.contains_key(&name) {
                    tags_table.remove(&name);
                }
            }
            for (name, tag_value) in tags {
                set_toml_field(tags_table, name, Some(value(tag_value)))?;
            }
        }
        Ok(())
    }
}

fn set_toml_field(
    table: &mut dyn TableLike,
    name: &str,
    replacement: Option<Item>,
) -> Result<(), ConfigError> {
    match (table.get_mut(name), replacement) {
        (Some(current), Some(replacement)) => {
            let Some(current_value) = current.as_value_mut() else {
                return Err(ConfigError::Serialize(format!(
                    "TOML field '{name}' must be a value to update it"
                )));
            };
            let Ok(mut replacement_value) = replacement.into_value() else {
                return Err(ConfigError::Serialize(format!(
                    "replacement for TOML field '{name}' is not a value"
                )));
            };
            *replacement_value.decor_mut() = current_value.decor().clone();
            *current_value = replacement_value;
        }
        (None, Some(replacement)) => {
            table.insert(name, replacement);
        }
        (Some(_), None) => {
            table.remove(name);
        }
        (None, None) => {}
    }
    Ok(())
}

/// An opaque content revision used to detect changes made since a configuration was loaded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigRevision([u8; 32]);

/// A validated configuration document together with the revision it was loaded from.
#[derive(Clone, Debug)]
pub struct ConfigSnapshot {
    document: ConfigDocument,
    revision: ConfigRevision,
}

impl ConfigSnapshot {
    /// Returns the loaded document.
    pub fn document(&self) -> &ConfigDocument {
        &self.document
    }

    /// Returns the content revision captured during loading.
    pub fn revision(&self) -> &ConfigRevision {
        &self.revision
    }
}

fn toml_root_table<'a>(
    document: &'a mut DocumentMut,
    name: &str,
) -> Result<&'a mut dyn TableLike, ConfigError> {
    let item = document
        .as_table_mut()
        .entry(name)
        .or_insert_with(|| Item::Table(Table::new()));
    item.as_table_like_mut().ok_or_else(|| {
        ConfigError::Serialize(format!(
            "TOML field '{name}' must be a table or inline table to update it"
        ))
    })
}

/// Loads, discovers, and atomically persists configuration documents.
pub struct ConfigStore;

impl ConfigStore {
    /// Returns an explicit CLI path or the `KMUX_CONFIG` environment path.
    pub fn explicit_path(explicit: Option<&Path>) -> Option<PathBuf> {
        explicit
            .map(Path::to_owned)
            .or_else(|| env::var_os(CONFIG_ENV).map(PathBuf::from))
    }

    /// Returns the default XDG TOML configuration path.
    pub fn default_path() -> Result<PathBuf, ConfigError> {
        let config_home = env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
            .ok_or(ConfigError::ConfigHomeUnavailable)?;
        Ok(config_home.join("kmux").join("config.toml"))
    }

    /// Loads and validates a serialized configuration document.
    pub fn load(path: &Path) -> Result<ConfigDocument, ConfigError> {
        Self::load_source(path).map(|(document, _)| document)
    }

    /// Loads a configuration document and captures a content-based revision.
    pub fn load_versioned(path: &Path) -> Result<ConfigSnapshot, ConfigError> {
        let (document, source) = Self::load_source(path)?;
        Ok(ConfigSnapshot {
            document,
            revision: revision(&source),
        })
    }

    fn load_source(path: &Path) -> Result<(ConfigDocument, String), ConfigError> {
        let format = ConfigFormat::from_path(path)?;
        let decoder: &dyn ConfigDecoder = match format {
            ConfigFormat::Yaml => &YamlConfigDecoder,
            ConfigFormat::Json => &JsonConfigDecoder,
            ConfigFormat::Toml => &TomlConfigDecoder,
        };
        let source = read_config(path)?;
        let mut document = decoder.decode(&source)?.normalized();
        if format == ConfigFormat::Toml {
            document.toml =
                Some(source.parse().map_err(|error: toml_edit::TomlError| {
                    ConfigError::Parse(error.to_string())
                })?);
        }
        document.validate()?;
        Ok((document, source))
    }

    /// Loads, mutates, validates, and atomically persists a configuration under a process lock.
    ///
    /// The lock is held while `mutate` runs, so cooperating writers cannot overwrite one another.
    /// A content revision is checked again before persistence to detect edits by non-cooperating
    /// writers. Detection of non-cooperating writers is best-effort: such writers do not acquire
    /// this lock, so an edit in the small interval between the final revision check and atomic
    /// replacement cannot be excluded.
    pub fn update<F>(path: &Path, mutate: F) -> Result<(), ConfigError>
    where
        F: FnOnce(&mut ConfigDocument) -> Result<(), ConfigError>,
    {
        let _lock = ConfigLock::acquire(path)?;
        let snapshot = Self::load_versioned(path)?;
        let original = snapshot.document.clone();
        let mut document = snapshot.document;
        mutate(&mut document)?;
        document.validate()?;
        if document.is_unchanged_from(&original) {
            if current_revision(path)?.as_ref() != Some(&snapshot.revision) {
                return Err(ConfigError::Conflict(path.to_owned()));
            }
            return Ok(());
        }
        Self::save_unlocked(path, &document, Some(&snapshot.revision))
    }

    /// Saves a document only if the file still has the revision in `snapshot`.
    ///
    /// Cooperating writers are serialized by the process lock. Detection of changes by
    /// non-cooperating tools is best-effort; edits can still race the final atomic replacement.
    pub fn save_if_unchanged(
        path: &Path,
        snapshot: &ConfigSnapshot,
        document: &ConfigDocument,
    ) -> Result<(), ConfigError> {
        let _lock = ConfigLock::acquire(path)?;
        Self::save_unlocked(path, document, Some(&snapshot.revision))
    }

    /// Validates and atomically writes a document with private permissions under the process lock.
    ///
    /// This operation is unconditional with respect to the document's origin. Use
    /// [`Self::save_if_unchanged`] when the document was derived from a previously loaded file and
    /// overwriting intervening edits would be unsafe.
    pub fn save(path: &Path, document: &ConfigDocument) -> Result<(), ConfigError> {
        let _lock = ConfigLock::acquire(path)?;
        Self::save_unlocked(path, document, None)
    }

    fn save_unlocked(
        path: &Path,
        document: &ConfigDocument,
        expected_revision: Option<&ConfigRevision>,
    ) -> Result<(), ConfigError> {
        let document = document.clone().normalized();
        document.validate()?;
        let output = match ConfigFormat::from_path(path)? {
            ConfigFormat::Toml => match &document.toml {
                Some(toml) => {
                    let output = toml.to_string();
                    let rendered = TomlConfigDecoder.decode(&output)?.normalized();
                    rendered.validate()?;
                    if !document.matches_serialized(&rendered) {
                        return Err(ConfigError::Serialize(
                            "edited TOML no longer matches the validated configuration".to_owned(),
                        ));
                    }
                    output
                }
                None => toml::to_string_pretty(&document)
                    .map_err(|error| ConfigError::Serialize(error.to_string()))?,
            },
            ConfigFormat::Yaml => serde_saphyr::to_string(&document)
                .map_err(|error| ConfigError::Serialize(error.to_string()))?,
            ConfigFormat::Json => serde_json::to_string_pretty(&document)
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
        if let Some(expected_revision) = expected_revision
            && current_revision(path)?.as_ref() != Some(expected_revision)
        {
            return Err(ConfigError::Conflict(path.to_owned()));
        }
        temporary
            .persist(path)
            .map_err(|error| ConfigError::Write {
                path: path.to_owned(),
                source: error.error,
            })?;
        Ok(())
    }

    /// Discovers a configured or default configuration path.
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

    /// Discovers exactly one supported configuration file in `directory`.
    pub fn discover_in(directory: PathBuf) -> Result<ConfigPath, ConfigError> {
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

fn revision(source: &str) -> ConfigRevision {
    ConfigRevision(Sha256::digest(source.as_bytes()).into())
}

fn current_revision(path: &Path) -> Result<Option<ConfigRevision>, ConfigError> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(ConfigError::Read {
                path: path.to_owned(),
                source,
            });
        }
    };
    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192];
    loop {
        let count = file.read(&mut buffer).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(Some(ConfigRevision(hasher.finalize().into())))
}

struct ConfigLock(File);

impl ConfigLock {
    fn acquire(path: &Path) -> Result<Self, ConfigError> {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::create_dir_all(parent).map_err(|source| ConfigError::Write {
            path: parent.to_owned(),
            source,
        })?;
        let lock_path = lock_path(path);
        let file = fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)
            .map_err(|source| ConfigError::Write {
                path: lock_path.clone(),
                source,
            })?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|source| ConfigError::Write {
                path: lock_path.clone(),
                source,
            })?;
        rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive).map_err(|source| {
            ConfigError::Write {
                path: lock_path,
                source: source.into(),
            }
        })?;
        Ok(Self(file))
    }
}

impl Drop for ConfigLock {
    fn drop(&mut self) {
        let _ = rustix::fs::flock(&self.0, rustix::fs::FlockOperation::Unlock);
    }
}

fn lock_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    PathBuf::from(name)
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// A discovered configuration filesystem path.
pub struct ConfigPath(PathBuf);

impl ConfigPath {
    /// Returns the underlying filesystem path.
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

#[derive(Debug)]
/// An error loading, validating, discovering, or saving configuration.
pub enum ConfigError {
    /// The configuration changed since the supplied snapshot was loaded.
    Conflict(PathBuf),
    /// Reading a configuration file failed.
    Read {
        /// Path that could not be read.
        path: PathBuf,
        /// Underlying filesystem error.
        source: std::io::Error,
    },
    /// A configuration file or serialized output exceeded its size limit.
    TooLarge {
        /// Path associated with the oversized content.
        path: PathBuf,
        /// Maximum permitted byte length.
        limit: usize,
    },
    /// Parsing serialized configuration failed.
    Parse(String),
    /// A configuration path has an unsupported extension.
    UnsupportedFormat(PathBuf),
    /// Neither `XDG_CONFIG_HOME` nor `HOME` was available for discovery.
    ConfigHomeUnavailable,
    /// No supported configuration file was found in this directory.
    ConfigNotFound(PathBuf),
    /// More than one supported configuration file was found.
    AmbiguousConfig(Vec<PathBuf>),
    /// The document schema version is unsupported.
    UnsupportedVersion(u32),
    /// Agent names collided after normalization.
    DuplicateAgent(AgentName),
    /// A referenced or requested agent is absent.
    UnknownAgent(AgentName),
    /// An agent cannot be removed while these key aliases reference it.
    AgentInUse(AgentName, Vec<String>),
    /// A requested key alias is absent.
    UnknownKey(KeyAlias),
    /// Serializing a configuration document failed.
    Serialize(String),
    /// Writing a configuration file failed.
    Write {
        /// Path that could not be written.
        path: PathBuf,
        /// Underlying filesystem error.
        source: std::io::Error,
    },
    /// The document violated a schema validation rule.
    Validation(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict(path) => write!(
                formatter,
                "configuration '{}' changed since it was loaded; refusing to overwrite it",
                path.display()
            ),
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
                write!(
                    formatter,
                    "no config found in '{}', run 'kmux init' to create config file",
                    path.display()
                )
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
                write!(
                    formatter,
                    "unknown agent '{agent}', run 'kmux agent add --socket /path/to/agent.sock {agent}'"
                )
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentDocument {
    #[serde(rename = "type")]
    kind: AgentKind,
    socket: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum AgentKind {
    Unix,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyDocument {
    fingerprint: String,
    agent: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    tags: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::{
        AgentDocument, AgentKind, Config, ConfigDocument, ConfigError, ConfigStore, KeyDocument,
        MAX_CONFIG_BYTES, MAX_YAML_ALIASES, SUPPORTED_VERSION, lock_path,
    };
    use crate::agent::{AgentDefinition, AgentName};
    use crate::catalog::{Fingerprint, KeyAlias, KeyCatalog, KeyEntry};
    use crate::scope::ScopePath;
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::Command;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMPORARY_PATH_ID: AtomicU64 = AtomicU64::new(0);

    const FINGERPRINT: &str = "SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+Y";
    const COMMENTED_TOML: &str = include_str!("../../tests/fixtures/commented-config.toml");
    const INLINE_TOML: &str = concat!(
        "version = 1\n\n",
        "agents = { bitwarden = { type = \"unix\", socket = \"/tmp/bitwarden.sock\" } }\n\n",
        "keys = { github = { fingerprint = \"SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+Y\", agent = \"bitwarden\" } }\n"
    );
    const DOTTED_TOML: &str = concat!(
        "version = 1\n",
        "agents.bitwarden.socket = \"/tmp/bitwarden.sock\"\n",
        "agents.bitwarden.type = \"unix\"\n"
    );

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
                    comment: Some("Production deployment key".to_owned()),
                },
            )]),
            toml: None,
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
            assert_eq!(entry.comment(), Some("Production deployment key"));
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
            toml: None,
        };
        assert!(ConfigStore::save(&path, &document).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn omits_empty_new_key_metadata_and_preserves_loaded_empty_comments() {
        let directory = temporary_directory();
        let path = directory.join("config.toml");
        let mut document = ConfigDocument::empty();
        let agent = AgentName::new("work").unwrap();
        document
            .add_agent(agent.clone(), "/tmp/work.sock".into())
            .unwrap();
        document
            .add_key(
                KeyEntry::new(
                    KeyAlias::new("deploy").unwrap(),
                    Fingerprint::from_str(FINGERPRINT).unwrap(),
                    agent,
                    [],
                    BTreeMap::new(),
                )
                .with_comment(Some(String::new())),
            )
            .unwrap();
        ConfigStore::save(&path, &document).unwrap();
        let output = fs::read_to_string(&path).unwrap();
        assert!(!output.contains("scopes = []"));
        assert!(!output.contains("[keys.deploy.tags]"));
        assert!(!output.contains("comment = \"\""));
        fs::write(&path, format!("{output}comment = \"\"\n")).unwrap();
        let loaded = ConfigStore::load(&path).unwrap();
        ConfigStore::save(&path, &loaded).unwrap();
        assert!(
            fs::read_to_string(&path)
                .unwrap()
                .contains("comment = \"\"")
        );
        assert!(
            ConfigStore::load(&path)
                .unwrap()
                .validate()
                .unwrap()
                .catalog()
                .entries()
                .next()
                .unwrap()
                .comment()
                .is_none()
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn saving_a_loaded_toml_without_mutations_preserves_its_text() {
        let path = write_config("toml", COMMENTED_TOML);
        let document = ConfigStore::load(&path).unwrap();
        ConfigStore::save(&path, &document).unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), COMMENTED_TOML);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn toml_mutations_preserve_unaffected_comments_and_formatting() {
        let path = write_config("toml", COMMENTED_TOML);
        let mut document = ConfigStore::load(&path).unwrap();
        let backup = AgentName::new("backup").unwrap();
        document
            .add_agent(backup.clone(), "/tmp/backup.sock".into())
            .unwrap();
        document
            .add_key(KeyEntry::new(
                KeyAlias::new("archive").unwrap(),
                Fingerprint::from_str("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                    .unwrap(),
                backup,
                [ScopePath::from_str("personal/backup").unwrap()],
                BTreeMap::from([("source.host".to_owned(), "backup".to_owned())]),
            ))
            .unwrap();
        ConfigStore::save(&path, &document).unwrap();

        let output = fs::read_to_string(&path).unwrap();
        for preserved in [
            "# My personal SSH configuration\nversion = 1",
            "# Password manager\n[agents.bitwarden]\ntype   = 'unix'\nsocket = '/tmp/bitwarden.sock' # Local socket",
            "# GitHub personal identity\n[keys.github]\nfingerprint = 'SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+Y'\nagent       = 'bitwarden'\nscopes      = ['personal'] # Available to personal projects\ncomment = \"\"",
            "[keys.github.tags]\nprovider = 'github'",
        ] {
            assert!(
                output.contains(preserved),
                "missing preserved text: {preserved}"
            );
        }
        assert!(output.contains("[agents.backup]"));
        assert!(output.contains("[keys.archive]"));
        assert!(output.contains("[keys.archive.tags]"));
        assert!(output.contains("\"source.host\" = \"backup\""));
        assert!(output.find("[agents.bitwarden]").unwrap() < output.find("[keys.github]").unwrap());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn removing_toml_entries_keeps_unrelated_content() {
        let path = write_config("toml", COMMENTED_TOML);
        let mut document = ConfigStore::load(&path).unwrap();
        document
            .remove_key(&KeyAlias::new("github").unwrap())
            .unwrap();
        document
            .add_agent(AgentName::new("backup").unwrap(), "/tmp/backup.sock".into())
            .unwrap();
        document
            .remove_agent(&AgentName::new("backup").unwrap())
            .unwrap();
        ConfigStore::save(&path, &document).unwrap();

        let output = fs::read_to_string(&path).unwrap();
        assert!(output.contains("# My personal SSH configuration\nversion = 1"));
        assert!(output.contains("# Password manager\n[agents.bitwarden]\ntype   = 'unix'\nsocket = '/tmp/bitwarden.sock' # Local socket"));
        assert!(!output.contains("[keys.github]"));
        assert!(!output.contains("[keys.github.tags]"));
        assert!(!output.contains("[agents.backup]"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn mutates_inline_agent_and_key_tables_without_converting_them() {
        let path = write_config("toml", INLINE_TOML);
        let mut document = ConfigStore::load(&path).unwrap();
        document
            .add_agent(AgentName::new("spare").unwrap(), "/tmp/spare.sock".into())
            .unwrap();
        ConfigStore::save(&path, &document).unwrap();
        assert!(
            fs::read_to_string(&path)
                .unwrap()
                .contains("spare = { type = \"unix\", socket = \"/tmp/spare.sock\" }")
        );
        document
            .remove_agent(&AgentName::new("spare").unwrap())
            .unwrap();
        document
            .add_key(KeyEntry::new(
                KeyAlias::new("archive").unwrap(),
                Fingerprint::from_str("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                    .unwrap(),
                AgentName::new("bitwarden").unwrap(),
                [],
                BTreeMap::new(),
            ))
            .unwrap();
        document
            .remove_key(&KeyAlias::new("github").unwrap())
            .unwrap();
        ConfigStore::save(&path, &document).unwrap();

        let output = fs::read_to_string(&path).unwrap();
        assert!(output.contains("agents = { bitwarden = {"));
        assert!(output.contains("keys = { archive = {"));
        assert!(!output.contains("[agents."));
        assert!(!output.contains("[keys."));
        assert!(!output.contains("github"));
        let config = ConfigStore::load(&path).unwrap().validate().unwrap();
        assert_eq!(config.agents().len(), 1);
        assert_eq!(config.catalog().entries().count(), 1);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn dotted_keys_remain_valid_after_an_unrelated_toml_mutation() {
        let path = write_config("toml", DOTTED_TOML);
        let mut document = ConfigStore::load(&path).unwrap();
        document
            .add_agent(AgentName::new("backup").unwrap(), "/tmp/backup.sock".into())
            .unwrap();
        ConfigStore::save(&path, &document).unwrap();

        let output = fs::read_to_string(&path).unwrap();
        assert!(output.contains("agents.bitwarden.socket"));
        assert!(ConfigStore::load(&path).unwrap().validate().is_ok());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn saving_toml_without_a_final_newline_adds_one() {
        let path = write_config("toml", "version = 1");
        let document = ConfigStore::load(&path).unwrap();
        ConfigStore::save(&path, &document).unwrap();

        assert!(fs::read_to_string(&path).unwrap().ends_with('\n'));
        fs::remove_file(path).unwrap();
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

    #[test]
    fn versioned_save_rejects_external_changes() {
        let directory = temporary_directory();
        let path = directory.join("config.toml");
        ConfigStore::save(&path, &ConfigDocument::empty()).unwrap();
        let snapshot = ConfigStore::load_versioned(&path).unwrap();
        fs::write(&path, "version = [broken\n").unwrap();

        assert!(matches!(
            ConfigStore::save_if_unchanged(&path, &snapshot, snapshot.document()),
            Err(ConfigError::Conflict(conflict_path)) if conflict_path == path
        ));
        assert_eq!(fs::read_to_string(&path).unwrap(), "version = [broken\n");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn concurrent_updates_preserve_both_changes() {
        let directory = temporary_directory();
        let path = directory.join("config.toml");
        ConfigStore::save(&path, &ConfigDocument::empty()).unwrap();
        let first_path = path.clone();
        let second_path = path.clone();
        let first = std::thread::spawn(move || {
            ConfigStore::update(&first_path, |document| {
                document.add_agent(AgentName::new("first").unwrap(), "/tmp/first.sock".into())
            })
        });
        let second = std::thread::spawn(move || {
            ConfigStore::update(&second_path, |document| {
                document.add_agent(AgentName::new("second").unwrap(), "/tmp/second.sock".into())
            })
        });
        first.join().unwrap().unwrap();
        second.join().unwrap().unwrap();

        assert_eq!(
            fs::metadata(lock_path(&path)).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let config = ConfigStore::load(&path).unwrap().validate().unwrap();
        assert!(
            config
                .agents()
                .contains_key(&AgentName::new("first").unwrap())
        );
        assert!(
            config
                .agents()
                .contains_key(&AgentName::new("second").unwrap())
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn config_update_worker() {
        let Ok(path) = std::env::var("KMUX_TEST_CONFIG_UPDATE_PATH") else {
            return;
        };
        let name = std::env::var("KMUX_TEST_CONFIG_UPDATE_AGENT").unwrap();
        ConfigStore::update(Path::new(&path), |document| {
            document.add_agent(
                AgentName::new(name).unwrap(),
                "/tmp/process-agent.sock".into(),
            )
        })
        .unwrap();
    }

    #[test]
    fn independent_process_updates_preserve_both_changes() {
        let directory = temporary_directory();
        let path = directory.join("config.toml");
        ConfigStore::save(&path, &ConfigDocument::empty()).unwrap();
        let executable = std::env::current_exe().unwrap();
        let mut children = ["process-first", "process-second"].map(|name| {
            Command::new(&executable)
                .arg("--exact")
                .arg("config::schema::tests::config_update_worker")
                .env("KMUX_TEST_CONFIG_UPDATE_PATH", &path)
                .env("KMUX_TEST_CONFIG_UPDATE_AGENT", name)
                .spawn()
                .unwrap()
        });
        for child in &mut children {
            assert!(child.wait().unwrap().success());
        }

        let config = ConfigStore::load(&path).unwrap().validate().unwrap();
        assert!(
            config
                .agents()
                .contains_key(&AgentName::new("process-first").unwrap())
        );
        assert!(
            config
                .agents()
                .contains_key(&AgentName::new("process-second").unwrap())
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn external_edit_during_update_returns_conflict_without_overwriting() {
        let directory = temporary_directory();
        let path = directory.join("config.toml");
        ConfigStore::save(&path, &ConfigDocument::empty()).unwrap();
        let external_content = "version = [externally, changed\n";

        let result = ConfigStore::update(&path, |document| {
            fs::write(&path, external_content).map_err(|source| ConfigError::Write {
                path: path.clone(),
                source,
            })?;
            document.add_agent(AgentName::new("work").unwrap(), "/tmp/work.sock".into())
        });

        assert!(
            matches!(result, Err(ConfigError::Conflict(conflict_path)) if conflict_path == path)
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), external_content);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn failed_update_preserves_file_and_releases_lock() {
        let directory = temporary_directory();
        let path = directory.join("config.toml");
        let original = "version = 1\n";
        fs::write(&path, original).unwrap();

        assert!(matches!(
            ConfigStore::update(&path, |_| Err(ConfigError::Validation(
                "injected failure".into()
            ))),
            Err(ConfigError::Validation(_))
        ));
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        ConfigStore::update(&path, |document| {
            document.add_agent(AgentName::new("work").unwrap(), "/tmp/work.sock".into())
        })
        .unwrap();
        assert!(ConfigStore::load(&path).unwrap().validate().is_ok());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn transaction_preserves_unmodified_toml_comments_and_formatting() {
        let directory = temporary_directory();
        let path = directory.join("config.toml");
        fs::write(&path, COMMENTED_TOML).unwrap();
        ConfigStore::update(&path, |document| {
            document.add_agent(AgentName::new("backup").unwrap(), "/tmp/backup.sock".into())
        })
        .unwrap();

        let output = fs::read_to_string(&path).unwrap();
        assert!(output.contains("# My personal SSH configuration\nversion = 1"));
        assert!(output.contains("type   = 'unix'\nsocket = '/tmp/bitwarden.sock' # Local socket"));
        assert!(output.contains("[agents.backup]"));
        fs::remove_dir_all(directory).unwrap();
    }
}
