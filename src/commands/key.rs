use kmux::agent::{AgentName, UnixSocketAgent, UpstreamAgent};
use kmux::catalog::{Fingerprint, Identity, KeyAlias, KeyEntry};
use kmux::config::{ConfigPath, ConfigStore};
use kmux::scope::ScopePath;
use std::collections::BTreeMap;
use std::io::{IsTerminal, stdin};
use std::str::FromStr;

struct KeyAddRequest {
    alias: String,
    agent: Option<String>,
    fingerprint: Option<String>,
    comment: Option<String>,
    scopes: Vec<String>,
    tags: Vec<String>,
}

pub fn add(
    path: &ConfigPath,
    alias: String,
    agent: Option<String>,
    fingerprint: Option<String>,
    comment: Option<String>,
    scopes: Vec<String>,
    tags: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    add_with(
        path,
        KeyAddRequest {
            alias,
            agent,
            fingerprint,
            comment,
            scopes,
            tags,
        },
        &InquireKeyPrompter,
        |definition| UnixSocketAgent::new(definition.socket().to_owned()).identities(),
    )
}

fn add_with(
    path: &ConfigPath,
    request: KeyAddRequest,
    prompter: &dyn KeyPrompter,
    identities: impl FnOnce(
        &kmux::agent::AgentDefinition,
    ) -> Result<Vec<Identity>, kmux::agent::AgentError>,
) -> Result<(), Box<dyn std::error::Error>> {
    let KeyAddRequest {
        alias,
        agent,
        fingerprint,
        comment,
        scopes,
        tags,
    } = request;
    let alias = KeyAlias::new(alias)?;
    let has_flags = agent.is_some()
        || fingerprint.is_some()
        || comment.is_some()
        || !scopes.is_empty()
        || !tags.is_empty();
    let document = ConfigStore::load(path.as_path())?;
    let entry = if has_flags {
        let agent =
            agent.ok_or("missing required --agent when using non-interactive key creation")?;
        let fingerprint = fingerprint
            .ok_or("missing required --fingerprint when using non-interactive key creation")?;
        entry(alias, agent, fingerprint, comment, scopes, tags)?
    } else {
        interactive_entry_with(&document.validate()?, alias, prompter, identities)?
    };
    ConfigStore::update(path.as_path(), move |document| document.add_key(entry))?;
    Ok(())
}

pub fn remove(
    path: &ConfigPath,
    alias: String,
    yes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    remove_with(path, alias, yes, &TerminalConfirmation)
}

fn remove_with(
    path: &ConfigPath,
    alias: String,
    yes: bool,
    confirmation: &dyn KeyRemovalConfirmation,
) -> Result<(), Box<dyn std::error::Error>> {
    let alias = KeyAlias::new(alias)?;
    if !yes {
        if !confirmation.is_terminal() {
            return Err("refusing to remove a key without --yes outside a terminal".into());
        }
        if !confirmation.confirm(&alias)? {
            return Ok(());
        }
    }
    ConfigStore::update(path.as_path(), move |document| document.remove_key(&alias))?;
    Ok(())
}

trait KeyRemovalConfirmation {
    fn is_terminal(&self) -> bool;
    fn confirm(&self, alias: &KeyAlias) -> Result<bool, Box<dyn std::error::Error>>;
}

struct TerminalConfirmation;

impl KeyRemovalConfirmation for TerminalConfirmation {
    fn is_terminal(&self) -> bool {
        stdin().is_terminal()
    }

    fn confirm(&self, alias: &KeyAlias) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(inquire::Confirm::new(&format!("Remove key '{alias}'?"))
            .with_default(false)
            .prompt()?)
    }
}

fn entry(
    alias: KeyAlias,
    agent: String,
    fingerprint: String,
    comment: Option<String>,
    scopes: Vec<String>,
    tags: Vec<String>,
) -> Result<KeyEntry, Box<dyn std::error::Error>> {
    let agent = AgentName::new(agent)?;
    let fingerprint = Fingerprint::from_str(&fingerprint)?;
    let scopes = scopes
        .into_iter()
        .map(|scope| ScopePath::from_str(&scope))
        .collect::<Result<Vec<_>, _>>()?;
    let tags = parse_tags(tags)?;
    Ok(KeyEntry::new(alias, fingerprint, agent, scopes, tags).with_comment(comment))
}

fn interactive_entry_with(
    config: &kmux::config::Config,
    alias: KeyAlias,
    prompter: &dyn KeyPrompter,
    identities: impl FnOnce(
        &kmux::agent::AgentDefinition,
    ) -> Result<Vec<Identity>, kmux::agent::AgentError>,
) -> Result<KeyEntry, Box<dyn std::error::Error>> {
    let names = config.agents().keys().cloned().collect::<Vec<_>>();
    let agent = prompter.select_agent(&names)?;
    let definition = config.agents().get(&agent).expect("selected agent exists");
    let identity = prompter.select_identity(&identities(definition)?)?;
    let scopes = split_values(prompter.scopes()?);
    let tags = split_values(prompter.tags()?);
    if !prompter.confirm(&alias, &agent, &identity)? {
        return Err("key creation cancelled".into());
    }
    entry(
        alias,
        agent.to_string(),
        identity.fingerprint.to_string(),
        identity.comment,
        scopes,
        tags,
    )
}

fn split_values(value: String) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

trait KeyPrompter {
    fn select_agent(&self, agents: &[AgentName]) -> Result<AgentName, Box<dyn std::error::Error>>;
    fn select_identity(
        &self,
        identities: &[Identity],
    ) -> Result<Identity, Box<dyn std::error::Error>>;
    fn scopes(&self) -> Result<String, Box<dyn std::error::Error>>;
    fn tags(&self) -> Result<String, Box<dyn std::error::Error>>;
    fn confirm(
        &self,
        alias: &KeyAlias,
        agent: &AgentName,
        identity: &Identity,
    ) -> Result<bool, Box<dyn std::error::Error>>;
}

struct InquireKeyPrompter;

impl KeyPrompter for InquireKeyPrompter {
    fn select_agent(&self, agents: &[AgentName]) -> Result<AgentName, Box<dyn std::error::Error>> {
        match agents {
            [] => Err("no configured agents are available".into()),
            [agent] => Ok(agent.clone()),
            _ => Ok(inquire::Select::new("Select agent", agents.to_vec()).prompt()?),
        }
    }

    fn select_identity(
        &self,
        identities: &[Identity],
    ) -> Result<Identity, Box<dyn std::error::Error>> {
        if identities.is_empty() {
            return Err("selected agent has no public identities".into());
        }
        Ok(inquire::Select::new(
            "Select identity",
            identities.iter().cloned().map(IdentityOption).collect(),
        )
        .prompt()?
        .0)
    }

    fn scopes(&self) -> Result<String, Box<dyn std::error::Error>> {
        Ok(inquire::Text::new("Scopes (comma-separated, optional)")
            .prompt_skippable()?
            .unwrap_or_default())
    }

    fn tags(&self) -> Result<String, Box<dyn std::error::Error>> {
        Ok(
            inquire::Text::new("Tags (comma-separated KEY=VALUE, optional)")
                .prompt_skippable()?
                .unwrap_or_default(),
        )
    }

    fn confirm(
        &self,
        alias: &KeyAlias,
        agent: &AgentName,
        identity: &Identity,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(inquire::Confirm::new(&format!(
            "Add key '{alias}' using {} from agent '{agent}'?",
            identity.fingerprint
        ))
        .with_default(true)
        .prompt()?)
    }
}

pub(crate) fn parse_tags(
    tags: Vec<String>,
) -> Result<BTreeMap<String, String>, Box<dyn std::error::Error>> {
    let mut parsed = BTreeMap::new();
    for tag in tags {
        let Some((name, value)) = tag.split_once('=') else {
            return Err(format!("tags must use non-empty KEY=VALUE syntax: '{tag}'").into());
        };
        if name.is_empty()
            || value.is_empty()
            || parsed.insert(name.to_owned(), value.to_owned()).is_some()
        {
            return Err(format!("tags must use unique non-empty KEY=VALUE syntax: '{tag}'").into());
        }
    }
    Ok(parsed)
}

struct IdentityOption(Identity);

impl std::fmt::Display for IdentityOption {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let comment = self.0.comment.as_deref().unwrap_or("no comment");
        write!(
            formatter,
            "{} - {}",
            self.0.fingerprint,
            comment.replace(|character: char| character.is_control(), " ")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        InquireKeyPrompter, KeyAddRequest, KeyPrompter, KeyRemovalConfirmation, add, add_with,
        interactive_entry_with, remove, remove_with,
    };
    use kmux::agent::AgentName;
    use kmux::catalog::{Fingerprint, Identity, KeyAlias};
    use kmux::config::{Config, ConfigDocument, ConfigStore};
    use std::fs;
    use std::str::FromStr;

    const FINGERPRINT: &str = "SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+Y";

    fn path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "kmux-key-command-{}-{name}.toml",
            std::process::id()
        ))
    }

    #[test]
    fn flag_mode_requires_complete_key_data_and_persists_multiple_scopes() {
        let path = path("flags");
        let mut document = ConfigDocument::empty();
        document
            .add_agent(AgentName::new("work").unwrap(), "/tmp/work.sock".into())
            .unwrap();
        ConfigStore::save(&path, &document).unwrap();
        let config = Config::discover(Some(&path)).unwrap();

        assert!(
            add(
                &config,
                "deploy".to_owned(),
                Some("work".to_owned()),
                None,
                None,
                vec![],
                vec![],
            )
            .is_err()
        );
        for (agent, fingerprint, scopes, tags) in [
            (None, Some(FINGERPRINT.to_owned()), vec![], vec![]),
            (None, None, vec!["company".to_owned()], vec![]),
            (None, None, vec![], vec!["provider=aws".to_owned()]),
        ] {
            assert!(
                add(
                    &config,
                    "incomplete".to_owned(),
                    agent,
                    fingerprint,
                    None,
                    scopes,
                    tags
                )
                .is_err()
            );
        }
        assert!(
            add_with(
                &config,
                KeyAddRequest {
                    alias: "comment-only".to_owned(),
                    agent: None,
                    fingerprint: None,
                    comment: Some("metadata".to_owned()),
                    scopes: vec![],
                    tags: vec![],
                },
                &FakePrompter { confirmed: true },
                |_| panic!("comment is a data flag and must not invoke the wizard"),
            )
            .is_err()
        );
        add(
            &config,
            "deploy".to_owned(),
            Some("work".to_owned()),
            Some(FINGERPRINT.to_owned()),
            Some("Production deployment key".to_owned()),
            vec!["company/production".to_owned(), "company/backup".to_owned()],
            vec!["provider=aws".to_owned()],
        )
        .unwrap();
        let loaded = ConfigStore::load(&path).unwrap().validate().unwrap();
        let entry = loaded.catalog().entries().next().unwrap();
        assert_eq!(entry.scopes().len(), 2);
        assert_eq!(entry.comment(), Some("Production deployment key"));
        assert_eq!(
            entry.tags().get("provider").map(String::as_str),
            Some("aws")
        );
        assert!(
            add(
                &config,
                "other".to_owned(),
                Some("work".to_owned()),
                Some(FINGERPRINT.to_owned()),
                None,
                vec![],
                vec![],
            )
            .is_err()
        );
        assert!(
            add(
                &config,
                "unknown-agent".to_owned(),
                Some("missing".to_owned()),
                Some("SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+A".to_owned()),
                None,
                vec![],
                vec![],
            )
            .is_err()
        );
        assert!(
            add(
                &config,
                "bad-fingerprint".to_owned(),
                Some("work".to_owned()),
                Some("SHA256:not-a-fingerprint".to_owned()),
                None,
                vec![],
                vec![],
            )
            .is_err()
        );
        assert!(
            add(
                &config,
                "duplicate-tag".to_owned(),
                Some("work".to_owned()),
                Some("SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+A".to_owned()),
                None,
                vec![],
                vec!["provider=aws".to_owned(), "provider=gcp".to_owned()],
            )
            .is_err()
        );
        remove(&config, "deploy".to_owned(), true).unwrap();
        assert!(
            ConfigStore::load(&path)
                .unwrap()
                .validate()
                .unwrap()
                .catalog()
                .entries()
                .next()
                .is_none()
        );
        fs::remove_file(path).unwrap();
    }

    struct FakePrompter {
        confirmed: bool,
    }

    struct FakeConfirmation {
        terminal: bool,
        confirmed: bool,
    }

    impl KeyRemovalConfirmation for FakeConfirmation {
        fn is_terminal(&self) -> bool {
            self.terminal
        }

        fn confirm(&self, _: &KeyAlias) -> Result<bool, Box<dyn std::error::Error>> {
            Ok(self.confirmed)
        }
    }

    impl KeyPrompter for FakePrompter {
        fn select_agent(
            &self,
            agents: &[AgentName],
        ) -> Result<AgentName, Box<dyn std::error::Error>> {
            Ok(agents[0].clone())
        }

        fn select_identity(
            &self,
            identities: &[Identity],
        ) -> Result<Identity, Box<dyn std::error::Error>> {
            Ok(identities[0].clone())
        }

        fn scopes(&self) -> Result<String, Box<dyn std::error::Error>> {
            Ok("company/production,company/backup".to_owned())
        }

        fn tags(&self) -> Result<String, Box<dyn std::error::Error>> {
            Ok("provider=aws".to_owned())
        }

        fn confirm(
            &self,
            _: &KeyAlias,
            _: &AgentName,
            _: &Identity,
        ) -> Result<bool, Box<dyn std::error::Error>> {
            Ok(self.confirmed)
        }
    }

    #[test]
    fn interactive_key_creation_uses_public_identities_from_an_injected_source() {
        let mut document = ConfigDocument::empty();
        document
            .add_agent(AgentName::new("work").unwrap(), "/tmp/work.sock".into())
            .unwrap();
        let identity = Identity {
            key_blob: vec![1, 2, 3],
            fingerprint: Fingerprint::from_str(FINGERPRINT).unwrap(),
            comment: Some("deploy key".to_owned()),
        };
        let entry = interactive_entry_with(
            &document.validate().unwrap(),
            KeyAlias::new("deploy").unwrap(),
            &FakePrompter { confirmed: true },
            |_| Ok(vec![identity.clone()]),
        )
        .unwrap();
        assert_eq!(entry.fingerprint().as_str(), FINGERPRINT);
        assert_eq!(entry.comment(), Some("deploy key"));
        assert_eq!(entry.scopes().len(), 2);
        assert_eq!(
            entry.tags().get("provider").map(String::as_str),
            Some("aws")
        );
    }

    #[test]
    fn wizard_rejects_missing_agents_and_identities() {
        let empty = ConfigDocument::empty();
        let error = interactive_entry_with(
            &empty.validate().unwrap(),
            KeyAlias::new("deploy").unwrap(),
            &InquireKeyPrompter,
            |_| Ok(vec![]),
        )
        .unwrap_err();
        assert!(error.to_string().contains("no configured agents"));

        let mut document = ConfigDocument::empty();
        document
            .add_agent(AgentName::new("work").unwrap(), "/tmp/work.sock".into())
            .unwrap();
        let error = interactive_entry_with(
            &document.validate().unwrap(),
            KeyAlias::new("deploy").unwrap(),
            &InquireKeyPrompter,
            |_| Ok(vec![]),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("selected agent has no public identities")
        );
    }

    #[test]
    fn cancelled_wizard_does_not_persist_a_key() {
        let path = path("cancelled-wizard");
        let mut document = ConfigDocument::empty();
        document
            .add_agent(AgentName::new("work").unwrap(), "/tmp/work.sock".into())
            .unwrap();
        ConfigStore::save(&path, &document).unwrap();
        let config = Config::discover(Some(&path)).unwrap();
        let identity = Identity {
            key_blob: vec![1],
            fingerprint: Fingerprint::from_str(FINGERPRINT).unwrap(),
            comment: None,
        };
        assert!(
            add_with(
                &config,
                KeyAddRequest {
                    alias: "deploy".to_owned(),
                    agent: None,
                    fingerprint: None,
                    comment: None,
                    scopes: vec![],
                    tags: vec![],
                },
                &FakePrompter { confirmed: false },
                |_| Ok(vec![identity]),
            )
            .is_err()
        );
        assert!(
            ConfigStore::load(&path)
                .unwrap()
                .validate()
                .unwrap()
                .catalog()
                .entries()
                .next()
                .is_none()
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn key_removal_requires_confirmation_unless_yes_is_provided() {
        let path = path("confirmation");
        let mut document = ConfigDocument::empty();
        document
            .add_agent(AgentName::new("work").unwrap(), "/tmp/work.sock".into())
            .unwrap();
        ConfigStore::save(&path, &document).unwrap();
        let config = Config::discover(Some(&path)).unwrap();
        add(
            &config,
            "deploy".to_owned(),
            Some("work".to_owned()),
            Some(FINGERPRINT.to_owned()),
            None,
            vec![],
            vec![],
        )
        .unwrap();
        assert!(
            remove_with(
                &config,
                "deploy".to_owned(),
                false,
                &FakeConfirmation {
                    terminal: false,
                    confirmed: true,
                },
            )
            .is_err()
        );
        remove_with(
            &config,
            "deploy".to_owned(),
            false,
            &FakeConfirmation {
                terminal: true,
                confirmed: false,
            },
        )
        .unwrap();
        assert!(
            ConfigStore::load(&path)
                .unwrap()
                .validate()
                .unwrap()
                .catalog()
                .entries()
                .next()
                .is_some()
        );
        remove(&config, "deploy".to_owned(), true).unwrap();
        assert!(remove(&config, "missing".to_owned(), true).is_err());
        fs::remove_file(path).unwrap();
    }
}
