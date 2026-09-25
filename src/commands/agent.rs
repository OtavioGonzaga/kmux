use kmux::agent::AgentName;
use kmux::config::ConfigPath;
use kmux::management::{AddAgentRequest, add_agent, remove_agent};
use std::path::PathBuf;

pub fn add(
    path: &ConfigPath,
    name: String,
    socket: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let name = AgentName::new(name)?;
    add_agent(path.as_path(), AddAgentRequest { name, socket })?;
    Ok(())
}

pub fn remove(path: &ConfigPath, name: String) -> Result<(), Box<dyn std::error::Error>> {
    let name = AgentName::new(name)?;
    remove_agent(path.as_path(), name)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{add, remove};
    use kmux::agent::AgentName;
    use kmux::catalog::{Fingerprint, KeyAlias, KeyEntry};
    use kmux::config::{Config, ConfigDocument, ConfigStore};
    use std::fs;
    use std::str::FromStr;

    fn path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "kmux-agent-command-{}-{name}.toml",
            std::process::id()
        ))
    }

    #[test]
    fn adds_and_removes_agents() {
        let path = path("add-remove");
        ConfigStore::save(&path, &ConfigDocument::empty()).unwrap();
        let config = Config::discover(Some(&path)).unwrap();
        add(&config, "work".to_owned(), "/tmp/work.sock".into()).unwrap();
        assert!(
            ConfigStore::load(&path)
                .unwrap()
                .validate()
                .unwrap()
                .agents()
                .len()
                == 1
        );
        assert!(add(&config, "work".to_owned(), "/tmp/work.sock".into()).is_err());
        remove(&config, "work".to_owned()).unwrap();
        assert!(
            ConfigStore::load(&path)
                .unwrap()
                .validate()
                .unwrap()
                .agents()
                .is_empty()
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_removing_an_agent_referenced_by_a_key() {
        let path = path("referenced");
        let mut document = ConfigDocument::empty();
        let agent = AgentName::new("work").unwrap();
        document
            .add_agent(agent.clone(), "/tmp/work.sock".into())
            .unwrap();
        document
            .add_key(KeyEntry::new(
                KeyAlias::new("deploy").unwrap(),
                Fingerprint::from_str("SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+Y")
                    .unwrap(),
                agent,
                [],
                Default::default(),
            ))
            .unwrap();
        ConfigStore::save(&path, &document).unwrap();
        let config = Config::discover(Some(&path)).unwrap();
        let error = remove(&config, "work".to_owned()).unwrap_err();
        assert!(error.to_string().contains("deploy"));
        fs::remove_file(path).unwrap();
    }
}
