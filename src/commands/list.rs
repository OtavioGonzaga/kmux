use kmux::config::Config;
use std::collections::BTreeSet;

pub fn print_keys(config: &Config) {
    for entry in config.catalog().entries() {
        let scopes = entry
            .scopes()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "{}\t{}\t{}\t{scopes}",
            entry.alias(),
            entry.fingerprint(),
            entry.agent()
        );
    }
}

pub fn print_scopes(config: &Config) {
    for scope in listed_scopes(config) {
        println!("{scope}");
    }
}

fn listed_scopes(config: &Config) -> BTreeSet<kmux::scope::ScopePath> {
    config
        .catalog()
        .entries()
        .flat_map(|entry| entry.scopes().iter().flat_map(|scope| scope.ancestors()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::listed_scopes;
    use kmux::agent::{AgentDefinition, AgentName};
    use kmux::catalog::{Fingerprint, KeyAlias, KeyCatalog, KeyEntry};
    use kmux::config::Config;
    use kmux::scope::ScopePath;
    use std::collections::BTreeMap;
    use std::str::FromStr;

    #[test]
    fn scopes_include_derived_ancestors_in_order() {
        let agent = AgentName::new("agent").unwrap();
        let entry = KeyEntry::new(
            KeyAlias::new("key").unwrap(),
            Fingerprint::from_str("SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+Y").unwrap(),
            agent.clone(),
            [ScopePath::from_str("hogix/postgres-walg/production").unwrap()],
            BTreeMap::new(),
        )
        .unwrap();
        let config = Config::from_parts(
            BTreeMap::from([(
                agent.clone(),
                AgentDefinition::new(agent, "/tmp/agent.sock").unwrap(),
            )]),
            KeyCatalog::from_entries([entry]).unwrap(),
        );
        assert_eq!(
            listed_scopes(&config)
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            [
                "hogix",
                "hogix/postgres-walg",
                "hogix/postgres-walg/production"
            ]
        );
    }
}
