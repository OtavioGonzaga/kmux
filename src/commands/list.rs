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
    use kmux::config::Config;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn scopes_include_derived_ancestors_in_order() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("kmux-list-{unique}.yaml"));
        fs::write(
            &path,
            "version: 1\nagents:\n  agent:\n    type: unix\n    socket: /tmp/agent.sock\nkeys:\n  key:\n    fingerprint: SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+Y\n    agent: agent\n    scopes: [hogix/postgres-walg/production]\n",
        )
        .unwrap();
        let config = Config::load(&path).unwrap();
        fs::remove_file(path).unwrap();
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
