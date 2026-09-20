use kmux::catalog::{KeyQuery, QueryMatch};
use kmux::config::Config;
use std::collections::BTreeSet;

pub fn print_keys(
    config: &Config,
    query: &KeyQuery,
) -> Result<(), kmux::selection::SelectionError> {
    kmux::selection::validate_agent(config, query)?;
    for line in key_lines(config, query) {
        println!("{line}");
    }
    Ok(())
}

fn key_lines(config: &Config, query: &KeyQuery) -> Vec<String> {
    matching_keys(config, query)
        .into_iter()
        .map(|matched| {
            let entry = matched.entry;
            let scopes = entry
                .scopes()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "{}\t{}\t{}\t{scopes}",
                entry.alias(),
                entry.fingerprint(),
                entry.agent()
            )
        })
        .collect()
}

fn matching_keys<'a>(config: &'a Config, query: &KeyQuery) -> Vec<QueryMatch<'a>> {
    config.catalog().query_static(query)
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
    use super::{key_lines, listed_scopes, matching_keys};
    use kmux::catalog::KeyQuery;
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

    #[test]
    fn keys_apply_static_filters_without_contacting_an_unavailable_agent() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        fs::write(
            &path,
            "version = 1\n[agents.primary]\ntype = \"unix\"\nsocket = \"/missing/agent.sock\"\n[keys.aws-production]\nfingerprint = \"SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+Y\"\nagent = \"primary\"\nscopes = [\"hogix/production\"]\ntags = { provider = \"aws\", environment = \"production\" }\ncomment = \"AWS production\"\n[keys.unscoped]\nfingerprint = \"SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU\"\nagent = \"primary\"\ntags = { provider = \"gcp\" }\n",
        )
        .unwrap();
        let config = Config::load(&path).unwrap();

        let matching = |scope, comment, key, fingerprint, tags: Vec<String>, agent| {
            matching_keys(
                &config,
                &KeyQuery::from_values(scope, comment, key, fingerprint, tags, agent).unwrap(),
            )
            .into_iter()
            .map(|matched| matched.entry.alias().to_string())
            .collect::<Vec<_>>()
        };

        assert_eq!(
            matching(None, None, None, None, vec![], None),
            ["aws-production", "unscoped"]
        );
        assert_eq!(
            matching(Some("hogix".to_owned()), None, None, None, vec![], None),
            ["aws-production"]
        );
        assert_eq!(
            matching(None, Some("AWS".to_owned()), None, None, vec![], None),
            ["aws-production"]
        );
        assert_eq!(
            matching(
                None,
                None,
                Some("aws-production".to_owned()),
                None,
                vec![],
                None
            ),
            ["aws-production"]
        );
        assert_eq!(
            matching(None, None, None, Some("Wda9mr6".to_owned()), vec![], None),
            ["aws-production"]
        );
        assert_eq!(
            matching(
                None,
                None,
                None,
                None,
                vec!["provider=gcp".to_owned()],
                None
            ),
            ["unscoped"]
        );
        assert_eq!(
            matching(None, None, None, None, vec![], Some("primary".to_owned())),
            ["aws-production", "unscoped"]
        );
        assert_eq!(
            matching(
                Some("hogix".to_owned()),
                Some("production".to_owned()),
                None,
                None,
                vec!["environment=production".to_owned()],
                Some("primary".to_owned())
            ),
            ["aws-production"]
        );
        assert!(matching(None, Some("missing".to_owned()), None, None, vec![], None).is_empty());
        assert_eq!(
            key_lines(&config, &KeyQuery::default()),
            [
                "aws-production\tSHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+Y\tprimary\thogix/production",
                "unscoped\tSHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU\tprimary\t"
            ]
        );
    }

    #[test]
    fn scopes_ignore_unscoped_keys() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        fs::write(
            &path,
            "version = 1\n[agents.primary]\ntype = \"unix\"\nsocket = \"/missing/agent.sock\"\n[keys.unscoped]\nfingerprint = \"SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU\"\nagent = \"primary\"\n[keys.scoped]\nfingerprint = \"SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+Y\"\nagent = \"primary\"\nscopes = [\"hogix/production\"]\n",
        )
        .unwrap();
        let config = Config::load(&path).unwrap();

        assert_eq!(
            listed_scopes(&config)
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["hogix", "hogix/production"]
        );
    }
}
