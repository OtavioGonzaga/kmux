use crate::cli::OutputFormat;
use kmux::agent::{AgentName, UnixSocketAgent, UpstreamAgent};
use kmux::catalog::{Identity, KeyAlias};
use kmux::config::Config;
use kmux::scope::ScopePath;
use std::collections::BTreeSet;

pub fn import_agent(
    config: &Config,
    name: &str,
    scope: ScopePath,
    format: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let name = AgentName::new(name)?;
    let definition = config.agents().get(&name).ok_or("unknown agent")?;
    let identities = UnixSocketAgent::new(definition.socket().to_owned()).identities()?;
    let aliases = suggested_aliases(
        &identities,
        config
            .catalog()
            .entries()
            .map(|entry| entry.alias().clone()),
    );
    match format {
        OutputFormat::Yaml => {
            println!("keys:");
            for (alias, identity) in aliases.iter().zip(&identities) {
                if let Some(comment) = identity
                    .comment
                    .as_deref()
                    .filter(|comment| !comment.contains(['\n', '\r']))
                {
                    println!("  # {comment}");
                }
                println!(
                    "  {alias}:\n    fingerprint: \"{}\"\n    agent: {}\n    scopes: [\"{}\"]",
                    identity.fingerprint, name, scope
                );
            }
        }
        OutputFormat::Json => {
            let keys = aliases.iter().zip(&identities).map(|(alias, identity)| (alias.to_string(), serde_json::json!({"fingerprint": identity.fingerprint.as_str(), "agent": name.as_str(), "scopes": [scope.to_string()]}))).collect::<serde_json::Map<_, _>>();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({"keys": keys}))?
            );
        }
        OutputFormat::Toml => {
            for (alias, identity) in aliases.iter().zip(&identities) {
                if let Some(comment) = identity
                    .comment
                    .as_deref()
                    .filter(|comment| !comment.contains(['\n', '\r']))
                {
                    println!("# {comment}");
                }
                println!(
                    "[keys.{alias}]\nfingerprint = \"{}\"\nagent = \"{}\"\nscopes = [\"{}\"]",
                    identity.fingerprint, name, scope
                );
            }
        }
    }
    Ok(())
}

fn suggested_aliases(
    identities: &[Identity],
    existing: impl IntoIterator<Item = KeyAlias>,
) -> Vec<KeyAlias> {
    let mut used = existing.into_iter().collect::<BTreeSet<_>>();
    identities
        .iter()
        .enumerate()
        .map(|(index, identity)| {
            let base = identity
                .comment
                .as_deref()
                .and_then(comment_alias)
                .unwrap_or_else(|| format!("identity-{}", index + 1));
            let mut suffix = 1;
            loop {
                let candidate = if suffix == 1 {
                    base.clone()
                } else {
                    format!("{base}-{suffix}")
                };
                let alias = KeyAlias::new(candidate).expect("generated aliases are valid");
                if used.insert(alias.clone()) {
                    return alias;
                }
                suffix += 1;
            }
        })
        .collect()
}

fn comment_alias(comment: &str) -> Option<String> {
    let normalized = comment
        .bytes()
        .fold(String::new(), |mut alias, byte| {
            if byte.is_ascii_alphanumeric() {
                alias.push((byte as char).to_ascii_lowercase());
            } else if !alias.is_empty() && !alias.ends_with('-') {
                alias.push('-');
            }
            alias
        })
        .trim_matches('-')
        .to_owned();
    (!normalized.is_empty()).then_some(normalized)
}

#[cfg(test)]
mod tests {
    use super::{comment_alias, suggested_aliases};
    use kmux::catalog::{Fingerprint, Identity, KeyAlias};
    use std::str::FromStr;

    fn identity(comment: Option<&str>) -> Identity {
        Identity {
            key_blob: vec![],
            fingerprint: Fingerprint::from_str(
                "SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+Y",
            )
            .unwrap(),
            comment: comment.map(str::to_owned),
        }
    }

    #[test]
    fn comments_produce_deterministic_valid_aliases() {
        assert_eq!(
            comment_alias("AWS Lightsail VPS Hogix Debian-2 deploy"),
            Some("aws-lightsail-vps-hogix-debian-2-deploy".to_owned())
        );
        assert_eq!(
            suggested_aliases(
                &[identity(Some("Deploy Key")), identity(None)],
                [] as [KeyAlias; 0]
            )
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
            ["deploy-key", "identity-2"]
        );
    }

    #[test]
    fn duplicate_suggestions_receive_deterministic_suffixes() {
        let aliases = suggested_aliases(
            &[identity(Some("Deploy Key")), identity(Some("deploy-key"))],
            [KeyAlias::new("deploy-key").unwrap()],
        );
        assert_eq!(
            aliases.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["deploy-key-2", "deploy-key-3"]
        );
    }
}
