use crate::cli::OutputFormat;
use crate::commands::key::parse_tags;
use kmux::agent::{AgentName, UnixSocketAgent, UpstreamAgent};
use kmux::catalog::{Identity, KeyAlias, KeyEntry};
use kmux::config::{Config, ConfigDocument, ConfigPath, ConfigStore};
use kmux::scope::ScopePath;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

struct ImportedKey {
    alias: KeyAlias,
    identity: Identity,
}

struct ImportPlan {
    additions: Vec<ImportedKey>,
    already_configured: usize,
    document: ConfigDocument,
    scopes: Vec<ScopePath>,
    tags: BTreeMap<String, String>,
}

pub fn import_agent(
    path: &ConfigPath,
    name: &str,
    scopes: Vec<String>,
    tags: Vec<String>,
    dry_run: bool,
    stdout: bool,
    format: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let document = ConfigStore::load(path.as_path())?;
    let config = document.validate()?;
    let name = AgentName::new(name)?;
    let definition = config
        .agents()
        .get(&name)
        .ok_or_else(|| format!("unknown agent '{name}'"))?;
    let identities = UnixSocketAgent::new(definition.socket().to_owned()).identities()?;
    let plan = plan_import(&document, &config, &name, identities, scopes, tags)?;

    if stdout {
        print!(
            "{}",
            render_import(&plan.additions, &name, &plan.scopes, &plan.tags, format)?
        );
        return Ok(());
    }

    if !dry_run && !plan.additions.is_empty() {
        ConfigStore::save(path.as_path(), &plan.document)?;
    }
    print_summary(&name, &plan, dry_run);
    Ok(())
}

fn plan_import(
    document: &ConfigDocument,
    config: &Config,
    name: &AgentName,
    identities: Vec<Identity>,
    scopes: Vec<String>,
    tags: Vec<String>,
) -> Result<ImportPlan, Box<dyn std::error::Error>> {
    let mut known_fingerprints = config
        .catalog()
        .entries()
        .map(|entry| entry.fingerprint().clone())
        .collect::<BTreeSet<_>>();
    let mut new_identities = Vec::new();
    let mut already_configured = 0;
    for identity in identities {
        if !known_fingerprints.insert(identity.fingerprint.clone()) {
            already_configured += 1;
        } else {
            new_identities.push(identity);
        }
    }

    let aliases = suggested_aliases(
        &new_identities,
        config
            .catalog()
            .entries()
            .map(|entry| entry.alias().clone()),
    );
    let scopes = scopes
        .into_iter()
        .map(|scope| ScopePath::from_str(&scope))
        .collect::<Result<Vec<_>, _>>()?;
    let tags = parse_tags(tags)?;
    let mut candidate = document.clone();
    let additions = aliases
        .into_iter()
        .zip(new_identities)
        .map(|(alias, identity)| {
            let entry = KeyEntry::new(
                alias.clone(),
                identity.fingerprint.clone(),
                name.clone(),
                scopes.clone(),
                tags.clone(),
            )
            .with_comment(identity.comment.clone());
            candidate.add_key(entry)?;
            Ok(ImportedKey { alias, identity })
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    candidate.validate()?;

    Ok(ImportPlan {
        additions,
        already_configured,
        document: candidate,
        scopes,
        tags,
    })
}

fn print_summary(name: &AgentName, plan: &ImportPlan, dry_run: bool) {
    println!("Importing identities from '{name}'");
    if dry_run {
        println!("(dry run; no changes written)");
    }
    for imported in &plan.additions {
        println!("+ {}\n  {}", imported.alias, imported.identity.fingerprint);
    }
    if plan.already_configured > 0 {
        println!("= {} already configured", plan.already_configured);
    }
    println!(
        "{} key{} {}, {} already configured",
        plan.additions.len(),
        if plan.additions.len() == 1 { "" } else { "s" },
        if dry_run { "would be added" } else { "added" },
        plan.already_configured
    );
}

#[derive(Serialize)]
struct SnippetDocument {
    keys: BTreeMap<String, SnippetKey>,
}

#[derive(Serialize)]
struct SnippetKey {
    fingerprint: String,
    agent: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    scopes: Vec<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    tags: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
}

fn render_import(
    additions: &[ImportedKey],
    name: &AgentName,
    scopes: &[ScopePath],
    tags: &BTreeMap<String, String>,
    format: OutputFormat,
) -> Result<String, Box<dyn std::error::Error>> {
    let keys = additions
        .iter()
        .map(|imported| {
            (
                imported.alias.to_string(),
                SnippetKey {
                    fingerprint: imported.identity.fingerprint.to_string(),
                    agent: name.to_string(),
                    scopes: scopes.iter().map(ToString::to_string).collect(),
                    tags: tags.clone(),
                    comment: imported
                        .identity
                        .comment
                        .clone()
                        .filter(|comment| !comment.is_empty()),
                },
            )
        })
        .collect();
    let document = SnippetDocument { keys };
    let output = match format {
        OutputFormat::Toml => toml::to_string_pretty(&document)?,
        OutputFormat::Yaml => serde_saphyr::to_string(&document)?,
        OutputFormat::Json => serde_json::to_string_pretty(&document)?,
    };
    Ok(format!("{output}\n"))
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
    use super::{comment_alias, import_agent, plan_import, render_import, suggested_aliases};
    use crate::cli::OutputFormat;
    use kmux::agent::AgentName;
    use kmux::catalog::{Fingerprint, Identity, KeyAlias};
    use kmux::config::{Config, ConfigDocument, ConfigStore};
    use kmux::scope::ScopePath;
    use std::collections::BTreeMap;
    use std::fs;
    use std::str::FromStr;

    fn identity(comment: Option<&str>, fingerprint: &str) -> Identity {
        Identity {
            key_blob: vec![],
            fingerprint: Fingerprint::from_str(fingerprint).unwrap(),
            comment: comment.map(str::to_owned),
        }
    }

    const FIRST: &str = "SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+Y";
    const SECOND: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn comments_produce_deterministic_valid_aliases() {
        assert_eq!(
            comment_alias("AWS Lightsail VPS Hogix Debian-2 deploy"),
            Some("aws-lightsail-vps-hogix-debian-2-deploy".to_owned())
        );
        assert_eq!(
            suggested_aliases(
                &[identity(Some("Deploy Key"), FIRST), identity(None, SECOND)],
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
            &[
                identity(Some("Deploy Key"), FIRST),
                identity(Some("deploy-key"), SECOND),
            ],
            [KeyAlias::new("deploy-key").unwrap()],
        );
        assert_eq!(
            aliases.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["deploy-key-2", "deploy-key-3"]
        );
    }

    #[test]
    fn unusable_comments_use_deterministic_fallbacks() {
        let aliases = suggested_aliases(
            &[
                identity(Some("  Multi___separator!!! Key  "), FIRST),
                identity(Some(""), SECOND),
                identity(Some("---"), FIRST),
            ],
            [] as [KeyAlias; 0],
        );
        assert_eq!(
            aliases.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["multi-separator-key", "identity-2", "identity-3"]
        );
    }

    #[test]
    fn rendered_snippets_are_valid_in_each_format() {
        let identities = [identity(Some("public key"), FIRST)];
        let aliases = suggested_aliases(&identities, [] as [KeyAlias; 0]);
        let name = AgentName::new("agent").unwrap();
        let imported = aliases
            .into_iter()
            .zip(identities)
            .map(|(alias, identity)| super::ImportedKey { alias, identity })
            .collect::<Vec<_>>();
        let scope = ScopePath::from_str("company").unwrap();
        let tags = BTreeMap::from([(String::from("source"), String::from("test"))]);
        let toml = render_import(
            &imported,
            &name,
            std::slice::from_ref(&scope),
            &tags,
            OutputFormat::Toml,
        )
        .unwrap();
        let _: toml::Value = toml::from_str(&toml).unwrap();
        assert!(toml.contains("company"));
        assert!(toml.contains("source = \"test\""));
        assert!(toml.contains("comment = \"public key\""));
        let yaml =
            render_import(&imported, &name, &[], &BTreeMap::new(), OutputFormat::Yaml).unwrap();
        assert!(!yaml.contains("scopes:"));
        assert!(!yaml.contains("tags:"));
        let _: serde_json::Value = serde_saphyr::from_str(&yaml).unwrap();
        let json =
            render_import(&imported, &name, &[], &BTreeMap::new(), OutputFormat::Json).unwrap();
        let _: serde_json::Value = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn planner_skips_existing_fingerprints_and_applies_common_metadata() {
        let mut document = ConfigDocument::empty();
        let agent = AgentName::new("agent").unwrap();
        document
            .add_agent(agent.clone(), "/tmp/agent.sock".into())
            .unwrap();
        document
            .add_key(kmux::catalog::KeyEntry::new(
                KeyAlias::new("existing").unwrap(),
                Fingerprint::from_str(FIRST).unwrap(),
                agent.clone(),
                [],
                BTreeMap::new(),
            ))
            .unwrap();
        let config = document.validate().unwrap();
        let plan = plan_import(
            &document,
            &config,
            &agent,
            vec![
                identity(Some("existing comment"), FIRST),
                identity(Some("New Key"), SECOND),
            ],
            vec!["company".to_owned(), "production".to_owned()],
            vec!["source=test".to_owned()],
        )
        .unwrap();

        assert_eq!(plan.already_configured, 1);
        assert_eq!(plan.additions.len(), 1);
        assert_eq!(plan.additions[0].alias.as_str(), "new-key");
        let planned = plan.document.validate().unwrap();
        let entry = planned
            .catalog()
            .entries()
            .find(|entry| entry.alias().as_str() == "new-key")
            .unwrap();
        assert_eq!(entry.scopes().len(), 2);
        assert_eq!(entry.tags().get("source").map(String::as_str), Some("test"));
    }

    #[test]
    fn planner_rejects_invalid_tags_before_mutating_the_document() {
        let agent = AgentName::new("agent").unwrap();
        let mut document = ConfigDocument::empty();
        document
            .add_agent(agent.clone(), "/tmp/agent.sock".into())
            .unwrap();
        let config = document.validate().unwrap();
        assert!(
            plan_import(
                &document,
                &config,
                &agent,
                vec![identity(Some("New Key"), FIRST)],
                vec![],
                vec!["invalid".to_owned()],
            )
            .is_err()
        );
        assert!(
            document
                .validate()
                .unwrap()
                .catalog()
                .entries()
                .next()
                .is_none()
        );
    }

    #[test]
    fn planner_accepts_zero_identities_without_changes() {
        let mut document = ConfigDocument::empty();
        let agent = AgentName::new("agent").unwrap();
        document
            .add_agent(agent.clone(), "/tmp/agent.sock".into())
            .unwrap();
        let config = document.validate().unwrap();
        let plan = plan_import(&document, &config, &agent, vec![], vec![], vec![]).unwrap();
        assert!(plan.additions.is_empty());
        assert_eq!(plan.already_configured, 0);
    }

    #[test]
    fn import_rejects_unknown_and_unreachable_agents() {
        let path = std::env::temp_dir().join(format!(
            "kmux-import-errors-{}-test.toml",
            std::process::id()
        ));
        let mut document = ConfigDocument::empty();
        document
            .add_agent(
                AgentName::new("offline").unwrap(),
                "/tmp/kmux-no-agent.sock".into(),
            )
            .unwrap();
        ConfigStore::save(&path, &document).unwrap();
        let config = Config::discover(Some(&path)).unwrap();
        assert!(
            import_agent(
                &config,
                "missing",
                vec![],
                vec![],
                false,
                false,
                OutputFormat::Toml
            )
            .is_err()
        );
        assert!(
            import_agent(
                &config,
                "offline",
                vec![],
                vec![],
                false,
                false,
                OutputFormat::Toml
            )
            .is_err()
        );
        fs::remove_file(path).unwrap();
    }
}
