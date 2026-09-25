use crate::cli::OutputFormat;
use crate::commands::key::parse_tags;
use ::kmux::management::{self, ImportPlan, ImportRequest};
use kmux::agent::{AgentName, UnixSocketAgent, UpstreamAgent};
use kmux::catalog::KeyEntry;
use kmux::config::{ConfigPath, ConfigStore};
use kmux::scope::ScopePath;
use serde::Serialize;
use std::collections::BTreeMap;
use std::str::FromStr;

pub fn import_agent(
    path: &ConfigPath,
    name: &str,
    scopes: Vec<String>,
    tags: Vec<String>,
    dry_run: bool,
    stdout: bool,
    format: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let snapshot = ConfigStore::load_versioned(path.as_path())?;
    let config = snapshot.document().validate()?;
    let name = AgentName::new(name)?;
    let definition = config.agents().get(&name).ok_or_else(|| {
        format!("unknown agent '{name}', run 'kmux agent add --socket /path/to/agent.sock {name}'")
    })?;
    let identities = UnixSocketAgent::new(definition.socket().to_owned()).identities()?;
    let scopes = scopes
        .into_iter()
        .map(|scope| ScopePath::from_str(&scope))
        .collect::<Result<Vec<_>, _>>()?;
    let tags = parse_tags(tags)?;
    let plan = management::plan_import(
        snapshot,
        ImportRequest {
            agent: name.clone(),
            identities: identities.clone(),
            scopes,
            tags,
        },
    )?;

    if stdout {
        print!("{}", render_import(plan.additions(), format)?);
        return Ok(());
    }

    if !dry_run && !plan.additions().is_empty() {
        management::apply_import(&plan)?;
    }
    print_summary(&name, &plan, dry_run);
    Ok(())
}

fn print_summary(name: &AgentName, plan: &ImportPlan, dry_run: bool) {
    println!("Importing identities from '{name}'");
    if dry_run {
        println!("(dry run; no changes written)");
    }
    for entry in plan.additions() {
        println!("+ {}\n  {}", entry.alias(), entry.fingerprint());
    }
    if plan.already_configured() > 0 {
        println!("= {} already configured", plan.already_configured());
    }
    println!(
        "{} key{} {}, {} already configured",
        plan.additions().len(),
        if plan.additions().len() == 1 { "" } else { "s" },
        if dry_run { "would be added" } else { "added" },
        plan.already_configured()
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
    additions: &[KeyEntry],
    format: OutputFormat,
) -> Result<String, Box<dyn std::error::Error>> {
    let keys = additions
        .iter()
        .map(|imported| {
            (
                imported.alias().to_string(),
                SnippetKey {
                    fingerprint: imported.fingerprint().to_string(),
                    agent: imported.agent().to_string(),
                    scopes: imported.scopes().iter().map(ToString::to_string).collect(),
                    tags: imported.tags().clone(),
                    comment: imported.comment().map(str::to_owned),
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

#[cfg(test)]
mod tests {
    use super::{import_agent, render_import};
    use crate::cli::OutputFormat;
    use kmux::agent::AgentName;
    use kmux::catalog::{Fingerprint, KeyEntry};
    use kmux::config::{ConfigDocument, ConfigStore};
    use kmux::scope::ScopePath;
    use std::collections::BTreeMap;
    use std::str::FromStr;

    #[test]
    fn rendered_snippets_are_valid_in_each_format() {
        let entry = KeyEntry::new(
            kmux::catalog::KeyAlias::new("public-key").unwrap(),
            Fingerprint::from_str("SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+Y").unwrap(),
            AgentName::new("agent").unwrap(),
            [ScopePath::from_str("company").unwrap()],
            BTreeMap::from([(String::from("source"), String::from("test"))]),
        )
        .with_comment(Some("public key".to_owned()));
        let toml = render_import(std::slice::from_ref(&entry), OutputFormat::Toml).unwrap();
        let _: toml::Value = toml::from_str(&toml).unwrap();
        assert!(toml.contains("company"));
        assert!(toml.contains("source = \"test\""));
        assert!(toml.contains("comment = \"public key\""));
        let yaml = render_import(std::slice::from_ref(&entry), OutputFormat::Yaml).unwrap();
        assert!(serde_saphyr::from_str::<serde_json::Value>(&yaml).is_ok());
        let json = render_import(&[entry], OutputFormat::Json).unwrap();
        assert!(serde_json::from_str::<serde_json::Value>(&json).is_ok());
    }

    #[test]
    fn import_rejects_unknown_and_unreachable_agents() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        let mut document = ConfigDocument::empty();
        document
            .add_agent(
                AgentName::new("offline").unwrap(),
                directory.path().join("missing.sock"),
            )
            .unwrap();
        ConfigStore::save(&path, &document).unwrap();
        let config = kmux::config::Config::discover(Some(&path)).unwrap();
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
    }
}
