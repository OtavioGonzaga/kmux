use crate::cli::KeysFormat;
use kmux::catalog::{KeyQuery, QueryMatch};
use kmux::config::Config;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, IsTerminal, Write};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, serde::Deserialize)]
struct KeyOutput {
    alias: String,
    fingerprint: String,
    agent: String,
    scopes: Vec<String>,
    tags: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
}

pub fn print_keys(
    config: &Config,
    query: &KeyQuery,
    format: KeysFormat,
    no_trunc: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    kmux::selection::validate_agent(config, query)?;
    let mut stdout = io::stdout();
    let terminal_width = if format == KeysFormat::Table && stdout.is_terminal() {
        rustix::termios::tcgetwinsize(&stdout)
            .ok()
            .map(|size| usize::from(size.ws_col))
            .filter(|width| *width > 0)
    } else {
        None
    };
    render_keys(
        &key_outputs(config, query),
        format,
        no_trunc,
        terminal_width,
        &mut stdout,
    )?;
    Ok(())
}

fn key_outputs(config: &Config, query: &KeyQuery) -> Vec<KeyOutput> {
    matching_keys(config, query)
        .into_iter()
        .map(|matched| {
            let entry = matched.entry;
            KeyOutput {
                alias: entry.alias().to_string(),
                fingerprint: entry.fingerprint().to_string(),
                agent: entry.agent().to_string(),
                scopes: entry.scopes().iter().map(ToString::to_string).collect(),
                tags: entry.tags().clone(),
                comment: entry.comment().map(str::to_owned),
            }
        })
        .collect()
}

fn render_keys<W: Write>(
    keys: &[KeyOutput],
    format: KeysFormat,
    no_trunc: bool,
    terminal_width: Option<usize>,
    out: &mut W,
) -> io::Result<()> {
    match format {
        KeysFormat::Table => render_table(keys, no_trunc, terminal_width, out),
        KeysFormat::Tsv => {
            for key in keys {
                writeln!(
                    out,
                    "{}\t{}\t{}\t{}",
                    key.alias,
                    key.fingerprint,
                    key.agent,
                    key.scopes.join(",")
                )?;
            }
            Ok(())
        }
        KeysFormat::Json => serde_json::to_writer_pretty(&mut *out, &KeysDocument { keys })
            .map_err(io::Error::other)
            .and_then(|()| writeln!(out)),
        KeysFormat::Yaml => serde_saphyr::to_string(&KeysDocument { keys })
            .map_err(io::Error::other)
            .and_then(|text| write!(out, "{text}")),
        KeysFormat::Toml => toml::to_string(&KeysDocument { keys })
            .map_err(io::Error::other)
            .and_then(|text| write!(out, "{text}")),
    }
}

#[derive(Serialize)]
struct KeysDocument<'a> {
    keys: &'a [KeyOutput],
}

fn render_table<W: Write>(
    keys: &[KeyOutput],
    no_trunc: bool,
    terminal_width: Option<usize>,
    out: &mut W,
) -> io::Result<()> {
    let rows = keys
        .iter()
        .map(|key| {
            [
                key.alias.clone(),
                key.agent.clone(),
                if key.scopes.is_empty() {
                    "-".to_owned()
                } else {
                    key.scopes.join(",")
                },
                if no_trunc || terminal_width.is_some() {
                    key.fingerprint.clone()
                } else {
                    truncate_fingerprint(&key.fingerprint, 18)
                },
            ]
        })
        .collect::<Vec<_>>();
    let headers = ["KEY", "AGENT", "SCOPES", "FINGERPRINT"];
    let mut widths = (0..4)
        .map(|column| {
            rows.iter()
                .map(|row| row[column].chars().count())
                .max()
                .unwrap_or(0)
                .max(headers[column].chars().count())
        })
        .collect::<Vec<_>>();
    if !no_trunc && let Some(terminal_width) = terminal_width {
        let mut overflow = widths
            .iter()
            .sum::<usize>()
            .saturating_add(6)
            .saturating_sub(terminal_width);
        for column in [2, 3, 0, 1] {
            let minimum = headers[column].chars().count();
            let reduction = overflow.min(widths[column].saturating_sub(minimum));
            widths[column] -= reduction;
            overflow -= reduction;
        }
    }
    for (index, header) in headers.iter().enumerate() {
        if index > 0 {
            write!(out, "  ")?;
        }
        if index == headers.len() - 1 {
            write!(out, "{header}")?;
        } else {
            write!(out, "{header:<width$}", width = widths[index])?;
        }
    }
    writeln!(out)?;
    for row in rows {
        for index in 0..4 {
            if index > 0 {
                write!(out, "  ")?;
            }
            let cell = if index == 3 && !no_trunc {
                truncate_fingerprint(&row[index], widths[index])
            } else if index != 3 {
                truncate_cell(&row[index], widths[index])
            } else {
                row[index].clone()
            };
            if index == 3 {
                write!(out, "{cell}")?;
            } else {
                write!(out, "{cell:<width$}", width = widths[index])?;
            }
        }
        writeln!(out)?;
    }
    Ok(())
}

fn truncate_fingerprint(value: &str, max_width: usize) -> String {
    const PREFIX: &str = "SHA256:";
    value.strip_prefix(PREFIX).map_or_else(
        || value.to_owned(),
        |digest| {
            let digest = digest.trim_end_matches('…');
            if value.chars().count() > max_width && max_width > PREFIX.len() {
                let visible = max_width - PREFIX.len() - 1;
                format!(
                    "{PREFIX}{}…",
                    digest.chars().take(visible).collect::<String>()
                )
            } else {
                value.to_owned()
            }
        },
    )
}

fn truncate_cell(value: &str, max_width: usize) -> String {
    if value.chars().count() <= max_width {
        return value.to_owned();
    }
    if max_width == 0 {
        return String::new();
    }
    format!("{}…", value.chars().take(max_width - 1).collect::<String>())
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
    use super::{key_outputs, listed_scopes, matching_keys, render_keys};
    use crate::cli::KeysFormat;
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
            {
                let mut output = Vec::new();
                render_keys(
                    &key_outputs(&config, &KeyQuery::default()),
                    KeysFormat::Tsv,
                    false,
                    None,
                    &mut output,
                )
                .unwrap();
                String::from_utf8(output).unwrap()
            },
            "aws-production\tSHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+Y\tprimary\thogix/production\nunscoped\tSHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU\tprimary\t\n"
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

    #[test]
    fn structured_formats_round_trip_full_metadata_and_empty_lists() {
        let key = super::KeyOutput {
            alias: "github".into(),
            fingerprint: "SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+Y".into(),
            agent: "bitwarden".into(),
            scopes: vec!["personal/github".into(), "company/team".into()],
            tags: std::collections::BTreeMap::from([("source.host".into(), "a=\"b".into())]),
            comment: Some("say \"hello\"\\today".into()),
        };
        for format in [KeysFormat::Json, KeysFormat::Yaml, KeysFormat::Toml] {
            let mut output = Vec::new();
            render_keys(std::slice::from_ref(&key), format, false, None, &mut output).unwrap();
            let output = String::from_utf8(output).unwrap();
            let document: serde_json::Value = match format {
                KeysFormat::Json => serde_json::from_str(&output).unwrap(),
                KeysFormat::Yaml => serde_saphyr::from_str(&output).unwrap(),
                KeysFormat::Toml => toml::from_str(&output).unwrap(),
                _ => unreachable!(),
            };
            assert_eq!(document["keys"][0]["fingerprint"], key.fingerprint);
            assert_eq!(document["keys"][0]["scopes"].as_array().unwrap().len(), 2);
            assert_eq!(document["keys"][0]["tags"]["source.host"], "a=\"b");
            assert_eq!(document["keys"][0]["comment"], "say \"hello\"\\today");

            let mut empty = Vec::new();
            render_keys(&[], format, false, None, &mut empty).unwrap();
            let empty = String::from_utf8(empty).unwrap();
            let document: serde_json::Value = match format {
                KeysFormat::Json => serde_json::from_str(&empty).unwrap(),
                KeysFormat::Yaml => serde_saphyr::from_str(&empty).unwrap(),
                KeysFormat::Toml => toml::from_str(&empty).unwrap(),
                _ => unreachable!(),
            };
            assert_eq!(document["keys"].as_array().unwrap().len(), 0);
        }
    }

    #[test]
    fn table_has_aligned_header_truncation_and_no_truncation_mode() {
        let key = super::KeyOutput {
            alias: "aws".into(),
            fingerprint: "SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+Y".into(),
            agent: "agent".into(),
            scopes: vec![],
            tags: Default::default(),
            comment: None,
        };
        let mut output = Vec::new();
        render_keys(
            std::slice::from_ref(&key),
            KeysFormat::Table,
            false,
            None,
            &mut output,
        )
        .unwrap();
        let truncated = String::from_utf8(output).unwrap();
        assert!(truncated.starts_with("KEY  AGENT  SCOPES  FINGERPRINT\n"));
        assert!(truncated.contains("SHA256:Wda9mr6okK…"));
        let mut output = Vec::new();
        render_keys(&[key], KeysFormat::Table, true, None, &mut output).unwrap();
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+Y")
        );
    }

    #[test]
    fn table_truncates_cells_to_fit_a_narrow_terminal() {
        let key = super::KeyOutput {
            alias: "aws-production".into(),
            fingerprint: "SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+Y".into(),
            agent: "bitwarden".into(),
            scopes: vec!["company/long-production-scope".into()],
            tags: Default::default(),
            comment: None,
        };
        let mut output = Vec::new();
        render_keys(
            std::slice::from_ref(&key),
            KeysFormat::Table,
            false,
            Some(40),
            &mut output,
        )
        .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.lines().all(|line| line.chars().count() <= 40));
        assert!(output.contains("…"));
        let mut full = Vec::new();
        render_keys(&[key], KeysFormat::Table, true, Some(40), &mut full).unwrap();
        assert!(
            String::from_utf8(full)
                .unwrap()
                .contains("SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+Y")
        );
    }

    #[test]
    fn table_uses_extra_terminal_width_to_show_full_fingerprint() {
        let key = super::KeyOutput {
            alias: "aws-production".into(),
            fingerprint: "SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+Y".into(),
            agent: "bitwarden".into(),
            scopes: vec!["company/production".into()],
            tags: Default::default(),
            comment: None,
        };
        let mut output = Vec::new();
        render_keys(
            std::slice::from_ref(&key),
            KeysFormat::Table,
            false,
            Some(120),
            &mut output,
        )
        .unwrap();
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+Y")
        );
    }
}
