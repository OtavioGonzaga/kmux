mod agent;
mod diagnostics;
mod exec;
mod import;
mod init;
mod key;
mod list;

use crate::cli::{
    AgentCommand, Cli, Command, ConfigCommand, FilterArgs, ImportCommand, KeyCommand,
};
use kmux::catalog::KeyQuery;
use kmux::config::Config;

pub fn run(cli: Cli) -> Result<i32, Box<dyn std::error::Error>> {
    if cli.command.is_some() && !cli.filters.is_empty() {
        return Err(
            "filters before a subcommand are only valid for direct command execution; use `kmux exec -s hogix ...`"
                .into(),
        );
    }
    if let Some(Command::Init { format, force }) = &cli.command {
        init::initialize(cli.config.as_deref(), format.clone(), *force)?;
        return Ok(0);
    }
    let path = Config::discover(cli.config.as_deref())?;
    match cli.command {
        Some(Command::Agent {
            command: AgentCommand::Add { name, socket },
        }) => {
            agent::add(&path, name, socket)?;
            return Ok(0);
        }
        Some(Command::Agent {
            command: AgentCommand::Remove { name },
        }) => {
            agent::remove(&path, name)?;
            return Ok(0);
        }
        Some(Command::Key {
            command:
                KeyCommand::Add {
                    alias,
                    agent,
                    fingerprint,
                    comment,
                    scopes,
                    tags,
                },
        }) => {
            key::add(&path, alias, agent, fingerprint, comment, scopes, tags)?;
            return Ok(0);
        }
        Some(Command::Key {
            command: KeyCommand::Remove { alias, yes },
        }) => {
            key::remove(&path, alias, yes)?;
            return Ok(0);
        }
        _ => {}
    }
    if let Some(Command::Import {
        command:
            ImportCommand::Agent {
                name,
                scopes,
                tags,
                dry_run,
                stdout,
                format,
            },
    }) = cli.command
    {
        import::import_agent(
            &path,
            &name,
            scopes,
            tags,
            dry_run,
            stdout,
            format.unwrap_or(crate::cli::OutputFormat::Toml),
        )?;
        return Ok(0);
    }
    let config = Config::load(path.as_path())?;
    match cli.command {
        Some(Command::Exec { filters, command }) => {
            return exec::execute(&config, key_query(filters)?, command);
        }
        Some(Command::Import { .. }) => unreachable!("import returns before loading configuration"),
        Some(Command::Config {
            command: ConfigCommand::Check,
        }) => println!("configuration is valid"),
        Some(Command::Keys { filters }) => list::print_keys(&config, &key_query(filters)?)?,
        Some(Command::Scopes) => list::print_scopes(&config),
        Some(Command::Doctor) => diagnostics::doctor(&config)?,
        Some(Command::Init { .. } | Command::Agent { .. } | Command::Key { .. }) => {
            unreachable!("mutating commands return before loading configuration")
        }
        None if !cli.child_command.is_empty() => {
            return exec::execute(&config, key_query(cli.filters)?, cli.child_command);
        }
        None => return Err("a child command is required".into()),
    }
    Ok(0)
}

fn key_query(filters: FilterArgs) -> Result<KeyQuery, Box<dyn std::error::Error>> {
    Ok(KeyQuery::from_values(
        filters.scope,
        filters.comment,
        filters.key,
        filters.fingerprint,
        filters.tags,
        filters.agent,
    )?)
}

#[cfg(test)]
mod tests {
    use super::run;
    use crate::cli::Cli;
    use clap::Parser;

    #[test]
    fn rejects_root_filters_before_all_subcommands() {
        for arguments in [
            ["kmux", "-s", "hogix", "exec", "ssh", "host"].as_slice(),
            ["kmux", "-c", "aws", "doctor"].as_slice(),
            ["kmux", "-s", "hogix", "keys"].as_slice(),
        ] {
            let error = run(Cli::try_parse_from(arguments).unwrap()).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("filters before a subcommand are only valid")
            );
        }
    }
}
