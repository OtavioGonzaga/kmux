mod diagnostics;
mod exec;
mod import;
mod list;

use crate::cli::{Cli, Command, ConfigCommand, FilterArgs, ImportCommand};
use kmux::catalog::KeyQuery;
use kmux::config::Config;

pub fn run(cli: Cli) -> Result<i32, Box<dyn std::error::Error>> {
    let path = Config::discover(cli.config.as_deref())?;
    let config = Config::load(path.as_path())?;
    match cli.command {
        Some(Command::Exec { filters, command }) => {
            return exec::execute(&config, key_query(filters)?, command);
        }
        Some(Command::Import {
            command:
                ImportCommand::Agent {
                    name,
                    scope,
                    format,
                },
        }) => import::import_agent(&config, &name, scope.parse()?, format)?,
        Some(Command::Config {
            command: ConfigCommand::Check,
        }) => println!("configuration is valid"),
        Some(Command::Keys) => list::print_keys(&config),
        Some(Command::Scopes) => list::print_scopes(&config),
        Some(Command::Doctor) => diagnostics::doctor(&config)?,
        None if !cli.child_command.is_empty() => {
            return exec::execute(&config, key_query(cli.filters)?, cli.child_command);
        }
        None => return Err("a command is required after `--`".into()),
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
