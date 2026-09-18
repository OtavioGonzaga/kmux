mod diagnostics;
mod exec;
mod import;
mod list;

use crate::cli::{Cli, Command, ConfigCommand, ImportCommand};
use kmux::config::Config;

pub fn run(cli: Cli) -> Result<i32, Box<dyn std::error::Error>> {
    let path = Config::discover(cli.config.as_deref())?;
    let config = Config::load(path.as_path())?;
    match cli.command {
        Command::Keys => list::print_keys(&config),
        Command::Scopes => list::print_scopes(&config),
        Command::Doctor => diagnostics::doctor(&config)?,
        Command::Exec { scope, command } => return exec::execute(&config, scope.parse()?, command),
        Command::Import {
            command:
                ImportCommand::Agent {
                    name,
                    scope,
                    format,
                },
        } => import::import_agent(&config, &name, scope.parse()?, format)?,
        Command::Config {
            command: ConfigCommand::Check,
        } => println!("configuration is valid"),
    }
    Ok(0)
}
