use clap::{Parser, Subcommand};
use kmux::agent::{UnixSocketAgent, UpstreamAgent};
use kmux::config::Config;
use std::collections::BTreeSet;
use std::path::PathBuf;

#[derive(Parser)]
struct Cli {
    #[arg(long)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Keys,
    Scopes,
    Doctor,
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
}
#[derive(Subcommand)]
enum ConfigCommand {
    Check,
}

fn main() {
    let cli = Cli::parse();
    let result = run(cli);
    if let Err(error) = result {
        eprintln!("kmux: {error}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let path = Config::discover(cli.config.as_deref())?;
    let config = Config::load(path.as_path())?;
    match cli.command {
        Command::Keys => print_keys(&config),
        Command::Scopes => print_scopes(&config),
        Command::Doctor => doctor(&config)?,
        Command::Config {
            command: ConfigCommand::Check,
        } => println!("configuration is valid"),
    }
    Ok(())
}

fn print_keys(config: &Config) {
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

fn print_scopes(config: &Config) {
    let scopes = config
        .catalog()
        .entries()
        .flat_map(|entry| entry.scopes().iter())
        .collect::<BTreeSet<_>>();
    for scope in scopes {
        println!("{scope}");
    }
}

fn doctor(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let mut available = BTreeSet::new();
    for (name, definition) in config.agents() {
        let agent = UnixSocketAgent::new(definition.socket().to_owned());
        let identities = agent.identities()?;
        println!("ok\tagent\t{name}\t{} identities", identities.len());
        available.extend(identities.into_iter().map(|identity| identity.fingerprint));
    }

    let missing = config
        .catalog()
        .entries()
        .filter(|entry| !available.contains(entry.fingerprint()))
        .map(|entry| format!("{} ({})", entry.alias(), entry.fingerprint()))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "configured fingerprints unavailable: {}",
            missing.join(", ")
        )
        .into());
    }
    println!("ok\tcatalog\tall configured fingerprints are available");
    Ok(())
}
