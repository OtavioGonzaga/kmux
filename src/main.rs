use clap::{Parser, Subcommand};
use kmux::config::Config;
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
        Command::Keys => {
            for entry in config.catalog().entries() {
                println!("{}\t{}", entry.alias(), entry.fingerprint());
            }
        }
        Command::Scopes => {
            for entry in config.catalog().entries() {
                for scope in entry.scopes() {
                    println!("{scope}");
                }
            }
        }
        Command::Config {
            command: ConfigCommand::Check,
        } => println!("configuration is valid"),
    }
    Ok(())
}
