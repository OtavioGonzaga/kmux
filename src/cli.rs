use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
pub struct Cli {
    #[arg(long)]
    pub config: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    Keys,
    Scopes,
    Doctor,
    Exec {
        scope: String,
        #[arg(required = true, trailing_var_arg = true)]
        command: Vec<String>,
    },
    Import {
        #[command(subcommand)]
        command: ImportCommand,
    },
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
}

#[derive(Subcommand)]
pub enum ImportCommand {
    Agent {
        name: String,
        #[arg(long)]
        scope: String,
        #[arg(long, value_enum, default_value_t = OutputFormat::Yaml)]
        format: OutputFormat,
    },
}

#[derive(Clone, ValueEnum)]
pub enum OutputFormat {
    Yaml,
    Json,
    Toml,
}

#[derive(Subcommand)]
pub enum ConfigCommand {
    Check,
}
