use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "kmux", version)]
pub struct Cli {
    #[arg(long)]
    pub config: Option<PathBuf>,
    #[command(flatten)]
    pub filters: FilterArgs,
    #[command(subcommand)]
    pub command: Option<Command>,
    #[arg(value_name = "COMMAND", trailing_var_arg = true)]
    pub child_command: Vec<String>,
}

#[derive(Args, Clone, Debug, Default)]
pub struct FilterArgs {
    #[arg(short, long)]
    pub scope: Option<String>,
    #[arg(short, long)]
    pub comment: Option<String>,
    #[arg(short = 'k', long)]
    pub key: Option<String>,
    #[arg(short, long)]
    pub fingerprint: Option<String>,
    #[arg(short, long = "tag", value_name = "KEY=VALUE")]
    pub tags: Vec<String>,
    #[arg(long)]
    pub agent: Option<String>,
}

impl FilterArgs {
    pub fn is_empty(&self) -> bool {
        self.scope.is_none()
            && self.comment.is_none()
            && self.key.is_none()
            && self.fingerprint.is_none()
            && self.tags.is_empty()
            && self.agent.is_none()
    }
}

#[derive(Subcommand)]
pub enum Command {
    Keys,
    Scopes,
    Doctor,
    Exec {
        #[command(flatten)]
        filters: FilterArgs,
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

#[cfg(test)]
mod tests {
    use super::{Cli, Command};
    use clap::Parser;

    #[test]
    fn parses_root_execution_filters_and_the_child_command() {
        let cli = Cli::try_parse_from([
            "kmux",
            "-s",
            "hogix",
            "-c",
            "aws",
            "-t",
            "provider=aws",
            "--agent",
            "bitwarden",
            "--",
            "ssh",
            "host",
        ])
        .unwrap();
        assert!(cli.command.is_none());
        assert_eq!(cli.filters.scope.as_deref(), Some("hogix"));
        assert_eq!(cli.filters.comment.as_deref(), Some("aws"));
        assert_eq!(cli.filters.tags, ["provider=aws"]);
        assert_eq!(cli.child_command, ["ssh", "host"]);
    }

    #[test]
    fn parses_root_filters_without_a_separator_and_preserves_child_flags() {
        let cli = Cli::try_parse_from(["kmux", "-s", "hogix", "ssh", "-v", "host"]).unwrap();

        assert!(cli.command.is_none());
        assert_eq!(cli.filters.scope.as_deref(), Some("hogix"));
        assert_eq!(cli.child_command, ["ssh", "-v", "host"]);
    }

    #[test]
    fn parses_all_filters_and_preserves_child_filter_collisions() {
        let cli = Cli::try_parse_from([
            "kmux",
            "-s",
            "hogix",
            "-c",
            "aws",
            "-k",
            "aws-production",
            "-f",
            "Wda9mr6okK7",
            "-t",
            "provider=aws",
            "--agent",
            "bitwarden",
            "some-command",
            "--scope",
            "child-value",
        ])
        .unwrap();

        assert_eq!(cli.filters.scope.as_deref(), Some("hogix"));
        assert_eq!(cli.filters.comment.as_deref(), Some("aws"));
        assert_eq!(cli.filters.key.as_deref(), Some("aws-production"));
        assert_eq!(cli.filters.fingerprint.as_deref(), Some("Wda9mr6okK7"));
        assert_eq!(cli.filters.tags, ["provider=aws"]);
        assert_eq!(cli.filters.agent.as_deref(), Some("bitwarden"));
        assert_eq!(
            cli.child_command,
            ["some-command", "--scope", "child-value"]
        );
    }

    #[test]
    fn parses_explicit_exec_syntax() {
        let explicit =
            Cli::try_parse_from(["kmux", "exec", "-s", "hogix", "--", "ssh", "host"]).unwrap();
        let Some(Command::Exec { filters, command }) = explicit.command else {
            panic!("expected exec");
        };
        assert_eq!(filters.scope.as_deref(), Some("hogix"));
        assert_eq!(command, ["ssh", "host"]);
    }

    #[test]
    fn parses_explicit_exec_without_a_separator_and_preserves_child_flags() {
        let explicit =
            Cli::try_parse_from(["kmux", "exec", "-s", "hogix", "ssh", "-v", "host"]).unwrap();
        let Some(Command::Exec { filters, command }) = explicit.command else {
            panic!("expected exec");
        };

        assert_eq!(filters.scope.as_deref(), Some("hogix"));
        assert_eq!(command, ["ssh", "-v", "host"]);
    }
}
