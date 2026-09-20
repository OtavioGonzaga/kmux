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
    Init {
        #[arg(long, value_enum)]
        format: Option<OutputFormat>,
        #[arg(long)]
        force: bool,
    },
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
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
        #[arg(long = "scope")]
        scopes: Vec<String>,
        #[arg(long = "tag", value_name = "KEY=VALUE")]
        tags: Vec<String>,
        #[arg(long, conflicts_with = "stdout")]
        dry_run: bool,
        #[arg(long, conflicts_with = "dry_run")]
        stdout: bool,
        #[arg(long, value_enum, requires = "stdout")]
        format: Option<OutputFormat>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    Yaml,
    Json,
    Toml,
}

#[derive(Subcommand)]
pub enum ConfigCommand {
    Check,
}

#[derive(Subcommand)]
pub enum AgentCommand {
    Add {
        name: String,
        #[arg(long)]
        socket: PathBuf,
    },
    Remove {
        name: String,
    },
}

#[derive(Subcommand)]
pub enum KeyCommand {
    Add {
        alias: String,
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        fingerprint: Option<String>,
        #[arg(long)]
        comment: Option<String>,
        #[arg(long = "scope")]
        scopes: Vec<String>,
        #[arg(long = "tag", value_name = "KEY=VALUE")]
        tags: Vec<String>,
    },
    Remove {
        alias: String,
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::{AgentCommand, Cli, Command, ImportCommand, KeyCommand, OutputFormat};
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

    #[test]
    fn import_defaults_to_toml_output() {
        let cli = Cli::try_parse_from(["kmux", "import", "agent", "primary"]).unwrap();
        let Some(Command::Import {
            command: ImportCommand::Agent { format, scopes, .. },
        }) = cli.command
        else {
            panic!("expected import agent");
        };

        assert_eq!(format, None);
        assert!(scopes.is_empty());
    }

    #[test]
    fn import_accepts_every_supported_output_format() {
        for (value, expected) in [
            ("toml", OutputFormat::Toml),
            ("yaml", OutputFormat::Yaml),
            ("json", OutputFormat::Json),
        ] {
            let cli = Cli::try_parse_from([
                "kmux", "import", "agent", "primary", "--stdout", "--format", value,
            ])
            .unwrap();
            let Some(Command::Import {
                command: ImportCommand::Agent { format, .. },
            }) = cli.command
            else {
                panic!("expected import agent");
            };

            assert_eq!(format, Some(expected));
        }
    }

    #[test]
    fn parses_import_scopes_tags_and_modes() {
        let cli = Cli::try_parse_from([
            "kmux",
            "import",
            "agent",
            "primary",
            "--scope",
            "company",
            "--scope",
            "production",
            "--tag",
            "provider=aws",
            "--tag",
            "environment=prod",
            "--dry-run",
        ])
        .unwrap();
        let Some(Command::Import {
            command:
                ImportCommand::Agent {
                    scopes,
                    tags,
                    dry_run,
                    stdout,
                    ..
                },
        }) = cli.command
        else {
            panic!("expected import agent");
        };
        assert_eq!(scopes, ["company", "production"]);
        assert_eq!(tags, ["provider=aws", "environment=prod"]);
        assert!(dry_run);
        assert!(!stdout);
    }

    #[test]
    fn import_modes_are_mutually_exclusive() {
        assert!(
            Cli::try_parse_from([
                "kmux",
                "import",
                "agent",
                "primary",
                "--dry-run",
                "--stdout"
            ])
            .is_err()
        );
    }

    #[test]
    fn import_format_requires_stdout() {
        assert!(
            Cli::try_parse_from(["kmux", "import", "agent", "primary", "--format", "yaml"])
                .is_err()
        );
    }

    #[test]
    fn parses_mutating_commands_and_repeated_key_values() {
        let init = Cli::try_parse_from(["kmux", "init", "--format", "yaml", "--force"]).unwrap();
        assert!(matches!(
            init.command,
            Some(Command::Init {
                format: Some(OutputFormat::Yaml),
                force: true
            })
        ));

        let agent = Cli::try_parse_from([
            "kmux",
            "agent",
            "add",
            "work",
            "--socket",
            "/tmp/agent.sock",
        ])
        .unwrap();
        assert!(matches!(
            agent.command,
            Some(Command::Agent {
                command: AgentCommand::Add { .. }
            })
        ));

        let key = Cli::try_parse_from([
            "kmux",
            "key",
            "add",
            "deploy",
            "--agent",
            "work",
            "--fingerprint",
            "SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+Y",
            "--scope",
            "company",
            "--scope",
            "production",
            "--tag",
            "provider=aws",
        ])
        .unwrap();
        let Some(Command::Key {
            command: KeyCommand::Add { scopes, tags, .. },
        }) = key.command
        else {
            panic!("expected key add");
        };
        assert_eq!(scopes, ["company", "production"]);
        assert_eq!(tags, ["provider=aws"]);

        let key_with_comment = Cli::try_parse_from([
            "kmux",
            "key",
            "add",
            "deploy",
            "--agent",
            "work",
            "--fingerprint",
            "SHA256:Wda9mr6okK7Rb2vORVFqw5ARYcfo6HxnVLJ4Ru1K8+Y",
            "--comment",
            "Production deployment key",
        ])
        .unwrap();
        let Some(Command::Key {
            command: KeyCommand::Add { comment, .. },
        }) = key_with_comment.command
        else {
            panic!("expected key add");
        };
        assert_eq!(comment.as_deref(), Some("Production deployment key"));
    }
}
