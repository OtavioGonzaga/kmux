use clap::{Parser, Subcommand};
use kmux::agent::{UnixSocketAgent, UpstreamAgent};
use kmux::config::Config;
use kmux::proxy::{FilteredAgent, ProxyServer};
use kmux::selection::{choose, resolve};
use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::time::{SystemTime, UNIX_EPOCH};

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
    Exec {
        scope: String,
        #[arg(required = true, trailing_var_arg = true)]
        command: Vec<String>,
    },
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
    match result {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("kmux: {error}");
            std::process::exit(1);
        }
    }
}

fn run(cli: Cli) -> Result<i32, Box<dyn std::error::Error>> {
    let path = Config::discover(cli.config.as_deref())?;
    let config = Config::load(path.as_path())?;
    match cli.command {
        Command::Keys => print_keys(&config),
        Command::Scopes => print_scopes(&config),
        Command::Doctor => doctor(&config)?,
        Command::Exec { scope, command } => return execute(&config, scope.parse()?, command),
        Command::Config {
            command: ConfigCommand::Check,
        } => println!("configuration is valid"),
    }
    Ok(0)
}

fn execute(
    config: &Config,
    scope: kmux::scope::ScopePath,
    command: Vec<String>,
) -> Result<i32, Box<dyn std::error::Error>> {
    let candidate = choose(resolve(config, scope)?)?;
    let definition = config
        .agents()
        .get(candidate.entry.agent())
        .ok_or("selected agent is missing")?;
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("kmux");
    std::fs::create_dir_all(&runtime)?;
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700))?;
    let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let socket = runtime.join(format!("{}-{unique}.sock", std::process::id()));
    let server = ProxyServer::bind(
        &socket,
        FilteredAgent::new(
            UnixSocketAgent::new(definition.socket().to_owned()),
            [candidate.identity.key_blob],
        ),
    )?;
    let status = ProcessCommand::new(&command[0])
        .args(&command[1..])
        .env("SSH_AUTH_SOCK", server.path())
        .status()?;
    Ok(status.code().unwrap_or(1))
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
