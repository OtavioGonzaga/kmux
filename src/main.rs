use clap::{Parser, Subcommand, ValueEnum};
use kmux::agent::{UnixSocketAgent, UpstreamAgent};
use kmux::config::Config;
use kmux::proxy::{FilteredAgent, ProxyServer};
use kmux::selection::{choose, resolve};
use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing_subscriber::EnvFilter;

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
enum ImportCommand {
    Agent {
        name: String,
        #[arg(long)]
        scope: String,
        #[arg(long, value_enum, default_value_t = OutputFormat::Yaml)]
        format: OutputFormat,
    },
}
#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Yaml,
    Json,
    Toml,
}
#[derive(Subcommand)]
enum ConfigCommand {
    Check,
}

fn main() {
    init_logging();
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

fn init_logging() {
    let filter = EnvFilter::try_from_env("KMUX_LOG")
        .or_else(|_| EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| EnvFilter::new("warn"));
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

fn run(cli: Cli) -> Result<i32, Box<dyn std::error::Error>> {
    let path = Config::discover(cli.config.as_deref())?;
    let config = Config::load(path.as_path())?;
    match cli.command {
        Command::Keys => print_keys(&config),
        Command::Scopes => print_scopes(&config),
        Command::Doctor => doctor(&config)?,
        Command::Exec { scope, command } => return execute(&config, scope.parse()?, command),
        Command::Import {
            command:
                ImportCommand::Agent {
                    name,
                    scope,
                    format,
                },
        } => import_agent(&config, &name, scope.parse()?, format)?,
        Command::Config {
            command: ConfigCommand::Check,
        } => println!("configuration is valid"),
    }
    Ok(0)
}

fn import_agent(
    config: &Config,
    name: &str,
    scope: kmux::scope::ScopePath,
    format: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let name = kmux::agent::AgentName::new(name)?;
    let definition = config.agents().get(&name).ok_or("unknown agent")?;
    let identities = UnixSocketAgent::new(definition.socket().to_owned()).identities()?;
    match format {
        OutputFormat::Yaml => {
            println!("keys:");
            for (index, identity) in identities.iter().enumerate() {
                println!(
                    "  identity-{}:\n    fingerprint: \"{}\"\n    agent: {}\n    scopes: [\"{}\"]",
                    index + 1,
                    identity.fingerprint,
                    name,
                    scope
                );
            }
        }
        OutputFormat::Json => {
            let keys = identities.iter().enumerate().map(|(index, identity)| (format!("identity-{}", index + 1), serde_json::json!({"fingerprint": identity.fingerprint.as_str(), "agent": name.as_str(), "scopes": [scope.to_string()]}))).collect::<serde_json::Map<_, _>>();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({"keys": keys}))?
            );
        }
        OutputFormat::Toml => {
            for (index, identity) in identities.iter().enumerate() {
                println!(
                    "[keys.identity-{}]\nfingerprint = \"{}\"\nagent = \"{}\"\nscopes = [\"{}\"]",
                    index + 1,
                    identity.fingerprint,
                    name,
                    scope
                );
            }
        }
    }
    Ok(())
}

fn execute(
    config: &Config,
    scope: kmux::scope::ScopePath,
    command: Vec<String>,
) -> Result<i32, Box<dyn std::error::Error>> {
    tracing::info!(scope = %scope, command = %command[0], "starting filtered command");
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
    tracing::debug!(socket = %server.path().display(), agent = %candidate.entry.agent(), "started filtered agent proxy");
    let received_signal = Arc::new(AtomicUsize::new(0));
    signal_hook::flag::register_usize(
        signal_hook::consts::SIGINT,
        received_signal.clone(),
        signal_hook::consts::SIGINT as usize,
    )?;
    signal_hook::flag::register_usize(
        signal_hook::consts::SIGTERM,
        received_signal.clone(),
        signal_hook::consts::SIGTERM as usize,
    )?;
    let mut child = ProcessCommand::new(&command[0])
        .args(&command[1..])
        .env("SSH_AUTH_SOCK", server.path())
        .spawn()?;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        let signal = received_signal.swap(0, Ordering::Relaxed);
        if signal != 0 {
            tracing::info!(
                signal,
                child_pid = child.id(),
                "forwarding termination signal to child"
            );
            // The child receives the same terminal signal before the proxy is dropped.
            unsafe { libc::kill(child.id() as i32, signal as i32) };
        }
        thread::sleep(std::time::Duration::from_millis(10));
    };
    let code = status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1);
    tracing::info!(exit_code = code, "filtered command exited");
    Ok(code)
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
    let mut available = std::collections::BTreeMap::new();
    for (name, definition) in config.agents() {
        let agent = UnixSocketAgent::new(definition.socket().to_owned());
        let identities = agent.identities()?;
        println!("ok\tagent\t{name}\t{} identities", identities.len());
        available.insert(
            name.clone(),
            identities
                .into_iter()
                .map(|identity| identity.fingerprint)
                .collect::<BTreeSet<_>>(),
        );
    }

    let missing = config
        .catalog()
        .entries()
        .filter(|entry| {
            !available
                .get(entry.agent())
                .is_some_and(|keys| keys.contains(entry.fingerprint()))
        })
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
