mod cli;
mod commands;

use clap::Parser;
use cli::Cli;
use tracing_subscriber::EnvFilter;

fn main() {
    init_logging();
    match commands::run(Cli::parse()) {
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
