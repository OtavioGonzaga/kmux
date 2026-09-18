use kmux::agent::UnixSocketAgent;
use kmux::config::Config;
use kmux::proxy::{FilteredAgent, ProxyServer};
use kmux::scope::ScopePath;
use kmux::selection::{choose, resolve};
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

pub fn execute(
    config: &Config,
    scope: ScopePath,
    command: Vec<String>,
) -> Result<i32, Box<dyn std::error::Error>> {
    tracing::info!(scope = %scope, command = %command[0], "starting filtered command");
    let candidate = choose(resolve(config, scope)?)?;
    let definition = config
        .agents()
        .get(candidate.entry.agent())
        .ok_or("selected agent is missing")?;
    let server = ProxyServer::bind(
        runtime_socket()?,
        FilteredAgent::new(
            UnixSocketAgent::new(definition.socket().to_owned()),
            [candidate.identity.key_blob],
        ),
    )?;
    let received_signal = register_signals()?;
    let mut child = ProcessCommand::new(&command[0])
        .args(&command[1..])
        .env("SSH_AUTH_SOCK", server.path())
        .spawn()?;
    let status = wait_for_child(&mut child, &received_signal)?;
    Ok(status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1))
}

fn runtime_socket() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("kmux");
    std::fs::create_dir_all(&runtime)?;
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700))?;
    let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    Ok(runtime.join(format!("{}-{unique}.sock", std::process::id())))
}

fn register_signals() -> Result<Arc<AtomicUsize>, Box<dyn std::error::Error>> {
    let received = Arc::new(AtomicUsize::new(0));
    signal_hook::flag::register_usize(
        signal_hook::consts::SIGINT,
        received.clone(),
        signal_hook::consts::SIGINT as usize,
    )?;
    signal_hook::flag::register_usize(
        signal_hook::consts::SIGTERM,
        received.clone(),
        signal_hook::consts::SIGTERM as usize,
    )?;
    Ok(received)
}

fn wait_for_child(
    child: &mut std::process::Child,
    received_signal: &AtomicUsize,
) -> Result<std::process::ExitStatus, std::io::Error> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        let signal = received_signal.swap(0, Ordering::Relaxed);
        if signal != 0 {
            unsafe { libc::kill(child.id() as i32, signal as i32) };
        }
        thread::sleep(std::time::Duration::from_millis(10));
    }
}
