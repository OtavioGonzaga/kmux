use kmux::agent::UnixSocketAgent;
use kmux::config::Config;
use kmux::proxy::{FilteredAgent, ProxyServer};
use kmux::scope::ScopePath;
use kmux::selection::{choose, resolve};
use rustix::process::{Pid, Signal, kill_process};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::thread;

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
    let runtime = RuntimeDirectory::new()?;
    let server = ProxyServer::bind(
        runtime.socket_path(),
        FilteredAgent::new(
            UnixSocketAgent::new(definition.socket().to_owned()),
            [candidate.identity.key_blob],
        ),
    )?;
    let signals = SignalRegistration::new()?;
    let mut child = ProcessCommand::new(&command[0])
        .args(&command[1..])
        .env("SSH_AUTH_SOCK", server.path())
        .spawn()?;
    let status = wait_for_child(&mut child, &signals.received)?;
    Ok(status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1))
}

enum RuntimeDirectory {
    Xdg(PathBuf),
    Temporary(tempfile::TempDir),
}

impl RuntimeDirectory {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        match std::env::var_os("XDG_RUNTIME_DIR") {
            Some(base) => {
                let path = PathBuf::from(base).join("kmux");
                match std::fs::symlink_metadata(&path) {
                    Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                        return Err(format!(
                            "runtime path '{}' is not a directory",
                            path.display()
                        )
                        .into());
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        std::fs::create_dir(&path)?
                    }
                    Err(error) => return Err(error.into()),
                }
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
                Ok(Self::Xdg(path))
            }
            None => Ok(Self::temporary()?),
        }
    }

    fn socket_path(&self) -> PathBuf {
        let directory = match self {
            Self::Xdg(path) => path,
            Self::Temporary(path) => path.path(),
        };
        directory.join(format!("{}.sock", std::process::id()))
    }

    fn temporary() -> Result<Self, std::io::Error> {
        let directory = tempfile::Builder::new().prefix("kmux-").tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        Ok(Self::Temporary(directory))
    }
}

struct SignalRegistration {
    received: Arc<AtomicUsize>,
    registrations: [signal_hook::SigId; 2],
}

impl SignalRegistration {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let received = Arc::new(AtomicUsize::new(0));
        let interrupt = signal_hook::flag::register_usize(
            signal_hook::consts::SIGINT,
            received.clone(),
            signal_hook::consts::SIGINT as usize,
        )?;
        let terminate = signal_hook::flag::register_usize(
            signal_hook::consts::SIGTERM,
            received.clone(),
            signal_hook::consts::SIGTERM as usize,
        )?;
        Ok(Self {
            received,
            registrations: [interrupt, terminate],
        })
    }
}

impl Drop for SignalRegistration {
    fn drop(&mut self) {
        for registration in self.registrations {
            signal_hook::low_level::unregister(registration);
        }
    }
}

fn wait_for_child(
    child: &mut std::process::Child,
    received_signal: &AtomicUsize,
) -> Result<std::process::ExitStatus, Box<dyn std::error::Error>> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        match received_signal.swap(0, Ordering::Relaxed) {
            value if value == signal_hook::consts::SIGINT as usize => {
                forward_signal(child, Signal::INT)?
            }
            value if value == signal_hook::consts::SIGTERM as usize => {
                forward_signal(child, Signal::TERM)?
            }
            0 => {}
            _ => unreachable!("only registered signals are stored"),
        }
        thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn forward_signal(
    child: &std::process::Child,
    signal: Signal,
) -> Result<(), Box<dyn std::error::Error>> {
    match kill_process(Pid::from_child(child), signal) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
        Err(error) => {
            Err(std::io::Error::other(format!("could not forward signal to child: {error}")).into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RuntimeDirectory;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn temporary_runtime_directory_is_private_and_unique() {
        let first = RuntimeDirectory::temporary().unwrap();
        let second = RuntimeDirectory::temporary().unwrap();
        let first_path = first.socket_path();
        let second_path = second.socket_path();
        assert_ne!(first_path.parent(), second_path.parent());
        assert_eq!(
            std::fs::metadata(first_path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
    }
}
