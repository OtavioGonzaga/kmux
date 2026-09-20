use kmux::agent::UnixSocketAgent;
use kmux::catalog::KeyQuery;
use kmux::config::Config;
use kmux::proxy::{FilteredAgent, ProxyServer};
use kmux::selection::resolve_for_execution;
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
    query: KeyQuery,
    has_filters: bool,
    select: bool,
    command: Vec<String>,
) -> Result<i32, Box<dyn std::error::Error>> {
    if command.is_empty() {
        return Err("a child command is required".into());
    }
    tracing::info!(query = %query, command = %command[0], "starting filtered command");
    let candidates = resolve_for_execution(config, &query, has_filters, select)?;
    let definition = config
        .agents()
        .get(candidates[0].entry.agent())
        .ok_or("selected agent is missing")?;
    let runtime = RuntimeDirectory::new()?;
    let server = ProxyServer::bind(
        runtime.socket_path(),
        FilteredAgent::new(
            UnixSocketAgent::new(definition.socket().to_owned()),
            candidates
                .into_iter()
                .map(|candidate| candidate.identity.key_blob),
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

struct RuntimeDirectory(tempfile::TempDir);

impl RuntimeDirectory {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let directory = match std::env::var_os("XDG_RUNTIME_DIR") {
            Some(base) => Self::new_in(base)?,
            None => Self::from_tempdir(tempfile::Builder::new().prefix("kmux-").tempdir()?)?,
        };
        Ok(directory)
    }

    fn socket_path(&self) -> PathBuf {
        self.0.path().join("agent.sock")
    }

    fn new_in(base: impl AsRef<std::path::Path>) -> Result<Self, std::io::Error> {
        Self::from_tempdir(tempfile::Builder::new().prefix("kmux-").tempdir_in(base)?)
    }

    fn from_tempdir(directory: tempfile::TempDir) -> Result<Self, std::io::Error> {
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        Ok(Self(directory))
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
    use std::sync::{Arc, Barrier, mpsc};
    use std::thread;

    #[test]
    fn runtime_directories_are_private_unique_and_cleaned_up() {
        let base = tempfile::tempdir().unwrap();
        let first = RuntimeDirectory::new_in(base.path()).unwrap();
        let second = RuntimeDirectory::new_in(base.path()).unwrap();
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
        drop(first);
        drop(second);
        assert!(!first_path.parent().unwrap().exists());
        assert!(!second_path.parent().unwrap().exists());
    }

    #[test]
    fn concurrent_runtime_directories_do_not_collide() {
        let base = tempfile::tempdir().unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let (paths_sent, paths_received) = mpsc::channel();
        thread::scope(|scope| {
            let base = base.path();
            for _ in 0..2 {
                let barrier = barrier.clone();
                let paths_sent = paths_sent.clone();
                scope.spawn(move || {
                    barrier.wait();
                    let runtime = RuntimeDirectory::new_in(base).unwrap();
                    let path = runtime.socket_path();
                    let mode = std::fs::metadata(path.parent().unwrap())
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o077;
                    paths_sent.send((path, mode)).unwrap();
                    barrier.wait();
                });
            }
            barrier.wait();
            let first = paths_received.recv().unwrap();
            let second = paths_received.recv().unwrap();
            assert_ne!(first.0.parent(), second.0.parent());
            assert_eq!(first.1, 0);
            assert_eq!(second.1, 0);
            assert!(first.0.parent().unwrap().exists());
            assert!(second.0.parent().unwrap().exists());
            barrier.wait();
        });
    }
}
