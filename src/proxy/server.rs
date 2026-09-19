use super::{FilteredAgent, ProxyError};
use std::collections::BTreeMap;
use std::io;
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

struct Connections {
    active: Mutex<BTreeMap<u64, ConnectionSession>>,
    workers: Mutex<Vec<JoinHandle<()>>>,
}

struct ConnectionSession {
    downstream: UnixStream,
    upstream: Option<UnixStream>,
}

pub struct ProxyServer {
    path: PathBuf,
    running: Arc<AtomicBool>,
    listener: Option<JoinHandle<()>>,
    connections: Arc<Connections>,
}

impl ProxyServer {
    pub fn bind(path: impl Into<PathBuf>, agent: FilteredAgent) -> Result<Self, ProxyError> {
        let path = path.into();
        let listener = UnixListener::bind(&path).map_err(ProxyError::Io)?;
        listener.set_nonblocking(true).map_err(ProxyError::Io)?;
        let running = Arc::new(AtomicBool::new(true));
        let connections = Arc::new(Connections {
            active: Mutex::new(BTreeMap::new()),
            workers: Mutex::new(Vec::new()),
        });
        let listener_running = running.clone();
        let listener_connections = connections.clone();
        let connection_ids = Arc::new(AtomicU64::new(0));
        let listener = thread::spawn(move || {
            while listener_running.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if !listener_running.load(Ordering::Acquire) {
                            let _ = stream.shutdown(Shutdown::Both);
                            break;
                        }
                        let connection_id = connection_ids.fetch_add(1, Ordering::Relaxed) + 1;
                        let control = match stream.try_clone() {
                            Ok(control) => control,
                            Err(error) => {
                                tracing::debug!(connection_id, %error, "could not track downstream agent connection");
                                continue;
                            }
                        };
                        lock(&listener_connections.active).insert(
                            connection_id,
                            ConnectionSession {
                                downstream: control,
                                upstream: None,
                            },
                        );
                        let worker_agent = agent.clone();
                        let worker_connections = listener_connections.clone();
                        let worker = thread::spawn(move || {
                            tracing::debug!(connection_id, "accepted downstream agent connection");
                            let upstream_connections = worker_connections.clone();
                            if let Err(error) =
                                worker_agent.serve_connection(stream, move |upstream| {
                                    if let Some(session) =
                                        lock(&upstream_connections.active).get_mut(&connection_id)
                                    {
                                        session.upstream = Some(upstream);
                                    } else {
                                        let _ = upstream.shutdown(Shutdown::Both);
                                    }
                                })
                            {
                                tracing::debug!(connection_id, %error, "agent connection closed with error");
                            }
                            lock(&worker_connections.active).remove(&connection_id);
                        });
                        lock(&listener_connections.workers).push(worker);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => {
                        tracing::debug!(%error, "filtered agent listener stopped");
                        break;
                    }
                }
            }
        });
        Ok(Self {
            path,
            running,
            listener: Some(listener),
            connections,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn shutdown(&mut self) {
        self.running.store(false, Ordering::Release);
        let _ = UnixStream::connect(&self.path);
        if let Some(listener) = self.listener.take() {
            let _ = listener.join();
        }
        // Remove sessions before closing them so a concurrent upstream callback either
        // registers before this point or closes its newly connected upstream itself.
        let sessions = std::mem::take(&mut *lock(&self.connections.active));
        for session in sessions.values() {
            let _ = session.downstream.shutdown(Shutdown::Both);
            if let Some(upstream) = &session.upstream {
                let _ = upstream.shutdown(Shutdown::Both);
            }
        }
        let workers = std::mem::take(&mut *lock(&self.connections.workers));
        for worker in workers {
            let _ = worker.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Drop for ProxyServer {
    fn drop(&mut self) {
        tracing::debug!(socket = %self.path.display(), "stopping filtered agent proxy");
        self.shutdown();
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
