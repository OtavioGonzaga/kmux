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
    active: Mutex<BTreeMap<u64, UnixStream>>,
    workers: Mutex<Vec<JoinHandle<()>>>,
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
                        listener_connections
                            .active
                            .lock()
                            .unwrap()
                            .insert(connection_id, control);
                        let worker_agent = agent.clone();
                        let worker_connections = listener_connections.clone();
                        let worker = thread::spawn(move || {
                            tracing::debug!(connection_id, "accepted downstream agent connection");
                            if let Err(error) = worker_agent.serve_connection(stream) {
                                tracing::debug!(connection_id, %error, "agent connection closed with error");
                            }
                            worker_connections
                                .active
                                .lock()
                                .unwrap()
                                .remove(&connection_id);
                        });
                        listener_connections.workers.lock().unwrap().push(worker);
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
        for stream in self.connections.active.lock().unwrap().values() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        let workers = std::mem::take(&mut *self.connections.workers.lock().unwrap());
        for worker in workers {
            let _ = worker.join();
        }
    }
}

impl Drop for ProxyServer {
    fn drop(&mut self) {
        tracing::debug!(socket = %self.path.display(), "stopping filtered agent proxy");
        self.shutdown();
        let _ = std::fs::remove_file(&self.path);
    }
}
