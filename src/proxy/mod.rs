mod filtered_agent;
mod protocol;
mod server;

pub use filtered_agent::FilteredAgent;
pub use server::ProxyServer;

use crate::agent::AgentError;
use std::fmt;
use std::io;

#[derive(Debug)]
pub enum ProxyError {
    Agent(AgentError),
    Io(io::Error),
    MalformedResponse,
}

impl From<AgentError> for ProxyError {
    fn from(value: AgentError) -> Self {
        Self::Agent(value)
    }
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Agent(error) => error.fmt(f),
            Self::Io(error) => write!(f, "proxy socket error: {error}"),
            Self::MalformedResponse => f.write_str("malformed SSH agent response"),
        }
    }
}

impl std::error::Error for ProxyError {}

#[cfg(test)]
mod tests {
    use super::protocol::{EXTENSION, EXTENSION_FAILURE, FAILURE, SIGN_REQUEST, put_string};
    use super::{FilteredAgent, ProxyServer};
    use crate::agent::{UnixSocketAgent, read_frame, write_frame};
    use std::io;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    };
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    struct FakeAgent {
        path: PathBuf,
        running: Arc<AtomicBool>,
        connections: Arc<AtomicUsize>,
        worker: Option<thread::JoinHandle<()>>,
        connection_workers: Arc<Mutex<Vec<thread::JoinHandle<()>>>>,
    }

    impl FakeAgent {
        fn start(identities: Vec<Vec<u8>>) -> Self {
            let path = socket_path("upstream");
            let listener = UnixListener::bind(&path).unwrap();
            listener.set_nonblocking(true).unwrap();
            let running = Arc::new(AtomicBool::new(true));
            let worker_running = running.clone();
            let connections = Arc::new(AtomicUsize::new(0));
            let worker_connections = connections.clone();
            let connection_workers = Arc::new(Mutex::new(Vec::new()));
            let listener_workers = connection_workers.clone();
            let worker = thread::spawn(move || {
                while worker_running.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let identities = identities.clone();
                            let id = worker_connections.fetch_add(1, Ordering::Relaxed) + 1;
                            let workers = listener_workers.clone();
                            workers.lock().unwrap().push(thread::spawn(move || {
                                serve_fake_connection(stream, identities, id)
                            }));
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(1))
                        }
                        Err(_) => break,
                    }
                }
            });
            Self {
                path,
                running,
                connections,
                worker: Some(worker),
                connection_workers,
            }
        }
    }

    impl Drop for FakeAgent {
        fn drop(&mut self) {
            self.running.store(false, Ordering::Release);
            let _ = UnixStream::connect(&self.path);
            if let Some(worker) = self.worker.take() {
                worker.join().unwrap();
            }
            for worker in std::mem::take(&mut *self.connection_workers.lock().unwrap()) {
                worker.join().unwrap();
            }
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn serve_fake_connection(mut stream: UnixStream, identities: Vec<Vec<u8>>, id: usize) {
        while let Ok(request) = read_frame(&mut stream) {
            let response = match request.first() {
                Some(11) => {
                    let mut response = vec![12];
                    response.extend_from_slice(&(identities.len() as u32).to_be_bytes());
                    for identity in &identities {
                        put_string(&mut response, identity);
                        put_string(&mut response, format!("connection-{id}").as_bytes());
                    }
                    response
                }
                Some(&SIGN_REQUEST) => vec![14, id as u8],
                Some(&EXTENSION) => vec![6, id as u8],
                _ => vec![FAILURE],
            };
            if write_frame(&mut stream, &response).is_err() {
                return;
            }
        }
    }

    fn socket_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("kmux-{name}-{}-{unique}.sock", std::process::id()))
    }

    fn request(stream: &mut UnixStream, payload: &[u8]) -> Vec<u8> {
        write_frame(stream, payload).unwrap();
        read_frame(stream).unwrap()
    }

    fn sign_request(blob: &[u8]) -> Vec<u8> {
        let mut request = vec![SIGN_REQUEST];
        put_string(&mut request, blob);
        put_string(&mut request, b"data");
        request.extend_from_slice(&0_u32.to_be_bytes());
        request
    }

    #[test]
    fn proxy_filters_operations_and_isolates_upstream_connections() {
        let allowed = b"allowed".to_vec();
        let upstream = FakeAgent::start(vec![allowed.clone(), b"denied".to_vec()]);
        let path = socket_path("proxy");
        let server = ProxyServer::bind(
            &path,
            FilteredAgent::new(UnixSocketAgent::new(&upstream.path), [allowed.clone()]),
        )
        .unwrap();
        let mut first = UnixStream::connect(server.path()).unwrap();
        assert_eq!(request(&mut first, &sign_request(&allowed)), [14, 1]);
        assert_eq!(request(&mut first, &sign_request(b"denied")), [FAILURE]);
        assert_eq!(request(&mut first, &[SIGN_REQUEST]), [FAILURE]);
        let mut trailing = sign_request(&allowed);
        trailing.push(0);
        assert_eq!(request(&mut first, &trailing), [FAILURE]);
        assert_eq!(request(&mut first, &[99]), [FAILURE]);
        let mut extension = vec![EXTENSION];
        put_string(&mut extension, b"unknown@kmux");
        assert_eq!(request(&mut first, &extension), [EXTENSION_FAILURE]);
        assert_eq!(request(&mut first, &[EXTENSION]), [EXTENSION_FAILURE]);
        let mut session_bind = vec![EXTENSION];
        put_string(&mut session_bind, b"session-bind@openssh.com");
        assert_eq!(request(&mut first, &session_bind), [6, 1]);
        let mut second = UnixStream::connect(server.path()).unwrap();
        assert_eq!(request(&mut second, &sign_request(&allowed)), [14, 2]);
        assert_eq!(upstream.connections.load(Ordering::Acquire), 2);
    }

    #[test]
    fn shutdown_closes_active_connections_and_removes_socket() {
        let allowed = b"allowed".to_vec();
        let upstream = FakeAgent::start(vec![allowed.clone()]);
        let path = socket_path("proxy-drop");
        let mut server = ProxyServer::bind(
            &path,
            FilteredAgent::new(UnixSocketAgent::new(&upstream.path), [allowed.clone()]),
        )
        .unwrap();
        let mut downstream = UnixStream::connect(server.path()).unwrap();
        assert_eq!(request(&mut downstream, &sign_request(&allowed)), [14, 1]);
        server.shutdown();
        server.shutdown();
        assert!(!path.exists());
        if write_frame(&mut downstream, &sign_request(&allowed)).is_ok() {
            assert!(read_frame(&mut downstream).is_err());
        }
    }

    #[test]
    fn shutdown_interrupts_a_worker_waiting_for_upstream_response() {
        let allowed = b"allowed".to_vec();
        let upstream_path = socket_path("stalled-upstream");
        let listener = UnixListener::bind(&upstream_path).unwrap();
        let (received_request, request_received) = mpsc::channel();
        let (upstream_closed, closed) = mpsc::channel();
        let upstream_worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            assert_eq!(read_frame(&mut stream).unwrap()[0], SIGN_REQUEST);
            received_request.send(()).unwrap();
            assert!(read_frame(&mut stream).is_err());
            upstream_closed.send(()).unwrap();
        });
        let path = socket_path("stalled-proxy");
        let mut server = ProxyServer::bind(
            &path,
            FilteredAgent::new(UnixSocketAgent::new(&upstream_path), [allowed.clone()]),
        )
        .unwrap();
        let mut downstream = UnixStream::connect(server.path()).unwrap();
        write_frame(&mut downstream, &sign_request(&allowed)).unwrap();
        request_received
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        server.shutdown();
        assert!(!path.exists());
        assert!(read_frame(&mut downstream).is_err());
        closed.recv_timeout(Duration::from_secs(1)).unwrap();
        upstream_worker.join().unwrap();
        let _ = std::fs::remove_file(upstream_path);
    }
}
