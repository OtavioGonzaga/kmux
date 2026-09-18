use crate::agent::{AgentError, UnixSocketAgent, UpstreamAgent, read_frame, write_frame};
use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const FAILURE: u8 = 5;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const EXTENSION: u8 = 27;
const EXTENSION_FAILURE: u8 = 28;

#[derive(Clone, Debug)]
pub struct FilteredAgent {
    upstream: UnixSocketAgent,
    allowed_blobs: BTreeSet<Vec<u8>>,
}

impl FilteredAgent {
    pub fn new(
        upstream: UnixSocketAgent,
        allowed_blobs: impl IntoIterator<Item = Vec<u8>>,
    ) -> Self {
        Self {
            upstream,
            allowed_blobs: allowed_blobs.into_iter().collect(),
        }
    }

    /// Serves one downstream connection using one connection to the upstream agent.
    pub fn serve_connection(&self, mut downstream: UnixStream) -> Result<(), ProxyError> {
        let mut upstream = self.upstream.connect()?;
        tracing::debug!("connected downstream client to upstream agent");
        loop {
            let request = match read_frame(&mut downstream) {
                Ok(request) => request,
                Err(AgentError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {
                    return Ok(());
                }
                Err(error) => return Err(error.into()),
            };
            let response = match request.first().copied() {
                Some(REQUEST_IDENTITIES) if request.len() == 1 => {
                    tracing::trace!(operation = "request-identities", "handling agent request");
                    self.filter_identities(&mut upstream)?
                }
                Some(SIGN_REQUEST)
                    if self
                        .signing_blob(&request)
                        .is_some_and(|blob| self.allowed_blobs.contains(blob)) =>
                {
                    tracing::trace!(operation = "sign", "forwarding authorized signing request");
                    self.forward(&mut upstream, &request)?
                }
                Some(SIGN_REQUEST) => {
                    tracing::warn!(operation = "sign", "rejected unauthorized signing request");
                    vec![FAILURE]
                }
                Some(EXTENSION)
                    if extension_name(&request) == Some(b"session-bind@openssh.com".as_slice()) =>
                {
                    tracing::trace!(operation = "session-bind", "forwarding OpenSSH extension");
                    self.forward(&mut upstream, &request)?
                }
                Some(EXTENSION) => {
                    tracing::warn!(
                        operation = "extension",
                        "rejected unsupported agent extension"
                    );
                    vec![EXTENSION_FAILURE]
                }
                _ => {
                    tracing::warn!(operation = "unknown", "rejected unsupported agent request");
                    vec![FAILURE]
                }
            };
            write_frame(&mut downstream, &response)?;
        }
    }

    fn forward(&self, upstream: &mut UnixStream, request: &[u8]) -> Result<Vec<u8>, ProxyError> {
        write_frame(upstream, request)?;
        Ok(read_frame(upstream)?)
    }

    fn filter_identities(&self, upstream: &mut UnixStream) -> Result<Vec<u8>, ProxyError> {
        let response = self.forward(upstream, &[REQUEST_IDENTITIES])?;
        let mut reader = Reader::new(&response);
        if reader.byte()? != IDENTITIES_ANSWER {
            return Err(ProxyError::MalformedResponse);
        }
        let count = reader.u32()? as usize;
        let mut allowed = Vec::new();
        for _ in 0..count {
            let blob = reader.string()?.to_owned();
            let comment = reader.string()?.to_owned();
            if self.allowed_blobs.contains(&blob) {
                allowed.push((blob, comment));
            }
        }
        if !reader.empty() {
            return Err(ProxyError::MalformedResponse);
        }
        let mut filtered = Vec::new();
        filtered.push(IDENTITIES_ANSWER);
        filtered.extend_from_slice(&(allowed.len() as u32).to_be_bytes());
        for (blob, comment) in allowed {
            put_string(&mut filtered, &blob);
            put_string(&mut filtered, &comment);
        }
        Ok(filtered)
    }

    fn signing_blob<'a>(&self, request: &'a [u8]) -> Option<&'a [u8]> {
        let mut reader = Reader::new(request);
        (reader.byte().ok()? == SIGN_REQUEST)
            .then(|| reader.string().ok())
            .flatten()
    }
}

pub struct ProxyServer {
    path: PathBuf,
    running: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl ProxyServer {
    pub fn bind(path: impl Into<PathBuf>, agent: FilteredAgent) -> Result<Self, ProxyError> {
        let path = path.into();
        let listener = UnixListener::bind(&path).map_err(ProxyError::Io)?;
        listener.set_nonblocking(true).map_err(ProxyError::Io)?;
        let running = Arc::new(AtomicBool::new(true));
        let worker_running = running.clone();
        let connection_ids = Arc::new(AtomicU64::new(0));
        let worker = thread::spawn(move || {
            while worker_running.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if !worker_running.load(Ordering::Relaxed) {
                            break;
                        }
                        let agent = agent.clone();
                        let connection_id = connection_ids.fetch_add(1, Ordering::Relaxed) + 1;
                        thread::spawn(move || {
                            tracing::debug!(connection_id, "accepted downstream agent connection");
                            if let Err(error) = agent.serve_connection(stream) {
                                tracing::debug!(connection_id, %error, "agent connection closed with error");
                            }
                        });
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10))
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            path,
            running,
            worker: Some(worker),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ProxyServer {
    fn drop(&mut self) {
        tracing::debug!(socket = %self.path.display(), "stopping filtered agent proxy");
        self.running.store(false, Ordering::Relaxed);
        let _ = UnixStream::connect(&self.path);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

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

fn extension_name(request: &[u8]) -> Option<&[u8]> {
    let mut reader = Reader::new(request);
    (reader.byte().ok()? == EXTENSION)
        .then(|| reader.string().ok())
        .flatten()
}
fn put_string(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u32).to_be_bytes());
    target.extend_from_slice(value);
}
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn byte(&mut self) -> Result<u8, ProxyError> {
        self.take(1).map(|value| value[0])
    }
    fn u32(&mut self) -> Result<u32, ProxyError> {
        self.take(4)
            .map(|value| u32::from_be_bytes(value.try_into().unwrap()))
    }
    fn string(&mut self) -> Result<&'a [u8], ProxyError> {
        let length = self.u32()? as usize;
        self.take(length)
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], ProxyError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ProxyError::MalformedResponse)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ProxyError::MalformedResponse)?;
        self.offset = end;
        Ok(value)
    }
    fn empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{EXTENSION, FAILURE, FilteredAgent, ProxyServer, SIGN_REQUEST, extension_name};
    use crate::agent::{UnixSocketAgent, read_frame, write_frame};
    use std::io;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    struct FakeAgent {
        path: PathBuf,
        running: Arc<AtomicBool>,
        connections: Arc<AtomicUsize>,
        worker: Option<thread::JoinHandle<()>>,
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
            let worker = thread::spawn(move || {
                while worker_running.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let identities = identities.clone();
                            let id = worker_connections.fetch_add(1, Ordering::Relaxed) + 1;
                            thread::spawn(move || serve_fake_connection(stream, identities, id));
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(1));
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
            }
        }
    }

    impl Drop for FakeAgent {
        fn drop(&mut self) {
            self.running.store(false, Ordering::Relaxed);
            let _ = UnixStream::connect(&self.path);
            if let Some(worker) = self.worker.take() {
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
                        super::put_string(&mut response, identity);
                        super::put_string(&mut response, format!("connection-{id}").as_bytes());
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
        super::put_string(&mut request, blob);
        super::put_string(&mut request, b"data");
        request.extend_from_slice(&0_u32.to_be_bytes());
        request
    }

    #[test]
    fn only_session_bind_is_an_allowed_extension() {
        let agent = FilteredAgent::new(UnixSocketAgent::new("/tmp/agent"), []);
        let mut request = vec![27];
        super::put_string(&mut request, b"session-bind@openssh.com");
        assert!(agent.allowed_blobs.is_empty());
        assert_eq!(
            extension_name(&request),
            Some(b"session-bind@openssh.com".as_slice())
        );
    }

    #[test]
    fn proxy_filters_identities_forwards_allowed_operations_and_isolates_connections() {
        let allowed = b"allowed".to_vec();
        let upstream = FakeAgent::start(vec![allowed.clone(), b"denied".to_vec()]);
        let path = socket_path("proxy");
        let server = ProxyServer::bind(
            &path,
            FilteredAgent::new(UnixSocketAgent::new(&upstream.path), [allowed.clone()]),
        )
        .unwrap();

        let mut first = UnixStream::connect(server.path()).unwrap();
        let identities = request(&mut first, &[11]);
        assert_eq!(identities[0], 12);
        assert_eq!(u32::from_be_bytes(identities[1..5].try_into().unwrap()), 1);
        assert_eq!(&identities[9..16], b"allowed");
        assert_eq!(request(&mut first, &sign_request(&allowed)), [14, 1]);
        assert_eq!(request(&mut first, &sign_request(b"denied")), [FAILURE]);

        let mut extension = vec![EXTENSION];
        super::put_string(&mut extension, b"session-bind@openssh.com");
        assert_eq!(request(&mut first, &extension), [6, 1]);

        let mut second = UnixStream::connect(server.path()).unwrap();
        assert_eq!(request(&mut second, &sign_request(&allowed)), [14, 2]);
        assert_eq!(upstream.connections.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn dropping_proxy_removes_its_socket() {
        let upstream = FakeAgent::start(Vec::new());
        let path = socket_path("proxy-drop");
        let server = ProxyServer::bind(
            &path,
            FilteredAgent::new(UnixSocketAgent::new(&upstream.path), []),
        )
        .unwrap();
        assert!(server.path().exists());
        drop(server);
        assert!(!path.exists());
    }
}
