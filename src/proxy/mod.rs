use crate::agent::{AgentError, UnixSocketAgent, UpstreamAgent, read_frame, write_frame};
use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::os::unix::net::UnixStream;

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
                    self.filter_identities(&mut upstream)?
                }
                Some(SIGN_REQUEST)
                    if self
                        .signing_blob(&request)
                        .is_some_and(|blob| self.allowed_blobs.contains(blob)) =>
                {
                    self.forward(&mut upstream, &request)?
                }
                Some(SIGN_REQUEST) => vec![FAILURE],
                Some(EXTENSION)
                    if extension_name(&request) == Some(b"session-bind@openssh.com".as_slice()) =>
                {
                    self.forward(&mut upstream, &request)?
                }
                Some(EXTENSION) => vec![EXTENSION_FAILURE],
                _ => vec![FAILURE],
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

#[derive(Debug)]
pub enum ProxyError {
    Agent(AgentError),
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
    use super::{FilteredAgent, extension_name};
    use crate::agent::UnixSocketAgent;

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
}
