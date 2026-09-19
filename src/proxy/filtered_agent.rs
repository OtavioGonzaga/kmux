use super::ProxyError;
use super::protocol::{
    EXTENSION, EXTENSION_FAILURE, FAILURE, IDENTITIES_ANSWER, MAX_IDENTITIES, REQUEST_IDENTITIES,
    Reader, SIGN_REQUEST, put_string,
};
use crate::agent::{AgentError, UnixSocketAgent, UpstreamAgent, read_frame, write_frame};
use std::collections::BTreeSet;
use std::io;
use std::os::unix::net::UnixStream;

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
    pub fn serve_connection(
        &self,
        mut downstream: UnixStream,
        on_upstream_connected: impl FnOnce(UnixStream),
    ) -> Result<(), ProxyError> {
        let mut upstream = self.upstream.connect()?;
        on_upstream_connected(upstream.try_clone().map_err(ProxyError::Io)?);
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
                    self.filter_identities(&mut upstream)?
                }
                Some(SIGN_REQUEST) if self.authorized_signing_blob(&request) => {
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

    fn authorized_signing_blob(&self, request: &[u8]) -> bool {
        let mut reader = Reader::new(request);
        let Ok(SIGN_REQUEST) = reader.byte() else {
            return false;
        };
        let Ok(blob) = reader.string() else {
            return false;
        };
        // A sign request must contain blob, data, flags, and no trailing bytes.
        reader.string().is_ok()
            && reader.u32().is_ok()
            && reader.empty()
            && self.allowed_blobs.contains(blob)
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
        if count > MAX_IDENTITIES {
            return Err(ProxyError::MalformedResponse);
        }
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
}

fn extension_name(request: &[u8]) -> Option<&[u8]> {
    let mut reader = Reader::new(request);
    (reader.byte().ok()? == EXTENSION)
        .then(|| reader.string().ok())
        .flatten()
}
