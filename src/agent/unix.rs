use crate::catalog::{Fingerprint, Identity};
use std::fmt;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const MAX_MESSAGE_SIZE: usize = 256 * 1024;

pub trait UpstreamAgent {
    fn identities(&self) -> Result<Vec<Identity>, AgentError>;
    fn connect(&self) -> Result<UnixStream, AgentError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnixSocketAgent {
    socket: PathBuf,
}

impl UnixSocketAgent {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
        }
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }
}

impl UpstreamAgent for UnixSocketAgent {
    fn identities(&self) -> Result<Vec<Identity>, AgentError> {
        let mut stream = self.connect()?;
        write_frame(&mut stream, &[REQUEST_IDENTITIES])?;
        let response = read_frame(&mut stream)?;
        let mut reader = Reader::new(&response);
        if reader.byte()? != IDENTITIES_ANSWER {
            return Err(AgentError::UnexpectedResponse);
        }
        let count = reader.u32()? as usize;
        if count > 16_384 {
            return Err(AgentError::MalformedResponse);
        }
        let mut identities = Vec::with_capacity(count);
        for _ in 0..count {
            let key_blob = reader.string()?.to_owned();
            let comment = String::from_utf8_lossy(reader.string()?).into_owned();
            identities.push(Identity {
                fingerprint: Fingerprint::from_public_key_blob(&key_blob),
                key_blob,
                comment: (!comment.is_empty()).then_some(comment),
            });
        }
        if !reader.is_empty() {
            return Err(AgentError::MalformedResponse);
        }
        Ok(identities)
    }

    fn connect(&self) -> Result<UnixStream, AgentError> {
        UnixStream::connect(&self.socket).map_err(AgentError::Connect)
    }
}

#[derive(Debug)]
pub enum AgentError {
    Connect(std::io::Error),
    Io(std::io::Error),
    UnexpectedResponse,
    MalformedResponse,
}

impl fmt::Display for AgentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(error) => write!(formatter, "could not connect to SSH agent: {error}"),
            Self::Io(error) => write!(formatter, "SSH agent communication failed: {error}"),
            Self::UnexpectedResponse => {
                formatter.write_str("SSH agent sent an unexpected response")
            }
            Self::MalformedResponse => formatter.write_str("SSH agent sent a malformed response"),
        }
    }
}

impl std::error::Error for AgentError {}

pub(crate) fn read_frame(stream: &mut impl Read) -> Result<Vec<u8>, AgentError> {
    let mut length = [0; 4];
    stream.read_exact(&mut length).map_err(AgentError::Io)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_MESSAGE_SIZE {
        return Err(AgentError::MalformedResponse);
    }
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).map_err(AgentError::Io)?;
    Ok(payload)
}

pub(crate) fn write_frame(stream: &mut impl Write, payload: &[u8]) -> Result<(), AgentError> {
    if payload.is_empty() || payload.len() > MAX_MESSAGE_SIZE {
        return Err(AgentError::MalformedResponse);
    }
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .map_err(AgentError::Io)?;
    stream.write_all(payload).map_err(AgentError::Io)?;
    stream.flush().map_err(AgentError::Io)
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn byte(&mut self) -> Result<u8, AgentError> {
        Ok(*self.take(1)?.first().unwrap())
    }
    fn u32(&mut self) -> Result<u32, AgentError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn string(&mut self) -> Result<&'a [u8], AgentError> {
        let length = self.u32()? as usize;
        self.take(length)
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], AgentError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(AgentError::MalformedResponse)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(AgentError::MalformedResponse)?;
        self.offset = end;
        Ok(value)
    }
    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{read_frame, write_frame};
    use std::io::Cursor;

    #[test]
    fn frames_round_trip() {
        let mut bytes = Cursor::new(Vec::new());
        write_frame(&mut bytes, &[11]).unwrap();
        bytes.set_position(0);
        assert_eq!(read_frame(&mut bytes).unwrap(), [11]);
    }

    #[test]
    fn rejects_empty_frames() {
        let mut bytes = Cursor::new(0_u32.to_be_bytes().to_vec());
        assert!(read_frame(&mut bytes).is_err());
    }
}
