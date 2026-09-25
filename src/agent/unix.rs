//! Unix-domain implementation of the SSH Agent client protocol.

use crate::catalog::{Fingerprint, Identity};
use std::fmt;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const MAX_MESSAGE_SIZE: usize = 256 * 1024;

/// An SSH Agent that can enumerate public identities and open a connection.
pub trait UpstreamAgent {
    /// Retrieves the identities currently advertised by the agent.
    fn identities(&self) -> Result<Vec<Identity>, AgentError>;
    /// Opens a raw connection to the upstream agent.
    fn connect(&self) -> Result<UnixStream, AgentError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// An upstream SSH Agent addressed by a Unix socket.
pub struct UnixSocketAgent {
    socket: PathBuf,
}

impl UnixSocketAgent {
    /// Creates an agent client for `socket`.
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
        }
    }

    /// Returns the configured socket path.
    pub fn socket(&self) -> &Path {
        &self.socket
    }
}

impl UpstreamAgent for UnixSocketAgent {
    fn identities(&self) -> Result<Vec<Identity>, AgentError> {
        self.identities_with_timeout(None)
    }

    fn connect(&self) -> Result<UnixStream, AgentError> {
        UnixStream::connect(&self.socket).map_err(AgentError::Connect)
    }
}

impl UnixSocketAgent {
    /// Retrieves identities with a timeout for connecting, reading, and writing.
    pub fn identities_with_timeout(
        &self,
        timeout: Option<Duration>,
    ) -> Result<Vec<Identity>, AgentError> {
        let mut stream = match timeout {
            Some(timeout) => connect_with_timeout(&self.socket, timeout)?,
            None => self.connect()?,
        };
        stream.set_read_timeout(timeout).map_err(AgentError::Io)?;
        stream.set_write_timeout(timeout).map_err(AgentError::Io)?;
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
}

fn connect_with_timeout(path: &Path, timeout: Duration) -> Result<UnixStream, AgentError> {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    use rustix::net::sockopt::socket_error;

    if timeout.is_zero() {
        return Err(AgentError::Connect(std::io::Error::from(
            rustix::io::Errno::TIMEDOUT,
        )));
    }
    use rustix::net::{
        AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with,
    };

    let fd = socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|error| AgentError::Connect(error.into()))?;
    let address = SocketAddrUnix::new(path).map_err(|error| AgentError::Connect(error.into()))?;
    match connect(&fd, &address) {
        Ok(()) => {}
        Err(error)
            if error == rustix::io::Errno::INPROGRESS || error == rustix::io::Errno::WOULDBLOCK =>
        {
            let timeout = Timespec {
                tv_sec: timeout.as_secs().try_into().unwrap_or(i64::MAX),
                tv_nsec: timeout.subsec_nanos().into(),
            };
            let mut poll_fd = [PollFd::new(&fd, PollFlags::IN | PollFlags::OUT)];
            if poll(&mut poll_fd, Some(&timeout))
                .map_err(|error| AgentError::Connect(error.into()))?
                == 0
            {
                return Err(AgentError::Connect(std::io::Error::from(
                    rustix::io::Errno::TIMEDOUT,
                )));
            }
            socket_error(&fd)
                .map_err(|error| AgentError::Connect(error.into()))?
                .map_err(|error| AgentError::Connect(error.into()))?;
        }
        Err(error) => return Err(AgentError::Connect(error.into())),
    }
    let stream = UnixStream::from(fd);
    stream.set_nonblocking(false).map_err(AgentError::Connect)?;
    Ok(stream)
}

#[derive(Debug)]
/// Failure while communicating with an upstream SSH Agent.
pub enum AgentError {
    /// Connecting to the Unix socket failed.
    Connect(std::io::Error),
    /// Reading or writing an agent frame failed.
    Io(std::io::Error),
    /// The agent returned a message of the wrong kind.
    UnexpectedResponse,
    /// The agent returned an invalid or oversized message.
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

    #[test]
    fn rejects_oversized_and_truncated_frames() {
        let mut oversized = Cursor::new(((256 * 1024 + 1) as u32).to_be_bytes().to_vec());
        assert!(read_frame(&mut oversized).is_err());
        let mut truncated = Cursor::new([0, 0, 0, 2, 11].to_vec());
        assert!(read_frame(&mut truncated).is_err());
    }
}
