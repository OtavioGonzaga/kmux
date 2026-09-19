use super::ProxyError;

pub const EXTENSION: u8 = 27;
pub const EXTENSION_FAILURE: u8 = 28;
pub const FAILURE: u8 = 5;
pub const IDENTITIES_ANSWER: u8 = 12;
pub const REQUEST_IDENTITIES: u8 = 11;
pub const SIGN_REQUEST: u8 = 13;
pub const MAX_IDENTITIES: usize = 16_384;

pub fn put_string(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u32).to_be_bytes());
    target.extend_from_slice(value);
}

pub struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub fn byte(&mut self) -> Result<u8, ProxyError> {
        self.take(1).map(|value| value[0])
    }

    pub fn u32(&mut self) -> Result<u32, ProxyError> {
        self.take(4)
            .map(|value| u32::from_be_bytes(value.try_into().unwrap()))
    }

    pub fn boolean(&mut self) -> Result<bool, ProxyError> {
        self.byte().map(|value| value != 0)
    }

    pub fn string(&mut self) -> Result<&'a [u8], ProxyError> {
        let length = self.u32()? as usize;
        self.take(length)
    }

    pub fn empty(&self) -> bool {
        self.offset == self.bytes.len()
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
}
