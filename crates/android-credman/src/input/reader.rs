use crate::*;
use std::cmp::min;
use std::io::{self, Read, Seek, SeekFrom};

/// Streaming reader for the registered credentials metadata blob.
///
/// This reader uses the host's offset-based `ReadCredentialsBuffer` and handles
/// short reads (the host may return fewer bytes than requested).
#[derive(Debug, Clone)]
pub struct CredentialReader {
    size: u64,
    offset: u64,
}

impl CredentialReader {
    /// Create a new reader positioned at offset 0.
    pub fn new() -> Self {
        let size = abi::get_credentials_size() as u64;
        Self { size, offset: 0 }
    }

    /// Total size of the credentials blob (in bytes).
    pub fn len(&self) -> u64 {
        self.size
    }

    /// Returns true if the credentials blob is empty.
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Current position (in bytes from start).
    pub fn position(&self) -> u64 {
        self.offset
    }

    /// Returns true if there is no more data to read.
    pub fn is_eof(&self) -> bool {
        self.offset >= self.size
    }
}

impl Default for CredentialReader {
    fn default() -> Self {
        Self::new()
    }
}

impl Read for CredentialReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.offset >= self.size {
            return Ok(0);
        }
        if out.is_empty() {
            return Ok(0);
        }
        let remaining = (self.size - self.offset) as usize;
        let to_request = min(out.len(), remaining);
        // SAFETY: host may return fewer bytes; we advance by the actual count returned.
        let nread = abi::read_credentials_buffer(&mut out[..to_request], self.offset as usize);
        self.offset = self.offset.saturating_add(nread as u64);
        Ok(nread)
    }
}

impl Seek for CredentialReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let Some(new_off) = (match pos {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(n) => self.size.checked_add_signed(n),
            SeekFrom::Current(n) => self.offset.checked_add_signed(n),
        }) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        };
        self.offset = new_off;
        Ok(self.offset)
    }
}
