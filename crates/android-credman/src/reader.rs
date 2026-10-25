use crate::host::{CredentialsError, Host};
use std::io::{self, Read, Seek, SeekFrom};

/// The credential blob the wallet registered, as [`Read`] and [`Seek`], for
/// a decoder that streams it. Each read asks the host for the bytes with
/// [`Host::read_credentials_at`].
#[derive(Debug, Clone)]
pub struct CredentialReader {
    host: Host,
    size: usize,
    position: u64,
}

impl CredentialReader {
    /// A reader at offset 0. Reads the blob's length once.
    pub fn new(host: Host) -> Self {
        Self {
            host,
            size: host.credentials_size(),
            position: 0,
        }
    }

    /// The blob's length in bytes.
    pub fn len(&self) -> u64 {
        self.size as u64
    }

    /// Whether the blob holds no bytes.
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

impl Read for CredentialReader {
    /// Asks the host for up to `out.len()` bytes; it copies at most what
    /// remains of the blob. A host that breaks that contract makes an
    /// [`io::Error`] carrying a [`CredentialsError`].
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        // A position beyond usize lies past the end, where a read returns 0.
        let Ok(offset) = usize::try_from(self.position) else {
            return Ok(0);
        };
        let size = self.size;
        let remaining = size.saturating_sub(offset);
        if remaining == 0 || out.is_empty() {
            return Ok(0);
        }
        let copied = self
            .host
            .read_credentials_at(out, offset)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if copied == 0 {
            let error = CredentialsError::Incomplete {
                delivered: offset,
                size,
            };
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, error));
        }
        if copied > remaining {
            let error = CredentialsError::PastEnd {
                offset,
                copied,
                size,
            };
            return Err(io::Error::new(io::ErrorKind::InvalidData, error));
        }
        self.position += copied as u64;
        Ok(copied)
    }
}

impl Seek for CredentialReader {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let target = match to {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(n) => (self.size as u64).checked_add_signed(n),
            SeekFrom::Current(n) => self.position.checked_add_signed(n),
        };
        let target = target
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before the start"))?;
        self.position = target;
        Ok(target)
    }
}
