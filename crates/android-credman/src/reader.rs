use crate::host::Host;
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
    /// remains of the blob.
    ///
    /// # Panics
    ///
    /// When the host copies nothing before the end of the blob, or more
    /// than remains of it.
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        // A position beyond usize lies past the end, where a read returns 0.
        let Ok(offset) = usize::try_from(self.position) else {
            return Ok(0);
        };
        if offset >= self.size || out.is_empty() {
            return Ok(0);
        }
        let copied = self
            .host
            .read_credentials_before_end(out, offset, self.size);
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
        // A seek before the start is the one error a seek gives: its kind names it.
        let target = target.ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        self.position = target;
        Ok(target)
    }
}
