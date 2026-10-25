//! A `std::io` view of the registered blob, for decoders that stream.

use crate::host::Host;
use std::io::{self, Read, Seek, SeekFrom};

/// Reads the registered blob through `ReadCredentialsBuffer` at the current
/// position, without copying it whole first.
#[derive(Debug, Clone)]
pub struct CredentialReader {
    host: Host,
    size: u64,
    position: u64,
}

impl CredentialReader {
    /// A reader at the start of the blob.
    pub fn new(host: Host) -> Self {
        Self {
            host,
            size: host.credentials_size() as u64,
            position: 0,
        }
    }

    /// The blob's size in bytes, as the host reported it.
    pub fn len(&self) -> u64 {
        self.size
    }

    /// Whether the host reported an empty blob.
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

impl Read for CredentialReader {
    /// Reads at most `out.len()` bytes from the current position and returns
    /// the count the host reported. `Ok(0)` at the end of the blob, or when
    /// the host returns nothing.
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let remaining = self.size.saturating_sub(self.position);
        let asked = usize::try_from(remaining).map_or(out.len(), |r| r.min(out.len()));
        if asked == 0 {
            return Ok(0);
        }
        let offset = usize::try_from(self.position)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "position beyond usize"))?;
        let copied = self
            .host
            .read_credentials_at(out.split_at_mut(asked).0, offset);
        self.position = self.position.saturating_add(copied as u64);
        Ok(copied)
    }
}

impl Seek for CredentialReader {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let target = match to {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(n) => self.size.checked_add_signed(n),
            SeekFrom::Current(n) => self.position.checked_add_signed(n),
        };
        let target = target
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before the start"))?;
        self.position = target;
        Ok(target)
    }
}
