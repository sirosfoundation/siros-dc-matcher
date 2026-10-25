use crate::host::Host;
use std::io::{self, Read, Seek, SeekFrom};

#[derive(Debug, Clone)]
pub struct CredentialReader {
    host: Host,
    size: u64,
    position: u64,
}

impl CredentialReader {
    pub fn new(host: Host) -> Self {
        Self {
            host,
            size: host.credentials_size() as u64,
            position: 0,
        }
    }

    pub fn len(&self) -> u64 {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

impl Read for CredentialReader {
    /// `Ok(0)` also when the host returns nothing before the end.
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
