use crate::app::CallingApp;
use crate::entry::{
    DelegationType, InlineIssuanceEntry, LegacyEntry, PackageInfo, PaymentEntry, StringIdEntry,
};
use crate::levels::{Credman, Credman2, Credman4, V1, V4};
use crate::set::Sent;
use crate::sets_on_host::EntrySets;

/// The host of one matcher invocation: the verifier's request, the wallet's
/// credentials, the calling app, the standalone entries, and the entry sets
/// from [`Host::entry_sets`]. [`Host::credman`] gives the host's functions
/// one by one.
#[derive(Debug, Clone, Copy)]
pub struct Host {
    credman: Credman,
    delegation: Option<Sent<DelegationType>>,
}

impl Host {
    /// Reads the host level with
    /// [`GetWasmVersion`](android_credman_sys::credman::GetWasmVersion). A
    /// matcher connects first, here or with [`Host::connect_with`].
    pub fn connect() -> Self {
        Self {
            credman: Credman::connect(),
            delegation: None,
        }
    }

    /// The host's functions at the base level. [`Credman::version`] grants
    /// a higher level when the host reports it.
    pub fn credman(&self) -> &Credman {
        &self.credman
    }

    /// Where the matcher sends its entry sets, when the host reaches level 2.
    pub fn entry_sets(&self) -> Option<EntrySets<'_>> {
        self.credman
            .version::<Credman2>()
            .map(|host| EntrySets::new(&self.credman, host, self.delegation))
    }

    /// The verifier's request: the Digital Credentials API request as JSON.
    /// A matcher reads it once.
    ///
    /// # Panics
    ///
    /// When the reported length cannot be allocated.
    pub fn request(&self) -> Vec<u8> {
        self.credman.request()
    }

    /// The length in bytes of the credential blob the wallet registered.
    pub fn credentials_size(&self) -> usize {
        self.credman.credentials_size()
    }

    /// Copies the blob's bytes from `offset` into `buffer`. Returns the count
    /// the host copied, which may be lower than `buffer.len()` and is 0 past
    /// the end.
    ///
    /// # Panics
    ///
    /// When the host reports more bytes than `buffer` holds.
    pub fn read_credentials_at(&self, buffer: &mut [u8], offset: usize) -> usize {
        let asked = buffer.len();
        let copied = self.credman.read_credentials_buffer(buffer, offset);
        // ReadCredentialsBuffer copies at most the bytes asked for. A host
        // that reports more either wrote past `buffer` or reports a false
        // count, and no byte of the blob can be trusted after either.
        assert!(
            copied <= asked,
            "host reported {copied} credential bytes for a {asked}-byte buffer"
        );
        copied
    }

    /// Copies the blob's bytes from `offset`, which lies before `size`, the
    /// length the host reported, into `buffer`. Returns the count the host
    /// copied: at least 1, and at most what remains of the blob.
    ///
    /// # Panics
    ///
    /// When the host copies nothing, or more than `buffer` holds or than
    /// remains of the blob.
    pub(crate) fn read_credentials_before_end(
        &self,
        buffer: &mut [u8],
        offset: usize,
        size: usize,
    ) -> usize {
        let copied = self.read_credentials_at(buffer, offset);
        // The host holds the `size` bytes it reported and copies from what
        // remains of them (ReadCredentialsBuffer). A host that copies none
        // before the end, or more than remains, broke that contract: the
        // blob it reported does not exist, and no read can recover it.
        assert!(
            copied > 0,
            "host stopped at credential byte {offset} of {size}"
        );
        assert!(
            copied <= size.saturating_sub(offset),
            "host reported {copied} credential bytes from {offset}, past its size {size}"
        );
        copied
    }

    /// The credential blob the wallet registered, read in as many calls as
    /// the host needs. A matcher reads it once.
    ///
    /// # Panics
    ///
    /// When the reported length cannot be allocated, when the host copies
    /// nothing before that length, and when it reports more bytes than it
    /// was asked for.
    pub fn credentials(&self) -> Vec<u8> {
        let size = self.credentials_size();
        // The blob is the matcher's only input besides the request. A size
        // the module cannot allocate leaves nothing to match against: past
        // `isize::MAX` the allocation panics, below it a failed allocation
        // aborts.
        let mut blob = vec![0; size];
        let mut delivered = 0;
        while let Some(rest) = blob.get_mut(delivered..).filter(|rest| !rest.is_empty()) {
            delivered += self.read_credentials_before_end(rest, delivered, size);
        }
        blob
    }

    /// The app that called the Digital Credentials API, converted once.
    ///
    /// # Panics
    ///
    /// When a field's text is not UTF-8.
    pub fn calling_app(&self) -> CallingApp {
        CallingApp::from_host(&self.credman.calling_app_info())
    }

    /// Adds a standalone verification entry, then its fields, then its link.
    /// For a host below level 2, which has no sets.
    pub fn add_string_id_entry(&self, entry: &StringIdEntry<'_>) {
        let host = &self.credman;
        host.add_string_id_entry(entry.cred_id, &entry.display);
        for field in entry.fields {
            host.add_field_for_string_id_entry(entry.cred_id, field);
        }
        if let Some(link) = entry.link {
            host.set_additional_disclaimer_and_url_for_verification_entry(entry.cred_id, &link);
        }
    }

    /// Adds a standalone entry named by a number, then its fields. Google's
    /// header deprecates it for [`Host::add_string_id_entry`].
    pub fn add_legacy_entry(&self, entry: &LegacyEntry<'_>) {
        let host = &self.credman;
        host.add_entry(entry.cred_id, &entry.display);
        for field in entry.fields {
            host.add_field(entry.cred_id, field);
        }
    }

    /// Adds a standalone payment entry. For a host below level 2, which has
    /// no sets.
    pub fn add_payment_entry(&self, entry: &PaymentEntry<'_>) {
        self.credman
            .add_payment_entry(entry.cred_id, &entry.display);
    }

    /// Adds an entry that offers to issue a credential the wallet lacks.
    pub fn add_inline_issuance_entry(&self, entry: &InlineIssuanceEntry<'_>) {
        self.credman.add_inline_issuance_entry(entry);
    }
}

/// What [`Host::connect_with`] applies after reading the host level.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HostOptions<'a> {
    /// Declared once with [`V4::self_declare_package_info`] when the host
    /// reaches level 4. Google's header says the call works for system apps
    /// only; what the picker does with the values is unconfirmed.
    pub package_info: Option<PackageInfo<'a>>,
    /// The delegation of every set entry without its own, sent from level 7.
    pub delegation: Option<DelegationType>,
}

impl Host {
    /// Reads the host level as [`Host::connect`] does, then applies the
    /// options.
    pub fn connect_with(options: HostOptions<'_>) -> Self {
        let host = Self {
            credman: Credman::connect(),
            delegation: options.delegation.map(Sent::delegation),
        };
        if let (Some(info), Some(level)) =
            (options.package_info, host.credman.version::<Credman4>())
        {
            level.self_declare_package_info(&info);
        }
        host
    }
}
