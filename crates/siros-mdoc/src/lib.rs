//! ISO/IEC 18013-5 mdocs for the SIROS wallet core.
//!
//! [`Mdoc::parse`] reads a stored credential: base64url of an `IssuerSigned`, a `Document`, or a
//! `DeviceResponse` with one document. An [`Mdoc`] holds the document type, the namespaces with
//! their items, `issuerAuth` and the MSO. Each `IssuerSignedItemBytes` and `issuerAuth` keep the
//! bytes the issuer wrote. Parsing refuses a credential whose `Document` names another
//! `docType` than its MSO, or whose items do not have the digests `valueDigests` lists.
//!
//! [`device_signing_input`] gives the data the device key signs from a session transcript, a
//! document type and the `DeviceSigned` namespaces.
//!
//! The feature `crypto` adds the Document Signer certificate ([`P256Certificate`]) and ES256
//! verification ([`es256_verifies`]).

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::cognitive_complexity)]
// Nothing panics outside the tests. scripts/check_panic_sites.py refuses an
// allow of these lints there and finds the panics they cannot see.
#![cfg_attr(
    not(test),
    deny(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::disallowed_methods
    )
)]

mod device;
mod error;
mod issuer_auth;
mod mdoc;
mod mso;

#[cfg(feature = "crypto")]
mod es256;
#[cfg(feature = "crypto")]
mod x509;

pub use device::{device_signing_digest, device_signing_input, DeviceNameSpaces};
pub use error::MdocError;
pub use issuer_auth::IssuerAuth;
pub use mdoc::{IssuerNameSpace, IssuerSignedItem, Mdoc};
pub use mso::{DigestAlgorithm, KeyAuthorizations, Mso, P256Key, Validity};

#[cfg(feature = "crypto")]
pub use es256::es256_verifies;
#[cfg(feature = "crypto")]
pub use x509::{chains_to, CertificateError, P256Certificate};
