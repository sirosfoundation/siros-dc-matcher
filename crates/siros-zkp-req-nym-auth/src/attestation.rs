//! The Wallet's tests of a credential (system rulebooks, Section 7, step 1), with the codes of
//! Section 9. [`UsableAttestation`] is the credential that passes them at a proof time, and
//! [`OpenedSeed`] is a delivered `secret_seed` that opens its `ssc` (privatedata, Section 5A.2).

use std::fmt;

use siros_codec::date::DateTime;
use siros_mdoc::{chains_to, es256_verifies, CertificateError, MdocError, P256Certificate};
use zeroize::Zeroizing;

use crate::mdoc::{self, FormError, NymAuthMdoc, Reading};
use crate::outcome::CredentialCode;
use crate::verifier_id::sha256;

/// A nym_auth credential with its Document Signer certificate read.
#[derive(Debug, Clone)]
pub struct Credential {
    mdoc: NymAuthMdoc,
    certificate: P256Certificate,
}

impl Credential {
    /// The attestation.
    pub fn mdoc(&self) -> &NymAuthMdoc {
        &self.mdoc
    }

    /// The Document Signer certificate.
    pub fn certificate(&self) -> &P256Certificate {
        &self.certificate
    }
}

/// Why a credential cannot be read in the nym_auth form: `credential_form`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Unreadable {
    /// The mdoc.
    Form(FormError),
    /// The Document Signer certificate.
    Certificate(CertificateError),
}

impl Unreadable {
    /// A stable identifier: the code of the mdoc's or the certificate's rule.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Form(e) => e.code(),
            Self::Certificate(e) => e.code(),
        }
    }
}

/// A credential that reads and fails tests at the proof time.
#[derive(Debug, Clone)]
pub struct Failures {
    credential: Credential,
    codes: Vec<CredentialCode>,
}

impl Failures {
    /// The credential. The item tests still apply to it.
    pub fn credential(&self) -> &Credential {
        &self.credential
    }

    /// The codes of the failed tests, in the order `issuer_signature`, `issuer_untrusted`,
    /// `validity`. It holds at least one.
    pub fn codes(&self) -> &[CredentialCode] {
        &self.codes
    }
}

/// Why a stored credential is no usable attestation at the proof time.
#[derive(Debug, Clone)]
pub enum Unusable {
    /// An mdoc of another `docType`: it does not match the query.
    OtherDocType,
    /// The credential cannot be read in the nym_auth form: `credential_form`.
    Unreadable(Unreadable),
    /// The MSO lists another digest of an element, or none: `issuer_signature`.
    Unlisted,
    /// The credential reads and fails the tests of [`Failures::codes`].
    Fails(Box<Failures>),
}

impl Unusable {
    /// The codes of Section 9 of the failed tests. An mdoc of another `docType` has none.
    pub fn codes(&self) -> &[CredentialCode] {
        match self {
            Self::OtherDocType => &[],
            Self::Unreadable(_) => &[CredentialCode::CredentialForm],
            Self::Unlisted => &[CredentialCode::IssuerSignature],
            Self::Fails(failures) => failures.codes(),
        }
    }

    /// The credential, when it reads in the nym_auth form.
    pub fn credential(&self) -> Option<&Credential> {
        match self {
            Self::Fails(failures) => Some(failures.credential()),
            Self::OtherDocType | Self::Unreadable(_) | Self::Unlisted => None,
        }
    }

    /// A stable identifier: `other_doc_type`, the code of the one failed test, or `credential`
    /// for the tests of [`Failures`].
    pub fn code(&self) -> &'static str {
        match self {
            Self::OtherDocType => "other_doc_type",
            Self::Unreadable(_) => CredentialCode::CredentialForm.code(),
            Self::Unlisted => CredentialCode::IssuerSignature.code(),
            Self::Fails(_) => "credential",
        }
    }
}

impl fmt::Display for Unusable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for Unusable {}

/// A credential that passes the tests that need neither the seed nor the device signature at a
/// proof time: the form, the issuer signature and the listed digests, the trust in the issuer
/// when the query names authorities, and the validity. Proving requires it.
#[derive(Debug, Clone)]
pub struct UsableAttestation {
    credential: Credential,
    proof_time: DateTime,
}

impl UsableAttestation {
    /// Reads `data` of a stored `mso_mdoc` credential and tests it at `proof_time`. `anchors`
    /// are the DER certificates the issuer must chain to, when the query names authorities.
    ///
    /// # Errors
    ///
    /// [`Unusable`]: another `docType`, an unreadable credential, or the failed tests.
    pub fn new(
        data: &str,
        anchors: Option<&[Vec<u8>]>,
        proof_time: DateTime,
    ) -> Result<Self, Unusable> {
        let mdoc = match mdoc::read(data) {
            Ok(Reading::NymAuth(mdoc)) => *mdoc,
            Ok(Reading::OtherDocType) => return Err(Unusable::OtherDocType),
            Err(FormError::Mdoc(MdocError::ItemDigest)) => return Err(Unusable::Unlisted),
            Err(e) => return Err(Unusable::Unreadable(Unreadable::Form(e))),
        };
        let certificate = P256Certificate::parse(mdoc.document_signer())
            .map_err(|e| Unusable::Unreadable(Unreadable::Certificate(e)))?;
        let mut codes = Vec::new();
        if !es256_verifies(
            certificate.key(),
            mdoc.sig_structure(),
            mdoc.issuer_signature(),
        ) {
            codes.push(CredentialCode::IssuerSignature);
        }
        if anchors.is_some_and(|anchors| !chains_to(&certificate, anchors)) {
            codes.push(CredentialCode::IssuerUntrusted);
        }
        if !(mdoc.valid_from() <= proof_time && proof_time < mdoc.valid_until()) {
            codes.push(CredentialCode::Validity);
        }
        let credential = Credential { mdoc, certificate };
        if codes.is_empty() {
            Ok(Self {
                credential,
                proof_time,
            })
        } else {
            Err(Unusable::Fails(Box::new(Failures { credential, codes })))
        }
    }

    /// The credential.
    pub fn credential(&self) -> &Credential {
        &self.credential
    }

    /// The proof time the credential passes the tests at.
    pub fn proof_time(&self) -> DateTime {
        self.proof_time
    }
}

/// `SHA-256(secret_seed)` is not the credential's `ssc`: `seed_mismatch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SeedMismatch;

impl SeedMismatch {
    /// A stable identifier.
    pub fn code(self) -> &'static str {
        "seed_mismatch"
    }
}

impl fmt::Display for SeedMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for SeedMismatch {}

/// A delivered `secret_seed` whose SHA-256 is the credential's `ssc`. The Wallet opens it again
/// for each use (privatedata, Section 5A.2). It is zeroed on drop.
#[derive(Clone)]
pub struct OpenedSeed(Zeroizing<[u8; 16]>);

impl OpenedSeed {
    /// Opens the `ssc` of `credential` with `secret_seed`.
    ///
    /// # Errors
    ///
    /// [`SeedMismatch`] when `SHA-256(secret_seed)` is not `ssc`.
    pub fn open(credential: &Credential, secret_seed: &[u8; 16]) -> Result<Self, SeedMismatch> {
        if sha256(secret_seed) == *credential.mdoc().ssc().value() {
            Ok(Self(Zeroizing::new(*secret_seed)))
        } else {
            Err(SeedMismatch)
        }
    }

    /// The 16-byte `secret_seed`.
    pub fn secret_seed(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Shows nothing: the seed is a delivered secret.
impl fmt::Debug for OpenedSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenedSeed").finish_non_exhaustive()
    }
}
