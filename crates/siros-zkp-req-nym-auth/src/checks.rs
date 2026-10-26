//! The Wallet's tests of a credential (system rulebooks, Section 7, step 1), with the codes of
//! Section 9.

use siros_codec::date::DateTime;
use siros_mdoc::{chains_to, es256_verifies, CertificateError, MdocError, P256Certificate};

use crate::mdoc::{self, FormError, NymAuthMdoc, Reading};
use crate::outcome::CredentialCode;
use crate::verifier_id::sha256;

/// A nym_auth credential with its Document Signer certificate read.
#[derive(Debug, Clone)]
pub struct Credential {
    /// The attestation.
    pub mdoc: NymAuthMdoc,
    /// The Document Signer certificate.
    pub certificate: P256Certificate,
}

/// Why a credential cannot be read in the nym_auth form: `credential_form`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Unreadable {
    /// The mdoc.
    Form(FormError),
    /// The Document Signer certificate.
    Certificate(CertificateError),
}

/// What reading and checking a stored credential gives.
#[derive(Debug, Clone)]
pub enum Checked {
    /// An mdoc of another `docType`: it does not match the query.
    OtherDocType,
    /// The credential cannot be read in the nym_auth form.
    Unreadable(Unreadable),
    /// The MSO lists another digest of an element, or none: `issuer_signature`.
    Unlisted,
    /// The credential, and the checks it fails at the proof time. Empty when it passes.
    Read(Box<Credential>, Vec<CredentialCode>),
}

/// Reads `data` and runs the tests that need neither the seed nor the device signature: the
/// issuer signature and the listed digests, the trust in the issuer when the query names
/// authorities, and the validity at `proof_time`.
pub fn check(data: &str, anchors: Option<&[Vec<u8>]>, proof_time: DateTime) -> Checked {
    let mdoc = match mdoc::read(data) {
        Ok(Reading::NymAuth(mdoc)) => *mdoc,
        Ok(Reading::OtherDocType) => return Checked::OtherDocType,
        Err(FormError::Mdoc(MdocError::ItemDigest)) => return Checked::Unlisted,
        Err(e) => return Checked::Unreadable(Unreadable::Form(e)),
    };
    let certificate = match P256Certificate::parse(&mdoc.document_signer) {
        Ok(certificate) => certificate,
        Err(e) => return Checked::Unreadable(Unreadable::Certificate(e)),
    };
    let mut failures = Vec::new();
    if !es256_verifies(
        certificate.key(),
        &mdoc.sig_structure,
        &mdoc.issuer_signature,
    ) {
        failures.push(CredentialCode::IssuerSignature);
    }
    if anchors.is_some_and(|anchors| !chains_to(&certificate, anchors)) {
        failures.push(CredentialCode::IssuerUntrusted);
    }
    if !(mdoc.valid_from <= proof_time && proof_time < mdoc.valid_until) {
        failures.push(CredentialCode::Validity);
    }
    Checked::Read(Box::new(Credential { mdoc, certificate }), failures)
}

/// Whether `SHA-256(secret_seed)` is the credential's `ssc`.
pub fn opens_ssc(mdoc: &NymAuthMdoc, secret_seed: &[u8; 16]) -> bool {
    sha256(secret_seed) == mdoc.ssc.value
}
