//! The Wallet's tests of a credential (system rulebooks, Section 7, step 1), with the codes of
//! Section 9.

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};

use crate::date::DateTime;
use crate::mdoc::{self, MdocError, NymAuthMdoc, P256Key, Reading, SignedElement};
use crate::outcome::CredentialCode;
use crate::verifier_id::sha256;
use crate::x509::{chains_to, CertificateError, P256Certificate};

/// A nym_auth credential with its Document Signer certificate read.
#[derive(Debug, Clone)]
pub struct Credential {
    /// The attestation.
    pub mdoc: NymAuthMdoc,
    /// `x5chain[0]`.
    pub certificate: P256Certificate,
}

/// Why a credential cannot be read in the nym_auth form: `credential_form`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Unreadable {
    /// The mdoc.
    Mdoc(MdocError),
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
        Err(e) => return Checked::Unreadable(Unreadable::Mdoc(e)),
    };
    let certificate = match mdoc.x5chain.first().map(|der| P256Certificate::parse(der)) {
        Some(Ok(certificate)) => certificate,
        Some(Err(e)) => return Checked::Unreadable(Unreadable::Certificate(e)),
        None => return Checked::Unreadable(Unreadable::Mdoc(MdocError::X5chain)),
    };
    let mut failures = Vec::new();
    if !issuer_signed(&mdoc, &certificate.key) {
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

/// Whether `issuerAuth` verifies under `key` and the MSO lists the digest of every element.
fn issuer_signed(mdoc: &NymAuthMdoc, key: &P256Key) -> bool {
    es256_verifies(key, &mdoc.sig_structure, &mdoc.issuer_signature)
        && listed(mdoc, &mdoc.birth_date)
        && listed(mdoc, &mdoc.ssc)
        && mdoc.psc.as_ref().is_none_or(|p| listed(mdoc, p))
}

/// Whether the MSO lists the digest of `element` under its `digestID`.
fn listed<T>(mdoc: &NymAuthMdoc, element: &SignedElement<T>) -> bool {
    let digest = sha256(&element.bytes);
    mdoc.value_digests
        .iter()
        .any(|(id, d)| *id == element.digest_id && d.as_slice() == digest.as_slice())
}

/// Whether `signature` (`r ‖ s`) is an ES256 signature of `message` under `key`.
pub fn es256_verifies(key: &P256Key, message: &[u8], signature: &[u8; 64]) -> bool {
    let (Ok(key), Ok(signature)) = (
        VerifyingKey::from_sec1_bytes(&key.sec1()),
        Signature::from_slice(signature),
    ) else {
        return false;
    };
    key.verify(message, &signature).is_ok()
}

/// Whether `SHA-256(secret_seed)` is the credential's `ssc`.
pub fn opens_ssc(mdoc: &NymAuthMdoc, secret_seed: &[u8; 16]) -> bool {
    sha256(secret_seed) == mdoc.ssc.value
}
