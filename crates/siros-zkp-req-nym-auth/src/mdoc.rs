//! The ISO/IEC 18013-5 form of the attestation (nym_auth catalogue, "Attestation" and
//! "ISO/IEC 18013-5 encoding"), read from a stored credential.

use std::fmt;

use siros_zkp_req::base64url;
use siros_zkp_req::cbor::{self, CborError, Item, Kind};

use crate::catalogue::MDOC_DOCTYPE;
use crate::date::{Date, DateTime};

/// The largest stored credential read, in bytes.
pub const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;

/// A credential as the Wallet stores it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCredential {
    /// The Wallet's identifier.
    pub id: String,
    /// The credential format, `mso_mdoc` here.
    pub format: String,
    /// The credential as issued: base64url, without padding, of an `IssuerSigned`, of a
    /// `Document`, or of a `DeviceResponse` with one document.
    pub data: String,
    /// The identifier of the device key, for `sign`.
    pub kid: String,
}

/// The part of an `mso_mdoc` that is unreadable, or out of the nym_auth form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MdocError {
    /// `data` is not base64url without padding, or is too long.
    Encoding,
    /// The bytes are not one CBOR item the strict reader accepts.
    Cbor(CborError),
    /// The top level is no `IssuerSigned`, `Document` or one-document `DeviceResponse`.
    Envelope,
    /// `issuerAuth` is not a `COSE_Sign1` array.
    IssuerAuth,
    /// The protected header does not name ES256 (`{1: -7}`).
    Algorithm,
    /// The unprotected header has no `x5chain` (label 33) of DER certificates.
    X5chain,
    /// The signature is not 64 bytes.
    Signature,
    /// The payload is not `#6.24(bstr .cbor MobileSecurityObject)`.
    Payload,
    /// `docType` is missing, or the MSO's and the document's differ.
    DocType,
    /// `digestAlgorithm` is not `SHA-256`.
    DigestAlgorithm,
    /// `valueDigests` has no map of digests for the nym_auth namespace.
    ValueDigests,
    /// `deviceKeyInfo.deviceKey` is no P-256 `COSE_Key` with 32-byte coordinates.
    DeviceKey,
    /// `validityInfo` lacks `signed`, `validFrom` or `validUntil` as a 20-character `tdate`.
    Validity,
    /// The nym_auth namespace is missing or holds something other than `IssuerSignedItemBytes`.
    NameSpace,
    /// An element other than `birth_date`, `ssc` and `psc`, or one of them twice.
    Element,
    /// `birth_date` is missing or not a tag-1004 `full-date`.
    BirthDate,
    /// `ssc` is missing or not 32 bytes.
    Ssc,
}

impl fmt::Display for MdocError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "mso_mdoc: {self:?}")
    }
}

impl std::error::Error for MdocError {}

/// A signed data element and the bytes its digest covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedElement<T> {
    /// The element's value.
    pub value: T,
    /// `digestID`.
    pub digest_id: u64,
    /// `IssuerSignedItemBytes`: the tag-24 item, as issued.
    pub bytes: Vec<u8>,
}

/// A P-256 public key, coordinates big-endian.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct P256Key {
    /// x.
    pub x: [u8; 32],
    /// y.
    pub y: [u8; 32],
}

impl P256Key {
    /// The uncompressed SEC 1 point.
    pub fn sec1(&self) -> [u8; 65] {
        let mut point = [0u8; 65];
        point[0] = 0x04;
        point[1..33].copy_from_slice(&self.x);
        point[33..].copy_from_slice(&self.y);
        point
    }
}

/// A nym_auth attestation in the ISO/IEC 18013-5 form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NymAuthMdoc {
    /// The `IssuerSigned` structure, as issued.
    pub issuer_signed: Vec<u8>,
    /// The COSE `Sig_structure` the issuer signed.
    pub sig_structure: Vec<u8>,
    /// The issuer's ES256 signature, `r ‖ s`.
    pub issuer_signature: [u8; 64],
    /// `x5chain`, the Document Signer certificate first.
    pub x5chain: Vec<Vec<u8>>,
    /// The digests of the nym_auth namespace, by `digestID`.
    pub value_digests: Vec<(u64, Vec<u8>)>,
    /// `deviceKeyInfo.deviceKey`.
    pub device_key: P256Key,
    /// `validityInfo.validFrom`.
    pub valid_from: DateTime,
    /// `validityInfo.validUntil`.
    pub valid_until: DateTime,
    /// `birth_date`.
    pub birth_date: SignedElement<Date>,
    /// `ssc`.
    pub ssc: SignedElement<[u8; 32]>,
    /// `psc`, when issued.
    pub psc: Option<SignedElement<[u8; 32]>>,
}

/// Whether a stored credential is a nym_auth mdoc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reading {
    /// It is.
    NymAuth(Box<NymAuthMdoc>),
    /// It is an mdoc of another `docType`.
    OtherDocType,
}

/// Reads `data` of a stored `mso_mdoc` credential.
///
/// # Errors
///
/// [`MdocError`]: what makes the credential unreadable or puts it out of the nym_auth form.
pub fn read(data: &str) -> Result<Reading, MdocError> {
    if data.len() > MAX_CREDENTIAL_BYTES * 4 / 3 + 4 {
        return Err(MdocError::Encoding);
    }
    let bytes = base64url::decode(data).ok_or(MdocError::Encoding)?;
    let root = cbor::decode(&bytes).map_err(MdocError::Cbor)?;
    let (issuer_signed, doc_type) = envelope(&root)?;
    let auth = issuer_signed
        .get("issuerAuth")
        .ok_or(MdocError::IssuerAuth)?;
    let signed = read_issuer_auth(auth)?;
    let mso = read_mso(signed.payload)?;
    if doc_type.is_some_and(|d| d != mso.doc_type) {
        return Err(MdocError::DocType);
    }
    if mso.doc_type != MDOC_DOCTYPE {
        return Ok(Reading::OtherDocType);
    }
    let spaces = issuer_signed
        .get("nameSpaces")
        .ok_or(MdocError::NameSpace)?;
    let elements = read_elements(spaces)?;
    Ok(Reading::NymAuth(Box::new(NymAuthMdoc {
        issuer_signed: issuer_signed.raw.to_vec(),
        sig_structure: signed.sig_structure,
        issuer_signature: signed.signature,
        x5chain: signed.x5chain,
        value_digests: mso.value_digests,
        device_key: mso.device_key,
        valid_from: mso.valid_from,
        valid_until: mso.valid_until,
        birth_date: elements.birth_date.ok_or(MdocError::BirthDate)?,
        ssc: elements.ssc.ok_or(MdocError::Ssc)?,
        psc: elements.psc,
    })))
}

/// The `IssuerSigned` map, and the `Document`'s `docType` when there is one.
fn envelope<'i, 'a>(root: &'i Item<'a>) -> Result<(&'i Item<'a>, Option<&'a str>), MdocError> {
    if root.get("issuerAuth").is_some() {
        return Ok((root, None));
    }
    let document = match root.get("documents").and_then(Item::as_array) {
        Some([document]) => document,
        Some(_) => return Err(MdocError::Envelope),
        None => root,
    };
    let issuer_signed = document.get("issuerSigned").ok_or(MdocError::Envelope)?;
    let doc_type = document
        .get("docType")
        .and_then(Item::as_text)
        .ok_or(MdocError::DocType)?;
    Ok((issuer_signed, Some(doc_type)))
}

struct IssuerAuth<'a> {
    sig_structure: Vec<u8>,
    signature: [u8; 64],
    x5chain: Vec<Vec<u8>>,
    payload: &'a [u8],
}

/// `COSE_Sign1 = [protected: bstr, unprotected: map, payload: bstr, signature: bstr]`.
fn read_issuer_auth<'a>(auth: &Item<'a>) -> Result<IssuerAuth<'a>, MdocError> {
    let Some([protected, unprotected, payload, signature]) = auth.as_array() else {
        return Err(MdocError::IssuerAuth);
    };
    let header = protected
        .as_bytes()
        .and_then(|b| cbor::decode(b).ok())
        .ok_or(MdocError::Algorithm)?;
    if header.get_int(1).and_then(Item::as_int) != Some(-7) {
        return Err(MdocError::Algorithm);
    }
    let x5chain = read_x5chain(unprotected.get_int(33).ok_or(MdocError::X5chain)?)?;
    let payload_bytes = payload.as_bytes().ok_or(MdocError::Payload)?;
    let signature: [u8; 64] = signature
        .as_bytes()
        .and_then(|s| s.try_into().ok())
        .ok_or(MdocError::Signature)?;
    // RFC 9052, Section 4.4: ["Signature1", protected, external_aad = h'', payload], with the
    // protected header and the payload as issued.
    let sig_structure = [
        &[0x84, 0x6a][..],
        b"Signature1",
        protected.raw,
        &[0x40],
        payload.raw,
    ]
    .concat();
    Ok(IssuerAuth {
        sig_structure,
        signature,
        x5chain,
        payload: payload_bytes,
    })
}

/// `x5chain`: one DER certificate, or an array of them, the signer's first (RFC 9360).
fn read_x5chain(item: &Item<'_>) -> Result<Vec<Vec<u8>>, MdocError> {
    match &item.kind {
        Kind::Bytes(der) => Ok(vec![der.to_vec()]),
        Kind::Array(items) if !items.is_empty() => items
            .iter()
            .map(|c| c.as_bytes().map(<[u8]>::to_vec).ok_or(MdocError::X5chain))
            .collect(),
        _ => Err(MdocError::X5chain),
    }
}

struct Mso {
    doc_type: String,
    value_digests: Vec<(u64, Vec<u8>)>,
    device_key: P256Key,
    valid_from: DateTime,
    valid_until: DateTime,
}

/// `MobileSecurityObjectBytes = #6.24(bstr .cbor MobileSecurityObject)`.
fn read_mso(payload: &[u8]) -> Result<Mso, MdocError> {
    let tagged = cbor::decode(payload).map_err(|_| MdocError::Payload)?;
    let inner = tagged
        .untag(24)
        .and_then(Item::as_bytes)
        .ok_or(MdocError::Payload)?;
    let mso = cbor::decode(inner).map_err(|_| MdocError::Payload)?;
    let doc_type = mso
        .get("docType")
        .and_then(Item::as_text)
        .ok_or(MdocError::DocType)?;
    if mso.get("digestAlgorithm").and_then(Item::as_text) != Some("SHA-256") {
        return Err(MdocError::DigestAlgorithm);
    }
    let validity = mso.get("validityInfo").ok_or(MdocError::Validity)?;
    let time = |name: &str| -> Result<DateTime, MdocError> {
        validity
            .get(name)
            .and_then(|t| t.untag(0))
            .and_then(Item::as_text)
            .and_then(DateTime::parse)
            .ok_or(MdocError::Validity)
    };
    time("signed")?;
    Ok(Mso {
        doc_type: doc_type.to_owned(),
        value_digests: read_digests(mso.get("valueDigests"))?,
        device_key: read_device_key(mso.get("deviceKeyInfo"))?,
        valid_from: time("validFrom")?,
        valid_until: time("validUntil")?,
    })
}

fn read_digests(value_digests: Option<&Item<'_>>) -> Result<Vec<(u64, Vec<u8>)>, MdocError> {
    let entries = value_digests
        .and_then(|v| v.get(MDOC_DOCTYPE))
        .and_then(Item::as_map)
        .ok_or(MdocError::ValueDigests)?;
    entries
        .iter()
        .map(|(id, digest)| match (&id.kind, digest.as_bytes()) {
            (Kind::Unsigned(id), Some(d)) => Ok((*id, d.to_vec())),
            _ => Err(MdocError::ValueDigests),
        })
        .collect()
}

/// `COSE_Key` of an EC2 P-256 key: `{1: 2, -1: 1, -2: x, -3: y}`.
fn read_device_key(info: Option<&Item<'_>>) -> Result<P256Key, MdocError> {
    let key = info
        .and_then(|i| i.get("deviceKey"))
        .ok_or(MdocError::DeviceKey)?;
    let int = |label: i64| key.get_int(label).and_then(Item::as_int);
    if int(1) != Some(2) || int(-1) != Some(1) {
        return Err(MdocError::DeviceKey);
    }
    let coordinate = |label: i64| -> Result<[u8; 32], MdocError> {
        key.get_int(label)
            .and_then(Item::as_bytes)
            .and_then(|c| c.try_into().ok())
            .ok_or(MdocError::DeviceKey)
    };
    Ok(P256Key {
        x: coordinate(-2)?,
        y: coordinate(-3)?,
    })
}

#[derive(Default)]
struct Elements {
    birth_date: Option<SignedElement<Date>>,
    ssc: Option<SignedElement<[u8; 32]>>,
    psc: Option<SignedElement<[u8; 32]>>,
}

/// The nym_auth namespace: `birth_date`, `ssc` and an optional `psc`, each once.
fn read_elements(spaces: &Item<'_>) -> Result<Elements, MdocError> {
    let items = spaces
        .get(MDOC_DOCTYPE)
        .and_then(Item::as_array)
        .ok_or(MdocError::NameSpace)?;
    let mut elements = Elements::default();
    for tagged in items {
        let item_bytes = tagged
            .untag(24)
            .and_then(Item::as_bytes)
            .ok_or(MdocError::NameSpace)?;
        let item = cbor::decode(item_bytes).map_err(|_| MdocError::NameSpace)?;
        let digest_id = match item.get("digestID").map(|d| &d.kind) {
            Some(Kind::Unsigned(id)) => *id,
            _ => return Err(MdocError::NameSpace),
        };
        let value = item.get("elementValue").ok_or(MdocError::NameSpace)?;
        let identifier = item.get("elementIdentifier").and_then(Item::as_text);
        let bytes = tagged.raw.to_vec();
        match identifier {
            Some("birth_date") => {
                let date = value
                    .untag(1004)
                    .and_then(Item::as_text)
                    .and_then(Date::parse)
                    .ok_or(MdocError::BirthDate)?;
                put(
                    &mut elements.birth_date,
                    SignedElement {
                        value: date,
                        digest_id,
                        bytes,
                    },
                )?;
            }
            Some("ssc") => put(
                &mut elements.ssc,
                commitment(value, digest_id, bytes, MdocError::Ssc)?,
            )?,
            Some("psc") => put(
                &mut elements.psc,
                commitment(value, digest_id, bytes, MdocError::Element)?,
            )?,
            _ => return Err(MdocError::Element),
        }
    }
    Ok(elements)
}

fn commitment(
    value: &Item<'_>,
    digest_id: u64,
    bytes: Vec<u8>,
    error: MdocError,
) -> Result<SignedElement<[u8; 32]>, MdocError> {
    let value: [u8; 32] = value
        .as_bytes()
        .and_then(|b| b.try_into().ok())
        .ok_or(error)?;
    Ok(SignedElement {
        value,
        digest_id,
        bytes,
    })
}

fn put<T>(slot: &mut Option<T>, element: T) -> Result<(), MdocError> {
    if slot.is_some() {
        return Err(MdocError::Element);
    }
    *slot = Some(element);
    Ok(())
}
