//! The `MobileSecurityObject` (ISO/IEC 18013-5, 9.1.2.4).

use rustc_hash::{FxHashMap, FxHashSet};
use sha2::{Digest, Sha256, Sha384, Sha512};
use siros_codec::cbor::{self, Item, Kind};
use siros_codec::date::DateTime;

use crate::error::MdocError;

/// The MSO the issuer signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mso {
    doc_type: String,
    digest_algorithm: DigestAlgorithm,
    value_digests: FxHashMap<String, FxHashMap<u64, Vec<u8>>>,
    device_key: P256Key,
    key_authorizations: KeyAuthorizations,
    validity: Validity,
}

impl Mso {
    /// `MobileSecurityObjectBytes = #6.24(bstr .cbor MobileSecurityObject)`.
    pub(crate) fn read(payload: &[u8]) -> Result<Self, MdocError> {
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
        let digest_algorithm = mso
            .get("digestAlgorithm")
            .and_then(Item::as_text)
            .and_then(DigestAlgorithm::from_name)
            .ok_or(MdocError::DigestAlgorithm)?;
        let device_key_info = mso.get("deviceKeyInfo").ok_or(MdocError::DeviceKey)?;
        Ok(Self {
            doc_type: doc_type.to_owned(),
            digest_algorithm,
            value_digests: read_value_digests(mso.get("valueDigests"), digest_algorithm)?,
            device_key: read_device_key(device_key_info.get("deviceKey"))?,
            key_authorizations: KeyAuthorizations::read(device_key_info.get("keyAuthorizations"))?,
            validity: Validity::read(mso.get("validityInfo"))?,
        })
    }

    /// `docType`.
    pub fn doc_type(&self) -> &str {
        &self.doc_type
    }

    /// `digestAlgorithm`.
    pub fn digest_algorithm(&self) -> DigestAlgorithm {
        self.digest_algorithm
    }

    /// The digest `valueDigests` lists for `digest_id` of `name_space`.
    pub fn value_digest(&self, name_space: &str, digest_id: u64) -> Option<&[u8]> {
        self.value_digests
            .get(name_space)
            .and_then(|digests| digests.get(&digest_id))
            .map(Vec::as_slice)
    }

    /// `deviceKeyInfo.deviceKey`.
    pub fn device_key(&self) -> &P256Key {
        &self.device_key
    }

    /// `deviceKeyInfo.keyAuthorizations`; none when it is absent.
    pub fn key_authorizations(&self) -> &KeyAuthorizations {
        &self.key_authorizations
    }

    /// `validityInfo`.
    pub fn validity(&self) -> &Validity {
        &self.validity
    }
}

/// A digest algorithm of `digestAlgorithm` (ISO/IEC 18013-5, 9.1.2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DigestAlgorithm {
    /// `SHA-256`.
    Sha256,
    /// `SHA-384`.
    Sha384,
    /// `SHA-512`.
    Sha512,
}

impl DigestAlgorithm {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "SHA-256" => Some(Self::Sha256),
            "SHA-384" => Some(Self::Sha384),
            "SHA-512" => Some(Self::Sha512),
            _ => None,
        }
    }

    fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// The digest of `bytes`.
    pub(crate) fn digest(self, bytes: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(bytes).to_vec(),
            Self::Sha384 => Sha384::digest(bytes).to_vec(),
            Self::Sha512 => Sha512::digest(bytes).to_vec(),
        }
    }
}

/// `ValueDigests = {+ NameSpace => {+ DigestID => Digest}}`.
fn read_value_digests(
    item: Option<&Item<'_>>,
    algorithm: DigestAlgorithm,
) -> Result<FxHashMap<String, FxHashMap<u64, Vec<u8>>>, MdocError> {
    let name_spaces = non_empty_map(item).ok_or(MdocError::ValueDigests)?;
    let mut value_digests = FxHashMap::default();
    for (name_space, digests) in name_spaces {
        let name_space = name_space.as_text().ok_or(MdocError::ValueDigests)?;
        let digests = non_empty_map(Some(digests)).ok_or(MdocError::ValueDigests)?;
        let mut by_id = FxHashMap::default();
        for (id, digest) in digests {
            let (Kind::Unsigned(id), Some(digest)) = (id.kind(), digest.as_bytes()) else {
                return Err(MdocError::ValueDigests);
            };
            if digest.len() != algorithm.output_len()
                || by_id.insert(*id, digest.to_vec()).is_some()
            {
                return Err(MdocError::ValueDigests);
            }
        }
        if value_digests.insert(name_space.to_owned(), by_id).is_some() {
            return Err(MdocError::ValueDigests);
        }
    }
    Ok(value_digests)
}

fn non_empty_map<'i, 'a>(item: Option<&'i Item<'a>>) -> Option<&'i [(Item<'a>, Item<'a>)]> {
    item.and_then(Item::as_map)
        .filter(|entries| !entries.is_empty())
}

/// A P-256 public key: its coordinates, big-endian.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct P256Key {
    pub(crate) x: [u8; 32],
    pub(crate) y: [u8; 32],
}

impl P256Key {
    /// The key of the big-endian coordinates `x` and `y`.
    pub fn new(x: [u8; 32], y: [u8; 32]) -> Self {
        Self { x, y }
    }

    /// The x-coordinate.
    pub fn x(&self) -> &[u8; 32] {
        &self.x
    }

    /// The y-coordinate.
    pub fn y(&self) -> &[u8; 32] {
        &self.y
    }

    /// The uncompressed SEC 1 point.
    pub fn sec1(&self) -> [u8; 65] {
        let mut point = [0x04; 65];
        for (slot, byte) in point.iter_mut().skip(1).zip(self.x.iter().chain(&self.y)) {
            *slot = *byte;
        }
        point
    }
}

/// `COSE_Key` of an EC2 P-256 key: `{1: 2, -1: 1, -2: x, -3: y}` (RFC 9053, Section 7.1).
fn read_device_key(key: Option<&Item<'_>>) -> Result<P256Key, MdocError> {
    let key = key.ok_or(MdocError::DeviceKey)?;
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

/// The elements the device key may sign in `DeviceSigned` (ISO/IEC 18013-5, 9.1.2.4):
/// every element of the namespaces of `nameSpaces`, and the elements `dataElements` names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyAuthorizations {
    name_spaces: FxHashSet<String>,
    data_elements: FxHashMap<String, FxHashSet<String>>,
}

impl KeyAuthorizations {
    /// `KeyAuthorizations = {? "nameSpaces": [+ NameSpace], ? "dataElements": {+ NameSpace =>
    /// [+ DataElementIdentifier]}}`. A namespace authorized whole is not also in `dataElements`.
    fn read(item: Option<&Item<'_>>) -> Result<Self, MdocError> {
        let Some(item) = item else {
            return Ok(Self::default());
        };
        if item.as_map().is_none() {
            return Err(MdocError::KeyAuthorizations);
        }
        let name_spaces = match item.get("nameSpaces") {
            Some(names) => names_once(names)?,
            None => FxHashSet::default(),
        };
        let mut data_elements = FxHashMap::default();
        if let Some(elements) = item.get("dataElements") {
            let entries = non_empty_map(Some(elements)).ok_or(MdocError::KeyAuthorizations)?;
            for (name_space, identifiers) in entries {
                let name_space = name_space.as_text().ok_or(MdocError::KeyAuthorizations)?;
                if name_spaces.contains(name_space)
                    || data_elements
                        .insert(name_space.to_owned(), names_once(identifiers)?)
                        .is_some()
                {
                    return Err(MdocError::KeyAuthorizations);
                }
            }
        }
        Ok(Self {
            name_spaces,
            data_elements,
        })
    }
}

/// A non-empty array of text strings, each once.
fn names_once(item: &Item<'_>) -> Result<FxHashSet<String>, MdocError> {
    let names = item
        .as_array()
        .filter(|names| !names.is_empty())
        .ok_or(MdocError::KeyAuthorizations)?;
    let mut set = FxHashSet::default();
    for name in names {
        let name = name.as_text().ok_or(MdocError::KeyAuthorizations)?;
        if !set.insert(name.to_owned()) {
            return Err(MdocError::KeyAuthorizations);
        }
    }
    Ok(set)
}

/// `validityInfo`: `signed ≤ validFrom < validUntil` (ISO/IEC 18013-5, 9.1.2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Validity {
    signed: DateTime,
    valid_from: DateTime,
    valid_until: DateTime,
}

impl Validity {
    fn read(item: Option<&Item<'_>>) -> Result<Self, MdocError> {
        let validity = item.ok_or(MdocError::Validity)?;
        let time = |name: &str| -> Result<DateTime, MdocError> {
            validity
                .get(name)
                .and_then(|t| t.untag(0))
                .and_then(Item::as_text)
                .and_then(DateTime::parse)
                .ok_or(MdocError::Validity)
        };
        let (signed, valid_from, valid_until) =
            (time("signed")?, time("validFrom")?, time("validUntil")?);
        if valid_from < signed || valid_until <= valid_from {
            return Err(MdocError::Validity);
        }
        Ok(Self {
            signed,
            valid_from,
            valid_until,
        })
    }

    /// `signed`: when the issuer signed the MSO.
    pub fn signed(&self) -> DateTime {
        self.signed
    }

    /// `validFrom`: the MSO is valid from this second.
    pub fn valid_from(&self) -> DateTime {
        self.valid_from
    }

    /// `validUntil`: the MSO is valid before this second.
    pub fn valid_until(&self) -> DateTime {
        self.valid_until
    }
}
