//! A stored mdoc: its `IssuerSigned` and the MSO (ISO/IEC 18013-5, 8.3.2.1.2.2 and 9.1.2).

use rustc_hash::FxHashSet;
use siros_codec::base64url;
use siros_codec::cbor::{self, Item, Kind, Value};

use crate::error::MdocError;
use crate::issuer_auth::IssuerAuth;
use crate::mso::Mso;

/// An mdoc whose `Document` and items agree with its MSO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mdoc {
    issuer_signed: Vec<u8>,
    name_spaces: Vec<IssuerNameSpace>,
    issuer_auth: IssuerAuth,
    mso: Mso,
}

/// A namespace of `IssuerSigned` and its items, in the issuer's order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerNameSpace {
    name: String,
    items: Vec<IssuerSignedItem>,
}

/// An `IssuerSignedItem` whose digest the MSO lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerSignedItem {
    bytes: Vec<u8>,
    digest_id: u64,
    identifier: String,
    value: Value,
}

impl Mdoc {
    /// Reads base64url, without padding, of an `IssuerSigned`, of a `Document`, or of a
    /// `DeviceResponse` with one document.
    ///
    /// # Errors
    ///
    /// [`MdocError`]: the first part of the credential that breaks its structure or disagrees
    /// with the MSO.
    pub fn parse(data: &str) -> Result<Self, MdocError> {
        let bytes = base64url::decode(data).ok_or(MdocError::Encoding)?;
        let root = cbor::decode(&bytes).map_err(MdocError::Cbor)?;
        let (issuer_signed, doc_type) = envelope(&root)?;
        let auth = issuer_signed
            .get("issuerAuth")
            .ok_or(MdocError::IssuerAuth)?;
        let (issuer_auth, payload) = IssuerAuth::read(auth)?;
        let mso = Mso::read(payload)?;
        if doc_type.is_some_and(|d| d != mso.doc_type()) {
            return Err(MdocError::DocType);
        }
        let name_spaces = match issuer_signed.get("nameSpaces") {
            Some(spaces) => read_name_spaces(spaces, &mso)?,
            None => Vec::new(),
        };
        Ok(Self {
            issuer_signed: issuer_signed.raw.to_vec(),
            name_spaces,
            issuer_auth,
            mso,
        })
    }

    /// `docType`.
    pub fn doc_type(&self) -> &str {
        self.mso.doc_type()
    }

    /// The namespaces of `IssuerSigned`, in the issuer's order.
    pub fn name_spaces(&self) -> &[IssuerNameSpace] {
        &self.name_spaces
    }

    /// `issuerAuth`.
    pub fn issuer_auth(&self) -> &IssuerAuth {
        &self.issuer_auth
    }

    /// The MSO.
    pub fn mso(&self) -> &Mso {
        &self.mso
    }

    /// The encoded `IssuerSigned`.
    pub fn issuer_signed(&self) -> &[u8] {
        &self.issuer_signed
    }
}

impl IssuerNameSpace {
    /// The namespace.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Its items, in the issuer's order, each element identifier once.
    pub fn items(&self) -> &[IssuerSignedItem] {
        &self.items
    }
}

impl IssuerSignedItem {
    /// `IssuerSignedItemBytes`, `#6.24(bstr .cbor IssuerSignedItem)`, as the issuer wrote it.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// `digestID`.
    pub fn digest_id(&self) -> u64 {
        self.digest_id
    }

    /// `elementIdentifier`.
    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    /// `elementValue`.
    pub fn value(&self) -> &Value {
        &self.value
    }

    /// `IssuerSignedItem = {"digestID": uint, "random": bstr, "elementIdentifier": tstr,
    /// "elementValue": any}`.
    fn read(tagged: &Item<'_>) -> Result<Self, MdocError> {
        let inner = tagged
            .untag(24)
            .and_then(Item::as_bytes)
            .ok_or(MdocError::NameSpaces)?;
        let item = cbor::decode(inner).map_err(|_| MdocError::Item)?;
        let Some(Kind::Unsigned(digest_id)) = item.get("digestID").map(|d| &d.kind) else {
            return Err(MdocError::Item);
        };
        item.get("random")
            .and_then(Item::as_bytes)
            .ok_or(MdocError::Item)?;
        let identifier = item
            .get("elementIdentifier")
            .and_then(Item::as_text)
            .ok_or(MdocError::Item)?;
        let value = item.get("elementValue").ok_or(MdocError::Item)?;
        Ok(Self {
            bytes: tagged.raw.to_vec(),
            digest_id: *digest_id,
            identifier: identifier.to_owned(),
            value: Value::from_item(value),
        })
    }
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

/// `IssuerNameSpaces = {+ NameSpace => [+ IssuerSignedItemBytes]}`, each item with the digest
/// the MSO lists.
fn read_name_spaces(spaces: &Item<'_>, mso: &Mso) -> Result<Vec<IssuerNameSpace>, MdocError> {
    let entries = spaces
        .as_map()
        .filter(|entries| !entries.is_empty())
        .ok_or(MdocError::NameSpaces)?;
    let mut names = FxHashSet::default();
    let mut name_spaces = Vec::with_capacity(entries.len());
    for (name, items) in entries {
        let name = name.as_text().ok_or(MdocError::NameSpaces)?;
        if !names.insert(name) {
            return Err(MdocError::NameSpaces);
        }
        let items = items
            .as_array()
            .filter(|items| !items.is_empty())
            .ok_or(MdocError::NameSpaces)?;
        name_spaces.push(IssuerNameSpace {
            name: name.to_owned(),
            items: read_items(name, items, mso)?,
        });
    }
    Ok(name_spaces)
}

fn read_items(
    name_space: &str,
    items: &[Item<'_>],
    mso: &Mso,
) -> Result<Vec<IssuerSignedItem>, MdocError> {
    let mut identifiers = FxHashSet::default();
    let mut read = Vec::with_capacity(items.len());
    for tagged in items {
        let item = IssuerSignedItem::read(tagged)?;
        if !identifiers.insert(item.identifier.clone()) {
            return Err(MdocError::RepeatedElement);
        }
        let digest = mso.digest_algorithm().digest(&item.bytes);
        if mso.value_digest(name_space, item.digest_id) != Some(digest.as_slice()) {
            return Err(MdocError::ItemDigest);
        }
        read.push(item);
    }
    Ok(read)
}
