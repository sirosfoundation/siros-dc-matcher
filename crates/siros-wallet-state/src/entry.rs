//! An entry of `S.credentials` (privatedata 3.1, Section 6.0).

use rustc_hash::FxHashMap;
use serde::de::DeserializeOwned;
use serde_json::value::RawValue;

use crate::error::WalletStateError;
use crate::ids::{BatchId, CredentialId, InstanceId, KeyId};

/// The members of a JSON object, each as its text. A repeated name keeps its last value, as
/// JavaScript's `JSON.parse` in `wallet-frontend` does.
pub(crate) type Members<'a> = FxHashMap<String, &'a RawValue>;

/// The members of the object `raw` holds.
pub(crate) fn object(raw: &RawValue) -> Option<Members<'_>> {
    serde_json::from_str(raw.get()).ok()
}

/// The elements of the array `raw` holds.
pub(crate) fn array(raw: &RawValue) -> Option<Vec<&RawValue>> {
    serde_json::from_str(raw.get()).ok()
}

/// `text`, or `None` for the empty string the wallet writes when it does not know a value.
pub(crate) fn known(text: String) -> Option<String> {
    (!text.is_empty()).then_some(text)
}

/// A credential entry: the eight members of Section 6.0 and its `metadata`.
pub struct CredentialEntry {
    credential_id: CredentialId,
    format: String,
    data: String,
    key_id: Option<KeyId>,
    instance_id: InstanceId,
    batch_id: BatchId,
    issuer: Option<String>,
    configuration_id: Option<String>,
    metadata: Vec<MetadataEntry>,
}

impl CredentialEntry {
    /// The entry `raw` holds: the members of Section 6.0 and `metadata`.
    pub(crate) fn parse(raw: &RawValue) -> Result<Self, WalletStateError> {
        let members = object(raw).ok_or(WalletStateError::CredentialEntry)?;
        Ok(Self {
            credential_id: CredentialId::new(member(&members, "credentialId")?),
            format: member(&members, "format")?,
            data: member(&members, "data")?,
            key_id: known(member(&members, "kid")?).map(KeyId::new),
            instance_id: InstanceId::new(member(&members, "instanceId")?),
            batch_id: BatchId::new(member(&members, "batchId")?),
            issuer: known(member(&members, "credentialIssuerIdentifier")?),
            configuration_id: known(member(&members, "credentialConfigurationId")?),
            metadata: match members.get("metadata") {
                Some(raw) => metadata(raw)?,
                None => Vec::new(),
            },
        })
    }

    /// `credentialId`.
    pub fn credential_id(&self) -> CredentialId {
        self.credential_id
    }

    /// `format`: the credential format identifier, for example `dc+sd-jwt`.
    pub fn format(&self) -> &str {
        &self.format
    }

    /// `data`: the stored credential, in the serialization of its format.
    pub fn data(&self) -> &str {
        &self.data
    }

    /// `kid`: the key pair the credential is bound to. `None` when the entry names none.
    pub fn key_id(&self) -> Option<&KeyId> {
        self.key_id.as_ref()
    }

    /// `instanceId`.
    pub fn instance_id(&self) -> InstanceId {
        self.instance_id
    }

    /// `batchId`.
    pub fn batch_id(&self) -> BatchId {
        self.batch_id
    }

    /// `credentialIssuerIdentifier`. `None` when the wallet did not know it.
    pub fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    /// `credentialConfigurationId`. `None` when the wallet did not know it.
    pub fn configuration_id(&self) -> Option<&str> {
        self.configuration_id.as_deref()
    }

    /// `metadata`, in its order. An absent member and an empty array both give no entry.
    pub fn metadata(&self) -> &[MetadataEntry] {
        &self.metadata
    }
}

/// The member `name` of `members`, as a `T`.
fn member<T: DeserializeOwned>(
    members: &Members<'_>,
    name: &'static str,
) -> Result<T, WalletStateError> {
    members
        .get(name)
        .and_then(|raw| serde_json::from_str(raw.get()).ok())
        .ok_or(WalletStateError::CredentialMember(name))
}

/// An entry of `metadata`: data a counterparty supplied for this credential entry.
pub struct MetadataEntry {
    kind: String,
    value: MetadataValue,
}

impl MetadataEntry {
    /// `type`. Its consumer defines the meaning of `value`.
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// `value`.
    pub fn value(&self) -> &MetadataValue {
        &self.value
    }
}

/// A `metadata` value as the container holds it. It may hold a delivered secret (privatedata
/// 3.1, Section 5A).
#[derive(Clone)]
pub struct MetadataValue(Box<RawValue>);

impl MetadataValue {
    /// The JSON text of the value, exactly as the container holds it.
    pub fn json(&self) -> &str {
        self.0.get()
    }
}

/// The entries of the `metadata` member `raw`.
fn metadata(raw: &RawValue) -> Result<Vec<MetadataEntry>, WalletStateError> {
    let entries = array(raw).ok_or(WalletStateError::Metadata)?;
    entries
        .into_iter()
        .map(|entry| {
            let members = object(entry).ok_or(WalletStateError::Metadata)?;
            let kind = members
                .get("type")
                .and_then(|kind| serde_json::from_str::<String>(kind.get()).ok())
                .and_then(known)
                .ok_or(WalletStateError::Metadata)?;
            let value = members.get("value").ok_or(WalletStateError::Metadata)?;
            Ok(MetadataEntry {
                kind,
                value: MetadataValue((*value).to_owned()),
            })
        })
        .collect()
}
