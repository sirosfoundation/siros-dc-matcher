//! An entry of the `transaction_data` request parameter (T1; OpenID4VP 1.0, Section 5.1).

use siros_codec::base64url;
use siros_codec::date::DateTime;
use siros_credential::Format;
use siros_dcql::{CredentialQuery, DcqlQuery, QueryId};
use siros_oid4vp::TransactionDataItem;

use crate::binding::Binding;
use crate::error::{MemberPath, TransactionDataError};
use crate::json::{self, Json, JsonError};
use crate::kind::{SupportedType, TransactionType};

/// A `transaction_data` entry of a supported type, its members parsed into typed values.
pub struct Entry {
    raw: TransactionDataItem,
    credential_ids: Vec<QueryId>,
    body: Box<dyn TransactionType>,
}

/// The paths of the members every entry has.
const TYPE: MemberPath = MemberPath::new("type");
const CREDENTIAL_IDS: MemberPath = MemberPath::new("credential_ids");

impl Entry {
    /// The entry `raw`, a string of the request's `transaction_data` array, against the
    /// request's `query`, at the time `now`.
    ///
    /// `raw` is base64url of a JSON object that repeats no member name in any object, with a
    /// string `type` and a non-empty array `credential_ids` of Credential Query ids of
    /// `query`. Its other members belong to its type, which refuses one it does not define.
    /// Each Credential Query named is of the format of the credentials that can authorize the
    /// type, and an SD-JWT VC query requires cryptographic holder binding (B.3.3). A rule of the
    /// type that depends on the time holds at `now`.
    ///
    /// # Errors
    ///
    /// [`TransactionDataError`]: the first rule `raw` breaks.
    pub fn parse(
        raw: &TransactionDataItem,
        query: &DcqlQuery,
        now: DateTime,
    ) -> Result<Self, TransactionDataError> {
        let bytes = base64url::decode(raw.as_str()).map_err(TransactionDataError::NotBase64url)?;
        let text = String::from_utf8(bytes).map_err(|_| TransactionDataError::NotJsonObject)?;
        let object = match Json::parse(&text) {
            Ok(Json::Object(object)) => object,
            Ok(_) | Err(JsonError::Malformed) => return Err(TransactionDataError::NotJsonObject),
            Err(JsonError::DuplicateKey) => return Err(TransactionDataError::DuplicateKey),
            Err(JsonError::TooDeep) => return Err(TransactionDataError::TooDeep),
        };
        let mut fields = object.into_fields();
        let identifier = json::text(fields.require("type", TYPE)?, TYPE)?;
        let named = credential_ids(fields.require("credential_ids", CREDENTIAL_IDS)?)?;
        let body = SupportedType::named(&identifier)
            .ok_or(TransactionDataError::UnsupportedType)?
            .parse(fields, now)?;
        let credential_ids = named
            .iter()
            .map(|id| {
                let credential = query
                    .credential(id)
                    .ok_or(TransactionDataError::UnknownCredentialId)?;
                authorizes(credential, body.format()).map(|()| credential.id.clone())
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            raw: raw.clone(),
            credential_ids,
            body,
        })
    }

    /// The `type` value.
    #[must_use]
    pub fn transaction_type(&self) -> SupportedType {
        self.body.identifier()
    }

    /// `credential_ids`: the Credential Query ids, at least one, in the verifier's order.
    #[must_use]
    pub fn credential_ids(&self) -> &[QueryId] {
        &self.credential_ids
    }

    /// Whether `credential_ids` names the Credential Query `id`.
    #[must_use]
    pub fn names(&self, id: &QueryId) -> bool {
        self.credential_ids.contains(id)
    }

    /// The string the request carried.
    pub(crate) fn raw(&self) -> &TransactionDataItem {
        &self.raw
    }

    /// The type of the entry.
    pub(crate) fn body(&self) -> &dyn TransactionType {
        self.body.as_ref()
    }

    /// What the entry binds into the presentation that authorizes it.
    pub(crate) fn binding(&self) -> Binding<'_> {
        self.body.binding()
    }
}

/// Refuses a Credential Query whose credentials cannot authorize a type of the format
/// `format`: a query of another format, or an SD-JWT VC query without cryptographic holder
/// binding (B.3.3).
fn authorizes(credential: &CredentialQuery, format: Format) -> Result<(), TransactionDataError> {
    if credential.format != format.identifier() {
        return Err(TransactionDataError::QueryFormat);
    }
    if credential.format == Format::SdJwtVc.identifier()
        && !credential.require_cryptographic_holder_binding
    {
        return Err(TransactionDataError::HolderBindingNotRequired);
    }
    Ok(())
}

/// `credential_ids`: a non-empty array of strings (Section 5.1).
fn credential_ids(value: Json) -> Result<Vec<String>, TransactionDataError> {
    let ids = json::array(value, CREDENTIAL_IDS)?
        .into_iter()
        .map(|id| json::text(id, CREDENTIAL_IDS))
        .collect::<Result<Vec<_>, _>>()?;
    if ids.is_empty() {
        return Err(TransactionDataError::InvalidValue(CREDENTIAL_IDS));
    }
    Ok(ids)
}
