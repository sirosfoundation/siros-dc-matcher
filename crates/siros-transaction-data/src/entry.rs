//! An entry of the `transaction_data` request parameter (T1; OpenID4VP 1.0, Section 5.1).

use siros_codec::base64url;
use siros_credential::Format;
use siros_dcql::DcqlQuery;

use crate::binding::Binding;
use crate::error::TransactionDataError;
use crate::json::{self, Json, JsonError};
use crate::kind::{self, TransactionType};

/// A `transaction_data` entry of a supported type, its members parsed into typed values.
pub struct Entry {
    raw: String,
    credential_ids: Vec<String>,
    body: Box<dyn TransactionType>,
}

impl Entry {
    /// The entry `raw`, a string of the request's `transaction_data` array, against the
    /// request's `query`.
    ///
    /// `raw` is base64url of a JSON object that repeats no member name in any object, with a
    /// string `type` and a non-empty array `credential_ids` of Credential Query ids of
    /// `query`. Its other members belong to its type, which refuses one it does not define.
    /// Each Credential Query named is of the format of the credentials that can authorize the
    /// type, and an SD-JWT VC query requires cryptographic holder binding (B.3.3).
    ///
    /// # Errors
    ///
    /// [`TransactionDataError`]: the first rule `raw` breaks.
    pub fn parse(raw: &str, query: &DcqlQuery) -> Result<Self, TransactionDataError> {
        let bytes = base64url::decode(raw).ok_or(TransactionDataError::NotBase64url)?;
        let text = String::from_utf8(bytes).map_err(|_| TransactionDataError::NotJsonObject)?;
        let object = match Json::parse(&text) {
            Ok(Json::Object(object)) => object,
            Ok(_) | Err(JsonError::Malformed) => return Err(TransactionDataError::NotJsonObject),
            Err(JsonError::DuplicateKey) => return Err(TransactionDataError::DuplicateKey),
            Err(JsonError::TooDeep) => return Err(TransactionDataError::TooDeep),
        };
        let mut fields = object.into_fields();
        let identifier = json::text(fields.require("type", "type")?, "type")?;
        let credential_ids = credential_ids(fields.require("credential_ids", "credential_ids")?)?;
        let body = kind::parse(&identifier, fields)?;
        for id in &credential_ids {
            let credential = query
                .credential(id)
                .ok_or(TransactionDataError::UnknownCredentialId)?;
            if credential.format != body.format().identifier() {
                return Err(TransactionDataError::QueryFormat);
            }
            if credential.format == Format::SdJwtVc.identifier()
                && !credential.require_cryptographic_holder_binding
            {
                return Err(TransactionDataError::HolderBindingNotRequired);
            }
        }
        Ok(Self {
            raw: raw.to_owned(),
            credential_ids,
            body,
        })
    }

    /// The `type` value.
    #[must_use]
    pub fn transaction_type(&self) -> &'static str {
        self.body.identifier()
    }

    /// `credential_ids`: the Credential Query ids, at least one, in the verifier's order.
    #[must_use]
    pub fn credential_ids(&self) -> &[String] {
        &self.credential_ids
    }

    /// The string the request carried.
    pub(crate) fn raw(&self) -> &str {
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

/// `credential_ids`: a non-empty array of strings (Section 5.1).
fn credential_ids(value: Json) -> Result<Vec<String>, TransactionDataError> {
    const PATH: &str = "credential_ids";
    let ids = json::array(value, PATH)?
        .into_iter()
        .map(|id| json::text(id, PATH))
        .collect::<Result<Vec<_>, _>>()?;
    if ids.is_empty() {
        return Err(TransactionDataError::InvalidValue(PATH));
    }
    Ok(ids)
}
