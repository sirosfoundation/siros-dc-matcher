//! The `vp_token` (OpenID4VP 1.0, Section 8.1) and the Authorization Response that carries it,
//! in JSON and in CBOR (`zkp_req.md`, Section 6.1).

use serde_json::{Map, Value};
use siros_codec::base64url;
use siros_codec::cbor::{self, Value as Cbor};

use super::ResponseError;
use crate::error_code::ErrorCode;
use crate::verified::VerifiedRequest;

/// One presentation of a `vp_token`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Presentation(Form);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Form {
    /// A presentation that is a string, as SD-JWT VC and mdoc presentations are.
    Text(String),
    /// A presentation that is a CBOR map, as a `zkp_req` `ZkpPresentation` is, encoded.
    Cbor(Vec<u8>),
}

impl Presentation {
    /// A presentation that is a string; it is the same string in JSON and in CBOR.
    #[must_use]
    pub fn text(text: String) -> Self {
        Self(Form::Text(text))
    }

    /// A presentation that is a CBOR map: in CBOR the map itself, in JSON the base64url of its
    /// encoding (`zkp_req.md`, Section 6.1).
    ///
    /// # Errors
    ///
    /// [`ResponseError::PresentationNotCborMap`] when `encoded` is not one CBOR map in the
    /// strict encoding of `siros-codec`.
    pub fn cbor_map(encoded: Vec<u8>) -> Result<Self, ResponseError> {
        match cbor::decode(&encoded) {
            Ok(item) if item.as_map().is_some() => Ok(Self(Form::Cbor(encoded))),
            _ => Err(ResponseError::PresentationNotCborMap),
        }
    }

    fn json(&self) -> Value {
        match &self.0 {
            Form::Text(text) => Value::String(text.clone()),
            Form::Cbor(encoded) => Value::String(base64url::encode(encoded)),
        }
    }

    fn cbor(&self) -> Cbor {
        match &self.0 {
            Form::Text(text) => Cbor::text(text),
            Form::Cbor(encoded) => Cbor::Encoded(encoded.clone()),
        }
    }
}

/// A `vp_token` for one verified request (Section 8.1).
///
/// Its existence guarantees that each key is the `id` of a Credential Query of the request,
/// once, with at least one presentation, and exactly one unless the query sets `multiple`.
#[derive(Debug, Clone)]
pub struct VpToken<'r> {
    pub(super) request: &'r VerifiedRequest,
    entries: Vec<(String, Vec<Presentation>)>,
}

impl VerifiedRequest {
    /// The `vp_token` of `entries`: the presentations answering each Credential Query, by its
    /// `id`.
    ///
    /// # Errors
    ///
    /// [`ResponseError`]: the first rule of Section 8.1 an entry breaks.
    pub fn vp_token(
        &self,
        entries: Vec<(String, Vec<Presentation>)>,
    ) -> Result<VpToken<'_>, ResponseError> {
        for (index, (id, presentations)) in entries.iter().enumerate() {
            let query = self
                .dcql_query
                .credential(id)
                .ok_or(ResponseError::UnknownQueryId)?;
            match presentations.len() {
                0 => return Err(ResponseError::NoPresentation),
                1 => {}
                _ if !query.multiple => return Err(ResponseError::MultipleNotAllowed),
                _ => {}
            }
            if entries.iter().take(index).any(|(earlier, _)| earlier == id) {
                return Err(ResponseError::DuplicateQueryId);
            }
        }
        Ok(VpToken {
            request: self,
            entries,
        })
    }
}

/// What an Authorization Response answers (Section 8.1, 8.5): a `vp_token` or an error.
pub(super) enum Answer<'a> {
    VpToken(&'a VpToken<'a>),
    Error(ErrorCode),
}

impl Answer<'_> {
    /// The response parameters in JSON, with `state` when given.
    pub(super) fn json(&self, state: Option<&str>) -> Map<String, Value> {
        let mut parameters = Map::new();
        match self {
            Self::VpToken(token) => {
                let token = token
                    .entries
                    .iter()
                    .map(|(id, presentations)| {
                        let list = presentations.iter().map(Presentation::json).collect();
                        (id.clone(), Value::Array(list))
                    })
                    .collect();
                parameters.insert("vp_token".into(), Value::Object(token));
            }
            Self::Error(code) => {
                parameters.insert("error".into(), code.as_str().into());
            }
        }
        if let Some(state) = state {
            parameters.insert("state".into(), state.into());
        }
        parameters
    }

    /// The Authorization Response in CBOR (`zkp_req.md`, Section 6.1), with `state` when given.
    pub(super) fn cbor(&self, state: Option<&str>) -> Cbor {
        let mut members = vec![match self {
            Self::VpToken(token) => {
                let token = token
                    .entries
                    .iter()
                    .map(|(id, presentations)| {
                        let list = presentations.iter().map(Presentation::cbor).collect();
                        (Cbor::text(id), Cbor::Array(list))
                    })
                    .collect();
                (Cbor::text("vp_token"), Cbor::Map(token))
            }
            Self::Error(code) => (Cbor::text("error"), Cbor::text(code.as_str())),
        }];
        if let Some(state) = state {
            members.push((Cbor::text("state"), Cbor::text(state)));
        }
        Cbor::Map(members)
    }
}
