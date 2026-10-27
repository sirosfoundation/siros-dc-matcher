//! The key set of an SD-JWT VC issuer, resolved through its JWT VC Issuer Metadata (SD-JWT VC,
//! Section 4.3; draft-ietf-oauth-sd-jwt-vc, `/.well-known/jwt-vc-issuer`), each document a host
//! fetch (H1).

use siros_codec::json::{Json, JsonFault};
use siros_oid4vp::{BodyLimit, HttpsUrl, MediaType};
use siros_wallet_state::IssuerIdentifier;

use super::jws::{JwkFault, VerifyingKey};
use crate::fetched::{FetchFault, Fetched, Step};
use crate::json;

/// The largest issuer metadata or key set document read.
const MAX_DOCUMENT: BodyLimit = BodyLimit::bytes(64 * 1024);

/// The path segment the issuer metadata's well-known URL inserts after the authority.
const WELL_KNOWN: &str = "/.well-known/jwt-vc-issuer";

/// Why the issuer's key set gives no key that verifies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySetFault {
    /// The Credential Issuer Identifier is no `https` URL.
    IssuerNotHttps,
    /// A fetch gave no document.
    Fetch(FetchFault),
    /// A document is no JSON document the strict reader holds.
    Json(JsonFault),
    /// The issuer metadata names another `issuer`, or names its keys by both `jwks` and
    /// `jwks_uri` or by neither, or one of them is malformed.
    Metadata,
    /// The key set has no `keys` array.
    Keys,
    /// No key of the set has the `kid`.
    KidUnknown,
    /// The key of the `kid` is no EC key this wallet verifies with.
    Key(JwkFault),
}

impl KeySetFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::IssuerNotHttps => "key_set_issuer_not_https",
            Self::Fetch(fault) => fault.code(),
            Self::Json(_) | Self::Metadata | Self::Keys => "key_set_malformed",
            Self::KidUnknown => "key_set_kid_unknown",
            Self::Key(fault) => fault.code(),
        }
    }
}

siros_codec::display_code!(KeySetFault);

impl std::error::Error for KeySetFault {}

/// The key of the key set of `issuer` that `kid` identifies; the fetch of the issuer metadata
/// or of its `jwks_uri` while the host has not given it.
pub(crate) fn key(
    issuer: &IssuerIdentifier,
    kid: &str,
    fetched: &Fetched,
) -> Result<Step<VerifyingKey>, KeySetFault> {
    let metadata_url = well_known(issuer).ok_or(KeySetFault::IssuerNotHttps)?;
    let metadata = match document(&metadata_url, fetched)? {
        Step::Fetch(fetch) => return Ok(Step::Fetch(fetch)),
        Step::Done(document) => document,
    };
    let mut fields = json::object(metadata).map_err(|_| KeySetFault::Metadata)?;
    match fields.take("issuer") {
        Some(Json::String(named)) if named == issuer.as_str() => {}
        _ => return Err(KeySetFault::Metadata),
    }
    let jwks = match (fields.take("jwks"), fields.take("jwks_uri")) {
        (Some(jwks), None) => jwks,
        (None, Some(Json::String(uri))) => {
            let url = HttpsUrl::parse(&uri).ok_or(KeySetFault::Metadata)?;
            match document(&url, fetched)? {
                Step::Fetch(fetch) => return Ok(Step::Fetch(fetch)),
                Step::Done(document) => document,
            }
        }
        _ => return Err(KeySetFault::Metadata),
    };
    let Some(Json::Array(keys)) = jwks.member("keys") else {
        return Err(KeySetFault::Keys);
    };
    let jwk = keys
        .iter()
        .find(|key| matches!(key.member("kid"), Some(Json::String(id)) if id == kid))
        .ok_or(KeySetFault::KidUnknown)?;
    VerifyingKey::of_jwk(jwk)
        .map(Step::Done)
        .map_err(KeySetFault::Key)
}

/// The URL of the JWT VC Issuer Metadata of `issuer`: the well-known segment between its
/// authority and its path.
fn well_known(issuer: &IssuerIdentifier) -> Option<HttpsUrl> {
    let url = HttpsUrl::parse(issuer.as_str())?;
    let rest = url.as_str().get("https://".len()..)?;
    let (authority, path) = match rest.find('/') {
        Some(at) => rest.split_at_checked(at)?,
        None => (rest, ""),
    };
    HttpsUrl::parse(&format!(
        "https://{authority}{WELL_KNOWN}{}",
        path.trim_end_matches('/')
    ))
}

/// The JSON document at `url`.
fn document(url: &HttpsUrl, fetched: &Fetched) -> Result<Step<Json>, KeySetFault> {
    match fetched
        .body(url, MediaType::JSON, MAX_DOCUMENT)
        .map_err(KeySetFault::Fetch)?
    {
        Step::Fetch(fetch) => Ok(Step::Fetch(fetch)),
        Step::Done(body) => Json::parse_unique(body)
            .map(Step::Done)
            .map_err(KeySetFault::Json),
    }
}
