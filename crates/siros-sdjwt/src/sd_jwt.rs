//! A stored SD-JWT: its compact form parsed and its disclosures processed (RFC 9901, Sections 4
//! and 7.1).

use rustc_hash::FxHashMap;
use siros_codec::base64url;

use crate::alg::HashAlg;
use crate::error::ParseError;
use crate::json::Json;
use crate::process::{self, Content, Pending};
use crate::tree::Object;

/// A stored SD-JWT whose disclosures all hang in its issuer-signed payload.
///
/// Parsing enforces Section 7.1, steps 1, 2.d, 3, 4 and 5: the digests are unique, every
/// disclosure is referenced, no reserved claim name is used, and `_sd_alg` names a supported
/// algorithm.
pub struct SdJwt {
    issuer_jwt: String,
    alg: HashAlg,
    claims: Object,
}

impl SdJwt {
    /// The SD-JWT of the compact form `compact`: the issuer JWT, then its disclosures, each after
    /// a `~`, with an optional final `~` (Section 4).
    ///
    /// # Errors
    ///
    /// [`ParseError`]: the first rule the text breaks.
    pub fn parse(compact: &str) -> Result<Self, ParseError> {
        let (issuer_jwt, disclosures) = split(compact);
        let payload = issuer_payload(issuer_jwt)?;
        let alg = sd_alg(&payload)?;
        let mut pending = FxHashMap::default();
        for (position, encoded) in disclosures.into_iter().enumerate() {
            let content = disclosure_content(encoded)?;
            let digest = alg.digest(encoded.as_bytes());
            let disclosure = Pending::new(position, encoded.to_owned(), content);
            if pending.insert(digest, disclosure).is_some() {
                return Err(ParseError::RepeatedDigest);
            }
        }
        let claims = process::claims(payload, pending)?;
        Ok(Self {
            issuer_jwt: issuer_jwt.to_owned(),
            alg,
            claims,
        })
    }

    /// The processed payload: every claim the credential holds, `_sd_alg` removed.
    pub fn claims(&self) -> &Object {
        &self.claims
    }

    pub(crate) fn issuer_jwt(&self) -> &str {
        &self.issuer_jwt
    }

    pub(crate) fn alg(&self) -> HashAlg {
        self.alg
    }
}

/// The issuer JWT and the disclosures of `compact`.
fn split(compact: &str) -> (&str, Vec<&str>) {
    let (issuer_jwt, rest) = compact.split_once('~').unwrap_or((compact, ""));
    // The forms `JWT` and `JWT~` leave `rest` empty.
    if rest.is_empty() {
        return (issuer_jwt, Vec::new());
    }
    let listed = rest.strip_suffix('~').unwrap_or(rest);
    (issuer_jwt, listed.split('~').collect())
}

/// The payload of the issuer JWT, a compact JWS (RFC 7515, Section 7.1).
fn issuer_payload(issuer_jwt: &str) -> Result<Vec<(String, Json)>, ParseError> {
    let mut segments = issuer_jwt.split('.');
    let (Some(header), Some(payload), Some(signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(ParseError::IssuerJwt);
    };
    if signature.is_empty() || base64url::decode(signature).is_none() {
        return Err(ParseError::IssuerJwt);
    }
    if segment_object(header).is_none() {
        return Err(ParseError::IssuerJwt);
    }
    segment_object(payload).ok_or(ParseError::IssuerJwt)
}

/// The members of the JSON object the base64url `segment` encodes.
fn segment_object(segment: &str) -> Option<Vec<(String, Json)>> {
    match Json::parse(&base64url::decode(segment)?)? {
        Json::Object(members) => Some(members),
        _ => None,
    }
}

/// The algorithm `_sd_alg` names, `sha-256` when it is absent (Section 4.1.1).
fn sd_alg(payload: &[(String, Json)]) -> Result<HashAlg, ParseError> {
    match payload.iter().find(|(name, _)| name == "_sd_alg") {
        None => Ok(HashAlg::Sha256),
        Some((_, Json::String(name))) => {
            HashAlg::from_name(name).ok_or(ParseError::UnsupportedSdAlg)
        }
        Some(_) => Err(ParseError::UnsupportedSdAlg),
    }
}

/// What the disclosure `encoded` reveals (Sections 4.2.1 and 4.2.2).
fn disclosure_content(encoded: &str) -> Result<Content, ParseError> {
    let Some(Json::Array(items)) = base64url::decode(encoded).and_then(|b| Json::parse(&b)) else {
        return Err(ParseError::Disclosure);
    };
    let mut items = items.into_iter();
    match (items.next(), items.next(), items.next(), items.next()) {
        (Some(Json::String(_)), Some(value), None, None) => Ok(Content::Element(value)),
        (Some(Json::String(_)), Some(Json::String(name)), Some(value), None) => {
            Ok(Content::Property { name, value })
        }
        _ => Err(ParseError::Disclosure),
    }
}
