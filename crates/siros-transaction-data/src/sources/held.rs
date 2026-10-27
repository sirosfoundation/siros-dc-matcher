//! The metadata the host holds for transaction data (PaSO Proof Metadata, Sections 6 and 8). The
//! host fetches and renews it outside presentations, because a fetch during a presentation
//! tells the publisher which credential is presented. The wallet verifies each document every
//! time it loads it.
//!
//! What the host holds, for each credential:
//!
//! - when the credential's issuer metadata configuration names a `credential_metadata_uri`, the
//!   signed credential metadata JWT it serves, fetched with `Accept: application/jwt` and the
//!   wallet's language as `Accept-Language`, and admitted by [`HeldJwt::verify_fetched`]; the
//!   host renews it before the [`Renewal`]'s expiry, from the URL the [`Renewal`] names (Section
//!   8);
//! - when the credential is an SD-JWT VC whose `vct` is an `https` URL, the Type Metadata at that
//!   URL and the documents its `transaction_data_types` entries reference (EC TS12 v1.0.1,
//!   Section 4.1). The credential's `#integrity` claims pin them, so they change only with the
//!   credential;
//! - when the credential carries no `x5c` chain, its issuer's JWT VC Issuer Metadata and the key
//!   set its `jwks_uri` names (SD-JWT VC, Section 4.3).
//!
//! [`HeldMetadata::wanted`] lists the documents of a credential the host does not hold yet.

use rustc_hash::FxHashMap;
use siros_codec::date::DateTime;
use siros_credential::Credential;
use siros_display::DisplayCache;
use siros_oid4vp::HttpsUrl;
use siros_wallet_state::{ConfigurationId, IssuerIdentifier};

use super::issuer_keys::{self, KeySetFault};
use super::ts12::{Ts12Fault, TypeMetadata};

/// A signed credential metadata JWT the host holds for a credential configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldJwt {
    issuer: IssuerIdentifier,
    configuration: ConfigurationId,
    jwt: String,
}

/// A document the host holds, by the URL it fetched it from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldDocument {
    url: HttpsUrl,
    body: Vec<u8>,
}

impl HeldDocument {
    /// The document `body` the host fetched from `url`.
    #[must_use]
    pub fn new(url: HttpsUrl, body: Vec<u8>) -> Self {
        Self { url, body }
    }
}

/// What a host can renew a signed credential metadata JWT by: when it expires, and the
/// `credential_metadata_uri` it names (Section 8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Renewal {
    pub(crate) expires: DateTime,
    pub(crate) from: HttpsUrl,
}

impl Renewal {
    /// The JWT's `exp`: the host fetches a new one before it.
    #[must_use]
    pub fn expires(&self) -> DateTime {
        self.expires
    }

    /// The JWT's `credential_metadata_uri`: the host fetches the next one from it.
    #[must_use]
    pub fn from(&self) -> &HttpsUrl {
        &self.from
    }
}

/// Why the host's metadata does not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeldError {
    /// Two JWTs are held for this credential configuration.
    JwtRepeated(IssuerIdentifier, ConfigurationId),
    /// Two documents are held for this URL.
    DocumentRepeated(HttpsUrl),
}

impl HeldError {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::JwtRepeated(..) => "held_jwt_repeated",
            Self::DocumentRepeated(_) => "held_document_repeated",
        }
    }
}

siros_codec::display_code!(HeldError);

impl std::error::Error for HeldError {}

/// The metadata the host holds: a signed credential metadata JWT per credential configuration,
/// and documents by URL.
#[derive(Debug, Clone, Default)]
pub struct HeldMetadata {
    jwts: FxHashMap<(IssuerIdentifier, ConfigurationId), String>,
    documents: FxHashMap<HttpsUrl, Vec<u8>>,
}

impl HeldMetadata {
    /// The metadata of `jwts` and `documents`.
    ///
    /// # Errors
    ///
    /// [`HeldError`]: two JWTs of one configuration, or two documents of one URL.
    pub fn new(jwts: Vec<HeldJwt>, documents: Vec<HeldDocument>) -> Result<Self, HeldError> {
        let mut held = Self::default();
        for HeldJwt {
            issuer,
            configuration,
            jwt,
        } in jwts
        {
            let key = (issuer, configuration);
            if held.jwts.insert(key.clone(), jwt).is_some() {
                let (issuer, configuration) = key;
                return Err(HeldError::JwtRepeated(issuer, configuration));
            }
        }
        for HeldDocument { url, body } in documents {
            if held.documents.insert(url.clone(), body).is_some() {
                return Err(HeldError::DocumentRepeated(url));
            }
        }
        Ok(held)
    }

    /// The signed credential metadata JWT held for `credential`'s configuration.
    pub(crate) fn jwt(&self, credential: &Credential) -> Option<&str> {
        let key = (
            credential.issuer()?.clone(),
            credential.configuration_id()?.clone(),
        );
        self.jwts.get(&key).map(String::as_str)
    }

    /// The document held for `url`.
    pub(crate) fn document(&self, url: &HttpsUrl) -> Option<&[u8]> {
        self.documents.get(url).map(Vec::as_slice)
    }

    /// The documents the host should hold for `credential` and does not, in the order the
    /// wallet reads them; `display` locates the signed credential metadata.
    ///
    /// # Errors
    ///
    /// [`WantedFault`]: a held document that does not read, so that the documents it
    /// references are unknown.
    pub fn wanted(
        &self,
        credential: &Credential,
        display: &DisplayCache,
    ) -> Result<Vec<Wanted>, WantedFault> {
        let mut wanted = Vec::new();
        if let Some(uri) = display.credential_metadata_uri(credential) {
            if self.jwt(credential).is_none() {
                wanted.push(Wanted::CredentialMetadata(uri.clone()));
            }
        }
        let referenced =
            TypeMetadata::documents(credential, self).map_err(WantedFault::TypeMetadata)?;
        let keys = match credential.issuer_chain() {
            Some(_) => Vec::new(),
            None => credential
                .issuer()
                .map(|issuer| issuer_keys::documents(issuer, self))
                .transpose()
                .map_err(WantedFault::KeySet)?
                .unwrap_or_default(),
        };
        wanted.extend(
            referenced
                .into_iter()
                .chain(keys)
                .filter(|url| self.document(url).is_none())
                .map(Wanted::Document),
        );
        Ok(wanted)
    }
}

impl HeldJwt {
    /// The JWT `jwt` the host holds for the configuration `configuration` of `issuer`.
    #[must_use]
    pub fn new(issuer: IssuerIdentifier, configuration: ConfigurationId, jwt: String) -> Self {
        Self {
            issuer,
            configuration,
            jwt,
        }
    }

    /// The configuration's issuer.
    #[must_use]
    pub fn issuer(&self) -> &IssuerIdentifier {
        &self.issuer
    }

    /// The configuration.
    #[must_use]
    pub fn configuration(&self) -> &ConfigurationId {
        &self.configuration
    }

    /// The JWT.
    #[must_use]
    pub fn jwt(&self) -> &str {
        &self.jwt
    }
}

/// A document the host should hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wanted {
    /// The signed credential metadata JWT this `credential_metadata_uri` serves.
    CredentialMetadata(HttpsUrl),
    /// The document at this URL.
    Document(HttpsUrl),
}

/// Why the documents a held document references are unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WantedFault {
    /// The held Type Metadata does not read.
    TypeMetadata(Ts12Fault),
    /// The held JWT VC Issuer Metadata does not read.
    KeySet(KeySetFault),
}

impl WantedFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::TypeMetadata(fault) => fault.code(),
            Self::KeySet(fault) => fault.code(),
        }
    }
}

siros_codec::display_code!(WantedFault);

impl std::error::Error for WantedFault {}
