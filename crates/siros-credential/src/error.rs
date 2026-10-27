//! Why a credential, a pointer or a validity witness is refused. Each error has a stable code.

use siros_mdoc::MdocError;
use siros_sdjwt::ParseError;

/// Why a wallet state entry is no credential the core reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum CredentialError {
    /// `format` is none of `dc+sd-jwt`, `vc+sd-jwt` and `mso_mdoc`.
    UnsupportedFormat,
    /// `data` is no SD-JWT [`siros_sdjwt::SdJwt::parse`] reads. The code is its own.
    SdJwt(#[from] ParseError),
    /// `data` is no mdoc [`siros_mdoc::Mdoc::parse`] reads. The code is its own.
    Mdoc(#[from] MdocError),
    /// The SD-JWT VC has no `vct`, or its `vct` is not a string (SD-JWT VC, Section 2.2.2.3).
    Vct,
    /// The SD-JWT VC discloses this registered claim, or one of its sub-claims, selectively:
    /// `iss`, `nbf`, `exp`, `cnf`, `vct`, `vct#integrity`, `aka_vcts` or `status` (SD-JWT VC,
    /// Section 2.2.2.3).
    #[error("{code}: {0}", code = self.code())]
    SelectivelyDisclosed(&'static str),
    /// The SD-JWT VC's `cnf` is not a JSON object (RFC 7800, Section 3.1).
    Cnf,
    /// The SD-JWT VC's `cnf` holds no P-256 `jwk`. The code is its own.
    HolderKey(#[source] HolderKeyError),
    /// The SD-JWT VC's `nbf` or `exp` is not a NumericDate of years 0000 to 9999 (RFC 7519,
    /// Section 2).
    #[error("{code}: {0}", code = self.code())]
    NumericDate(&'static str),
    /// An mdoc value holds a tag other than 0 (`tdate`) and 1004 (`full-date`).
    Tag,
    /// An mdoc `tdate` is not tag 0 over text `YYYY-MM-DDThh:mm:ssZ` of a real UTC second
    /// (ISO/IEC 18013-5, 7.2.1).
    Tdate,
    /// An mdoc `full-date` is not tag 1004 over text `YYYY-MM-DD` of a real date (RFC 8943).
    FullDate,
    /// An mdoc map value has a key other than text.
    MapKey,
    /// An mdoc value holds `undefined`.
    Undefined,
}

impl CredentialError {
    /// A stable identifier.
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedFormat => "format_unsupported",
            Self::SdJwt(e) => e.code(),
            Self::Mdoc(e) => e.code(),
            Self::Vct => "vct_malformed",
            Self::SelectivelyDisclosed(_) => "claim_selectively_disclosed",
            Self::Cnf => "cnf_malformed",
            Self::HolderKey(e) => e.code(),
            Self::NumericDate(_) => "numeric_date_malformed",
            Self::Tag => "claim_tag_unsupported",
            Self::Tdate => "tdate_malformed",
            Self::FullDate => "full_date_malformed",
            Self::MapKey => "map_key_not_text",
            Self::Undefined => "claim_undefined",
        }
    }
}

/// Why components are no claims path pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum PointerError {
    /// A claims path pointer is a non-empty array (OpenID4VP 1.0, Section 7).
    Empty,
}

impl PointerError {
    /// A stable identifier.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Empty => "pointer_empty",
        }
    }
}

/// Why a credential is not usable at a given time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum ValidityError {
    /// The time precedes `not_before`.
    NotYetValid,
    /// The time is `not_after` or later.
    Expired,
}

impl ValidityError {
    /// A stable identifier.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotYetValid => "not_yet_valid",
            Self::Expired => "expired",
        }
    }
}

/// Why an SD-JWT VC's `cnf` gives no P-256 holder key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum HolderKeyError {
    /// `cnf` has no `jwk` object (RFC 7800, Section 3.2).
    Jwk,
    /// The `jwk`'s `kty` is not `EC` or its `crv` not `P-256` (RFC 7518, Section 6.2.1).
    KeyType,
    /// The `jwk`'s `x` or `y` is not 32 bytes of base64url.
    Coordinate,
}

impl HolderKeyError {
    /// A stable identifier.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Jwk => "holder_key_jwk",
            Self::KeyType => "holder_key_type",
            Self::Coordinate => "holder_key_coordinate",
        }
    }
}
