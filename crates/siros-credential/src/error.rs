//! Why a credential, a pointer or a validity witness is refused. Each error has a stable code.

use std::fmt;

use siros_codec::Base64Error;
use siros_mdoc::MdocError;
use siros_sdjwt::ParseError;
use siros_trust::ChainError;

/// A registered claim of SD-JWT VC that is never selectively disclosed, with its
/// sub-claims (SD-JWT VC, Section 2.2.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegisteredClaim {
    /// `iss`.
    Iss,
    /// `nbf`.
    Nbf,
    /// `exp`.
    Exp,
    /// `cnf`.
    Cnf,
    /// `vct`.
    Vct,
    /// `vct#integrity`.
    VctIntegrity,
    /// `aka_vcts`.
    AkaVcts,
    /// `status`.
    Status,
}

impl RegisteredClaim {
    /// Every registered claim, in the order of Section 2.2.2.3.
    pub const ALL: [Self; 8] = [
        Self::Iss,
        Self::Nbf,
        Self::Exp,
        Self::Cnf,
        Self::Vct,
        Self::VctIntegrity,
        Self::AkaVcts,
        Self::Status,
    ];

    /// The claim's name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Iss => "iss",
            Self::Nbf => "nbf",
            Self::Exp => "exp",
            Self::Cnf => "cnf",
            Self::Vct => "vct",
            Self::VctIntegrity => "vct#integrity",
            Self::AkaVcts => "aka_vcts",
            Self::Status => "status",
        }
    }
}

/// Why a claim is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClaimFault {
    /// It is absent.
    Absent,
    /// It has another JSON type than its rule gives it.
    WrongType,
}

/// Why a wallet state entry is no credential the core reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialError {
    /// `format` is none of `dc+sd-jwt`, `vc+sd-jwt` and `mso_mdoc`.
    UnsupportedFormat,
    /// `data` is no SD-JWT [`siros_sdjwt::SdJwt::parse`] reads. The code is its own.
    SdJwt(ParseError),
    /// `data` is no mdoc [`siros_mdoc::Mdoc::parse`] reads. The code is its own.
    Mdoc(MdocError),
    /// The SD-JWT VC has no `vct`, or its `vct` is not a string (SD-JWT VC, Section 2.2.2.3).
    Vct(ClaimFault),
    /// The SD-JWT VC discloses this registered claim, or one of its sub-claims, selectively
    /// (SD-JWT VC, Section 2.2.2.3).
    SelectivelyDisclosed(RegisteredClaim),
    /// The SD-JWT VC's `cnf` is not a JSON object (RFC 7800, Section 3.1).
    Cnf,
    /// The SD-JWT VC's `cnf` holds no P-256 `jwk`. The code is its own.
    HolderKey(HolderKeyError),
    /// The SD-JWT VC's `nbf` or `exp` is not a NumericDate of years 0000 to 9999 (RFC 7519,
    /// Section 2).
    NumericDate(RegisteredClaim),
    /// An mdoc value holds this tag, other than 0 (`tdate`) and 1004 (`full-date`).
    Tag(u64),
    /// An mdoc `tdate` is not tag 0 over text `YYYY-MM-DDThh:mm:ssZ` of a real UTC second
    /// (ISO/IEC 18013-5, 7.2.1).
    Tdate,
    /// An mdoc `full-date` is not tag 1004 over text `YYYY-MM-DD` of a real date (RFC 8943).
    FullDate,
    /// An mdoc map value has a key other than text.
    MapKey,
    /// An mdoc value holds `undefined`.
    Undefined,
    /// The issuer chain does not parse (TR2). The code is its own.
    IssuerChain(ChainError),
}

impl CredentialError {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedFormat => "format_unsupported",
            Self::SdJwt(e) => e.code(),
            Self::Mdoc(e) => e.code(),
            Self::Vct(_) => "vct_malformed",
            Self::SelectivelyDisclosed(_) => "claim_selectively_disclosed",
            Self::Cnf => "cnf_malformed",
            Self::HolderKey(e) => e.code(),
            Self::NumericDate(_) => "numeric_date_malformed",
            Self::Tag(_) => "claim_tag_unsupported",
            Self::Tdate => "tdate_malformed",
            Self::FullDate => "full_date_malformed",
            Self::MapKey => "map_key_not_text",
            Self::Undefined => "claim_undefined",
            Self::IssuerChain(e) => e.code(),
        }
    }
}

impl fmt::Display for CredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelectivelyDisclosed(claim) | Self::NumericDate(claim) => {
                write!(f, "{}: {}", self.code(), claim.name())
            }
            _ => f.write_str(self.code()),
        }
    }
}

impl std::error::Error for CredentialError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SdJwt(e) => Some(e),
            Self::Mdoc(e) => Some(e),
            Self::HolderKey(e) => Some(e),
            Self::IssuerChain(e) => Some(e),
            Self::UnsupportedFormat
            | Self::Vct(_)
            | Self::SelectivelyDisclosed(_)
            | Self::Cnf
            | Self::NumericDate(_)
            | Self::Tag(_)
            | Self::Tdate
            | Self::FullDate
            | Self::MapKey
            | Self::Undefined => None,
        }
    }
}

impl From<ParseError> for CredentialError {
    fn from(e: ParseError) -> Self {
        Self::SdJwt(e)
    }
}

impl From<ChainError> for CredentialError {
    fn from(e: ChainError) -> Self {
        Self::IssuerChain(e)
    }
}

impl From<MdocError> for CredentialError {
    fn from(e: MdocError) -> Self {
        Self::Mdoc(e)
    }
}

/// Why components are no claims path pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PointerError {
    /// A claims path pointer is a non-empty array (OpenID4VP 1.0, Section 7).
    Empty,
}

impl PointerError {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Empty => "pointer_empty",
        }
    }
}

impl fmt::Display for PointerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for PointerError {}

/// Why a credential is not usable at a given time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValidityError {
    /// The time precedes `not_before`.
    NotYetValid,
    /// The time is `not_after` or later.
    Expired,
}

impl ValidityError {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotYetValid => "not_yet_valid",
            Self::Expired => "expired",
        }
    }
}

impl fmt::Display for ValidityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for ValidityError {}

/// A coordinate of a JWK of an EC key (RFC 7518, Section 6.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Coordinate {
    /// `x`.
    X,
    /// `y`.
    Y,
}

/// Why a coordinate of the `jwk` is no 32 bytes of base64url.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoordinateFault {
    /// It is absent or not a string.
    NotString,
    /// The string is not base64url.
    Base64(Base64Error),
    /// The bytes number this many, where a P-256 coordinate has 32.
    Length(usize),
}

/// Why an SD-JWT VC's `cnf` gives no P-256 holder key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HolderKeyError {
    /// `cnf` has no `jwk` object (RFC 7800, Section 3.2).
    Jwk,
    /// The `jwk`'s `kty` is not `EC` (RFC 7518, Section 6.2.1).
    KeyType,
    /// The `jwk`'s `crv` is not `P-256` (RFC 7518, Section 6.2.1).
    Curve,
    /// The `jwk`'s `x` or `y` is not 32 bytes of base64url.
    Coordinate(Coordinate, CoordinateFault),
}

impl HolderKeyError {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Jwk => "holder_key_jwk",
            Self::KeyType | Self::Curve => "holder_key_type",
            Self::Coordinate(..) => "holder_key_coordinate",
        }
    }
}

impl fmt::Display for HolderKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for HolderKeyError {}
