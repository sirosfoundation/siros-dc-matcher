//! Why a credential, a claim, a pointer or a validity witness is refused. Each error has a
//! stable code.

use std::fmt;

use siros_dcql::PathError;
use siros_mdoc::MdocError;
use siros_sdjwt::ParseError;

/// Why a wallet state entry is no credential the core reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialError {
    /// `format` is none of `dc+sd-jwt`, `vc+sd-jwt` and `mso_mdoc`.
    UnsupportedFormat,
    /// `data` is no SD-JWT [`siros_sdjwt::SdJwt::parse`] reads. The code is its own.
    SdJwt(ParseError),
    /// `data` is no mdoc [`siros_mdoc::Mdoc::parse`] reads. The code is its own.
    Mdoc(MdocError),
    /// The SD-JWT VC has no `vct`, or its `vct` is not a string (SD-JWT VC, Section 2.2.2.3).
    Vct,
    /// The SD-JWT VC discloses this registered claim, or one of its sub-claims, selectively:
    /// `iss`, `nbf`, `exp`, `cnf`, `vct`, `vct#integrity`, `aka_vcts` or `status` (SD-JWT VC,
    /// Section 2.2.2.3).
    SelectivelyDisclosed(&'static str),
    /// The SD-JWT VC's `cnf` is not a JSON object (RFC 7800, Section 3.1).
    Cnf,
    /// The SD-JWT VC's `nbf` or `exp` is not a NumericDate of years 0000 to 9999 (RFC 7519,
    /// Section 2).
    NumericDate(&'static str),
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
            Self::NumericDate(_) => "numeric_date_malformed",
        }
    }
}

impl fmt::Display for CredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelectivelyDisclosed(claim) | Self::NumericDate(claim) => {
                write!(f, "{}: {claim}", self.code())
            }
            _ => f.write_str(self.code()),
        }
    }
}

impl std::error::Error for CredentialError {}

impl From<ParseError> for CredentialError {
    fn from(e: ParseError) -> Self {
        Self::SdJwt(e)
    }
}

impl From<MdocError> for CredentialError {
    fn from(e: MdocError) -> Self {
        Self::Mdoc(e)
    }
}

/// Why the claims a pointer selects cannot be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimError {
    /// The pointer selects nothing, or does not fit the credential (OpenID4VP 1.0, Section 7).
    /// The code is its own.
    Path(PathError),
    /// A value has none of the ten types: an mdoc value under a tag other than 0 and 1004, a
    /// tag 0 or 1004 over text that is no `tdate` or `full-date`, a map key other than text,
    /// `undefined`, or a JSON number outside the range of `f64`.
    Untyped,
}

impl ClaimError {
    /// A stable identifier.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Path(e) => e.code(),
            Self::Untyped => "claim_value_untyped",
        }
    }
}

impl fmt::Display for ClaimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for ClaimError {}

impl From<PathError> for ClaimError {
    fn from(e: PathError) -> Self {
        Self::Path(e)
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
