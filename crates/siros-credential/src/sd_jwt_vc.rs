//! The rules of SD-JWT VC (draft-ietf-oauth-sd-jwt-vc-19) over a stored SD-JWT.

use siros_codec::date::DateTime;
use siros_sdjwt::{Claim, ClaimValue, Element, SdJwt};

use crate::error::CredentialError;
use crate::usable::Validity;

/// The registered claims that, with their sub-claims, are never selectively disclosed
/// (Section 2.2.2.3).
const PERMANENT: [&str; 8] = [
    "iss",
    "nbf",
    "exp",
    "cnf",
    "vct",
    "vct#integrity",
    "aka_vcts",
    "status",
];

/// An SD-JWT VC: an SD-JWT with a string `vct`, its registered claims permanently disclosed.
pub(crate) struct SdJwtVc {
    sd_jwt: SdJwt,
    vct: String,
    bound: bool,
    validity: Validity,
}

impl SdJwtVc {
    /// The SD-JWT VC of the compact form `data`.
    pub(crate) fn read(data: &str) -> Result<Self, CredentialError> {
        let sd_jwt = SdJwt::parse(data)?;
        let claims = sd_jwt.claims();
        for name in PERMANENT {
            if claims.get(name).is_some_and(disclosed) {
                return Err(CredentialError::SelectivelyDisclosed(name));
            }
        }
        let vct = match claims.get("vct").map(Claim::value) {
            Some(ClaimValue::String(vct)) => vct.clone(),
            _ => return Err(CredentialError::Vct),
        };
        let bound = match claims.get("cnf").map(Claim::value) {
            None => false,
            Some(ClaimValue::Object(_)) => true,
            Some(_) => return Err(CredentialError::Cnf),
        };
        let validity = Validity::new(
            numeric_date(claims.get("nbf"), "nbf")?,
            numeric_date(claims.get("exp"), "exp")?,
        );
        Ok(Self {
            sd_jwt,
            vct,
            bound,
            validity,
        })
    }

    pub(crate) fn sd_jwt(&self) -> &SdJwt {
        &self.sd_jwt
    }

    pub(crate) fn vct(&self) -> &str {
        &self.vct
    }

    /// Whether `cnf` names a holder key: the KB-JWT must be secured by that key (Section
    /// 2.2.2.3).
    pub(crate) fn bound(&self) -> bool {
        self.bound
    }

    pub(crate) fn validity(&self) -> Validity {
        self.validity
    }
}

/// Whether a disclosure reveals `claim` or one of its sub-claims.
fn disclosed(claim: &Claim) -> bool {
    claim.disclosure().is_some()
        || match claim.value() {
            ClaimValue::Object(object) => object.members().any(|(_, member)| disclosed(member)),
            ClaimValue::Array(elements) => elements.iter().any(|element| match element {
                Element::Present(member) => disclosed(member),
                Element::Withheld => false,
            }),
            _ => false,
        }
}

/// The NumericDate claim `claim`, named `name` (RFC 7519, Section 2).
///
/// A fractional NumericDate rounds up to the next second. For whole seconds `now`, `now ≥ t`
/// and `now ≥ ⌈t⌉` agree, and so do `now < t` and `now < ⌈t⌉`.
fn numeric_date(
    claim: Option<&Claim>,
    name: &'static str,
) -> Result<Option<DateTime>, CredentialError> {
    let Some(claim) = claim else {
        return Ok(None);
    };
    let ClaimValue::Number(number) = claim.value() else {
        return Err(CredentialError::NumericDate(name));
    };
    let seconds = match number.as_i64() {
        Some(seconds) => Some(seconds),
        None => number
            .as_f64()
            .map(f64::ceil)
            .filter(|s| (DateTime::MIN_UNIX as f64..=DateTime::MAX_UNIX as f64).contains(s))
            // Within the range above, the conversion is exact.
            .map(|s| s as i64),
    };
    seconds
        .and_then(DateTime::from_unix)
        .map(Some)
        .ok_or(CredentialError::NumericDate(name))
}
