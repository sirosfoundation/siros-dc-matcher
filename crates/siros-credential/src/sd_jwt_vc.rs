//! The rules of SD-JWT VC (draft-ietf-oauth-sd-jwt-vc-19) over a stored SD-JWT.

use siros_codec::base64url;
use siros_codec::date::DateTime;
use siros_mdoc::P256Key;
use siros_sdjwt::{Claim, ClaimValue, Element, Object, SdJwt};

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
    holder_key: Option<P256Key>,
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
        let (bound, holder_key) = match claims.get("cnf").map(Claim::value) {
            None => (false, None),
            Some(ClaimValue::Object(cnf)) => (true, p256_jwk(cnf)),
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
            holder_key,
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

    /// The key of `cnf.jwk` when it is a P-256 key (RFC 7800, Section 3.2).
    pub(crate) fn holder_key(&self) -> Option<P256Key> {
        self.holder_key
    }
}

/// The P-256 key of `cnf`'s `jwk`: `kty` `EC`, `crv` `P-256`, and `x` and `y` of 32 bytes of
/// base64url (RFC 7518, Section 6.2.1). `None` for any other confirmation method or key.
fn p256_jwk(cnf: &Object) -> Option<P256Key> {
    let ClaimValue::Object(jwk) = cnf.get("jwk")?.value() else {
        return None;
    };
    let text = |name: &str| match jwk.get(name).map(Claim::value) {
        Some(ClaimValue::String(text)) => Some(text.as_str()),
        _ => None,
    };
    if text("kty")? != "EC" || text("crv")? != "P-256" {
        return None;
    }
    let coordinate =
        |name: &str| -> Option<[u8; 32]> { base64url::decode(text(name)?)?.try_into().ok() };
    Some(P256Key::new(coordinate("x")?, coordinate("y")?))
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
