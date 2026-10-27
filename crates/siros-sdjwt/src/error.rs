//! Why a stored SD-JWT or a key binding is refused. Each error has a stable code.

/// Why text is not a stored SD-JWT (RFC 9901, Sections 4 and 7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum ParseError {
    /// The issuer JWT is not three base64url segments whose header and payload are JSON objects
    /// with unique member names.
    IssuerJwt,
    /// A disclosure is empty, is not base64url, or does not decode to a JSON array of a string
    /// salt and a value, or of a string salt, a string claim name and a value (Section 4.2).
    Disclosure,
    /// `_sd_alg` is not `sha-256`, `sha-384` or `sha-512` (Sections 4.1.1 and 9.4).
    UnsupportedSdAlg,
    /// `_sd`, `...` or `_sd_alg` appears outside its role: `_sd` holding an array of digest
    /// strings, `...` as the only member of an array element holding one digest string,
    /// `_sd_alg` at the top level of the payload (Sections 4.1, 4.1.1 and 7.1, step 3.c.ii.2).
    ReservedClaimName,
    /// A digest appears twice in the payload and the disclosures, or two disclosures share a
    /// digest (Section 7.1, step 4).
    RepeatedDigest,
    /// An `_sd` digest names an array element disclosure, or an array digest names an object
    /// property disclosure (Section 7.1, steps 3.c.ii.1 and 3.c.iii.1).
    MisplacedDisclosure,
    /// A disclosure names a claim that its object already has (Section 7.1, step 3.c.ii.3).
    ClaimNameExists,
    /// No digest of the payload or of another disclosure references a disclosure (Section 7.1,
    /// step 5).
    UnreferencedDisclosure,
    /// The claims nest deeper than [`MAX_DEPTH`](crate::MAX_DEPTH), disclosures included.
    TooDeep,
}

impl ParseError {
    /// A stable identifier.
    pub fn code(&self) -> &'static str {
        match self {
            Self::IssuerJwt => "issuer_jwt_malformed",
            Self::Disclosure => "disclosure_malformed",
            Self::UnsupportedSdAlg => "sd_alg_unsupported",
            Self::ReservedClaimName => "reserved_claim_name",
            Self::RepeatedDigest => "digest_repeated",
            Self::MisplacedDisclosure => "disclosure_misplaced",
            Self::ClaimNameExists => "claim_name_exists",
            Self::UnreferencedDisclosure => "disclosure_unreferenced",
            Self::TooDeep => "claims_too_deep",
        }
    }
}

/// Why claims do not form a KB-JWT payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum KeyBindingError {
    /// An extra claim is named `iat`, `aud`, `nonce` or `sd_hash`, or shares its name with
    /// another extra claim.
    ClaimCollision,
}

impl KeyBindingError {
    /// A stable identifier.
    pub fn code(&self) -> &'static str {
        match self {
            Self::ClaimCollision => "kb_jwt_claim_collision",
        }
    }
}
