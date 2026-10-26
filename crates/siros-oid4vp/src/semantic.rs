//! The semantics identifier of a Wallet-Relying Party (ETSI TS 119 475, Clauses 5.1.3 and
//! 5.1.5).
//!
//! "GEN-5.1.3-01: The organizationIdentifier shall follow the semantics defined in ETSI
//! EN 319 412-1 \[1\], clause 5.1.4." "GEN-5.1.5-01: The serialNumber with shall follow the
//! semantics defined in ETSI EN 319 412-1 \[1\], clause 5.1.3." Both clauses of EN 319 412-1
//! (LEG-5.1.4-02, NAT-5.1.3-02) give the value "the following structure in the presented order:
//! 3 character [...] identity type reference; 2 character ISO 3166-1 country code; hyphen-minus
//! "-" [...]; and identifier", where the type reference may instead be two characters of a local
//! scheme followed by ":" (LEG-5.1.4-03 point 5, NAT-5.1.3-03 point 6).

use std::fmt;

/// The legal person identity type references of ETSI EN 319 412-1, LEG-5.1.4-03, and those
/// ETSI TS 119 475, Table 2 adds.
const LEGAL_TYPES: [&str; 6] = ["VAT", "NTR", "PSD", "LEI", "EOR", "EXC"];
/// The natural person identity type references of ETSI EN 319 412-1, NAT-5.1.3-03.
const NATURAL_TYPES: [&str; 5] = ["PAS", "IDC", "PNO", "TAX", "TIN"];

/// The person a semantics identifier names, and the subject attribute that carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Person {
    /// A legal person: `organizationIdentifier`.
    Legal,
    /// A natural person: `serialNumber`.
    Natural,
}

impl Person {
    /// The identity type references of the person.
    fn types(self) -> &'static [&'static str] {
        match self {
            Self::Legal => &LEGAL_TYPES,
            Self::Natural => &NATURAL_TYPES,
        }
    }
}

/// A semantics identifier, such as `VATBE-0876866142`: an identity type reference of the
/// person, or two characters of a local scheme and `:`, two uppercase letters of an ISO 3166-1
/// country code, `-`, and a non-empty identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SemanticIdentifier(String);

/// Why a certificate subject gives no semantics identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SemanticIdError {
    /// The subject holds neither an `organizationIdentifier` nor a `serialNumber`.
    Absent,
    /// The subject holds the attribute more than once.
    Repeated,
    /// The value is neither a `UTF8String` nor a `PrintableString`.
    Encoding,
    /// The value starts with neither an identity type reference of the person nor two
    /// characters and `:`.
    TypeReference,
    /// The country code is not two uppercase letters.
    Country,
    /// No `-` follows the country code.
    Separator,
    /// The identifier after `-` is empty.
    Identifier,
}

impl SemanticIdError {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Absent => "semantic_id_absent",
            Self::Repeated => "semantic_id_repeated",
            Self::Encoding => "semantic_id_encoding",
            Self::TypeReference => "semantic_id_type_reference",
            Self::Country => "semantic_id_country",
            Self::Separator => "semantic_id_separator",
            Self::Identifier => "semantic_id_identifier",
        }
    }
}

impl fmt::Display for SemanticIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for SemanticIdError {}

impl SemanticIdentifier {
    /// The semantics identifier `text` of a `person`.
    ///
    /// # Errors
    ///
    /// [`SemanticIdError`]: the first part of the structure `text` breaks.
    pub fn parse(text: &str, person: Person) -> Result<Self, SemanticIdError> {
        let rest = match text.get(..3) {
            Some(head) if person.types().contains(&head) => text.get(3..),
            Some(head) if head.ends_with(':') && head.is_ascii() => text.get(3..),
            _ => None,
        }
        .ok_or(SemanticIdError::TypeReference)?;
        rest.get(..2)
            .filter(|country| country.bytes().all(|b| b.is_ascii_uppercase()))
            .ok_or(SemanticIdError::Country)?;
        let identifier = rest
            .get(2..)
            .and_then(|tail| tail.strip_prefix('-'))
            .ok_or(SemanticIdError::Separator)?;
        if identifier.is_empty() {
            return Err(SemanticIdError::Identifier);
        }
        Ok(Self(text.to_owned()))
    }

    /// The identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
