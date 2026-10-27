//! The members of the JSON documents transaction data reads, taken one by one against their
//! schema. siros-codec's strict reader reads the documents.

use siros_codec::json::{Json, JsonNumber};

use crate::error::{MemberPath, TransactionDataError};

/// The members of an object not taken yet, in their order.
pub(crate) struct Fields(Vec<(String, Json)>);

impl Fields {
    /// The members `members`, all to take.
    pub(crate) fn new(members: Vec<(String, Json)>) -> Self {
        Self(members)
    }

    /// Takes member `name`.
    pub(crate) fn take(&mut self, name: &str) -> Option<Json> {
        let at = self.0.iter().position(|(n, _)| n == name)?;
        Some(self.0.remove(at).1)
    }

    /// Takes member `name`, which must be present.
    pub(crate) fn require(
        &mut self,
        name: &str,
        path: MemberPath,
    ) -> Result<Json, TransactionDataError> {
        self.take(name)
            .ok_or(TransactionDataError::MissingMember(path))
    }

    /// The members not taken: those the schema of the object leaves open.
    pub(crate) fn rest(self) -> Vec<(String, Json)> {
        self.0
    }

    /// Refuses a member not taken (Section 8.5, unknown fields).
    pub(crate) fn finish(self) -> Result<(), TransactionDataError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(TransactionDataError::UnknownMember)
        }
    }
}

/// `value` as a string.
pub(crate) fn text(value: Json, path: MemberPath) -> Result<String, TransactionDataError> {
    match value {
        Json::String(text) => Ok(text),
        _ => Err(TransactionDataError::WrongType(path)),
    }
}

/// `value` as a boolean.
pub(crate) fn boolean(value: Json, path: MemberPath) -> Result<bool, TransactionDataError> {
    match value {
        Json::Bool(b) => Ok(b),
        _ => Err(TransactionDataError::WrongType(path)),
    }
}

/// `value` as a number.
pub(crate) fn number(value: Json, path: MemberPath) -> Result<JsonNumber, TransactionDataError> {
    match value {
        Json::Number(number) => Ok(number),
        _ => Err(TransactionDataError::WrongType(path)),
    }
}

/// `value` as a JSON Schema `integer`: a number without a fractional part.
pub(crate) fn integer(value: Json, path: MemberPath) -> Result<JsonNumber, TransactionDataError> {
    match value {
        Json::Number(number) if number.is_integer() => Ok(number),
        _ => Err(TransactionDataError::WrongType(path)),
    }
}

/// `value` as the members of an object.
pub(crate) fn object(value: Json, path: MemberPath) -> Result<Fields, TransactionDataError> {
    match value {
        Json::Object(members) => Ok(Fields::new(members)),
        _ => Err(TransactionDataError::WrongType(path)),
    }
}

/// `value` as the elements of an array.
pub(crate) fn array(value: Json, path: MemberPath) -> Result<Vec<Json>, TransactionDataError> {
    match value {
        Json::Array(items) => Ok(items),
        _ => Err(TransactionDataError::WrongType(path)),
    }
}

/// Member `name` of `fields`, read by `read` when present.
pub(crate) fn optional<T>(
    fields: &mut Fields,
    name: &str,
    path: MemberPath,
    read: impl FnOnce(Json, MemberPath) -> Result<T, TransactionDataError>,
) -> Result<Option<T>, TransactionDataError> {
    fields.take(name).map(|value| read(value, path)).transpose()
}
