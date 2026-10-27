//! JSON text errors as serde_json reports them, and, with the feature `json`, the strict JSON
//! reader (RFC 8259): one value, members in document order with the repeated member names a
//! document holds, every number with the text its writer chose, at most [`MAX_DEPTH`] levels
//! of objects and arrays.
//!
//! RFC 7519, Section 4 lets a JWT parser reject duplicate claim names, and a record a host
//! provisions names each member once: [`Json::parse_unique`] refuses a repeated name at every
//! level, and [`Json::repeated_member`] finds the first one.

use std::fmt;

use serde_json::error::Category;

#[cfg(feature = "json")]
mod reader;

#[cfg(feature = "json")]
pub use reader::{Json, JsonFault, JsonNumber, ReadFault, MAX_DEPTH};

/// What serde_json found in text that is no JSON value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JsonTextFault {
    /// Text that breaks the JSON syntax.
    Syntax,
    /// A value this reader holds no form of: a number beyond a 64-bit float.
    Value,
    /// The text ends inside a value.
    Eof,
}

/// Why bytes are no JSON text, and where.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JsonTextError {
    kind: JsonTextFault,
    line: usize,
    column: usize,
}

impl JsonTextError {
    /// What `error` found, and where.
    #[must_use]
    pub fn of(error: &serde_json::Error) -> Self {
        Self {
            kind: match error.classify() {
                Category::Syntax | Category::Io => JsonTextFault::Syntax,
                Category::Data => JsonTextFault::Value,
                Category::Eof => JsonTextFault::Eof,
            },
            line: error.line(),
            column: error.column(),
        }
    }

    /// What breaks the text.
    #[must_use]
    pub fn kind(self) -> JsonTextFault {
        self.kind
    }

    /// The line, from 1.
    #[must_use]
    pub fn line(self) -> usize {
        self.line
    }

    /// The column, from 1, or 0 at the start of a line.
    #[must_use]
    pub fn column(self) -> usize {
        self.column
    }
}

impl fmt::Display for JsonTextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} at line {} column {}",
            self.kind, self.line, self.column
        )
    }
}

impl std::error::Error for JsonTextError {}
