//! What Credential Manager returns to the wallet for a picked set entry: the standard metadata
//! object [`SetEntry::metadata`](crate::SetEntry::metadata) writes.

use serde_json::{Map, Value};

/// Whether the host shows every text a set entry carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Shown {
    /// The host shows every text.
    Full,
    /// The host's level leaves text of the entry out.
    Skipped,
}

/// The standard metadata object of a picked entry:
/// `{"display_skipped":bool,"host_level":n,"data":<the matcher's JSON>}`, `data` absent when the
/// matcher set none.
#[derive(Debug, Clone, PartialEq)]
pub struct Picked {
    shown: Shown,
    host_level: u32,
    data: Option<Value>,
}

/// A member of the standard metadata object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PickedMember {
    /// `display_skipped`: a boolean.
    DisplaySkipped,
    /// `host_level`: the host level, a non-negative integer.
    HostLevel,
}

/// Why a text is no standard metadata object.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PickedError {
    /// The text is no JSON object.
    #[error("entry metadata is no JSON object")]
    NotObject,
    /// A member is absent or of the wrong type.
    #[error("entry metadata member {} malformed", .0.as_str())]
    Member(PickedMember),
    /// The object has this member, which the standard object does not define.
    #[error("entry metadata member {0:?} unknown")]
    MemberUnknown(String),
}

impl PickedMember {
    /// The member's name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DisplaySkipped => "display_skipped",
            Self::HostLevel => "host_level",
        }
    }
}

/// The member that carries the matcher's JSON.
const DATA: &str = "data";

impl Picked {
    /// The standard metadata object `metadata`, as the host returns it with a picked entry.
    ///
    /// # Errors
    ///
    /// [`PickedError`]: the first rule `metadata` breaks.
    pub fn parse(metadata: &str) -> Result<Self, PickedError> {
        let object = match serde_json::from_str::<Value>(metadata) {
            Ok(Value::Object(object)) => object,
            Ok(_) | Err(_) => return Err(PickedError::NotObject),
        };
        let known = [
            PickedMember::DisplaySkipped.as_str(),
            PickedMember::HostLevel.as_str(),
            DATA,
        ];
        if let Some(unknown) = object.keys().find(|name| !known.contains(&name.as_str())) {
            return Err(PickedError::MemberUnknown(unknown.clone()));
        }
        let skipped = member(&object, PickedMember::DisplaySkipped)?
            .as_bool()
            .ok_or(PickedError::Member(PickedMember::DisplaySkipped))?;
        let host_level = member(&object, PickedMember::HostLevel)?
            .as_u64()
            .and_then(|level| u32::try_from(level).ok())
            .ok_or(PickedError::Member(PickedMember::HostLevel))?;
        Ok(Self {
            shown: if skipped { Shown::Skipped } else { Shown::Full },
            host_level,
            data: object.get(DATA).cloned(),
        })
    }

    /// Whether the host showed every text of the entry.
    pub fn shown(&self) -> Shown {
        self.shown
    }

    /// The level of the host that showed the entry.
    pub fn host_level(&self) -> u32 {
        self.host_level
    }

    /// The matcher's JSON value.
    pub fn data(&self) -> Option<&Value> {
        self.data.as_ref()
    }
}

/// The member `member` of `object`.
fn member(object: &Map<String, Value>, member: PickedMember) -> Result<&Value, PickedError> {
    object
        .get(member.as_str())
        .ok_or(PickedError::Member(member))
}
