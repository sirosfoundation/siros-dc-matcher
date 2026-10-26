//! Claims path pointers (OpenID4VP 1.0, Section 7).

use siros_dcql::PathComponent;

use crate::error::PointerError;

/// A claims path pointer: a non-empty array of keys, indexes and `null`s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimPointer(Vec<PathComponent>);

impl ClaimPointer {
    /// The pointer of `components`.
    ///
    /// # Errors
    ///
    /// [`PointerError::Empty`] for no component.
    pub fn parse(components: Vec<PathComponent>) -> Result<Self, PointerError> {
        if components.is_empty() {
            return Err(PointerError::Empty);
        }
        Ok(Self(components))
    }

    /// The components, at least one.
    pub fn components(&self) -> &[PathComponent] {
        &self.0
    }
}
