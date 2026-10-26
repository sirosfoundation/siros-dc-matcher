//! Claims path pointers — OpenID4VP 1.0 §7.
//!
//! A claims path pointer identifies one or more claims inside a credential.
//! It is "a non-empty array of strings, nulls and non-negative integers"
//! (§7), and what those components mean depends on the credential format:
//! §7.1 defines JSON semantics, §7.2 defines ISO mdoc semantics.
//!
//! Both are implemented here so that callers holding ordinary JSON or mdoc
//! credentials do not each reinvent the processing rules — which is where the
//! subtle mistakes live, since the spec distinguishes carefully between
//! *removing an element from the selection* and *aborting with an error*.
//! [`resolve`] is the one §7.1 implementation: any claim tree that implements
//! [`ClaimNode`] walks it, a JSON value and an SD-JWT claim tree alike.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One component of a claims path pointer (§7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PathComponent {
    /// A key to select within an object.
    Key(String),
    /// An index to select within an array.
    Index(u64),
    /// All elements of the currently selected array(s).
    ///
    /// Serialises as JSON `null`, which is how it appears on the wire.
    Null,
}

impl PathComponent {
    /// The key, if this component is one.
    pub fn as_key(&self) -> Option<&str> {
        match self {
            Self::Key(k) => Some(k),
            _ => None,
        }
    }
}

/// The position of a component within a claims path pointer, from 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ComponentIndex(usize);

impl ComponentIndex {
    /// The position `value`.
    #[must_use]
    pub fn new(value: usize) -> Self {
        Self(value)
    }

    /// The position, from 0.
    #[must_use]
    pub fn value(self) -> usize {
        self.0
    }
}

impl core::fmt::Display for ComponentIndex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Why a claims path pointer could not be processed.
///
/// The distinction matters: §7.1.1 says a *type* mismatch aborts processing,
/// while a *missing* key or index merely removes that element from the
/// selection. Collapsing the two would turn "this credential lacks the claim"
/// into "this query is malformed", and the caller responds differently to
/// each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    /// A component was applied to an element of the wrong kind — a string
    /// component to a non-object, or a null/integer to a non-array (§7.1.1).
    TypeMismatch {
        /// The offending component.
        at: ComponentIndex,
    },
    /// Nothing was selected once the pointer had been fully processed
    /// (§7.1.1 step 3). Ordinarily this means the credential does not carry
    /// the claim.
    Empty,
    /// The pointer is not valid for this credential format — for mdoc, "does
    /// not contain exactly two components or one of the components is not a
    /// string" (§7.2.1 step 1).
    Malformed,
}

impl core::fmt::Display for PathError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TypeMismatch { at } => write!(
                f,
                "path component {at} applied to the wrong kind of element"
            ),
            Self::Empty => write!(f, "path selected nothing"),
            Self::Malformed => write!(f, "path is not valid for this credential format"),
        }
    }
}

impl PathError {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::TypeMismatch { .. } => "path_type_mismatch",
            Self::Empty => "path_selects_nothing",
            Self::Malformed => "path_malformed",
        }
    }
}

/// What one component of a claims path pointer finds at one node (§7.1.1, steps 2.1 and 2.3).
pub enum Lookup<N> {
    /// The member or element the component names.
    Found(N),
    /// The node has the right kind and lacks the member, or the position is out of range or
    /// withheld. The node leaves the selection.
    Absent,
    /// The node is not an object (for a key) or not an array (for an index). Processing
    /// aborts.
    WrongKind,
}

/// A node of a claim tree as a claims path pointer walks it (§7.1).
///
/// An array counts its issued positions. A position may be withheld, as an undisclosed
/// SD-JWT array element is.
pub trait ClaimNode: Sized {
    /// The present elements of an array node, in order.
    type Elements: Iterator<Item = Self>;

    /// The member named `key` of an object node.
    fn member(&self, key: &str) -> Lookup<Self>;

    /// The element at position `index` of an array node.
    fn element(&self, index: u64) -> Lookup<Self>;

    /// The present elements of an array node. `None` when the node is not an array.
    fn elements(&self) -> Option<Self::Elements>;
}

/// Process a claims path pointer against the claim tree under `root` (§7.1.1).
///
/// Returns the selected nodes. Follows the specified steps exactly,
/// including the asymmetry that gives this function its shape: a component of
/// the wrong *type* aborts, whereas a key or index that simply is not there
/// drops that element from the selection and processing continues. An index
/// on a withheld position selects nothing, and `null` selects the present
/// elements.
///
/// # Errors
///
/// [`PathError::Malformed`] for an empty pointer, [`PathError::TypeMismatch`]
/// per steps 2.1–2.3, and [`PathError::Empty`] per step 3 when the selection
/// ends up empty.
pub fn resolve<N: ClaimNode>(root: N, path: &[PathComponent]) -> Result<Vec<N>, PathError> {
    // §7: "A claims path pointer MUST be a non-empty array". Processing an
    // empty one would fall through to step 3 with the root still selected and
    // hand back the entire credential — a query too malformed to say what it
    // wants would select everything in it.
    if path.is_empty() {
        return Err(PathError::Malformed);
    }

    // Step 1: select the root element.
    let mut selected = vec![root];

    // Step 2: process components from left to right.
    for (at, component) in path.iter().enumerate() {
        let at = ComponentIndex::new(at);
        let mut next = Vec::new();
        for node in &selected {
            match component {
                // 2.1 — string: select the key. Non-object aborts; a missing
                // key removes that element rather than aborting.
                PathComponent::Key(key) => take(node.member(key), &mut next, at)?,
                // 2.2 — null: select all elements of the selected array(s).
                // Non-array aborts. Note there is no "missing" case here: an
                // empty array contributes nothing and that is not an error yet.
                PathComponent::Null => {
                    next.extend(node.elements().ok_or(PathError::TypeMismatch { at })?);
                }
                // 2.3 — integer: select that index. Non-array aborts; an index
                // past the end removes that array rather than aborting.
                PathComponent::Index(i) => take(node.element(*i), &mut next, at)?,
            }
        }
        selected = next;
    }

    // Step 3: an empty selection is an error, not an empty result.
    if selected.is_empty() {
        return Err(PathError::Empty);
    }
    Ok(selected)
}

/// Add what component `at` found to the selection `next`.
fn take<N>(found: Lookup<N>, next: &mut Vec<N>, at: ComponentIndex) -> Result<(), PathError> {
    match found {
        Lookup::Found(child) => next.push(child),
        Lookup::Absent => {}
        Lookup::WrongKind => return Err(PathError::TypeMismatch { at }),
    }
    Ok(())
}

impl<'a> ClaimNode for &'a Value {
    type Elements = std::slice::Iter<'a, Value>;

    fn member(&self, key: &str) -> Lookup<Self> {
        match self.as_object() {
            Some(object) => object.get(key).map_or(Lookup::Absent, Lookup::Found),
            None => Lookup::WrongKind,
        }
    }

    fn element(&self, index: u64) -> Lookup<Self> {
        match self.as_array() {
            Some(array) => usize::try_from(index)
                .ok()
                .and_then(|i| array.get(i))
                .map_or(Lookup::Absent, Lookup::Found),
            None => Lookup::WrongKind,
        }
    }

    fn elements(&self) -> Option<Self::Elements> {
        self.as_array().map(|array| array.iter())
    }
}

/// Process a claims path pointer against a JSON credential (§7.1.1): [`resolve`]
/// over a [`serde_json::Value`].
///
/// # Errors
///
/// [`PathError`] as [`resolve`] gives it.
pub fn resolve_json<'a>(
    root: &'a Value,
    path: &[PathComponent],
) -> Result<Vec<&'a Value>, PathError> {
    resolve(root, path)
}

/// Validate a claims path pointer for an ISO mdoc credential (§7.2.1 step 1)
/// and return its `(namespace, data_element_identifier)`.
///
/// # Errors
///
/// [`PathError::Malformed`] unless the pointer is exactly two string
/// components.
///
/// Note what this rules out: an mdoc path may not use `null` or an index, and
/// may not be flattened to a single dotted string. ISO namespaces contain dots
/// themselves (`org.iso.18013.5.1`), so a flattened path cannot be split back
/// unambiguously — a mistake that yields namespace `org` and looks plausible
/// right up until nothing matches.
pub fn mdoc_components(path: &[PathComponent]) -> Result<(&str, &str), PathError> {
    match path {
        [PathComponent::Key(ns), PathComponent::Key(id)] => Ok((ns, id)),
        _ => Err(PathError::Malformed),
    }
}
