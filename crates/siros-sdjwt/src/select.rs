//! Selecting the disclosures that claims path pointers reach (OpenID4VP 1.0, Section 7.1.1;
//! RFC 9901, Section 7.2).

use rustc_hash::FxHashSet;
use siros_dcql::PathComponent;

use crate::error::SelectError;
use crate::key_binding::Presentation;
use crate::sd_jwt::SdJwt;
use crate::tree::{Claim, ClaimValue, Element, Object};

impl SdJwt {
    /// The presentation that discloses the claims `pointers` select.
    ///
    /// Each selected claim adds the disclosures on its path from the root, parents first (RFC
    /// 9901, Section 7.2, step 2), then the disclosures inside its value (OpenID4VP 1.0,
    /// Section 7.3 selects a claim "with its sub-claims as the value"). The disclosures follow
    /// the pointers' order, each once. An empty `pointers` gives the issuer JWT alone.
    ///
    /// A pointer follows OpenID4VP 1.0, Section 7.1.1. An index counts issued positions, and a
    /// withheld position selects nothing; `null` selects the present elements.
    ///
    /// # Errors
    ///
    /// [`SelectError`]: a pointer is empty, applies a component to the wrong kind of value, or
    /// selects no present claim.
    pub fn select<P: AsRef<[PathComponent]>>(
        &self,
        pointers: &[P],
    ) -> Result<Presentation, SelectError> {
        let mut chosen = Chosen::default();
        for pointer in pointers {
            for target in resolve(self.claims(), pointer.as_ref())? {
                for disclosure in target.path {
                    chosen.add(disclosure);
                }
                chosen.add_within(target.node);
            }
        }
        let mut text = self.issuer_jwt().to_owned();
        text.push('~');
        for disclosure in chosen.order {
            text.push_str(disclosure);
            text.push('~');
        }
        Ok(Presentation::new(text, self.alg()))
    }
}

/// A selected claim's value and the disclosures on its path, root first.
struct Target<'a> {
    node: Node<'a>,
    path: Vec<&'a str>,
}

impl<'a> Target<'a> {
    fn descend(&self, claim: &'a Claim) -> Self {
        let mut path = self.path.clone();
        path.extend(claim.disclosure_text());
        Target {
            node: Node::of(claim.value()),
            path,
        }
    }
}

/// A value as a pointer component sees it.
#[derive(Clone, Copy)]
enum Node<'a> {
    Object(&'a Object),
    Array(&'a [Element]),
    Leaf,
}

impl<'a> Node<'a> {
    fn of(value: &'a ClaimValue) -> Self {
        match value {
            ClaimValue::Object(object) => Node::Object(object),
            ClaimValue::Array(elements) => Node::Array(elements),
            _ => Node::Leaf,
        }
    }
}

/// The claims `pointer` selects in `root` (OpenID4VP 1.0, Section 7.1.1).
fn resolve<'a>(
    root: &'a Object,
    pointer: &[PathComponent],
) -> Result<Vec<Target<'a>>, SelectError> {
    if pointer.is_empty() {
        return Err(SelectError::EmptyPointer);
    }
    let mut selected = vec![Target {
        node: Node::Object(root),
        path: Vec::new(),
    }];
    for (at, component) in pointer.iter().enumerate() {
        let mut next = Vec::new();
        for target in &selected {
            match (component, target.node) {
                (PathComponent::Key(name), Node::Object(object)) => {
                    next.extend(object.get(name).map(|claim| target.descend(claim)));
                }
                (PathComponent::Null, Node::Array(elements)) => {
                    next.extend(present(elements).map(|claim| target.descend(claim)));
                }
                (PathComponent::Index(index), Node::Array(elements)) => {
                    let element = usize::try_from(*index).ok().and_then(|i| elements.get(i));
                    if let Some(Element::Present(claim)) = element {
                        next.push(target.descend(claim));
                    }
                }
                _ => return Err(SelectError::TypeMismatch { at }),
            }
        }
        selected = next;
    }
    if selected.is_empty() {
        Err(SelectError::NothingSelected)
    } else {
        Ok(selected)
    }
}

fn present(elements: &[Element]) -> impl Iterator<Item = &Claim> {
    elements.iter().filter_map(|element| match element {
        Element::Present(claim) => Some(claim),
        Element::Withheld => None,
    })
}

/// The chosen disclosures in the order they are first chosen.
#[derive(Default)]
struct Chosen<'a> {
    order: Vec<&'a str>,
    seen: FxHashSet<&'a str>,
}

impl<'a> Chosen<'a> {
    fn add(&mut self, disclosure: &'a str) {
        if self.seen.insert(disclosure) {
            self.order.push(disclosure);
        }
    }

    /// Every disclosure inside `node`, parents before children, in tree order.
    fn add_within(&mut self, node: Node<'a>) {
        let claims: Vec<&'a Claim> = match node {
            Node::Object(object) => object.members().map(|(_, claim)| claim).collect(),
            Node::Array(elements) => present(elements).collect(),
            Node::Leaf => Vec::new(),
        };
        for claim in claims {
            if let Some(disclosure) = claim.disclosure_text() {
                self.add(disclosure);
            }
            self.add_within(Node::of(claim.value()));
        }
    }
}
