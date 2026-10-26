//! Selecting the disclosures that claims path pointers reach (OpenID4VP 1.0, Section 7;
//! RFC 9901, Section 7.2).

use rustc_hash::FxHashSet;
use siros_dcql::{resolve, ClaimNode, Lookup, PathComponent, PathError};

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
    /// [`siros_dcql::resolve`] walks each pointer. An index counts issued positions, and a
    /// withheld position selects nothing; `null` selects the present elements.
    ///
    /// # Errors
    ///
    /// [`PathError`]: a pointer is empty, applies a component to the wrong kind of value, or
    /// selects no present claim.
    pub fn select<P: AsRef<[PathComponent]>>(
        &self,
        pointers: &[P],
    ) -> Result<Presentation, PathError> {
        let mut chosen = Chosen::default();
        for pointer in pointers {
            let root = Target {
                node: Node::Object(self.claims()),
                path: Vec::new(),
            };
            for target in resolve(root, pointer.as_ref())? {
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

/// A node of the claim tree and the disclosures on its path, root first.
struct Target<'a> {
    node: Node<'a>,
    path: Vec<&'a str>,
}

/// The node of `claim`, below the disclosures `path`.
fn child<'a>(path: &[&'a str], claim: &'a Claim) -> Target<'a> {
    let mut path = path.to_vec();
    path.extend(claim.disclosure_text());
    Target {
        node: Node::of(claim.value()),
        path,
    }
}

impl<'a> ClaimNode for Target<'a> {
    type Elements = Children<'a>;

    fn member(&self, key: &str) -> Lookup<Self> {
        match self.node {
            Node::Object(object) => object.get(key).map_or(Lookup::Absent, |claim| {
                Lookup::Found(child(&self.path, claim))
            }),
            _ => Lookup::WrongKind,
        }
    }

    fn element(&self, index: u64) -> Lookup<Self> {
        let Node::Array(elements) = self.node else {
            return Lookup::WrongKind;
        };
        match usize::try_from(index).ok().and_then(|i| elements.get(i)) {
            Some(Element::Present(claim)) => Lookup::Found(child(&self.path, claim)),
            Some(Element::Withheld) | None => Lookup::Absent,
        }
    }

    fn elements(&self) -> Option<Children<'a>> {
        match self.node {
            Node::Array(elements) => Some(Children {
                elements: elements.iter(),
                path: self.path.clone(),
            }),
            _ => None,
        }
    }
}

/// The present elements of an array, as nodes below the array's disclosures.
struct Children<'a> {
    elements: std::slice::Iter<'a, Element>,
    path: Vec<&'a str>,
}

impl<'a> Iterator for Children<'a> {
    type Item = Target<'a>;

    fn next(&mut self) -> Option<Target<'a>> {
        let claim = present(&mut self.elements).next()?;
        Some(child(&self.path, claim))
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

fn present<'a>(elements: impl Iterator<Item = &'a Element>) -> impl Iterator<Item = &'a Claim> {
    elements.filter_map(|element| match element {
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
            Node::Array(elements) => present(elements.iter()).collect(),
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
