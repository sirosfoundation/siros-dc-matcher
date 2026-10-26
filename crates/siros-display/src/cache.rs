//! The display metadata a host holds, keyed for resolution.

use rustc_hash::FxHashMap;

use crate::error::DisplayError;
use crate::issuer::IssuerMetadata;
use crate::type_metadata::TypeMetadata;

/// The display metadata a host holds: OpenID4VCI display metadata keyed by Credential Issuer
/// Identifier and credential configuration identifier, and SD-JWT VC Type Metadata keyed by
/// `vct`. Every `extends` names a type the cache holds, and no chain of `extends` returns to
/// its start (SD-JWT VC, Sections 5.4 and 7.4).
#[derive(Debug, Clone, Default)]
pub struct DisplayCache {
    issuers: FxHashMap<String, FxHashMap<String, IssuerMetadata>>,
    types: FxHashMap<String, TypeMetadata>,
}

impl DisplayCache {
    /// The cache of `issuers` and `types`.
    ///
    /// # Errors
    ///
    /// [`DisplayError::IssuerMetadataRepeated`] for two entries of one configuration,
    /// [`DisplayError::TypeMetadataRepeated`] for two documents of one `vct`,
    /// [`DisplayError::ExtendsUnknown`] for an `extends` the cache lacks, and
    /// [`DisplayError::ExtendsCycle`] for a chain of `extends` that returns to its start.
    pub fn new(
        issuers: Vec<IssuerMetadata>,
        types: Vec<TypeMetadata>,
    ) -> Result<Self, DisplayError> {
        let mut cache = Self::default();
        for metadata in issuers {
            let configurations = cache
                .issuers
                .entry(metadata.credential_issuer().to_owned())
                .or_default();
            if configurations
                .insert(metadata.configuration_id().to_owned(), metadata)
                .is_some()
            {
                return Err(DisplayError::IssuerMetadataRepeated);
            }
        }
        for metadata in types {
            if cache
                .types
                .insert(metadata.vct().to_owned(), metadata)
                .is_some()
            {
                return Err(DisplayError::TypeMetadataRepeated);
            }
        }
        for start in cache.types.values() {
            let mut steps = 0;
            let mut at = start;
            while let Some(extended) = at.extends() {
                at = cache
                    .types
                    .get(extended)
                    .ok_or(DisplayError::ExtendsUnknown)?;
                steps += 1;
                if steps > cache.types.len() {
                    return Err(DisplayError::ExtendsCycle);
                }
            }
        }
        Ok(cache)
    }

    /// The OpenID4VCI display metadata of configuration `configuration_id` of `issuer`.
    pub(crate) fn issuer(&self, issuer: &str, configuration_id: &str) -> Option<&IssuerMetadata> {
        self.issuers.get(issuer)?.get(configuration_id)
    }

    /// The Type Metadata of `vct`, then of each type it extends, in order.
    pub(crate) fn type_chain<'a>(&'a self, vct: &str) -> impl Iterator<Item = &'a TypeMetadata> {
        let mut next = self.types.get(vct);
        std::iter::from_fn(move || {
            let current = next?;
            next = current
                .extends()
                .and_then(|extended| self.types.get(extended));
            Some(current)
        })
    }
}
