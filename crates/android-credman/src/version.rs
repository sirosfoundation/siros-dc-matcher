//! The host's ABI level and the capability tokens it grants.
//!
//! A token is a zero-sized proof that the host reported a level high enough
//! for a group of functions. Only [`WasmVersion`] creates tokens, and only
//! `Host::connect` creates a `WasmVersion`, from `GetWasmVersion`. Every
//! call above the base level takes its token, so a matcher reaches a
//! function the host may lack only through the version the host reported.
//!
//! The thresholds are the minimum versions in `ABI.md`.

/// The ABI level the host reported through `GetWasmVersion`.
///
/// Levels 0 and 1 grant the same: the base `credman` module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WasmVersion(u32);

impl WasmVersion {
    /// The level as the host reported it.
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    pub(crate) const fn reported(level: u32) -> Self {
        Self(level)
    }

    /// The raw level.
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Entry sets (`credman_v2`), from level 2.
    #[cfg(feature = "v2")]
    pub fn v2(self) -> Option<V2> {
        (self.0 >= 2).then_some(V2(()))
    }

    /// `AddPaymentEntryToSetV2` in `credman_v2`, from level 3.
    #[cfg(feature = "v3")]
    pub fn v3(self) -> Option<V3> {
        (self.0 >= 3).then_some(V3(()))
    }

    /// `credman_v4`, from level 4.
    #[cfg(feature = "v4")]
    pub fn v4(self) -> Option<V4> {
        (self.0 >= 4).then_some(V4(()))
    }

    /// `credman_v5`, from level 5.
    #[cfg(feature = "v5")]
    pub fn v5(self) -> Option<V5> {
        (self.0 >= 5).then_some(V5(()))
    }

    /// `credman_v6`, from level 6.
    #[cfg(feature = "v6")]
    pub fn v6(self) -> Option<V6> {
        (self.0 >= 6).then_some(V6(()))
    }

    /// `credman_v7`, from level 7.
    #[cfg(feature = "v7")]
    pub fn v7(self) -> Option<V7> {
        (self.0 >= 7).then_some(V7(()))
    }
}

/// The host reported level 2 or higher. On the host, this token emits entry
/// sets through [`crate::SetSink`].
#[cfg(feature = "v2")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V2(());

/// The host reported level 3 or higher: payment entries in a set may carry
/// additional information.
#[cfg(feature = "v3")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V3(());

/// The host reported level 4 or higher: the registering app may declare its
/// name and icon.
#[cfg(feature = "v4")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V4(());

/// The host reported level 5 or higher: an entry in a set may carry
/// metadata display text.
#[cfg(feature = "v5")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V5(());

/// The host reported level 6 or higher: an entry in a set may carry a
/// verification link.
#[cfg(feature = "v6")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V6(());

/// The host reported level 7 or higher: an entry in a set may carry a
/// delegation type.
#[cfg(feature = "v7")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V7(());
