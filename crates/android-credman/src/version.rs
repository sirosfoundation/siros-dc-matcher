//! Capability tokens. Only `Host::connect` creates a [`WasmVersion`], and only
//! a `WasmVersion` creates tokens, so a token proves the host's level.

/// The level `GetWasmVersion` reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WasmVersion(u32);

impl WasmVersion {
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    pub(crate) const fn reported(level: u32) -> Self {
        Self(level)
    }

    pub const fn get(self) -> u32 {
        self.0
    }

    #[cfg(feature = "v2")]
    pub fn v2(self) -> Option<V2> {
        (self.0 >= 2).then_some(V2(()))
    }

    #[cfg(feature = "v3")]
    pub fn v3(self) -> Option<V3> {
        (self.0 >= 3).then_some(V3(()))
    }

    #[cfg(feature = "v4")]
    pub fn v4(self) -> Option<V4> {
        (self.0 >= 4).then_some(V4(()))
    }

    #[cfg(feature = "v5")]
    pub fn v5(self) -> Option<V5> {
        (self.0 >= 5).then_some(V5(()))
    }

    #[cfg(feature = "v6")]
    pub fn v6(self) -> Option<V6> {
        (self.0 >= 6).then_some(V6(()))
    }

    #[cfg(feature = "v7")]
    pub fn v7(self) -> Option<V7> {
        (self.0 >= 7).then_some(V7(()))
    }
}

/// Emits entry sets through [`crate::SetSink`].
#[cfg(feature = "v2")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V2(());

/// Unlocks [`crate::PaymentWithInfo`].
#[cfg(feature = "v3")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V3(());

/// Offers `self_declare_package_info`.
#[cfg(feature = "v4")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V4(());

/// Unlocks [`crate::SetEntry::with_metadata_display_text`].
#[cfg(feature = "v5")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V5(());

/// Unlocks [`crate::SetEntry::with_link`].
#[cfg(feature = "v6")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V6(());

/// Unlocks [`crate::SetEntry::with_delegation`].
#[cfg(feature = "v7")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V7(());
