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

    pub fn v2(self) -> Option<V2> {
        (self.0 >= 2).then_some(V2(()))
    }

    pub fn v3(self) -> Option<V3> {
        (self.0 >= 3).then_some(V3(()))
    }

    pub fn v4(self) -> Option<V4> {
        (self.0 >= 4).then_some(V4(()))
    }

    pub fn v5(self) -> Option<V5> {
        (self.0 >= 5).then_some(V5(()))
    }

    pub fn v6(self) -> Option<V6> {
        (self.0 >= 6).then_some(V6(()))
    }

    pub fn v7(self) -> Option<V7> {
        (self.0 >= 7).then_some(V7(()))
    }
}

/// Emits entry sets through [`crate::SetSink`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V2(());

/// Unlocks [`crate::PaymentWithInfo`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V3(());

/// Offers `self_declare_package_info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V4(());

/// Unlocks [`crate::WithMetadataDisplayText`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V5(());

/// Unlocks [`crate::WithLink`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V6(());

/// Unlocks [`crate::WithDelegation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V7(());
