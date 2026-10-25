//! Capability tokens. Only `Host::connect` creates a [`WasmVersion`], and only
//! a `WasmVersion` creates tokens, so a token proves the host's level.

/// The host level `GetWasmVersion` reported. It hands out the token of each
/// level the host reaches; every call above the base level takes its level's
/// token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WasmVersion(u32);

impl WasmVersion {
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    pub(crate) const fn reported(level: u32) -> Self {
        Self(level)
    }

    /// The level as a number.
    pub const fn get(self) -> u32 {
        self.0
    }

    /// The level-2 token, for entry sets.
    pub fn v2(self) -> Option<V2> {
        (self.0 >= 2).then_some(V2(()))
    }

    /// The level-3 token, for payment entries with additional information.
    pub fn v3(self) -> Option<V3> {
        (self.0 >= 3).then_some(V3(()))
    }

    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    pub(crate) fn v4(self) -> Option<V4> {
        (self.0 >= 4).then_some(V4(()))
    }

    /// The level-5 token, for display text on set entries.
    pub fn v5(self) -> Option<V5> {
        (self.0 >= 5).then_some(V5(()))
    }

    /// The level-6 token, for links on set entries.
    pub fn v6(self) -> Option<V6> {
        (self.0 >= 6).then_some(V6(()))
    }

    /// The level-7 token, for delegation on set entries.
    pub fn v7(self) -> Option<V7> {
        (self.0 >= 7).then_some(V7(()))
    }
}

/// Proof that the host reaches level 2. Sends entry sets through
/// [`crate::SetSink`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V2(());

/// Proof that the host reaches level 3. Unlocks [`crate::PaymentWithInfo`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V3(());

/// Proof that the host reaches level 4, for the package info
/// `Host::connect_with` declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct V4(());

/// Proof that the host reaches level 5. Unlocks
/// [`crate::WithMetadataDisplayText`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V5(());

/// Proof that the host reaches level 6. Unlocks [`crate::WithLink`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V6(());

/// Proof that the host reaches level 7. Unlocks [`crate::WithDelegation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V7(());
