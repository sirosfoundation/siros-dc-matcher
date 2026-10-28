//! The matcher binary.
//!
//! Android Credential Manager runs it inside the credential picker: no network, no filesystem,
//! no clock, and a hard time budget. It reads the verifier's request and the registration the
//! wallet registered with it, runs the presentation component's matching over them (K2), and
//! fills the picker with one entry set per offer (K3, K4).
//!
//! # A trap is a silent failure
//!
//! If this binary panics, the picker shows no entries — which the user cannot
//! tell apart from "you have no matching credential". There is no error
//! surface at all. That is why `unwrap` and `expect` are denied below rather
//! than merely discouraged, and why the release profile aborts instead of
//! unwinding. An input that does not read is a diagnostic. A broken guarantee
//! of another component is a bug that no entry set recovers from: it panics,
//! each site under an `#[expect]` that names the guarantee. The host's
//! guarantees are among them: `android-credman` turns a host that breaks its
//! ABI into a panic, and an input too large to allocate traps.
//!
//! # Two host behaviours every emitter must respect
//!
//! An entry with no icon is dropped, and declaring one set id twice discards
//! everything — both silently. See [`diagnostics`] for the full account.
//!
//! # The host
//!
//! Every host call goes through `android-credman`; its contract is
//! `crates/android-credman-sys/ABI.md`.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![deny(clippy::indexing_slicing)]
// A panicking std method that clippy.toml names takes an #[expect] with the
// reason it cannot recover, as each panic of the matcher does.
#![cfg_attr(not(test), deny(clippy::disallowed_methods))]
// Off the wasm target there is no host, and nothing reaches the decision path:
// the test host runs it in the built module. The wasm build, which CI lints,
// keeps dead code an error.
#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

mod diagnostics;
mod entries;
mod fields;
mod matching;
mod shown;
#[cfg(target_arch = "wasm32")]
mod simple_allocator;

// The host calls `_start`, which `wasm32-unknown-unknown` has no CRT to
// export. The shipped build is `wasm32-wasip1` (see the Makefile); this
// target is the WASI-free alternative and builds on the pinned toolchain:
//
//     cargo build -p siros-picker --target wasm32-unknown-unknown \
//         --profile wasm-release
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
#[unsafe(no_mangle)]
extern "C" fn _start() {
    main();
}

use android_credman::SetSink;
use siros_registration::Registration;

use crate::diagnostics::Diagnostics;
use crate::entries::HostLevel;

#[cfg(target_arch = "wasm32")]
fn main() {
    let host = android_credman::Host::connect();
    // Every entry this matcher offers is in a set. A host below level 2 has
    // no sets, so it gets nothing, and the inputs are not read.
    let Some(mut sets) = host.entry_sets() else {
        return;
    };
    let request = host.request();
    let registration = host.credentials();
    let input = Input {
        request: &request,
        registration: &registration,
        level: HostLevel::reported(host.credman()),
    };
    run(&input, &mut sets);
}

/// Off the wasm target there is no host: the test host runs the built module.
#[cfg(not(target_arch = "wasm32"))]
fn main() {}

/// What the host hands one invocation.
struct Input<'a> {
    /// The DC API request JSON.
    request: &'a [u8],
    /// The registration the wallet registered.
    registration: &'a [u8],
    /// The host level, which decides what the entries show (`display_skipped`).
    level: HostLevel,
}

/// One matcher invocation, from the host's inputs to emitted entry sets.
///
/// A registration this picker cannot read gives nothing: the debug flag lives inside it, and
/// the wallet registers the projection together with this binary.
fn run(input: &Input<'_>, sets: &mut impl SetSink) {
    let Ok(registration) = Registration::read(input.registration) else {
        return;
    };
    let unshown = matching::pick(input.request, &registration, input.level, sets);
    Diagnostics::of(&registration).emit(sets, &unshown);
}
