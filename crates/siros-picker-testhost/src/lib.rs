//! A host implementation of the Credential Manager matcher ABI.
//!
//! In production the only thing that implements this ABI is Play Services,
//! which means the only way to exercise a matcher is to install it on a phone
//! and drive a real verifier. That is a poor place to discover that a DCQL
//! `claim_sets` edge case is wrong.
//!
//! This crate implements the same ABI over wasmtime, so the real `.wasm`
//! binary runs in ordinary `cargo test`: `tests/matcher_wasm` compares the
//! picker's offers with the wallet's own plan (K2).

#![deny(missing_docs)]
#![deny(unsafe_code)]

mod imports;

use imports::add_credman;

use anyhow::{Context, Result};
use wasmtime::{Engine, Linker, Module, Store};
use wasmtime_wasi::preview1::{self, WasiP1Ctx};
use wasmtime_wasi::WasiCtxBuilder;

/// What the host offers a matcher on one invocation.
#[derive(Debug, Clone, Default)]
pub struct Invocation {
    /// The DC API request JSON, shaped `{"requests":[{"protocol":…,"data":…}]}`.
    pub request: Vec<u8>,
    /// The registration the wallet registered.
    pub credentials: Vec<u8>,
    /// Package name of the calling app, as the platform verified it.
    pub calling_package: String,
    /// Verified web origin, empty when the caller is a native app.
    pub origin: String,
    /// Host ABI version reported through `GetWasmVersion`.
    pub wasm_version: u32,
}

/// One credential the matcher offered to the picker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedEntry {
    /// Set this entry belongs to.
    pub set_id: String,
    /// Position within the set.
    pub index: i32,
    /// Wallet-side credential identifier.
    pub credential_id: String,
    /// Primary line shown to the user.
    pub title: String,
    /// Secondary line, typically the issuer: `None` for a null pointer, with the
    /// absent-versus-empty distinction of [`CapturedEntry::disclaimer`].
    pub subtitle: Option<String>,
    /// Opaque payload handed back to the wallet on selection; `None` for a
    /// null pointer.
    pub metadata: Option<String>,
    /// Icon bytes the matcher passed, if any.
    pub icon: Vec<u8>,
    /// The disclaimer pointer, distinguishing absent from empty.
    ///
    /// `None` for a null pointer and `Some("")` for a pointer to an empty
    /// string. The distinction is the whole point: the real host renders the
    /// presence of this field, so an empty string draws a label with nothing
    /// in it — the v0.6.1 warning-badge bug. A capture that collapsed the two
    /// could not tell that bug from correct behaviour.
    pub disclaimer: Option<String>,
    /// The warning pointer, with the same absent-versus-empty distinction.
    pub warning: Option<String>,
    /// Display fields attached to this entry, in emission order: each name,
    /// and its value, `None` for a null pointer.
    pub fields: Vec<(String, Option<String>)>,
    /// The delegation type sent at level 7.
    pub delegation: Option<i32>,
    /// The second disclaimer, link text and link target sent at level 6.
    pub link: Option<(String, String, String)>,
    /// The display text sent at level 5.
    pub metadata_display_text: Option<String>,
    /// The payment a payment entry shows; `None` for a verification entry. A payment entry's
    /// title, subtitle and icon are its payment method's.
    pub payment: Option<CapturedPayment>,
}

/// What a payment entry shows of its payment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedPayment {
    /// The payee.
    pub merchant: String,
    /// The amount as display text.
    pub amount: String,
    /// The further text sent at level 3; `None` for a null pointer or below level 3.
    pub additional_info: Option<String>,
}

/// Everything a matcher emitted during one run.
#[derive(Debug, Clone, Default)]
pub struct Captured {
    /// Sets declared, as `(set_id, declared_length)`.
    pub sets: Vec<(String, i32)>,
    /// Entries emitted, in order.
    pub entries: Vec<CapturedEntry>,
}

impl Captured {
    /// The entry at `set_id`/`index`, if the matcher emitted one.
    pub fn entry(&self, set_id: &str, index: i32) -> Option<&CapturedEntry> {
        self.entries
            .iter()
            .find(|e| e.set_id == set_id && e.index == index)
    }

    /// Whether the matcher offered nothing.
    ///
    /// Worth naming, because in the picker this is indistinguishable from a
    /// trap: both show the user no wallet at all.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Host state threaded through the wasmtime store.
struct State {
    wasi: WasiP1Ctx,
    input: Invocation,
    out: Captured,
}

/// Run a matcher module against one invocation and capture what it emitted.
///
/// # Errors
///
/// Returns an error if the module fails to compile, fails to instantiate
/// (typically a host import it needs and we do not provide), or traps.
pub fn run(wasm: &[u8], input: Invocation) -> Result<Captured> {
    let (engine, module) = compiled(wasm)?;

    let mut store = Store::new(
        &engine,
        State {
            wasi: WasiCtxBuilder::new().inherit_stdio().build_p1(),
            input,
            out: Captured::default(),
        },
    );

    let mut linker: Linker<State> = Linker::new(&engine);
    preview1::add_to_linker_sync(&mut linker, |s: &mut State| &mut s.wasi)
        .context("linking WASI preview 1")?;
    add_credman(&mut linker)?;
    // The real host links a module whose imports it lacks and traps when one
    // is called (ABI.md §3). The calls this host does not record behave the
    // same way.
    linker
        .define_unknown_imports_as_traps(&module)
        .context("defining the unrecorded imports")?;

    let instance = linker
        .instantiate(&mut store, &module)
        .context("instantiating matcher")?;

    instance
        .get_typed_func::<(), ()>(&mut store, "_start")
        .context("matcher has no _start export")?
        .call(&mut store, ())
        .context("matcher trapped — in a real picker this shows the user nothing at all")?;

    Ok(store.into_data().out)
}

/// Compile a module once per process, reusing it across runs.
///
/// Compiling is by far the slowest part of a run — the matcher is a few
/// hundred kilobytes and every test needs it — so recompiling per test turned
/// a fast suite into a slow one. Keyed by the bytes, because the guard tests
/// run hand-written modules of their own.
fn compiled(wasm: &[u8]) -> Result<(Engine, Module)> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    static ENGINE: OnceLock<Engine> = OnceLock::new();
    #[allow(clippy::type_complexity)]
    static MODULES: OnceLock<Mutex<HashMap<Vec<u8>, Module>>> = OnceLock::new();

    let engine = ENGINE.get_or_init(Engine::default).clone();

    // Keyed by the bytes themselves, not a hash of them. A collision would
    // silently run the wrong module, and "the wrong module ran" is close to
    // undiagnosable from a failing assertion. Only a handful of modules are
    // ever cached, so the copies cost nothing worth saving.
    let cache = MODULES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    let module = match cache.get(wasm) {
        Some(module) => module.clone(),
        None => {
            let module = Module::new(&engine, wasm).context("compiling matcher module")?;
            cache.insert(wasm.to_vec(), module.clone());
            module
        }
    };
    Ok((engine, module))
}
