//! A host implementation of the Credential Manager matcher ABI.
//!
//! In production the only thing that implements this ABI is Play Services,
//! which means the only way to exercise a matcher is to install it on a phone
//! and drive a real verifier. That is a poor place to discover that a DCQL
//! `claim_sets` edge case is wrong.
//!
//! This crate implements the same ABI over wasmtime, so the real `.wasm`
//! binary runs against fixtures in ordinary `cargo test`. It also lets the
//! same fixtures be replayed against another implementation for differential
//! testing — see `CONTRIBUTING.md` on how that oracle is obtained, and why it
//! is never vendored into this repository.

#![deny(missing_docs)]
#![deny(unsafe_code)]

use anyhow::{Context, Result};
use wasmtime::{Caller, Engine, Extern, Linker, Memory, Module, Store};
use wasmtime_wasi::preview1::{self, WasiP1Ctx};
use wasmtime_wasi::WasiCtxBuilder;

/// Environment variable naming a local matcher binary to use as a
/// differential-testing oracle. Tests skip when it is unset.
pub const ORACLE_ENV: &str = "MULTIPAZ_MATCHER_WASM";

/// What the host offers a matcher on one invocation.
#[derive(Debug, Clone, Default)]
pub struct Invocation {
    /// The DC API request JSON, shaped `{"requests":[{"protocol":…,"data":…}]}`.
    pub request: Vec<u8>,
    /// The credential blob the wallet registered. Format is the wallet's own.
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
    /// Secondary line, typically the issuer.
    pub subtitle: String,
    /// Opaque payload handed back to the wallet on selection.
    pub metadata: String,
    /// Icon bytes the matcher passed, if any.
    pub icon: Vec<u8>,
    /// Display fields attached to this entry, in emission order.
    pub fields: Vec<(String, String)>,
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

    let instance = linker.instantiate(&mut store, &module).context(
        "instantiating matcher — a missing import means the host lacks a function it needs",
    )?;

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

/// Register the `credman` and `credman_v2` imports the matcher links against.
fn add_credman(linker: &mut Linker<State>) -> Result<()> {
    linker.func_wrap(
        "credman",
        "GetWasmVersion",
        |mut c: Caller<'_, State>, ptr: i32| {
            let v = c.data().input.wasm_version;
            write_u32(&mut c, ptr, v)
        },
    )?;

    linker.func_wrap(
        "credman",
        "GetRequestSize",
        |mut c: Caller<'_, State>, ptr: i32| {
            let n = c.data().input.request.len() as u32;
            write_u32(&mut c, ptr, n)
        },
    )?;

    linker.func_wrap(
        "credman",
        "GetRequestBuffer",
        |mut c: Caller<'_, State>, ptr: i32| {
            let bytes = c.data().input.request.clone();
            write_bytes(&mut c, ptr, &bytes)
        },
    )?;

    linker.func_wrap(
        "credman",
        "GetCredentialsSize",
        |mut c: Caller<'_, State>, ptr: i32| {
            let n = c.data().input.credentials.len() as u32;
            write_u32(&mut c, ptr, n)
        },
    )?;

    // Returns how many bytes were actually read, which is not necessarily the
    // number asked for — a matcher may request past the end of the blob.
    linker.func_wrap(
        "credman",
        "ReadCredentialsBuffer",
        |mut c: Caller<'_, State>, ptr: i32, offset: i32, len: i32| -> Result<i32> {
            let blob = c.data().input.credentials.clone();
            let start = (offset.max(0) as usize).min(blob.len());
            let end = start.saturating_add(len.max(0) as usize).min(blob.len());
            let slice = blob.get(start..end).unwrap_or_default().to_vec();
            write_bytes(&mut c, ptr, &slice)?;
            Ok(slice.len() as i32)
        },
    )?;

    // Fixed-size NUL-padded buffers: 256 bytes of package name followed by
    // 512 of origin. The sizes are part of the ABI, not a convention.
    linker.func_wrap(
        "credman",
        "GetCallingAppInfo",
        |mut c: Caller<'_, State>, ptr: i32| {
            let (pkg, origin) = {
                let i = &c.data().input;
                (i.calling_package.clone(), i.origin.clone())
            };
            let mut buf = vec![0u8; 256 + 512];
            write_padded(&mut buf, 0, 256, &pkg);
            write_padded(&mut buf, 256, 512, &origin);
            write_bytes(&mut c, ptr, &buf)
        },
    )?;

    linker.func_wrap(
        "credman_v2",
        "AddEntrySet",
        |mut c: Caller<'_, State>, set_id: i32, len: i32| -> Result<()> {
            let set_id = read_cstr(&mut c, set_id)?;
            c.data_mut().out.sets.push((set_id, len));
            Ok(())
        },
    )?;

    #[allow(clippy::too_many_arguments)]
    linker.func_wrap(
        "credman_v2",
        "AddEntryToSet",
        |mut c: Caller<'_, State>,
         cred_id: i32,
         icon: i32,
         icon_len: i32,
         title: i32,
         subtitle: i32,
         _disclaimer: i32,
         _warning: i32,
         metadata: i32,
         set_id: i32,
         index: i32|
         -> Result<()> {
            // Read the icon by pointer and length, not as a C string: it is
            // arbitrary bytes and a PNG contains NULs, so treating it as text
            // would silently truncate at the first one.
            let icon = read_bytes(&mut c, icon, icon_len)?;
            let entry = CapturedEntry {
                set_id: read_cstr(&mut c, set_id)?,
                index,
                credential_id: read_cstr(&mut c, cred_id)?,
                title: read_cstr(&mut c, title)?,
                subtitle: read_cstr(&mut c, subtitle)?,
                metadata: read_cstr(&mut c, metadata)?,
                icon,
                fields: Vec::new(),
            };
            c.data_mut().out.entries.push(entry);
            Ok(())
        },
    )?;

    linker.func_wrap(
        "credman_v2",
        "AddFieldToEntrySet",
        |mut c: Caller<'_, State>,
         cred_id: i32,
         name: i32,
         value: i32,
         set_id: i32,
         index: i32|
         -> Result<()> {
            let (cred_id, set_id, name, value) = (
                read_cstr(&mut c, cred_id)?,
                read_cstr(&mut c, set_id)?,
                read_cstr(&mut c, name)?,
                read_cstr(&mut c, value)?,
            );
            // A field for an entry that was never added is a matcher bug, and
            // silently dropping it would hide exactly that bug.
            let out = &mut c.data_mut().out;
            let Some(entry) = out
                .entries
                .iter_mut()
                .find(|e| e.set_id == set_id && e.index == index)
            else {
                return Err(anyhow::anyhow!(
                    "field {name:?} added to unknown entry {set_id}[{index}]"
                ));
            };

            // The credential id is checked, not ignored. The platform keys
            // fields by credential id as well as set position, so a guest
            // passing the wrong one — or an empty one — produces fields that
            // never attach in a real picker. A host that accepted any id
            // would let that ship while every test stayed green, which is the
            // one failure mode a test host exists to prevent.
            if cred_id != entry.credential_id {
                return Err(anyhow::anyhow!(
                    "field {name:?} for entry {set_id}[{index}] carries credential id {cred_id:?}, \
                     but the entry was added as {:?}",
                    entry.credential_id
                ));
            }

            entry.fields.push((name, value));
            Ok(())
        },
    )?;

    Ok(())
}

/// The guest's linear memory.
fn memory(c: &mut Caller<'_, State>) -> Result<Memory> {
    match c.get_export("memory") {
        Some(Extern::Memory(m)) => Ok(m),
        _ => Err(anyhow::anyhow!("matcher does not export `memory`")),
    }
}

fn write_u32(c: &mut Caller<'_, State>, ptr: i32, value: u32) -> Result<()> {
    write_bytes(c, ptr, &value.to_le_bytes())
}

fn write_bytes(c: &mut Caller<'_, State>, ptr: i32, bytes: &[u8]) -> Result<()> {
    let mem = memory(c)?;
    mem.write(c, ptr as usize, bytes)
        .context("matcher passed a pointer outside its own memory")
}

/// Read `len` bytes from guest memory.
///
/// A null pointer or zero length means "no value", which is how the ABI says
/// an entry has no icon.
fn read_bytes(c: &mut Caller<'_, State>, ptr: i32, len: i32) -> Result<Vec<u8>> {
    if ptr == 0 || len <= 0 {
        return Ok(Vec::new());
    }
    let mem = memory(c)?;
    let data = mem.data(&c);
    let start = ptr as usize;
    let end = start
        .checked_add(len as usize)
        .context("icon length overflows the address space")?;
    data.get(start..end)
        .map(<[u8]>::to_vec)
        .context("matcher passed an icon outside its own memory")
}

/// Read a NUL-terminated string the guest passed as `char*`.
fn read_cstr(c: &mut Caller<'_, State>, ptr: i32) -> Result<String> {
    if ptr == 0 {
        return Ok(String::new());
    }
    let mem = memory(c)?;
    let data = mem.data(&c);
    let start = ptr as usize;
    let tail = data
        .get(start..)
        .context("matcher passed a pointer outside its own memory")?;
    let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
    Ok(String::from_utf8_lossy(tail.get(..end).unwrap_or_default()).into_owned())
}

/// Write `value` NUL-padded into a fixed-width ABI field.
fn write_padded(buf: &mut [u8], offset: usize, width: usize, value: &str) {
    let src = value.as_bytes();
    let n = src.len().min(width.saturating_sub(1));
    if let (Some(dst), Some(src)) = (buf.get_mut(offset..offset + n), src.get(..n)) {
        dst.copy_from_slice(src);
    }
}
