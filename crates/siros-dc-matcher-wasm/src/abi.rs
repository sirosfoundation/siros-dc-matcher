//! The Android Credential Manager matcher ABI.
//!
//! # Provenance
//!
//! These signatures are an interoperability interface, not borrowed code. They
//! were read directly off the import and export tables of a shipping matcher
//! binary: imports resolve against the modules `credman` and `credman_v2`, plus
//! a `wasi_snapshot_preview1` subset (`fd_write`, `fd_seek`, `fd_close`,
//! `fd_fdstat_get`, `proc_exit`); the only exports are `_start` and `memory`.
//!
//! That WASI subset is what settles the toolchain. Because the host already
//! speaks preview 1, the stock `wasm32-wasip1` target works as-is — no custom
//! shim, no `no_std`, and `std` collections and formatting remain available.
//!
//! # Host versions
//!
//! `credman_v2` is not present on every Play Services version. Call
//! [`wasm_version`] and fall back to the v1 emission functions rather than
//! assuming the set-based ones exist; a missing import is a link failure, not
//! a runtime `None`.

#![allow(unsafe_code)] // FFI to the host is the entire purpose of this module.

/// The calling application, as the platform verified it.
///
/// Fixed-size buffers because the host writes into memory we hand it. Sizes
/// are part of the ABI.
// Only constructed on the target, but kept compiled on the host so the ABI
// stays type-checked, formatted and clippy-clean in ordinary CI.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
#[repr(C)]
#[derive(Debug)]
pub struct CallingAppInfo {
    /// Package name of the calling app.
    pub package_name: [u8; 256],
    /// Web origin, when the caller is a browser acting for a page.
    pub origin: [u8; 512],
}

#[cfg(target_arch = "wasm32")]
mod imports {
    use super::CallingAppInfo;

    #[link(wasm_import_module = "credman")]
    extern "C" {
        pub fn GetCallingAppInfo(info: *mut CallingAppInfo);
        pub fn GetRequestSize(size: *mut u32);
        pub fn GetRequestBuffer(buffer: *mut u8);
        pub fn GetCredentialsSize(size: *mut u32);
        pub fn ReadCredentialsBuffer(buffer: *mut u8, offset: usize, len: usize) -> usize;
        pub fn GetWasmVersion(version: *mut u32);
    }

    #[link(wasm_import_module = "credman_v2")]
    extern "C" {
        pub fn AddEntrySet(set_id: *const core::ffi::c_char, set_length: i32);
        #[allow(clippy::too_many_arguments)]
        pub fn AddEntryToSet(
            cred_id: *const core::ffi::c_char,
            icon: *const core::ffi::c_char,
            icon_len: usize,
            title: *const core::ffi::c_char,
            subtitle: *const core::ffi::c_char,
            disclaimer: *const core::ffi::c_char,
            warning: *const core::ffi::c_char,
            metadata: *const core::ffi::c_char,
            set_id: *const core::ffi::c_char,
            set_index: i32,
        );
        pub fn AddFieldToEntrySet(
            cred_id: *const core::ffi::c_char,
            field_display_name: *const core::ffi::c_char,
            field_display_value: *const core::ffi::c_char,
            set_id: *const core::ffi::c_char,
            set_index: i32,
        );
    }
}

/// Host ABI version, used to decide whether `credman_v2` is available.
///
/// Returns 0 off-target, where there is no host at all.
pub fn wasm_version() -> u32 {
    #[cfg(target_arch = "wasm32")]
    {
        let mut v: u32 = 0;
        // SAFETY: the host writes exactly one u32 into the pointer we own.
        unsafe { imports::GetWasmVersion(&mut v) };
        v
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        0
    }
}

/// The verifier's request, as a JSON byte buffer.
///
/// Shaped `{"requests":[{"protocol": "...", "data": {...}}]}`.
///
/// Returns an empty vector off-target so the crate stays checkable, testable
/// and clippy-clean on the host — the real matcher only ever runs in the
/// sandbox.
pub fn request_bytes() -> Vec<u8> {
    #[cfg(target_arch = "wasm32")]
    {
        let mut size: u32 = 0;
        // SAFETY: the host writes exactly one u32 into the pointer we own.
        unsafe { imports::GetRequestSize(&mut size) };
        let mut buf = vec![0u8; size as usize];
        // SAFETY: buf is `size` bytes long, which is what the host reported.
        unsafe { imports::GetRequestBuffer(buf.as_mut_ptr()) };
        buf
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Vec::new()
    }
}

/// The credential blob this wallet registered, read back in full.
pub fn credentials_bytes() -> Vec<u8> {
    #[cfg(target_arch = "wasm32")]
    {
        let mut size: u32 = 0;
        // SAFETY: the host writes exactly one u32 into the pointer we own.
        unsafe { imports::GetCredentialsSize(&mut size) };
        let len = size as usize;
        let mut buf = vec![0u8; len];
        // SAFETY: buf is `len` bytes long, and we ask for exactly that many
        // starting at offset 0.
        unsafe { imports::ReadCredentialsBuffer(buf.as_mut_ptr(), 0, len) };
        buf
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Vec::new()
    }
}

/// The caller the platform verified, as `(package_name, origin)`.
///
/// Both fields are fixed-size, NUL-padded buffers on the wire; this trims at
/// the first NUL. `origin` is empty when the caller is a native app rather
/// than a browser acting for a page.
///
/// Trust note: this is the platform's own attestation of the caller. It is the
/// only trustworthy statement of who is asking — anything naming an origin
/// inside the request body is the request describing itself.
pub fn calling_app_info() -> (String, String) {
    #[cfg(target_arch = "wasm32")]
    {
        let mut info = CallingAppInfo {
            package_name: [0u8; 256],
            origin: [0u8; 512],
        };
        // SAFETY: the host writes into a struct we own, whose field sizes are
        // fixed by the ABI.
        unsafe { imports::GetCallingAppInfo(&mut info) };
        (trim_nul(&info.package_name), trim_nul(&info.origin))
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        (String::new(), String::new())
    }
}

/// Decode a NUL-padded ABI buffer, stopping at the first NUL.
///
/// Lossy on purpose: a matcher that traps produces no picker entries, which
/// the user reads as "no matching credential". Mangled text beats silence.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn trim_nul(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(buf.split_at(end).0).into_owned()
}

/// Emission — handing matched credentials back to the picker.
///
/// # Why only the v2 path
///
/// `credman_v2`'s set-based functions are what DCQL `credential_sets` needs: a
/// set can be satisfied by a *combination* of credentials that the picker must
/// present and select as one unit, which the flat v1 functions cannot express.
///
/// A v1 fallback is deliberately not implemented here, because a runtime check
/// cannot deliver one — as `docs/abi.md` explains. WebAssembly imports are
/// resolved at instantiation: a module that *declares* `credman_v2` will fail
/// to load on a host that lacks it, however carefully it inspects
/// [`wasm_version`] first. Supporting such a host means shipping a second
/// binary, not branching inside this one. Every Play Services version that
/// currently ships resolves these imports, so that second binary does not
/// exist yet — see the Phase 5 note in `docs/plan.md`.
///
/// [`wasm_version`] is still worth reading: it goes into entry metadata, so a
/// field report says which host ABI produced the behaviour.
pub mod emit {
    /// Declare a set of `len` entries that the user selects as one unit.
    pub fn entry_set(set_id: &str, len: usize) {
        let _ = (set_id, len);
        #[cfg(target_arch = "wasm32")]
        {
            let set_id = super::c(set_id);
            // SAFETY: both arguments outlive the call.
            unsafe { super::imports::AddEntrySet(set_id.as_ptr(), len as i32) };
        }
    }

    /// Add one credential to a set previously declared by [`entry_set`].
    ///
    /// `metadata` is opaque to the platform and survives the picker
    /// round-trip, so it carries the decision this matcher already made rather
    /// than leaving the wallet to re-derive it after selection.
    pub fn entry(set_id: &str, index: usize, e: &siros_dc_matcher_core::sink::Entry<'_>) {
        let _ = (set_id, index, e);
        #[cfg(target_arch = "wasm32")]
        {
            let (set_id, cred_id) = (super::c(set_id), super::c(e.credential_id));
            let (title, subtitle) = (super::c(e.title), super::c(e.subtitle));
            let metadata = super::c(e.metadata);
            let empty = super::c("");
            // A null pointer with length 0 for "no icon". The bytes, when
            // there are some, are borrowed straight from the decoded blob —
            // they outlive the call, and copying a bitmap per entry inside a
            // sandbox with a time budget is worth avoiding.
            let (icon_ptr, icon_len) = match e.icon {
                Some(bytes) if !bytes.is_empty() => {
                    (bytes.as_ptr() as *const core::ffi::c_char, bytes.len())
                }
                _ => (core::ptr::null(), 0),
            };
            // SAFETY: every pointer is to a value alive for the whole call,
            // and icon_len is the true length of the slice icon_ptr came from.
            unsafe {
                super::imports::AddEntryToSet(
                    cred_id.as_ptr(),
                    icon_ptr,
                    icon_len,
                    title.as_ptr(),
                    subtitle.as_ptr(),
                    empty.as_ptr(),
                    empty.as_ptr(),
                    metadata.as_ptr(),
                    set_id.as_ptr(),
                    index as i32,
                )
            };
        }
    }

    /// Add a displayable field to an entry already added to the set.
    ///
    /// `credential_id` must be the same id passed to [`entry`]. The platform
    /// keys fields by credential id as well as by set position, so passing
    /// anything else — an empty string included — risks the field never
    /// attaching to the entry in a real picker, with nothing said about it.
    pub fn field(set_id: &str, index: usize, credential_id: &str, name: &str, value: &str) {
        let _ = (set_id, index, credential_id, name, value);
        #[cfg(target_arch = "wasm32")]
        {
            let (set_id, name, value) = (super::c(set_id), super::c(name), super::c(value));
            let cred_id = super::c(credential_id);
            // SAFETY: every pointer is to a CString alive for the whole call.
            unsafe {
                super::imports::AddFieldToEntrySet(
                    cred_id.as_ptr(),
                    name.as_ptr(),
                    value.as_ptr(),
                    set_id.as_ptr(),
                    index as i32,
                )
            };
        }
    }
}

/// Encode a Rust string as the NUL-terminated `char*` the ABI expects.
///
/// Interior NULs are truncated rather than rejected. A credential whose title
/// contains a NUL is pathological, but dropping the whole picker entry over it
/// would present as "no matching credential" with no way to tell why.
#[cfg(target_arch = "wasm32")]
fn c(s: &str) -> std::ffi::CString {
    let bytes = s.as_bytes();
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    // SAFETY-adjacent: split_at(end) cannot contain a NUL, so this cannot fail.
    std::ffi::CString::new(bytes.split_at(end).0).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::trim_nul;

    #[test]
    fn trims_at_first_nul() {
        assert_eq!(trim_nul(b"org.siros.wallet\0\0\0"), "org.siros.wallet");
    }

    #[test]
    fn handles_unpadded_and_empty_buffers() {
        assert_eq!(trim_nul(b"abc"), "abc");
        assert_eq!(trim_nul(b""), "");
        assert_eq!(trim_nul(b"\0"), "");
    }

    /// Invalid UTF-8 must degrade, not trap.
    #[test]
    fn invalid_utf8_is_lossy_not_fatal() {
        assert_eq!(trim_nul(b"a\xffb\0"), "a\u{fffd}b");
    }
}
