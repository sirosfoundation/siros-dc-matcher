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
