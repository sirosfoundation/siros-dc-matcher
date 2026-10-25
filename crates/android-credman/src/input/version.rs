use crate::*;

/// Gets the API version of the host Credential Manager.
pub fn get_wasm_version() -> u32 {
    abi::get_wasm_version()
}
