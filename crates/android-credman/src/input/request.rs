use crate::*;

/// Fetches the Verifier's JSON request from the host.
pub fn get_request() -> Vec<u8> {
    let size = abi::get_request_size();
    if size == 0 {
        return Vec::new();
    }
    let mut buffer = vec![0u8; size as usize];
    abi::get_request_buffer(&mut buffer);
    buffer
}

/// Fetches the Verifier's JSON request as a String.
pub fn get_request_string() -> String {
    String::from_utf8_lossy(&get_request()).into_owned()
}
