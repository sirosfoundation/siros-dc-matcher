//! `application/x-www-form-urlencoded`: the query of an authorization request URI and the body
//! of a POST.

use rustc_hash::FxHashMap;

/// The parameters of a form-encoded string, each name once.
///
/// `None` when a name repeats, a percent-escape is malformed, or a decoded name or value is
/// not UTF-8.
pub(crate) fn parse(text: &str) -> Option<FxHashMap<String, String>> {
    let mut out = FxHashMap::default();
    for pair in text.split('&').filter(|p| !p.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if out.insert(decode(name)?, decode(value)?).is_some() {
            return None;
        }
    }
    Some(out)
}

/// `pairs` as a form-encoded string, every byte outside the unreserved set of RFC 3986,
/// Section 2.3 percent-encoded.
pub(crate) fn encode(pairs: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (index, (name, value)) in pairs.iter().enumerate() {
        if index > 0 {
            out.push('&');
        }
        escape(name, &mut out);
        out.push('=');
        escape(value, &mut out);
    }
    out
}

fn escape(text: &str, out: &mut String) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &byte in text.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            for nibble in [byte >> 4, byte & 0x0f] {
                out.push(char::from(
                    HEX.get(usize::from(nibble)).copied().unwrap_or(b'0'),
                ));
            }
        }
    }
}

fn decode(text: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(text.len());
    let mut iter = text.bytes();
    while let Some(byte) = iter.next() {
        match byte {
            b'+' => bytes.push(b' '),
            b'%' => {
                let high = hex(iter.next()?)?;
                let low = hex(iter.next()?)?;
                bytes.push(high << 4 | low);
            }
            other => bytes.push(other),
        }
    }
    String::from_utf8(bytes).ok()
}

fn hex(digit: u8) -> Option<u8> {
    char::from(digit)
        .to_digit(16)
        .and_then(|d| u8::try_from(d).ok())
}
