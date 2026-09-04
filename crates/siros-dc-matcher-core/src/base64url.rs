//! Unpadded base64url, decode only.
//!
//! A signed DC API request carries its authorization request object as the
//! payload of a JWS, and the matcher has to read `dcql_query` out of it to know
//! what to offer. That is the only reason this exists.
//!
//! Hand-written rather than a dependency: the `base64` crate is more binary
//! than this function, and the matcher runs inside someone else's process under
//! a size budget. It is also decode-only and rejects everything RFC 4648 §5
//! does not allow, which is a smaller surface to get right than a general
//! codec's.

/// Decode unpadded base64url (RFC 4648 §5).
///
/// Returns `None` for any input that is not exactly that: padding, whitespace,
/// the standard alphabet's `+` and `/`, or a length that cannot be produced by
/// encoding anything.
///
/// Strict on purpose. This decodes an *unverified* payload from a request a
/// verifier sent, and the value decides which credentials a user is offered —
/// so "close enough" is the wrong disposition. A rejection declines one
/// protocol and lets the caller fall through to another the verifier offered.
///
/// ```
/// use siros_dc_matcher_core::base64url;
/// assert_eq!(base64url::decode("aGk").as_deref(), Some(&b"hi"[..]));
/// assert_eq!(base64url::decode("aGk="), None); // padded
/// assert_eq!(base64url::decode("a"), None);    // impossible length
/// ```
#[must_use]
pub fn decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();

    // A base64 quantum is 4 characters carrying 3 bytes. A tail of 2 or 3
    // characters carries 1 or 2 bytes; a tail of exactly 1 carries nothing and
    // cannot be the output of any encoder.
    if bytes.len() % 4 == 1 {
        return None;
    }

    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 2);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;

    for &b in bytes {
        let value = sextet(b)?;
        acc = (acc << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }

    // Whatever is left over must be zero padding the encoder emitted, not data.
    // A non-zero remainder means the input was not produced by encoding these
    // bytes, and accepting it would make several distinct strings decode alike.
    if bits > 0 && (acc & ((1 << bits) - 1)) != 0 {
        return None;
    }

    Some(out)
}

/// The 6-bit value of one base64url character, or `None` if it is not one.
fn sextet(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::decode;

    #[test]
    fn round_trips_the_rfc_4648_examples() {
        // RFC 4648 §10, minus the padding this variant does not use.
        assert_eq!(decode("").as_deref(), Some(&b""[..]));
        assert_eq!(decode("Zg").as_deref(), Some(&b"f"[..]));
        assert_eq!(decode("Zm8").as_deref(), Some(&b"fo"[..]));
        assert_eq!(decode("Zm9v").as_deref(), Some(&b"foo"[..]));
        assert_eq!(decode("Zm9vYg").as_deref(), Some(&b"foob"[..]));
        assert_eq!(decode("Zm9vYmE").as_deref(), Some(&b"fooba"[..]));
        assert_eq!(decode("Zm9vYmFy").as_deref(), Some(&b"foobar"[..]));
    }

    /// The two characters that differ from standard base64 are the whole point
    /// of the URL-safe alphabet: a JWS payload travels in a URL and a header.
    #[test]
    fn uses_the_url_safe_alphabet() {
        assert_eq!(decode("-_8").as_deref(), Some(&[0xFB, 0xFF][..]));
        assert_eq!(decode("+/8"), None, "standard alphabet is not accepted");
    }

    /// Padding is not part of this variant. Accepting it would mean accepting
    /// two spellings of the same value from a party we do not trust.
    #[test]
    fn rejects_padding() {
        assert_eq!(decode("Zg=="), None);
        assert_eq!(decode("Zm8="), None);
    }

    #[test]
    fn rejects_characters_outside_the_alphabet() {
        assert_eq!(decode("Zm9v YmFy"), None, "whitespace");
        assert_eq!(decode("Zm9v\n"), None, "trailing newline");
        assert_eq!(decode("Zm9vä"), None, "non-ascii");
    }

    /// A four-character quantum carries three bytes, so a leftover of one
    /// character carries none. No encoder emits it.
    #[test]
    fn rejects_an_impossible_length() {
        assert_eq!(decode("a"), None);
        assert_eq!(decode("Zm9vY"), None);
    }

    /// `Zh` and `Zg` would otherwise both decode to `f`: the encoder only ever
    /// emits zeroes in the unused low bits, so a non-zero remainder means the
    /// input was not produced by encoding this value.
    #[test]
    fn rejects_a_non_canonical_tail() {
        assert_eq!(decode("Zg").as_deref(), Some(&b"f"[..]));
        assert_eq!(decode("Zh"), None);
        assert_eq!(decode("Zm9vYh"), None);
    }

    /// Decoding is bounded by the input, and a truncated JWS is a normal thing
    /// to receive rather than a reason to trap.
    #[test]
    fn handles_arbitrary_bytes_without_panicking() {
        for len in 0..64usize {
            let s: String = (0..len)
                .map(|i| char::from(b'A' + (i % 26) as u8))
                .collect();
            let _ = decode(&s);
        }
        assert!(decode(&"A".repeat(4096)).is_some());
    }
}
