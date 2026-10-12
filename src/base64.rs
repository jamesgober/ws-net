//! Base64 (RFC 4648 section 4, standard alphabet, padded), for the
//! handshake keys.
//!
//! Decoding is strict: padding is required, no whitespace, and the unused
//! low bits of the last character must be zero, so every byte string has
//! exactly one accepted encoding. This module is private and moves to the
//! owner's codec library once that library is published (see
//! `dev/ROADMAP.md`).

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encodes `input` into `out`, which must be exactly `encoded_len(input.len())`
/// bytes long.
pub(crate) fn encode_into(input: &[u8], out: &mut [u8]) {
    let mut o = 0;
    let mut chunks = input.chunks_exact(3);
    for c in &mut chunks {
        let n = (u32::from(c[0]) << 16) | (u32::from(c[1]) << 8) | u32::from(c[2]);
        put4(out, o, n, 4);
        o += 4;
    }
    match *chunks.remainder() {
        [a] => {
            put4(out, o, u32::from(a) << 16, 2);
        }
        [a, b] => {
            put4(out, o, (u32::from(a) << 16) | (u32::from(b) << 8), 3);
        }
        _ => {}
    }
}

/// Writes the four characters for the 24-bit group `n`, of which `keep` are
/// data and the rest padding.
fn put4(out: &mut [u8], at: usize, n: u32, keep: usize) {
    for i in 0..4 {
        let c = if i < keep {
            ALPHABET[((n >> (18 - 6 * i)) & 0x3f) as usize]
        } else {
            b'='
        };
        if let Some(slot) = out.get_mut(at + i) {
            *slot = c;
        }
    }
}

/// The encoded length of `n` input bytes.
#[cfg(test)]
pub(crate) const fn encoded_len(n: usize) -> usize {
    n.div_ceil(3) * 4
}

fn value(c: u8) -> Option<u32> {
    Some(u32::from(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    }))
}

/// Decodes `input` into `out`, returning the decoded length, or `None` when
/// the input is not canonical base64 or `out` is too small.
pub(crate) fn decode_into(input: &[u8], out: &mut [u8]) -> Option<usize> {
    if input.len() % 4 != 0 {
        return None;
    }
    let groups = input.len() / 4;
    let mut o = 0;
    for (g, quad) in input.chunks_exact(4).enumerate() {
        let last = g + 1 == groups;
        let pad = match quad {
            [_, _, b'=', b'='] if last => 2,
            [_, _, _, b'='] if last => 1,
            _ => 0,
        };
        let mut n = 0u32;
        for &c in &quad[..4 - pad] {
            n = (n << 6) | value(c)?;
        }
        n <<= 6 * pad as u32;
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        let keep = 3 - pad;
        // Canonical form: bits that padding hides must be zero.
        if bytes[keep..].iter().any(|&b| b != 0) {
            return None;
        }
        out.get_mut(o..o + keep)?.copy_from_slice(&bytes[..keep]);
        o += keep;
    }
    Some(o)
}

#[cfg(test)]
mod tests {
    use alloc::{string::String, vec, vec::Vec};

    use proptest::prelude::*;

    use super::*;

    fn encode(input: &[u8]) -> String {
        let mut out = vec![0u8; encoded_len(input.len())];
        encode_into(input, &mut out);
        String::from_utf8(out).unwrap()
    }

    fn decode(input: &str) -> Option<Vec<u8>> {
        let mut out = vec![0u8; input.len()];
        let n = decode_into(input.as_bytes(), &mut out)?;
        out.truncate(n);
        Some(out)
    }

    #[test]
    fn test_base64_rfc4648_vectors() {
        // RFC 4648 section 10.
        for (plain, coded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(plain.as_bytes()), coded);
            assert_eq!(decode(coded).as_deref(), Some(plain.as_bytes()));
        }
    }

    #[test]
    fn test_base64_decode_is_strict() {
        for bad in [
            "Zg", "Zg=", "Zg===", "Zh==", "Zm9=", "Z===", "====", "Zm 9v", "Zm9v\n", "Zm-v",
            "Zm_v", "Zg==Zg==", "=Zg=",
        ] {
            assert_eq!(decode(bad), None, "{bad:?}");
        }
        let mut small = [0u8; 2];
        assert_eq!(decode_into(b"Zm9v", &mut small), None);
    }

    proptest! {
        #[test]
        fn prop_round_trip(data in proptest::collection::vec(any::<u8>(), 0..100)) {
            let coded = encode(&data);
            prop_assert_eq!(coded.len(), encoded_len(data.len()));
            prop_assert_eq!(decode(&coded), Some(data));
        }

        #[test]
        fn prop_decode_accepts_only_canonical(text in "[A-Za-z0-9+/=]{0,16}") {
            // Anything decode accepts must re-encode to itself.
            if let Some(bytes) = decode(&text) {
                prop_assert_eq!(encode(&bytes), text);
            }
        }
    }
}
