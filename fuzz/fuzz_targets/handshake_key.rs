//! `Sec-WebSocket-Key`: accepted exactly when it is the canonical base64 of
//! 16 bytes (checked against the client's encoder of the decoded bytes).
#![no_main]

use libfuzzer_sys::fuzz_target;
use ws_net::{ClientHandshake, HandshakeError, ServerHandshake};

/// A plain reference decoder of 22 base64 characters plus `==`.
fn reference(key: &[u8]) -> Option<[u8; 16]> {
    if key.len() != 24 || &key[22..] != b"==" {
        return None;
    }
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bits: u32 = 0;
    let mut have = 0;
    let mut out = [0u8; 16];
    let mut n = 0;
    for &c in &key[..22] {
        let v = alphabet.iter().position(|&a| a == c)? as u32;
        bits = (bits << 6) | v;
        have += 6;
        if have >= 8 {
            have -= 8;
            if n == 16 {
                return None;
            }
            out[n] = (bits >> have) as u8;
            n += 1;
        }
    }
    (n == 16).then_some(out)
}

fuzz_target!(|data: &[u8]| {
    let fields = [
        ("Host", &b"a"[..]),
        ("Upgrade", b"websocket"),
        ("Connection", b"Upgrade"),
        ("Sec-WebSocket-Version", b"13"),
        ("Sec-WebSocket-Key", data),
    ];
    let accepted = ServerHandshake::from_request("GET", "/", fields);
    let canonical = reference(data)
        .is_some_and(|nonce| ClientHandshake::with_nonce(nonce).key().as_bytes() == data);
    match accepted {
        Ok(_) => assert!(canonical, "{data:?}"),
        Err(e) => assert!(!canonical || e != HandshakeError::InvalidKey, "{data:?}"),
    }
});
