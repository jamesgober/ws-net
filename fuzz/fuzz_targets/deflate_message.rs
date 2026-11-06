//! A server connection that negotiated permessage-deflate (with and
//! without context takeover, window bits from the input), fed arbitrary
//! bytes: compressed and plain messages, RSV1 anywhere, and DEFLATE data
//! of every shape. No panic, whole output frames, the same events and
//! output however the input is split, and memory within the bounds.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ws_net::{AcceptPolicy, Connection, DeflateConfig, OriginPolicy, ServerHandshake};

#[path = "drive.rs"]
mod drive;

fn server(select: u8) -> Connection {
    let bits = 8 + (select >> 4) % 8;
    let takeover = select & 0x08 != 0;
    let config = DeflateConfig::new()
        .with_client_context_takeover(takeover)
        .with_client_max_window_bits(bits);
    let offer: &[u8] = if takeover {
        b"permessage-deflate; client_max_window_bits"
    } else {
        b"permessage-deflate; client_no_context_takeover; client_max_window_bits"
    };
    let h = ServerHandshake::from_request(
        "GET",
        "/",
        [
            ("Host", &b"a"[..]),
            ("Upgrade", b"websocket"),
            ("Connection", b"Upgrade"),
            ("Sec-WebSocket-Version", b"13"),
            ("Sec-WebSocket-Key", b"dGhlIHNhbXBsZSBub25jZQ=="),
            ("Sec-WebSocket-Extensions", offer),
        ],
    )
    .expect("valid request");
    let policy = AcceptPolicy::new()
        .with_origins(OriginPolicy::any_origin())
        .with_deflate(config)
        .with_limits(drive::limits(select));
    let mut out = Vec::new();
    let conn = h.accept(&policy, &mut out).expect("accepted");
    assert!(conn.negotiated().deflate().is_some());
    conn
}

fuzz_target!(|data: &[u8]| {
    let Some((&select, rest)) = data.split_first() else { return };
    drive::check(|| server(select), rest, select);
});
