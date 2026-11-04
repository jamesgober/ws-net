//! A server's handshake policy, in memory: which pages may connect, which
//! subprotocol is spoken, and the limits of the connection that results.
//!
//! ```sh
//! cargo run --example accept_policy
//! ```
//!
//! Three requests arrive: one from the application's own page, one from a
//! page on another site (cross-site WebSocket hijacking: refused with 403),
//! and one that speaks none of the server's subprotocols (refused with 400).
//! The same policy works behind an HTTP layer: `AcceptPolicy::check` decides
//! without writing anything, for a server that writes its own 101.

use ws_net::{AcceptPolicy, Acceptor, Limits, OriginPolicy};

fn request(origin: &str, protocols: &str) -> Vec<u8> {
    format!(
        "GET /rpc HTTP/1.1\r\nHost: api.example.com\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\nOrigin: {origin}\r\n\
         Sec-WebSocket-Protocol: {protocols}\r\n\r\n"
    )
    .into_bytes()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy = AcceptPolicy::new()
        // Only the application's own pages; `null` and lookalikes never match.
        .with_origins(OriginPolicy::allow(&["https://app.example.com"])?.allow_missing(false))
        // The server's preference order wins over the client's.
        .with_protocols(&["rpc.v2", "rpc.v1"])?
        .require_protocol()
        .with_limits(Limits::new().with_max_message(1 << 20));

    let cases = [
        (
            "own page",
            request("https://app.example.com", "rpc.v1, rpc.v2"),
        ),
        ("other site", request("https://evil.example", "rpc.v2")),
        (
            "no shared protocol",
            request("https://app.example.com", "chat"),
        ),
    ];
    for (name, wire) in cases {
        let mut acceptor = Acceptor::with_policy(policy.clone());
        match acceptor.accept(&wire) {
            Ok(Some(accepted)) => {
                let status = String::from_utf8_lossy(&accepted.response);
                let first = status.lines().next().unwrap_or_default();
                let protocol = policy.check(&accepted.handshake)?.protocol;
                println!("{name}: {first}, protocol {protocol:?}");
            }
            Ok(None) => println!("{name}: head incomplete"),
            Err(refused) => {
                let mut response = Vec::new();
                refused.write_response(&mut response);
                let text = String::from_utf8_lossy(&response);
                let first = text.lines().next().unwrap_or_default();
                println!("{name}: {first} ({refused})");
            }
        }
    }
    Ok(())
}
