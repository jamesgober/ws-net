<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br>
    <b>ws-net</b>
    <br>
    <sub><sup>WEBSOCKET, SANS-IO</sup></sub>
</h1>

<div align="center">
    <a href="https://crates.io/crates/ws-net"><img alt="Crates.io" src="https://img.shields.io/crates/v/ws-net"></a>
    <a href="https://crates.io/crates/ws-net"><img alt="Downloads" src="https://img.shields.io/crates/d/ws-net?color=%230099ff"></a>
    <a href="https://docs.rs/ws-net"><img alt="docs.rs" src="https://img.shields.io/docsrs/ws-net"></a>
    <a href="https://github.com/jamesgober/ws-net/actions"><img alt="CI" src="https://github.com/jamesgober/ws-net/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md"><img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.85%2B-blue"></a>
</div>

<br>

<div align="left">
    <p>
        <strong>ws-net</strong> implements the WebSocket protocol (RFC 6455) without doing I/O: the opening handshake, frame parsing and serialization, masking, fragmentation and reassembly, ping/pong, and the closing handshake. Bytes from your socket go in, messages come out; messages you send become bytes you write. The same engine runs over <code>std::net</code>, an async runtime, or a test harness in memory.
    </p>
    <p>
        Every rule of the protocol is enforced, and every violation closes the connection with the right status code: masking direction, reserved bits and opcodes, control-frame size and fragmentation, minimal length encoding, fragment order, and UTF-8 validity of text, checked incrementally so a bad byte fails the connection the moment it arrives. Every size is bounded, checked from frame headers before any payload is read, so input from a hostile peer cannot grow memory past the budgets. The handshake works over raw request bytes on its own, or behind an HTTP layer such as <code>http-net</code>, and hands the server what its policy needs: the target, <code>Host</code>, <code>Origin</code>, and offered subprotocols. It is the WebSocket layer of LexerSketch Studio.
    </p>
    <br>
    <hr>
    <p>
        <strong>MSRV is 1.85+</strong> (Rust 2024 edition). <code>no_std</code>-compatible (needs only <code>alloc</code>), <code>#![forbid(unsafe_code)]</code>, no dependencies: SHA-1 and base64 for the handshake are implemented in the crate.
    </p>
    <blockquote>
        <strong>Status: pre-1.0.</strong> The public API is designed across the 0.x series and frozen at <code>1.0.0</code>, after LexerSketch Studio ships on it. See <a href="./docs/API.md"><code>docs/API.md</code></a> and <a href="./CHANGELOG.md"><code>CHANGELOG.md</code></a>.
    </blockquote>
</div>

<hr>
<br>

## The model

A handful of types, one per job:

- A **[`Connection`](./docs/API.md#connection)** is one WebSocket after the handshake, server or client. [`feed`](./docs/API.md#input) it bytes, [`poll`](./docs/API.md#connectionpoll) it for **[`Event`](./docs/API.md#event)**s (text, binary, ping, pong, close), [`send`](./docs/API.md#sending-messages) messages, and write its [`output`](./docs/API.md#output). Pings are answered and Close frames echoed automatically. **[`Limits`](./docs/API.md#limits)** sets its frame and message budgets.
- A **[`ServerHandshake`](./docs/API.md#serverhandshake)** is a validated upgrade request, from raw bytes or from an HTTP layer's parsed fields; it writes the `101` response. A **[`ClientHandshake`](./docs/API.md#clienthandshake)** writes the request and checks the response.
- A **[`WsError`](./docs/API.md#wserror)** is a connection failure, with the close code that was sent, or a refused call that changed nothing. A **[`HandshakeError`](./docs/API.md#handshakeerror)** says why a handshake was refused and writes the refusal.
- The **[`frame`](./docs/API.md#the-frame-module)** module is the raw header codec and the masking function, for callers that build or inspect frames.

<br>

What it guarantees, and how each guarantee is checked:

| Guarantee | How it is held |
|---|---|
| Frames follow RFC 6455 exactly; every violation fails the connection with the right close code. | 111 Autobahn-style cases written as data (framing, ping/pong, reserved bits and opcodes, fragmentation, UTF-8, close codes, limits, masking direction, length encoding), each run whole, one byte at a time, and in 7-byte pieces, with identical results. |
| Text is validated as UTF-8 incrementally, across fragment boundaries, and fails at the first bad byte (1007). | A property test accepts a text message exactly when `std::str::from_utf8` accepts its bytes, however it is fragmented and split. |
| Messages survive any fragmentation and any split of the wire bytes, with control frames interleaved. | Round-trip properties client to server and server to client, against the messages sent. |
| Hostile input cannot grow memory past the budgets, and never panics. | Budgets are checked from headers (a property compares the verdict with a direct computation); fuzz properties feed arbitrary bytes and frame-shaped noise with the budgets small, default, and lifted to `u64::MAX`; a peer that pings without reading leaves at most one Pong queued. |
| Every frame shape round-trips through the codec, and masking is its own inverse. | Properties over every opcode, length class, and mask, and over any masking offset, against a byte-by-byte reference. |
| The handshake is RFC 6455's, and refuses what it should. | RFC 6455's own example request and accept key, strict-head tests (bare CR/LF, folding, duplicate `Host`/`Origin`, wrong version, malformed keys), and a client-server round trip for arbitrary nonces. |
| SHA-1 and base64 are correct. | RFC 3174 and RFC 4648 test vectors, padding boundaries, and streaming-versus-one-shot and canonical-decoding properties. |

<hr>
<br>

## Installation

```toml
[dependencies]
ws-net = "0.2"
```

Without the standard library:

```toml
[dependencies]
ws-net = { version = "0.2", default-features = false }
```

<hr>
<br>

## Quick start

Accept a connection from raw bytes and echo a message:

```rust
use ws_net::{Connection, Event, ServerHandshake};

// The upgrade request as it came off the socket, with the first frame
// right behind it: a masked "Hello" (RFC 6455 sections 1.2 and 5.7).
let mut wire = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\n\
    Upgrade: websocket\r\nConnection: Upgrade\r\n\
    Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n".to_vec();
wire.extend_from_slice(&[0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58]);

// The handshake: validate, then answer 101.
let (handshake, head_len) = ServerHandshake::from_head(&wire)?.expect("complete head");
let mut response = Vec::new();
handshake.write_response(None, &mut response)?;
assert!(response.ends_with(b"sec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"));

// Messages: feed what followed the head, poll, reply, write the output.
let mut conn = Connection::server();
let _ = conn.feed(&wire[head_len..]);
let text = match conn.poll()? {
    Event::Text(text) => text.to_string(),
    other => panic!("{other:?}"),
};
conn.send_text(&text)?;
assert_eq!(conn.output(), [0x81, 0x05, b'H', b'e', b'l', b'l', b'o']);
# Ok::<(), Box<dyn std::error::Error>>(())
```

### Policy: Host and Origin

The crate validates the protocol; deciding who may connect is the server's. A browser always sends `Origin`, and checking it is what stops another web page from opening a socket to a local server:

```rust
use ws_net::ServerHandshake;

let request = b"GET /rpc HTTP/1.1\r\nHost: 127.0.0.1:53817\r\nOrigin: http://evil.example\r\n\
    Upgrade: websocket\r\nConnection: Upgrade\r\n\
    Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
let (handshake, _) = ServerHandshake::from_head(request)?.expect("complete head");
let allowed = handshake.host() == "127.0.0.1:53817"
    && handshake.origin() == Some("http://127.0.0.1:53817");
assert!(!allowed); // answer "HTTP/1.1 403 Forbidden" and close
# Ok::<(), ws_net::HandshakeError>(())
```

### Failures close with the right code

```rust
use ws_net::{CloseCode, Connection, WsError};

let mut conn = Connection::server();
// A masked text frame whose payload is not UTF-8.
let _ = conn.feed(&[0x81, 0x81, 0, 0, 0, 0, 0xFF]);
let err = conn.poll().unwrap_err();
assert_eq!(err, WsError::InvalidUtf8);
assert_eq!(err.close_code(), Some(CloseCode::INVALID_PAYLOAD));
// The Close frame (1007) is queued: write it, then close the socket.
assert_eq!(conn.output(), [0x88, 0x02, 0x03, 0xEF]);

// A refused call is different: nothing is sent, the connection is unchanged.
let mut conn = Connection::server();
let refused = conn.send_ping(&[0; 200]).unwrap_err();
assert_eq!(refused.close_code(), None);
conn.send_text("still open")?;
# Ok::<(), WsError>(())
```

### Behind an HTTP server

`ServerHandshake::from_request` takes the method, target, and header fields as `(&str, &[u8])` pairs, the shape `http-net`'s `RequestHead` yields, so the two compose with no glue and no dependency between them:

```rust
use ws_net::ServerHandshake;

let fields = [
    ("Host", &b"127.0.0.1:53817"[..]),
    ("Upgrade", b"websocket"),
    ("Connection", b"Upgrade"),
    ("Sec-WebSocket-Key", b"dGhlIHNhbXBsZSBub25jZQ=="),
    ("Sec-WebSocket-Version", b"13"),
];
// With http-net: from_request(req.method_str(), req.target(), req.headers())
let handshake = ServerHandshake::from_request("GET", "/rpc", fields)?;
assert_eq!(handshake.accept_key().as_str(), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
# Ok::<(), ws_net::HandshakeError>(())
```

<hr>
<br>

## Examples

Runnable programs in [`examples/`](./examples):

| Example | What it shows |
|---|---|
| [`sans_io`](./examples/sans_io.rs) | A client and a server talking through memory: the handshake as raw bytes, messages, a ping, a refused call, and the closing handshake. The loop every transport adapter wraps. `cargo run --example sans_io` |
| [`echo_server`](./examples/echo_server.rs) | A localhost echo server over `std::net`, one thread per connection, with no HTTP library: the handshake from raw bytes, refusals answered, protocol failures closed with their code. `cargo run --example echo_server -- 127.0.0.1:9001` |

<hr>
<br>

## Performance

The hot paths do no per-message allocation. A single-frame message that is already in the input buffer is unmasked in place and lent out as a slice of the buffer, with no copy. Masking runs eight bytes at a time. Frames are encoded straight into the output queue. Fragmented messages are reassembled into one reused buffer, which is released after delivery if a large message grew it.

Measured with the benchmarks in [`benches/`](./benches), Windows x86_64, Rust stable, release profile:

| Benchmark | What it measures | Windows |
|---|---|---:|
| `receive_100k/small_messages` | A server parsing 100,000 small masked messages (half JSON-RPC text, half binary) in 64 KiB reads. | ~1.1 ms (~90 M msg/s) |
| `receive_1mib/binary` | One 1 MiB masked binary message in 64 KiB reads. | ~4.3 GiB/s |
| `receive_1mib/text_utf8` | One 1 MiB masked text message, UTF-8 validated. | ~1.8 GiB/s |
| `send_100k/client_masked` | A client serializing and masking 100,000 small messages. | ~4.8 ms (~21 M msg/s) |
| `send_100k/server_unmasked` | A server serializing 100,000 small messages. | ~1.5 ms (~67 M msg/s) |
| `mask_1mib/in_place` | Masking 1 MiB in place. | ~70-100 GiB/s |
| `accept_key` | The handshake's SHA-1 and base64. | ~0.3 µs |
| `handshake/from_head_100k` | Validating a browser-sized upgrade request from raw bytes and writing the `101`, 100,000 times. | ~1.4 µs each |

Linux numbers have not been measured for this release. Numbers vary by CPU and by run (the masking benchmark is memory-bound and the noisiest); use the trend across runs, not a single absolute.

```bash
cargo bench --bench bench
```

<hr>
<br>

## Design notes

- **Sans-IO.** The engine never touches a socket, a clock, or a thread. That makes it testable byte by byte, usable from any runtime, and leaves timeouts and keep-alive pings (Studio sends one every 30 s) to the caller, who owns the clock.
- **Strict where the RFC is strict.** Payload lengths not in their shortest encoding are refused (RFC 6455 says the minimal encoding MUST be used, and accepting both forms gives one frame two encodings). A control frame using an extended length field is refused, whatever the field holds. The handshake head reader refuses bare CR or LF, line folding, and whitespace before a colon, and a request with two `Host` or two `Origin` fields, instead of picking one.
- **Failures and refusals are different things.** A protocol violation fails the connection and queues the Close frame with its code; a call the protocol does not allow (an oversized Ping, a reserved close code, sending after Close) is refused and changes nothing. `WsError::close_code` tells them apart.
- **Budgets come from headers, memory from bytes.** A frame or message over budget is refused from its header. A length in a header is a claim, so reassembly reserves at most 1 MiB ahead of the bytes that have actually arrived, even with the budgets lifted.
- **No dependencies.** SHA-1 (only for the handshake, as RFC 6455 fixes it; it is not used as a security primitive) and strict canonical base64 are small private modules. They move to the owner's crypto and codec libraries when those provide them, without an API change.

<hr>
<br>

## Testing

The suite runs on Windows, Linux, and macOS through the CI matrix, on stable and the 1.85 MSRV:

```bash
cargo test                       # unit + integration + property + doctests
cargo test --no-default-features # no_std + alloc
cargo clippy --all-targets --all-features -- -D warnings
cargo bench --bench bench
```

[`tests/autobahn.rs`](./tests/autobahn.rs) holds the protocol cases as data; [`tests/prop.rs`](./tests/prop.rs) the property tests for every invariant in [`dev/DIRECTIVES.md`](./dev/DIRECTIVES.md); [`tests/handshake.rs`](./tests/handshake.rs) and [`tests/closing.rs`](./tests/closing.rs) the two handshakes; [`tests/echo.rs`](./tests/echo.rs) a real localhost echo, including a protocol failure and an `Origin` refusal; [`tests/regressions.rs`](./tests/regressions.rs) one test per defect the pre-release review found. Every `rust` example in this README and in [`docs/API.md`](./docs/API.md) is compiled and run as a doctest.

<hr>
<br>

## Cross-platform support

- Linux (x86_64, aarch64)
- macOS (x86_64, Apple Silicon)
- Windows (x86_64)

The engine uses no operating-system facilities. With the `std` feature, a client's masking keys and handshake nonce are seeded from the standard library's OS-seeded hasher keys; without it, the caller supplies the seed.

<hr>
<br>

## Contributing

See [`REPS.md`](./REPS.md) for the engineering standards every change is held to, [`dev/DIRECTIVES.md`](./dev/DIRECTIVES.md) for the definition of done, and [`dev/ROADMAP.md`](./dev/ROADMAP.md) for what comes next. Before a PR: `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-features` must be clean.

<br>

<div id="license">
    <h2>License</h2>
    <p>Licensed under either of</p>
    <ul>
        <li><b>Apache License, Version 2.0</b> &mdash; <a href="./LICENSE-APACHE">LICENSE-APACHE</a></li>
        <li><b>MIT License</b> &mdash; <a href="./LICENSE-MIT">LICENSE-MIT</a></li>
    </ul>
    <p>at your option.</p>
</div>

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>James Gober.</strong></sup>
</div>
