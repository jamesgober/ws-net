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
- **[`accept`](./docs/API.md#tier-1-accept-and-acceptor)** takes a socket's first bytes and returns the `101` response and a fed `Connection`, with the same-origin policy applied. An **[`Acceptor`](./docs/API.md#tier-1-accept-and-acceptor)** does the same over a head read in pieces, scanning each byte once, and takes an **[`AcceptPolicy`](./docs/API.md#acceptpolicy-and-decision)** (which pages may connect through an **[`OriginPolicy`](./docs/API.md#originpolicy)**, which subprotocol, which limits).
- A **[`ServerHandshake`](./docs/API.md#serverhandshake)** is a validated upgrade request, from raw bytes or from an HTTP layer's parsed fields; it writes the `101` response. A **[`ClientHandshake`](./docs/API.md#clienthandshake)** writes the request and checks the response. A **[`HeadReader`](./docs/API.md#headreader)** reads either head from a socket in pieces with linear total work.
- A **[`WsError`](./docs/API.md#wserror)** is a connection failure, with the close code that was sent, or a refused call that changed nothing. A **[`HandshakeError`](./docs/API.md#handshakeerror)** says why a handshake was refused and writes the refusal.
- **[`Keepalive`](./docs/API.md#keepalive-millis-tick)** pings and times out on the caller's clock: `on_time(now)` and `next_deadline()`, so an idle connection costs no CPU. **[`PreparedMessage`](./docs/API.md#preparedmessage)** encodes a broadcast once. **[`Stats`](./docs/API.md#stats)**, `wipe`, and `release_memory` serve servers with many connections.
- The **[`blocking`](./docs/API.md#the-blocking-module)** module drives a connection over any `Read + Write` stream: `accept`, `connect`, `read`, `send`.
- The **[`frame`](./docs/API.md#the-frame-module)** module is the raw header codec and the masking function, for callers that build or inspect frames; the **[`extension`](./docs/API.md#the-extension-module)** module reads `Sec-WebSocket-Extensions`.

<br>

What it guarantees, and how each guarantee is checked:

| Guarantee | How it is held |
|---|---|
| The Autobahn TestSuite passes, strictly, in both roles. | Every case of sections 1 to 10 (301 cases) is OK in behavior and close behavior as a server and as a client, in CI on every change (`autobahn/check.py`; 3 cases are informational by the suite's own design). |
| Frames follow RFC 6455 exactly; every violation fails the connection with the right close code. | 111 Autobahn-style cases written as data (framing, ping/pong, reserved bits and opcodes, fragmentation, UTF-8, close codes, limits, masking direction, length encoding), each run whole, in pieces of every size from 1 to 15 bytes, and split in two at every point, with identical results. |
| Text is validated as UTF-8 incrementally, across fragment boundaries, and fails at the first bad byte (1007). | A property test accepts a text message exactly when `std::str::from_utf8` accepts its bytes, however it is fragmented and split. |
| Messages survive any fragmentation and any split of the wire bytes, with control frames interleaved. | Round-trip properties client to server and server to client, against the messages sent. |
| A slow reader cannot grow this end's memory either. | The output budget refuses a send that would exceed it and changes nothing; Pong and Close still fit in a 262-byte headroom; a property checks the bound under random sends, drains, and Pings. |
| Memory per connection is bounded and measured. | A counting allocator checks the peak of each scenario against the formula, zero heap for an idle connection after `release_memory`, and zero allocations per message in steady state. |
| Hostile input cannot grow memory past the budgets, and never panics. | Budgets are checked from headers (a property compares the verdict with a direct computation); fuzz properties feed arbitrary bytes and frame-shaped noise with the budgets small, default, and lifted to `u64::MAX`; a peer that pings without reading leaves at most one Pong queued. |
| Every frame shape round-trips through the codec, and masking is its own inverse. | Properties over every opcode, length class, and mask, and over any masking offset, against a byte-by-byte reference. |
| The handshake is RFC 6455's, and refuses what it should. | RFC 6455's own example request and accept key, strict-head tests (bare CR/LF, folding, duplicate `Host`/`Origin`, wrong version, malformed keys, a declared body), and a client-server round trip for arbitrary nonces. |
| A page on another site cannot open a socket as the user. | The Tier 1 path applies the same-origin rule; attack tests try lookalike hosts, userinfo tricks, `null`, other ports and schemes; a property checks `OriginPolicy` against a reference comparison. |
| A head sent one byte at a time costs linear work. | A unit test counts the bytes the `HeadReader` examines for a 16 KiB head fed one byte per call: each once. A property checks it agrees with the one-shot reader for every cut. |
| SHA-1 and base64 are correct. | RFC 3174 and RFC 4648 test vectors, padding boundaries, and streaming-versus-one-shot and canonical-decoding properties. |

<hr>
<br>

## Installation

```toml
[dependencies]
ws-net = "0.8"
```

Without the standard library:

```toml
[dependencies]
ws-net = { version = "0.8", default-features = false }
```

With permessage-deflate (RFC 7692), from 0.9:

```toml
[dependencies]
ws-net = { version = "0.9", features = ["deflate"] }
```

<hr>
<br>

## Quick start

Accept a connection from a socket's first bytes and echo a message:

```rust
use ws_net::Event;

// The upgrade request as it came off the socket, with the first frame
// right behind it: a masked "Hello" (RFC 6455 sections 1.2 and 5.7).
let mut wire = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\n\
    Upgrade: websocket\r\nConnection: Upgrade\r\nOrigin: https://server.example.com\r\n\
    Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n".to_vec();
wire.extend_from_slice(&[0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58]);

// One call: validate, check the Origin, answer 101, build the connection.
let mut accepted = ws_net::accept(&wire)?.expect("complete head");
assert!(accepted.response.ends_with(b"sec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"));

// Messages: poll, reply, write the output.
let conn = &mut accepted.connection;
let text = match conn.poll()? {
    Event::Text(text) => text.to_string(),
    other => panic!("{other:?}"),
};
conn.send_text(&text)?;
assert_eq!(conn.output(), [0x81, 0x05, b'H', b'e', b'l', b'l', b'o']);
# Ok::<(), Box<dyn std::error::Error>>(())
```

### Policy: who may connect

A browser attaches the user's cookies to a WebSocket request from any page on any site, so a server that does not check `Origin` lets another site's page talk to it as the user (cross-site WebSocket hijacking). `accept` applies the same-origin rule by default; an `AcceptPolicy` sets an allowlist, the subprotocols, and the limits:

```rust
use ws_net::{AcceptPolicy, Acceptor, HandshakeError, OriginPolicy};

let request = b"GET /rpc HTTP/1.1\r\nHost: api.example.com\r\nOrigin: https://evil.example\r\n\
    Upgrade: websocket\r\nConnection: Upgrade\r\n\
    Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
let refused = ws_net::accept(request).unwrap_err();
assert_eq!((refused, refused.status()), (HandshakeError::OriginRefused, 403));
let mut answer = Vec::new();
refused.write_response(&mut answer); // "HTTP/1.1 403 Forbidden", then close

let policy = AcceptPolicy::new()
    .with_origins(OriginPolicy::allow(&["https://app.example.com"])?)
    .with_protocols(&["rpc.v2", "rpc.v1"])?;
let mut acceptor = Acceptor::with_policy(policy); // feed it the same buffer as it grows
assert_eq!(acceptor.accept(&request[..40])?.map(|a| a.consumed), None);
# Ok::<(), HandshakeError>(())
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
| [`echo_server`](./examples/echo_server.rs) | A localhost echo server over `std::net`, one thread per connection, with no HTTP library: the handshake through an `Acceptor` (same-origin policy, linear head scanning), refusals answered, protocol failures closed with their code. `cargo run --example echo_server -- 127.0.0.1:9001` |
| [`blocking_echo`](./examples/blocking_echo.rs), [`blocking_client`](./examples/blocking_client.rs) | The blocking adapter on both ends: same-origin policy, keepalive pings, the closing handshake. `cargo run --example blocking_echo -- 127.0.0.1:9001` |
| [`http_net_upgrade`](./examples/http_net_upgrade.rs) | A WebSocket route behind http-net's blocking server: ws-net validates and decides, http-net writes the `101`, `on_upgrade` hands the socket to the adapter. `cargo run --example http_net_upgrade` |
| [`keepalive`](./examples/keepalive.rs) | Pings, an idle timeout, and the slow-message timeout on a simulated clock. `cargo run --example keepalive` |
| [`broadcast`](./examples/broadcast.rs) | One `PreparedMessage` to 10,000 connections, with a slow subscriber refused by its output budget. `cargo run --release --example broadcast` |
| [`accept_policy`](./examples/accept_policy.rs) | An `AcceptPolicy` deciding three requests: the application's own page (101 with the server's preferred subprotocol), another site's page (403), and a client with no shared subprotocol (400). `cargo run --example accept_policy` |

<hr>
<br>

## Performance

The hot paths do no per-message allocation (checked by a counting allocator in CI). A single-frame message already in the input buffer is unmasked in place and lent out with no copy; a streamed text message is validated once per byte as it arrives; frames are written straight into the output queue; client masking keys come from the OS in 1 KiB batches; a browser handshake allocates once.

Against tungstenite 0.30.0 on the same bytes, on GitHub's hosted runners (ratio: tungstenite's median over ws-net's; above 1.00, ws-net is faster):

| Workload | Linux x86_64 | macOS arm64 | Windows x86_64 |
|---|---:|---:|---:|
| Receive 100,000 small masked messages | 2.34 | 1.95 | 2.34 |
| Send 100,000 small messages, server | 2.55 | 2.12 | 4.83 |
| Send 100,000 small messages, client (masked) | 1.47 | 1.93 | 3.52 |
| Accept 10,000 browser upgrade requests | 1.07 | 1.11 | 1.38 |
| Receive one 1 MiB binary message | 0.19 | 1.02 | 1.17 |
| Receive one 1 MiB text message | 0.64 | 1.08 | 1.08 |

The 1 MiB rows on Linux are an open item: the crate's own benchmark measures the same path on the same runner level with tungstenite, so the gap points at a fresh-allocation cost in the harness, not the parser. [`docs/PERFORMANCE.md`](./docs/PERFORMANCE.md) has every number, the comparison with 0.2.0, the method, and how to reproduce it.

```bash
cargo bench --bench bench                          # the crate's benchmarks
cd bench-compare && cargo bench --bench compare    # against tungstenite
```

<hr>
<br>

## Design notes

- **Sans-IO.** The engine never touches a socket, a clock, or a thread. That makes it testable byte by byte and usable from any driver. Keepalive and timeouts are a state machine over the caller's monotonic milliseconds (`on_time`, `next_deadline`); the `blocking` module is a thin adapter on top, not a second engine.
- **Strict where the RFC is strict.** Payload lengths not in their shortest encoding are refused (RFC 6455 says the minimal encoding MUST be used, and accepting both forms gives one frame two encodings). A control frame using an extended length field is refused, whatever the field holds. The handshake head reader refuses bare CR or LF, line folding, and whitespace before a colon, and a request with two `Host` or two `Origin` fields, instead of picking one.
- **Failures and refusals are different things.** A protocol violation fails the connection and queues the Close frame with its code; a call the protocol does not allow (an oversized Ping, a reserved close code, sending after Close) is refused and changes nothing. `WsError::close_code` tells them apart.
- **Budgets come from headers, memory from bytes.** A frame or message over budget is refused from its header. A length in a header is a claim, so reassembly reserves at most 1 MiB ahead of the bytes that have actually arrived, even with the budgets lifted.
- **No third-party dependencies.** The shared HTTP grammar (tokens, lists, field values, `Origin`, `Host`) comes from the first-party `parse-net`, the OS cryptographic random source for masking seeds and nonces from the first-party `mod-rand` (feature `std`), and DEFLATE for permessage-deflate from the first-party `compress-lib` (feature `deflate`); none has dependencies of its own. SHA-1 (only for the handshake, as RFC 6455 fixes it; it is not used as a security primitive) and strict canonical base64 are small private modules.
- **Compression is opt-in and bounded.** permessage-deflate (feature `deflate`) is negotiated only when the policy or the client asks, with no context takeover by default, so attacker-chosen data in one message cannot probe a secret in another through compressed sizes (RFC 7692 section 8); `SendOptions::uncompressed()` opts a message out. Inflation stops at the message budget while it runs, so a small compressed bomb costs at most `max_message`.
- **Fail closed on randomness.** If the OS random source fails, `Connection::client` returns a connection that refuses every send and `ClientHandshake::new` one that refuses to write its request; neither falls back to a predictable value or panics. `try_client` and `try_new` report the failure up front.

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

[`tests/autobahn.rs`](./tests/autobahn.rs) holds the protocol cases as data; [`tests/keepalive.rs`](./tests/keepalive.rs), [`tests/backpressure.rs`](./tests/backpressure.rs), and [`tests/memory.rs`](./tests/memory.rs) the timers, the output budget, and memory per connection (with a counting allocator); [`tests/blocking.rs`](./tests/blocking.rs) and [`tests/http_net.rs`](./tests/http_net.rs) the blocking adapter over real sockets and the http-net hand-off; [`tests/attacks.rs`](./tests/attacks.rs) one test per threat (cross-site hijacking, smuggled bodies, slow heads, floods, log injection, cross-protocol bytes); [`tests/prop.rs`](./tests/prop.rs) the property tests for every invariant in [`dev/DIRECTIVES.md`](./dev/DIRECTIVES.md); [`tests/handshake.rs`](./tests/handshake.rs) and [`tests/closing.rs`](./tests/closing.rs) the two handshakes; [`tests/echo.rs`](./tests/echo.rs) a real localhost echo, including a protocol failure and an `Origin` refusal; [`tests/regressions.rs`](./tests/regressions.rs) one test per defect the pre-release review found. Every `rust` example in this README and in [`docs/API.md`](./docs/API.md) is compiled and run as a doctest.

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
        <li><b>Apache License, Version 2.0</b> - <a href="./LICENSE-APACHE">LICENSE-APACHE</a></li>
        <li><b>MIT License</b> - <a href="./LICENSE-MIT">LICENSE-MIT</a></li>
    </ul>
    <p>at your option.</p>
</div>

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>James Gober.</strong></sup>
</div>
