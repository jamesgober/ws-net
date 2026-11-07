# ws-net - API Reference

> Complete reference for every public item in `ws-net`, with examples.
> **Status: beta (0.9.0), design locked.** Every item of the 1.0 surface
> is listed in [The 1.0 API](#the-10-api-design-lock) with the version it
> landed in, and every one is shipped and documented below. The surface is
> frozen at `1.0.0`, after LexerSketch Studio ships on it. See
> [`../dev/ROADMAP.md`](../dev/ROADMAP.md) and [`../dev/PLAN.md`](../dev/PLAN.md).

<sub>Copyright &copy; 2026 <strong>James Gober</strong>.</sub>

## Table of contents

- [Overview](#overview)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Tier 1: `accept` and `Acceptor`](#tier-1-accept-and-acceptor)
- [Concepts](#concepts)
  - [The I/O loop](#the-io-loop)
  - [Failures and refused calls](#failures-and-refused-calls)
  - [Budgets and memory](#budgets-and-memory)
  - [The closing handshake](#the-closing-handshake)
  - [Handshake policy: Host, Origin, subprotocols](#handshake-policy-host-origin-subprotocols)
  - [Behind an HTTP layer](#behind-an-http-layer)
  - [Protocol rules and policies](#protocol-rules-and-policies)
- [`Connection`](#connection)
  - [Constructors](#connection-constructors)
  - [Input: `feed`, `read_buf`, `commit`, `feed_eof`](#input)
  - [`Connection::poll`](#connectionpoll)
  - [Sending messages](#sending-messages)
  - [Control frames: `send_ping`, `send_pong`, `close`](#control-frames)
  - [Output: `output`, `advance_output`](#output)
  - [Accessors: `limits`, `role`, `state`, `is_open`, `can_send`](#accessors)
  - [Keepalive: `with_keepalive`, `on_time`, `next_deadline`](#keepalive)
  - [Memory and observability](#memory-and-observability)
  - [Split borrow and detach: `poll_split`, `Sender`, `detach_message`](#split-borrow-and-detach)
- [`Event`](#event)
- [`Message` and `MessageKind`](#message-and-messagekind)
- [`PreparedMessage`](#preparedmessage)
- [`Keepalive`, `Millis`, `Tick`](#keepalive-millis-tick)
- [`Stats`](#stats)
- [`Limits`](#limits)
- [`Role`](#role)
- [`State`](#state)
- [`CloseCode`](#closecode)
- [`CloseFrame`](#closeframe)
- [`WsError`](#wserror)
- [`ServerHandshake`](#serverhandshake)
- [`AcceptPolicy` and `Decision`](#acceptpolicy-and-decision)
- [`OriginPolicy`](#originpolicy)
- [`HeadReader`](#headreader)
- [`ClientHandshake`](#clienthandshake)
- [`HandshakeError`](#handshakeerror)
- [`write_refusal`](#write_refusal)
- [The `extension` module](#the-extension-module)
- [permessage-deflate (feature `deflate`)](#permessage-deflate)
- [The `blocking` module](#the-blocking-module)
- [`accept_key` and `AcceptKey`](#accept_key-and-acceptkey)
- [The `frame` module](#the-frame-module)
  - [`Opcode`](#opcode)
  - [`FrameHeader`](#frameheader)
  - [`apply_mask`](#apply_mask)
- [Feature flags](#feature-flags)
- [Limits reference](#limits-reference)
- [The 1.0 API (design lock)](#the-10-api-design-lock)

## Overview

`ws-net` is a WebSocket protocol engine that does no I/O. The caller owns
the socket: bytes go in, events come out, and frames to send accumulate in
an output queue the caller writes. The same code runs over `std::net`, an
async runtime, a test harness, or memory.

| Item | Kind | Purpose |
|---|---|---|
| [`accept`, `Acceptor`, `Accepted`](#tier-1-accept-and-acceptor) | fn, struct | Tier 1: accept a WebSocket from a socket's first bytes, with the same-origin policy. |
| [`AcceptPolicy`, `Decision`](#acceptpolicy-and-decision) | struct | Who may connect, which subprotocol is spoken, the connection's limits. |
| [`OriginPolicy`](#originpolicy) | enum | Which pages may connect (cross-site WebSocket hijacking defense). |
| [`HeadReader`](#headreader) | struct | A resumable raw head reader with linear total work. |
| [`Connection`](#connection) | struct | One WebSocket connection after the handshake. |
| [`Message`, `MessageKind`](#message-and-messagekind) | enum | Owned messages; the kind of a data message. |
| [`PreparedMessage`](#preparedmessage) | struct | A server message encoded once for broadcast. |
| [`Keepalive`, `Millis`, `Tick`](#keepalive-millis-tick) | struct, enum | Pings and timeouts on the caller's clock. |
| [`Stats`](#stats) | struct | Per-connection counters. |
| [`Sender`](#split-borrow-and-detach) | struct | The output side, while an event borrows the input. |
| [`extension`](#the-extension-module) | module | `Sec-WebSocket-Extensions` offers and what was negotiated. |
| [`blocking`](#the-blocking-module) | module | A `Read + Write` adapter (feature `std`). |
| [`Event`](#event) | enum | What [`poll`](#connectionpoll) found: a message, a control frame, or a need. |
| [`Limits`](#limits) | struct | Frame and message budgets. |
| [`Role`](#role) | enum | Server or client: which way masking goes. |
| [`State`](#state) | enum | Open, Closing, Closed. |
| [`CloseCode`](#closecode) | struct | A Close status code. |
| [`CloseFrame`](#closeframe) | struct | A received Close frame's code and reason. |
| [`WsError`](#wserror) | enum | A connection failure, or a refused call. |
| [`ServerHandshake`](#serverhandshake) | struct | A validated upgrade request. |
| [`ClientHandshake`](#clienthandshake) | struct | The client's request and response check. |
| [`HandshakeError`](#handshakeerror) | enum | Why a handshake was refused. |
| [`accept_key`, `AcceptKey`](#accept_key-and-acceptkey) | fn, struct | The `Sec-WebSocket-Accept` computation. |
| [`frame::Opcode`, `frame::FrameHeader`, `frame::apply_mask`](#the-frame-module) | module | The raw frame codec. |
| `VERSION` | const | The crate version. |

## Installation

```toml
[dependencies]
ws-net = "0.8"

# no_std (alloc only)
ws-net = { version = "0.8", default-features = false }

# permessage-deflate (RFC 7692), from 0.9
ws-net = { version = "0.9", features = ["deflate"] }
```

## Quick start

A server: accept the upgrade from the socket's first bytes (validated, the
same-origin policy applied, the `101` written), then echo the first message.

```rust
use ws_net::Event;

let mut wire = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\n\
    Upgrade: websocket\r\nConnection: Upgrade\r\nOrigin: https://server.example.com\r\n\
    Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n".to_vec();
// A masked "Hello" (RFC 6455 section 5.7) right behind the head.
wire.extend_from_slice(&[0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58]);

let mut accepted = ws_net::accept(&wire)?.expect("complete head");
// Write `accepted.response` (the 101) to the socket, then drive the connection.
let conn = &mut accepted.connection;
let reply = match conn.poll()? {
    Event::Text(text) => text.to_uppercase(),
    other => panic!("{other:?}"),
};
conn.send_text(&reply)?;
assert_eq!(conn.output(), [0x81, 0x05, b'H', b'E', b'L', b'L', b'O']);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Tier 1: `accept` and `Acceptor`

```rust,ignore
pub fn accept(bytes: &[u8]) -> Result<Option<Accepted>, HandshakeError>;

pub struct Acceptor { /* private */ }
impl Acceptor {
    pub fn new() -> Acceptor;                               // the Tier 1 policy
    pub fn with_policy(policy: AcceptPolicy) -> Acceptor;   // Tier 2
    pub fn accept(&mut self, bytes: &[u8]) -> Result<Option<Accepted>, HandshakeError>;
}

#[non_exhaustive]
pub struct Accepted {
    pub response: Vec<u8>,          // the 101, to write first
    pub connection: Connection,     // the server end, already fed
    pub consumed: usize,            // input bytes used: head plus frames fed
    pub handshake: ServerHandshake, // the request, for routing on its target
}
```

`accept` takes a buffer that starts with the request head. Until the head
is complete it returns `Ok(None)`: read more, append, call again. Then it
validates the request (every rule of [`from_head`](#serverhandshake)),
applies the same-origin policy ([`AcceptPolicy::new`](#acceptpolicy-and-decision)),
writes the `101`, builds a server [`Connection`](#connection) with the
policy's limits, and feeds it the bytes that followed the head. A
connection takes at most its input buffer (64 KiB) per call, so a large
leftover is only partly taken: feed `bytes[consumed..]` after polling.

`accept` rescans the head on each call. An `Acceptor` is the resumable
form: pass it the same buffer each time, grown at the end, and each byte of
the head is scanned once over all calls, however small the reads (see
[`HeadReader`](#headreader)). One `Acceptor` accepts one connection.

**Errors.** Every [`HandshakeError`](#handshakeerror) of `from_head`, plus
`OriginRefused` (403) and, with a policy that requires one,
`ProtocolRequired`. Answer with `HandshakeError::write_response` and close
the transport. `Acceptor::accept` also returns `InvalidRequest` when the
buffer shrank between calls.

```rust
use ws_net::{AcceptPolicy, Acceptor, HandshakeError, OriginPolicy};

let request = b"GET / HTTP/1.1\r\nHost: api.example\r\nUpgrade: websocket\r\n\
    Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
    Sec-WebSocket-Version: 13\r\nOrigin: https://app.example\r\n\r\n";

// The default policy is same-origin: this page is on another host.
let refused = ws_net::accept(request).unwrap_err();
assert_eq!((refused, refused.status()), (HandshakeError::OriginRefused, 403));

// Allow the application's page; read the head in 5-byte pieces.
let policy = AcceptPolicy::new().with_origins(OriginPolicy::allow(&["https://app.example"])?);
let mut acceptor = Acceptor::with_policy(policy);
let mut buffer = Vec::new();
let mut accepted = None;
for piece in request.chunks(5) {
    buffer.extend_from_slice(piece);
    if let Some(a) = acceptor.accept(&buffer)? {
        accepted = Some(a);
    }
}
let accepted = accepted.expect("complete");
assert_eq!(accepted.consumed, request.len());
assert!(accepted.response.starts_with(b"HTTP/1.1 101 Switching Protocols\r\n"));
# Ok::<(), HandshakeError>(())
```

## Concepts

### The I/O loop

Every transport adapter is the same loop:

1. `poll()` the connection.
2. Act on the [`Event`](#event). On `NeedInput`, read from the socket into
   [`read_buf`](#input) and [`commit`](#input) the count (or
   [`feed`](#input) bytes you already hold); on a zero-byte read, call
   [`feed_eof`](#input).
3. Write [`output`](#output) to the socket and
   [`advance_output`](#output) by what was written.
4. Stop after `Event::Closed` or an error, once the output is flushed.

```rust
use ws_net::{Connection, Event, WsError};

/// One turn of a server's loop over in-memory "sockets".
fn turn(conn: &mut Connection, incoming: &mut &[u8], outgoing: &mut Vec<u8>) -> Result<bool, WsError> {
    let more = match conn.poll() {
        Ok(Event::Text(t)) => { let t = t.to_owned(); conn.send_text(&t)?; true }
        Ok(Event::Binary(b)) => { let b = b.to_vec(); conn.send_binary(&b)?; true }
        Ok(Event::NeedInput) if incoming.is_empty() => { conn.feed_eof(); true }
        Ok(Event::NeedInput) => { let n = conn.feed(incoming); *incoming = &incoming[n..]; true }
        Ok(Event::Closed) => false,
        Ok(_) => true, // pings are answered, closes echoed, automatically
        Err(_) => false, // the Close frame for the failure is in the output
    };
    // Always flush, including after an error.
    let out = conn.output();
    outgoing.extend_from_slice(out);
    let n = out.len();
    conn.advance_output(n);
    Ok(more)
}

let mut conn = Connection::server();
// Masked "hi", then a masked Close 1000.
let mut incoming: &[u8] = &[0x81, 0x82, 0, 0, 0, 0, b'h', b'i', 0x88, 0x82, 0, 0, 0, 0, 0x03, 0xE8];
let mut outgoing = Vec::new();
while turn(&mut conn, &mut incoming, &mut outgoing)? {}
// The echo of "hi", then the echoed Close.
assert_eq!(outgoing, [0x81, 0x02, b'h', b'i', 0x88, 0x02, 0x03, 0xE8]);
# Ok::<(), WsError>(())
```

### Failures and refused calls

A [`WsError`](#wserror) is one of two things, told apart by
[`close_code`](#wserror):

- **A connection failure** (`Some(code)`): the peer broke the protocol, a
  budget was exceeded, or the transport ended early. The connection queues
  a Close frame with that code (except 1006, which is never sent), reports
  the error once, and from then on `poll` returns `Event::Closed`. Flush the
  output, then close the socket.
- **A refused call** (`None`): [`InvalidArgument`](#wserror) or
  [`InvalidState`](#wserror). Nothing was sent and the connection is
  unchanged.

### Budgets and memory

What the peer sends cannot grow a connection's memory past its budgets, and
what this end sends is bounded too:

- The input buffer holds at most [`Limits::input_buffer`](#limits) (64 KiB
  by default); [`feed`](#input) takes what fits.
- A frame's payload length is checked against [`Limits::max_frame`](#limits)
  from its header, before any payload is read; a fragmented message's total
  against [`Limits::max_message`](#limits) before each fragment is read.
  Either violation fails with 1009. A message's buffer never grows past the
  message budget.
- Reassembly reserves at most 1 MiB ahead of the bytes that have arrived,
  even with the budgets lifted to `u64::MAX`: a length in a header is a
  claim, not an allocation.
- A send that would take the pending output over
  [`Limits::max_output`](#limits) (32 MiB by default) is refused with
  `OutputFull` and changes nothing. Automatic Pongs and Close frames may use
  262 bytes more, so a connection whose peer stopped reading can still
  answer and close.
- An automatic Pong still unwritten at the end of the output is replaced by
  the next one, so a peer that pings without reading cannot grow the output.
  At most one Close is ever queued.
- A reassembly or output buffer that grew past [`Limits::retain`](#limits)
  (64 KiB) shrinks once it holds nothing pending; [`release_memory`](#memory-and-observability)
  frees every empty buffer, so an idle connection holds no heap.

Peak memory of a busy connection: the input buffer, plus the message being
reassembled (at most `max_message` plus 1 MiB reserved ahead), plus the
output (at most twice `max_output` + 262 by vector growth, plus 64 KiB of
written prefix before compaction). An idle connection after
`release_memory`: `size_of::<Connection>()`, at most 512 bytes.
`tests/memory.rs` checks each bound with a counting allocator.

### The closing handshake

Either side starts it. [`close`](#control-frames) queues a Close frame and
moves to [`State::Closing`](#state); the peer's Close then arrives as
[`Event::Close`](#event) and the state becomes `Closed`. When the peer
starts it, the connection queues the echo (with the peer's code) and
reports `Event::Close`; the state is `Closed` at once. After a Close frame
has been sent, every send is refused with `InvalidState`. While `Closing`,
data the peer sends before its Close is still delivered, and Pings are
reported but not answered. The server closes the TCP connection first
(RFC 6455 section 7.1.1).

### Handshake policy: Host, Origin, subprotocols

A browser attaches the user's cookies to a WebSocket request from any page
on any site. Without an Origin check, a page on another site can open a
socket to this server as the user (cross-site WebSocket hijacking,
CWE-1385). Browsers always send `Origin`, and a page cannot change it, so
checking it is the defense.

- The Tier 1 path ([`accept`](#tier-1-accept-and-acceptor), `Acceptor::new`)
  applies the **same-origin rule**: the Origin's host and port must be the
  request's `Host`. A request without `Origin` comes from a non-browser
  client, which carries no ambient browser credentials, and is accepted;
  `OriginPolicy::same_origin().allow_missing(false)` refuses it.
- [`OriginPolicy::allow`](#originpolicy) pins exact serialized origins,
  scheme included. Comparison is by parsed origin, never by substring:
  `https://example.com.evil.net` is not `https://example.com`, and `null`
  never matches.
- [`OriginPolicy::any_origin`](#originpolicy) turns the check off, for
  endpoints that use no cookies or HTTP authentication.
- A request with two `Origin` (or two `Host`) fields is refused outright
  (`InvalidOrigin`, `InvalidHost`): a check could read one and a later
  layer trust the other.
- Subprotocols: [`AcceptPolicy::with_protocols`](#acceptpolicy-and-decision)
  lists the server's, in its order of preference; the first one the client
  offered is selected, and `require_protocol` refuses a client that offered
  none. `ServerHandshake::select_protocol` is the same choice without a
  policy.

A refused Origin is `HandshakeError::OriginRefused`, answered with
`HTTP/1.1 403 Forbidden`, and so is a `Host` outside
[`AcceptPolicy::with_hosts`](#acceptpolicy-and-decision)
(`HostRefused`, the DNS rebinding defense). Without an allowlist any `Host`
is accepted: compare [`host()`](#serverhandshake) with your own authority.

### Behind an HTTP layer

[`ServerHandshake::from_request`](#serverhandshake) takes the method,
target, and header fields as `(&str, &[u8])` pairs, exactly what `http-net`'s
`RequestHead` yields, so the two compose with no glue:

```rust,ignore
// With http-net (not a dependency of ws-net):
let handshake = ServerHandshake::from_request(req.method_str(), req.target(), req.headers())?;
let response = Response::switching_protocols("websocket")
    .header("sec-websocket-accept", handshake.accept_key().as_str());
// ... then hand the upgraded socket and its leftover bytes to Connection::server().
```

On the client, [`ClientHandshake::verify`](#clienthandshake) takes a
response's status and fields the same way.

### Protocol rules and policies

Enforced on every received frame, each with its close code:

| Rule | Error | Code |
|---|---|---|
| A server receives an unmasked frame; a client a masked one. | `UnmaskedFrame`, `MaskedFrame` | 1002 |
| RSV1-3 set (no extension is ever negotiated). | `ReservedBits` | 1002 |
| Opcode 0x3-0x7 or 0xB-0xF. | `ReservedOpcode` | 1002 |
| A control frame without FIN. | `FragmentedControl` | 1002 |
| A control frame over 125 bytes, or using an extended length field. | `ControlTooLong` | 1002 |
| A length not in its shortest encoding, or a 64-bit length with the high bit set. | `InvalidLength` | 1002 |
| A continuation with no message in progress. | `UnexpectedContinuation` | 1002 |
| A new data frame inside a fragmented message. | `ExpectedContinuation` | 1002 |
| Text (or a close reason) that is not UTF-8, detected at the first bad byte, across fragment boundaries. | `InvalidUtf8` | 1007 |
| A frame over the frame budget, or a message over the message budget. | `FrameTooLarge`, `MessageTooLarge` | 1009 |
| A Close payload of one byte. | `InvalidClosePayload` | 1002 |
| A Close code that may not be sent (1005, 1006, 1015, unassigned). | `InvalidCloseCode` | 1002 |
| The transport ends before the closing handshake completes. | `UnexpectedEof` | 1006 (not sent) |

**Non-minimal length encodings are refused.** RFC 6455 section 5.2 says the
minimal number of bytes MUST be used; accepting the longer forms would give
one frame several encodings. Many implementations accept them; this one
does not, and says so with 1002.

## `Connection`

```rust,ignore
pub struct Connection { /* private */ }
impl Debug for Connection {}
// Send + Sync
```

One WebSocket connection after the opening handshake: a sans-IO state
machine. All methods are synchronous and never block.

<a id="connection-constructors"></a>
### Constructors

| Method | Description |
|---|---|
| `Connection::server() -> Connection` | The accepting end. Refuses unmasked frames; sends unmasked. |
| `Connection::client() -> Connection` | The connecting end, masking keys drawn from the OS cryptographic random source (through `mod-rand`) in 1 KiB batches of 256 keys, held on the heap and freed by `release_memory`; a refill that fails refuses the send. If that source fails it fails closed: the connection is `Closed` and every send returns `RandomUnavailable`. Feature `std`. |
| `Connection::try_client() -> Result<Connection, WsError>` | As `client`, returning `WsError::RandomUnavailable` when the OS source fails. Feature `std`. |
| `Connection::client_with_seed(seed: [u8; 32]) -> Connection` | The connecting end, masking keys derived from a 32-byte secret seed. The seed must be unpredictable to the peer (RFC 6455 section 5.3); a fixed seed is for tests. |
| `Connection::with_limits(self, limits: Limits) -> Connection` | Replaces the [budgets](#limits). |
| `with_extensions(self, negotiated: Negotiated) -> Connection`, `negotiated(&self) -> &Negotiated` | What the handshake negotiated; set by `accept`, `ServerHandshake::accept`, and `ClientHandshake::connection`. With [permessage-deflate](#permessage-deflate) the connection compresses and inflates by the agreement. |

```rust
use ws_net::{Connection, Limits, Role};

let server = Connection::server().with_limits(Limits::new().with_max_message(1 << 20));
assert_eq!(server.role(), Role::Server);
let mut client = Connection::client_with_seed([7; 32]);
client.send_text("hi")?;
assert_eq!(client.output()[1] & 0x80, 0x80); // client frames are masked
# Ok::<(), ws_net::WsError>(())
```

<a id="input"></a>
### Input: `feed`, `read_buf`, `commit`, `feed_eof`

| Method | Description |
|---|---|
| `feed(&mut self, bytes: &[u8]) -> usize` | Copies as much of `bytes` as fits into the input buffer (at most `Limits::input_buffer` bytes buffered) and returns the count taken. Poll, then feed the rest. `#[must_use]`. |
| `read_buf(&mut self) -> &mut [u8]` | Spare space at the end of the input buffer, to read a socket into without a copy. Never empty while the connection is waiting for input. |
| `commit(&mut self, n: usize)` | Records that `n` bytes were written into `read_buf` (clamped to its size). |
| `feed_eof(&mut self)` | Records that the transport closed. Before the closing handshake completed, the next poll reports `UnexpectedEof`. |

```rust
let mut conn = ws_net::Connection::server();
let frame = [0x89, 0x80, 0, 0, 0, 0]; // a masked, empty Ping
conn.read_buf()[..6].copy_from_slice(&frame);
conn.commit(6);
assert!(matches!(conn.poll().unwrap(), ws_net::Event::Ping(b"")));
```

### `Connection::poll`

```rust,ignore
pub fn poll(&mut self) -> Result<Event<'_>, WsError>
```

Advances the parser and returns the next [`Event`](#event). Messages are
delivered whole; a single-frame message already in the buffer is unmasked
in place and lent out with no copy.

**Errors.** A protocol violation fails the connection: the Close frame
with the error's [`close_code`](#wserror) is queued in the output, the
error is returned once, and later polls return `Event::Closed`.

```rust
use ws_net::{Connection, WsError};

let mut conn = Connection::server();
// A masked text frame whose payload is the invalid byte 0xFF.
let _ = conn.feed(&[0x81, 0x81, 0, 0, 0, 0, 0xFF]);
assert_eq!(conn.poll().unwrap_err(), WsError::InvalidUtf8);
assert_eq!(conn.output(), [0x88, 0x02, 0x03, 0xEF]); // Close 1007
assert!(matches!(conn.poll().unwrap(), ws_net::Event::Closed));
```

### Sending messages

| Method | Description |
|---|---|
| `send_text(&mut self, text: &str) -> Result<(), WsError>` | A text message. Larger than the frame budget, it is split into frames of at most that size. |
| `send_binary(&mut self, data: &[u8]) -> Result<(), WsError>` | A binary message, split the same way. |
| `send_text_fragment(&mut self, text: &str, fin: bool) -> Result<(), WsError>` | One fragment of a text message; `fin` ends it. Each fragment is a `&str`, so the message is valid UTF-8. |
| `send_binary_fragment(&mut self, data: &[u8], fin: bool) -> Result<(), WsError>` | One fragment of a binary message. |

**Errors.** `InvalidState` after a Close frame was sent; while a
fragmented message is being sent (for `send_text` / `send_binary`); or
while a fragmented message of the other type is being sent. Control frames
may go between fragments; other messages may not.

```rust
let mut conn = ws_net::Connection::server();
conn.send_text_fragment("Hel", false)?;
conn.send_ping(b"")?; // allowed between fragments
conn.send_text_fragment("lo", true)?;
assert_eq!(conn.output(), [0x01, 0x03, b'H', b'e', b'l', 0x89, 0x00, 0x80, 0x02, b'l', b'o']);
assert!(conn.send_binary_fragment(b"x", true).is_ok());
# Ok::<(), ws_net::WsError>(())
```

<a id="control-frames"></a>
### Control frames: `send_ping`, `send_pong`, `close`

| Method | Description |
|---|---|
| `send_ping(&mut self, payload: &[u8]) -> Result<(), WsError>` | A Ping (payload at most 125 bytes). The peer's Pong arrives as `Event::Pong`. |
| `send_pong(&mut self, payload: &[u8]) -> Result<(), WsError>` | An unsolicited Pong (a one-way heartbeat). Replies to Pings are automatic. |
| `close(&mut self, code: CloseCode, reason: &str) -> Result<(), WsError>` | Starts the closing handshake with a sendable code and a reason of at most 123 bytes. |

**Errors.** `InvalidArgument` for a payload over 125 bytes, a code that may
not be sent (see [`CloseCode::is_sendable`](#closecode)), or a reason over
123 bytes; `InvalidState` after a Close frame was sent. A refused call sends
nothing.

```rust
use ws_net::{CloseCode, Connection, State, WsError};

let mut conn = Connection::server();
assert!(matches!(conn.send_ping(&[0; 126]), Err(WsError::InvalidArgument(_))));
assert!(matches!(conn.close(CloseCode::NO_STATUS, ""), Err(WsError::InvalidArgument(_))));
assert_eq!(conn.state(), State::Open); // refused calls change nothing
conn.close(CloseCode::NORMAL, "done")?;
assert_eq!(conn.output(), [0x88, 0x06, 0x03, 0xE8, b'd', b'o', b'n', b'e']);
assert!(matches!(conn.send_text("late"), Err(WsError::InvalidState(_))));
# Ok::<(), WsError>(())
```

<a id="output"></a>
### Output: `output`, `advance_output`

| Method | Description |
|---|---|
| `output(&mut self) -> &[u8]` | The bytes waiting to be written: your frames and the automatic Pong and Close replies. |
| `advance_output(&mut self, n: usize)` | Marks `n` bytes as written (clamped to what is queued). |

```rust
let mut conn = ws_net::Connection::server();
conn.send_text("abc")?; // 2 header bytes + "abc"
conn.advance_output(3); // the socket took three bytes
assert_eq!(conn.output(), b"bc");
# Ok::<(), ws_net::WsError>(())
```

<a id="accessors"></a>
### Accessors: `limits`, `role`, `state`, `is_open`, `can_send`

| Method | Returns |
|---|---|
| `limits(&self) -> &Limits` | The budgets. |
| `role(&self) -> Role` | Server or client. |
| `state(&self) -> State` | Open, Closing, or Closed. |
| `is_open(&self) -> bool` | `state() == State::Open`. |
| `can_send(&self) -> bool` | Whether a new data message would be accepted now: no Close sent, not failed, no fragmented message being sent. |

```rust
use ws_net::{Connection, Limits, Role, State};
let mut conn = Connection::server();
assert_eq!((conn.role(), conn.state(), *conn.limits()), (Role::Server, State::Open, Limits::new()));
assert!(conn.is_open() && conn.can_send());
conn.send_binary_fragment(b"part", false)?;
assert!(conn.is_open() && !conn.can_send());
# Ok::<(), ws_net::WsError>(())
```

<a id="keepalive"></a>
### Keepalive: `with_keepalive`, `on_time`, `next_deadline`

| Method | Description |
|---|---|
| `with_keepalive(self, keepalive: Keepalive) -> Connection` | Sets the ping interval and timeouts ([`Keepalive`](#keepalive-millis-tick)). |
| `on_time(&mut self, now: Millis) -> Result<Tick, WsError>` | Applies the rules at `now` (the caller's monotonic milliseconds). Any input since the last call is activity. Order: close timeout, idle timeout, message timeout, keepalive Ping. `Tick::PingQueued` means write the output. |
| `next_deadline(&self) -> Option<Millis>` | When `on_time` next has work; `None` with no timer armed. After `Closed`, the close timeout stays armed while output is unwritten (or a client waits for EOF). Sleep until then. |
| `should_close_transport(&self) -> bool` | `Closed` and the output written; a client also needs the server's EOF, a failure, or the close timeout (the server closes first). |

Errors from `on_time`: `IdleTimeout` (Close 1001 queued), `CloseTimeout`
(nothing more sent; close the transport), `MessageTimeout` (Close 1008
queued, the slow-message defense). Each is returned once; later ticks
return `Ok(Tick::Nothing)`. A clock that goes backwards is treated as no
time passing. Call `on_time` after each read and at `next_deadline`: its
precision is the spacing of those calls.

```rust
use core::time::Duration;
use ws_net::{Connection, Keepalive, Millis, Tick, WsError};

let k = Keepalive::new().with_ping_interval(Duration::from_secs(30)).with_idle_timeout(Duration::from_secs(75));
let mut conn = Connection::server().with_keepalive(k);
assert_eq!(conn.on_time(Millis(0))?, Tick::Nothing);
assert_eq!(conn.next_deadline(), Some(Millis(30_000)));
assert_eq!(conn.on_time(Millis(30_000))?, Tick::PingQueued); // Ping payload: the time
assert_eq!(conn.next_deadline(), Some(Millis(75_000)));
assert_eq!(conn.on_time(Millis(75_000)), Err(WsError::IdleTimeout)); // Close 1001 queued
assert_eq!(conn.next_deadline(), Some(Millis(80_000))); // the close timeout bounds the write
let n = conn.output().len();
conn.advance_output(n); // written
assert_eq!(conn.next_deadline(), None);
# Ok::<(), WsError>(())
```

### Memory and observability

| Method | Description |
|---|---|
| `buffered_output(&self) -> usize` | Bytes waiting for the transport. |
| `release_memory(&mut self)` | Frees every buffer that holds no pending bytes. |
| `memory_in_use(&self) -> usize` | Heap bytes held (capacities). |
| `stats(&self) -> Stats` | The [counters](#stats). |
| `wipe(&mut self)` | Zeroes input, reassembly, and output buffers and the masking seed (through `black_box`: best effort, not a guarantee, as no `unsafe` is used), then fails the connection. |

```rust
use ws_net::{Connection, Limits, WsError};

let mut conn = Connection::server().with_limits(Limits::new().with_max_output(1024));
conn.send_binary(&[0; 1000])?;
assert_eq!(conn.buffered_output(), 1004);
assert_eq!(conn.send_binary(&[0; 100]), Err(WsError::OutputFull)); // nothing changed
let n = conn.output().len();
conn.advance_output(n);
conn.release_memory();
assert_eq!(conn.memory_in_use(), 0);
assert_eq!(conn.stats().bytes_out, 1004);
# Ok::<(), WsError>(())
```

<a id="split-borrow-and-detach"></a>
### Split borrow and detach: `poll_split`, `Sender`, `detach_message`

| Item | Description |
|---|---|
| `poll_split(&mut self) -> Result<(Event<'_>, Sender<'_>), WsError>` | As `poll`, plus a `Sender` over the output side: reply while the event still borrows the message. |
| `Sender::{send_text, send_binary, send_text_with, send_binary_with, send_ping, send_pong, close, send_prepared}` | The `Connection` rules and budget. |
| `detach_message(&mut self, into: &mut Vec<u8>) -> Option<MessageKind>` | Right after a `Text` or `Binary` event, moves its bytes into `into`: a buffer swap for reassembled messages (no copy), one copy for single-frame ones. `None` otherwise, or after more input was fed. |
| `send(&mut self, message: &Message) -> Result<(), WsError>` | Sends an owned [`Message`](#message-and-messagekind). |
| `send_text_with(&mut self, text, options: SendOptions)`, `send_binary_with(&mut self, data, options)` | Per-message [`SendOptions`](#preparedmessage): `uncompressed()` for messages carrying secrets, `compressed()` to compress whatever the size. No effect on the wire without [permessage-deflate](#permessage-deflate). |
| `send_prepared(&mut self, message: &PreparedMessage) -> Result<(), WsError>` | Appends a [prepared message](#preparedmessage); server role only. |

```rust
use ws_net::{Connection, Event, MessageKind};

let mut conn = Connection::server();
let _ = conn.feed(&[0x81, 0x82, 0, 0, 0, 0, b'h', b'i']); // masked "hi"
let (event, mut sender) = conn.poll_split()?;
if let Event::Text(text) = event {
    sender.send_text(text)?; // echo without copying the message
}
let mut owned = Vec::new();
assert_eq!(conn.detach_message(&mut owned), Some(MessageKind::Text));
assert_eq!(owned, b"hi");
# Ok::<(), ws_net::WsError>(())
```

## `Event`

```rust,ignore
#[non_exhaustive]
pub enum Event<'a> {
    Text(&'a str),
    Binary(&'a [u8]),
    Ping(&'a [u8]),
    Pong(&'a [u8]),
    Close(Option<CloseFrame<'a>>),
    NeedInput,
    Closed,
}
```

| Variant | Meaning |
|---|---|
| `Text(&str)` | A complete text message, validated as UTF-8. |
| `Binary(&[u8])` | A complete binary message. |
| `Ping(&[u8])` | A Ping. The Pong is already queued (unless this end has sent a Close). |
| `Pong(&[u8])` | A Pong. |
| `Close(Option<CloseFrame>)` | The peer's Close (`None` when it carried no code). If this end had not sent one, the echo is queued. The state is now `Closed`. |
| `NeedInput` | More input is needed. |
| `Closed` | The connection is finished; nothing more will be read. |

The event borrows the connection: copy out what you need before calling a
`send` method.

```rust
use ws_net::{Connection, Event};
let mut conn = Connection::server();
let _ = conn.feed(&[0x88, 0x80, 0, 0, 0, 0]); // a masked, empty Close
assert!(matches!(conn.poll().unwrap(), Event::Close(None)));
assert_eq!(conn.output(), [0x88, 0x00]); // the echo
```

## `Message` and `MessageKind`

```rust,ignore
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message { Text(String), Binary(Vec<u8>), Ping(Vec<u8>), Pong(Vec<u8>), Close(Option<(CloseCode, String)>) }

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MessageKind { Text, Binary }
```

Owned messages for the convenience APIs and the blocking adapter.
`From<&str>`, `From<String>`, `From<&[u8]>`, `From<Vec<u8>>`; `is_data`,
`is_close`; `Event::to_message` copies an event into one.

```rust
use ws_net::{Connection, Message};

let mut conn = Connection::server();
let _ = conn.feed(&[0x82, 0x81, 0, 0, 0, 0, 7]);
let message = conn.poll()?.to_message().expect("a message");
assert_eq!(message, Message::from(vec![7]));
conn.send(&message)?;
assert_eq!(conn.output(), [0x82, 0x01, 7]);
# Ok::<(), ws_net::WsError>(())
```

## `PreparedMessage`

```rust,ignore
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PreparedMessage { /* private */ }
```

| Method | Description |
|---|---|
| `PreparedMessage::text(text: &str)`, `binary(data: &[u8])` | Unmasked frames encoded once, split at the default send-frame size. |
| `text_with(text, limits: &Limits)`, `binary_with(data, limits)` | Split at `limits.send_frame()`. |
| `as_bytes(&self) -> &[u8]`, `len`, `is_empty`, `payload_len` | Inspection. |
| `with_deflate(self, config: &DeflateConfig)`, `compressed_len(&self) -> Option<usize>` | Feature `deflate`: adds a form compressed once without context, sent to connections that agreed on `server_no_context_takeover` with a window at least as large; kept only when smaller. |

`SendOptions` (`new`, `uncompressed`, `compressed`, `is_uncompressed`;
`#[non_exhaustive]`, `Copy`, `Default`) chooses compression per message.
The default compresses when [permessage-deflate](#permessage-deflate) was
negotiated, the message is at least `min_size` (256 bytes by default), and
compressing makes it smaller; `uncompressed()` never compresses;
`compressed()` compresses whatever the size. Without a negotiated
compression every option sends the message as it is.

`Connection::send_prepared` appends the frames with one copy. It is refused
for a client (frames must be masked with fresh keys), after a Close, during
an outgoing fragmented message, and over the output budget.

```rust
use ws_net::{Connection, PreparedMessage};

let tick = PreparedMessage::text("tick");
let mut a = Connection::server();
let mut b = Connection::server();
a.send_prepared(&tick)?;
b.send_prepared(&tick)?;
assert_eq!(a.output(), b.output());
assert!(Connection::client_with_seed([1; 32]).send_prepared(&tick).is_err());
# Ok::<(), ws_net::WsError>(())
```

<a id="keepalive-millis-tick"></a>
## `Keepalive`, `Millis`, `Tick`

```rust,ignore
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Millis(pub u64);

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Keepalive { /* private */ }

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Tick { Nothing, PingQueued }
```

| Item | Default | Description |
|---|---|---|
| `Millis(u64)`, `Millis::from_duration`, `as_u64`, `+ Duration` (saturating) | | The caller's monotonic clock in milliseconds. |
| `Keepalive::new()` / `default()` | | The defaults below. |
| `with_ping_interval(self, Duration)` | off | Queue a Ping when no frame arrived for this long. |
| `with_idle_timeout(self, Duration)` | off | Fail with `IdleTimeout` when no byte arrived for this long. |
| `with_close_timeout(self, Duration)` | 5 s | Fail with `CloseTimeout` when the peer does not answer our Close. |
| `with_message_timeout(self, Duration)` | off | Fail with `MessageTimeout` when a data message stays incomplete. |
| `ping_interval`, `idle_timeout`, `close_timeout`, `message_timeout` | | Accessors (`Option<Duration>`). |

```rust
use core::time::Duration;
use ws_net::{Keepalive, Millis};

let k = Keepalive::new().with_message_timeout(Duration::from_secs(10));
assert_eq!(k.close_timeout(), Some(Duration::from_secs(5)));
assert_eq!(Millis(1) + Duration::from_millis(2), Millis(3));
```

## `Stats`

```rust,ignore
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Stats {
    pub bytes_in: u64, pub bytes_out: u64, pub frames_in: u64,
    pub messages_in: u64, pub messages_out: u64,
    pub pings_in: u64, pub pongs_in: u64, pub closes_in: u64,
}
impl Stats { pub const fn data_frames_in(&self) -> u64; }
```

Counters for metrics and rate limiting, saturating at `u64::MAX`.
`bytes_in` counts bytes taken by `feed` and `commit`; `bytes_out` bytes
acknowledged by `advance_output`. A frame counts once, when it is taken,
however its bytes were split. `data_frames_in()` is `frames_in` less the
Pings, Pongs, and Closes; `data_frames_in / messages_in` (fragments per
message) and `pings_in / messages_in` flag an abusive peer sooner than byte
rates, since a browser sends one frame per message and few Pings.

```rust
let mut conn = ws_net::Connection::server();
let _ = conn.feed(&[0x89, 0x80, 0, 0, 0, 0]); // masked empty Ping
let _ = conn.poll();
assert_eq!((conn.stats().frames_in, conn.stats().pings_in), (1, 1));
```

## `Limits`

```rust,ignore
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Limits { /* private */ }
```

Budgets on incoming frames and messages, checked from frame headers.
Outgoing messages are split into frames of at most `send_frame` bytes, which
follows the frame budget unless set, so a peer with the same limits accepts
them.

| Method | Description |
|---|---|
| `Limits::new() -> Limits` / `Limits::default()` | 1 MiB frames, 16 MiB messages (LexerSketch Studio's budgets). |
| `with_max_frame(self, bytes: u64) -> Limits` | The largest frame payload; at least 125 (the largest control frame). |
| `with_max_message(self, bytes: u64) -> Limits` | The largest message, summed over its fragments. |
| `max_frame(&self) -> u64` | The frame budget. |
| `max_message(&self) -> u64` | The message budget. |
| `with_send_frame(self, bytes: u64) -> Limits` | The largest outgoing frame payload, at least 125. Unset, it equals `max_frame`. |
| `send_frame(&self) -> u64` | The outgoing frame size. |
| `with_max_output(self, bytes: u64) -> Limits`, `max_output` | The pending-output budget (32 MiB); `u64::MAX` lifts it. |
| `with_input_buffer(self, bytes: usize) -> Limits`, `input_buffer` | The input buffer (64 KiB), clamped to 256 B to 1 MiB. |
| `with_retain(self, bytes: usize) -> Limits`, `retain` | Capacity kept per buffer after use (64 KiB). |
| `DEFAULT_MAX_FRAME`, `DEFAULT_MAX_MESSAGE`, `DEFAULT_MAX_OUTPUT`, `DEFAULT_INPUT_BUFFER`, `DEFAULT_RETAIN`, `MIN_INPUT_BUFFER`, `MAX_INPUT_BUFFER` | The defaults and bounds, as constants. |

```rust
use ws_net::{Connection, Limits, WsError};

let limits = Limits::new().with_max_frame(1).with_max_message(4096);
assert_eq!(limits.max_frame(), 125); // clamped
let mut conn = Connection::server().with_limits(limits);
// A masked binary frame announcing 200 bytes: refused from the header.
let _ = conn.feed(&[0x82, 0xFE, 0x00, 0xC8, 1, 2, 3, 4]);
assert_eq!(conn.poll().unwrap_err(), WsError::FrameTooLarge);

// Accept 1 MiB frames, send 16 KiB ones.
let mut conn = Connection::server().with_limits(Limits::new().with_send_frame(16 * 1024));
conn.send_binary(&vec![0; 40 * 1024]).unwrap();
assert_eq!(conn.output()[0], 0x02); // first frame: binary, not final
```

## `Role`

```rust,ignore
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role { Server, Client }
```

Which end a connection is. Clients mask every frame they send and refuse
masked frames; servers do the opposite.

```rust
assert_eq!(ws_net::Connection::client_with_seed([0; 32]).role(), ws_net::Role::Client);
```

## `State`

```rust,ignore
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum State { Open, Closing, Closed }
```

| Variant | Meaning |
|---|---|
| `Open` | Messages flow both ways. |
| `Closing` | This end sent a Close and waits for the peer's. |
| `Closed` | Both Close frames exchanged, or the connection failed. Flush the output, then close the transport. |

```rust
use ws_net::{CloseCode, Connection, State};
let mut conn = Connection::server();
conn.close(CloseCode::GOING_AWAY, "restart")?;
assert_eq!(conn.state(), State::Closing);
# Ok::<(), ws_net::WsError>(())
```

## `CloseCode`

```rust,ignore
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CloseCode(/* u16 */);
impl Display for CloseCode {}
impl From<CloseCode> for u16 {}
```

A Close status code. Any `u16` can be represented; `is_sendable` says
whether it may appear on the wire.

| Item | Description |
|---|---|
| `NORMAL` (1000), `GOING_AWAY` (1001), `PROTOCOL_ERROR` (1002), `UNSUPPORTED_DATA` (1003), `INVALID_PAYLOAD` (1007), `POLICY_VIOLATION` (1008), `MESSAGE_TOO_BIG` (1009), `MANDATORY_EXTENSION` (1010), `INTERNAL_ERROR` (1011), `SERVICE_RESTART` (1012), `TRY_AGAIN_LATER` (1013), `BAD_GATEWAY` (1014) | Sendable codes. |
| `NO_STATUS` (1005), `ABNORMAL` (1006), `TLS_HANDSHAKE` (1015) | Reporting only; never sent. |
| `CloseCode::new(code: u16) -> CloseCode` | Wraps any code (3000-4999 are for applications). |
| `as_u16(&self) -> u16` | The number. |
| `is_sendable(&self) -> bool` | 1000-1003, 1007-1014, 3000-4999. |
| `is_private_use`, `is_registered`, `is_reporting_only` | 4000-4999; 3000-3999; 1005, 1006, 1015. |

```rust
use ws_net::CloseCode;
assert!(CloseCode::new(4000).is_sendable());
assert!(!CloseCode::NO_STATUS.is_sendable());
assert!(!CloseCode::new(1004).is_sendable());
assert_eq!(u16::from(CloseCode::MESSAGE_TOO_BIG), 1009);
assert_eq!(CloseCode::NORMAL.to_string(), "1000");
```

## `CloseFrame`

```rust,ignore
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CloseFrame<'a> {
    pub code: CloseCode,   // always sendable
    pub reason: &'a str,   // valid UTF-8, at most 123 bytes
}
```

A received Close frame's code and reason, in [`Event::Close`](#event).

```rust
use ws_net::{CloseCode, Connection, Event};
let mut client = Connection::client_with_seed([7; 32]);
let _ = client.feed(&[0x88, 0x05, 0x03, 0xE8, b'b', b'y', b'e']);
match client.poll().unwrap() {
    Event::Close(Some(frame)) => assert_eq!((frame.code, frame.reason), (CloseCode::NORMAL, "bye")),
    other => panic!("{other:?}"),
}
```

## `WsError`

```rust,ignore
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WsError { /* variants below */ }
impl WsError { pub const fn close_code(&self) -> Option<CloseCode>; }
impl Display for WsError {}
impl core::error::Error for WsError {}
```

| Variant | Meaning | `close_code()` |
|---|---|---|
| `ReservedBits` | RSV1-3 set, except RSV1 on the first frame of a data message with permessage-deflate. | 1002 |
| `ReservedOpcode` | Opcode 0x3-0x7 or 0xB-0xF. | 1002 |
| `FragmentedControl` | A control frame without FIN. | 1002 |
| `ControlTooLong` | A received control frame over 125 bytes. | 1002 |
| `InvalidLength` | A non-minimal length, or the 64-bit high bit set. | 1002 |
| `UnmaskedFrame` | A server received an unmasked frame. | 1002 |
| `MaskedFrame` | A client received a masked frame. | 1002 |
| `UnexpectedContinuation` | A continuation with no message in progress. | 1002 |
| `ExpectedContinuation` | A new data frame inside a fragmented message. | 1002 |
| `InvalidUtf8` | Text or a close reason that is not UTF-8. | 1007 |
| `FrameTooLarge` | A frame over `Limits::max_frame`. | 1009 |
| `MessageTooLarge` | A message over `Limits::max_message`. | 1009 |
| `InvalidClosePayload` | A Close payload of one byte. | 1002 |
| `InvalidCloseCode` | A received Close code that may not be sent. | 1002 |
| `UnexpectedEof` | The transport closed before the closing handshake completed. | 1006 (never sent) |
| `InvalidArgument(&'static str)` | A refused call: an argument the protocol does not allow. The text names the rule. | `None` |
| `InvalidState(&'static str)` | A refused call made in the wrong state. The text names the rule. | `None` |
| `OutputFull` | A refused send: it would exceed `Limits::max_output`. Write the output, or close by policy. | `None` |
| `IdleTimeout` | No input for the idle timeout; Close 1001 queued. | 1001 |
| `CloseTimeout` | The peer did not answer our Close in time; nothing more sent. | 1006 (never sent) |
| `MessageTimeout` | A data message stayed incomplete past the message timeout; Close 1008 queued. | 1008 |
| `AllocationFailed` | Memory for an incoming message could not be allocated (the system is out of memory; the message was within budget); Close 1011 queued instead of the process aborting. | 1011 |
| `InvalidCompressedData` | A compressed message (permessage-deflate) is not valid DEFLATE: a bad block, a back-reference beyond the window or into a message the window does not hold, data after the final block. | 1007 |
| `RandomUnavailable` | A refused call: this client has no masking keys, because the OS random source failed when `Connection::client` ran. Use `try_client`. | `None` |

`close_code()` is the failure's status code, or `None` for a refused call,
which leaves the connection unchanged. The enum is `#[non_exhaustive]`.

```rust
use ws_net::{CloseCode, WsError};
assert_eq!(WsError::InvalidUtf8.close_code(), Some(CloseCode::INVALID_PAYLOAD));
assert_eq!(WsError::UnexpectedEof.close_code(), Some(CloseCode::ABNORMAL));
assert_eq!(WsError::InvalidState("x").close_code(), None);
assert_eq!(WsError::FrameTooLarge.to_string(), "frame exceeds the configured limit");
```

## `ServerHandshake`

```rust,ignore
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerHandshake { /* private */ }
```

A validated opening request (RFC 6455 section 4.2.1), ready to be accepted.

| Item | Description |
|---|---|
| `ServerHandshake::MAX_HEAD: usize` | 16 KiB: the largest head `from_head` (and `ClientHandshake::verify_head`) accepts. |
| `ServerHandshake::MAX_PROTOCOLS: usize` | 64: the most subprotocols accepted from one request. |
| `ServerHandshake::MAX_EXTENSION_OFFERS: usize` | 16: the most extension offers accepted from one request. |
| `extensions(&self) -> extension::Offers<'_>` | The offered extensions, parsed, in client order. |
| `write_response_with(&self, protocol, extensions: &Negotiated, extra: &[(&str, &[u8])], out)` | The `101` with extra response headers (validated: token names, not reserved, no control bytes). |
| `response_fields(&self, protocol, extensions: &Negotiated) -> Result<ResponseFields<'_>, HandshakeError>` | The `101`'s fields as `(name, value)` pairs for an HTTP layer that writes the status line. |
| `from_head(bytes: &[u8]) -> Result<Option<(ServerHandshake, usize)>, HandshakeError>` | Validates a request from its raw bytes. `Ok(None)` until the blank line ending the head arrives; then the handshake and the head's length (bytes after it are the first frames). |
| `from_request(method: &str, target: &str, headers: impl IntoIterator<Item = (&str, &[u8])>) -> Result<ServerHandshake, HandshakeError>` | Validates a request an HTTP layer has parsed. |
| `accept_key(&self) -> &AcceptKey` | The `Sec-WebSocket-Accept` value. |
| `target(&self) -> &str` | The request target, for routing. |
| `host(&self) -> &str` | The `Host` field. |
| `origin(&self) -> Option<&str>` | The `Origin` field, if sent. |
| `protocols(&self) -> impl Iterator<Item = &str>` | The offered subprotocols, in preference order. |
| `select_protocol<'p>(&self, preference: &[&'p str]) -> Option<&'p str>` | The first of the server's protocols that the client offered (exact, case-sensitive). |
| `accept(&self, policy: &AcceptPolicy, out: &mut Vec<u8>) -> Result<Connection, HandshakeError>` | Applies the policy, appends the `101`, returns the server connection with the policy's limits. Nothing is written on a refusal. |
| `write_response(&self, protocol: Option<&str>, out: &mut Vec<u8>) -> Result<(), HandshakeError>` | Appends the complete `101` response, selecting `protocol` or none. |

**Cost.** The record is one allocation: target, `Host`, `Origin`, the
offered protocols, and the offered extensions in one exactly-sized buffer.

**What is checked.** The method is `GET`; the target is visible ASCII;
exactly one `Host` (visible ASCII); `Upgrade` lists `websocket` and
`Connection` lists `upgrade`, case-insensitively, in any field of that name;
exactly one `Sec-WebSocket-Version`, equal to `13`; exactly one
`Sec-WebSocket-Key`, the canonical base64 of 16 bytes; at most one `Origin`
(visible ASCII); every offered subprotocol a token, at most 64; no body
(no `Transfer-Encoding`, no `Content-Length` other than `0`), because the
bytes after the head are the first frames and a front proxy that read a
body would disagree about where they start. Comma lists follow RFC 9110
through `parse-net`: a comma inside a quoted string does not split, and a
value that is not a valid list holds nothing.
`from_head` also checks the HTTP/1.1 syntax strictly: CRLF line endings (a
bare CR or LF is refused as soon as it arrives), `METHOD SP target SP
HTTP/1.1`, token field names with no whitespace before the colon, no line
folding, no control bytes in values, and at most `MAX_HEAD` bytes. Each
call scans the buffer from the start; for a head read in many pieces use
[`HeadReader`](#headreader) or an [`Acceptor`](#tier-1-accept-and-acceptor),
which scan each byte once.

**Errors.** `NotGet`, `MalformedHead`, `HeadTooLarge`, `InvalidHost`,
`MissingUpgrade`, `MissingConnectionUpgrade`, `UnsupportedVersion`,
`MissingKey`, `InvalidKey`, `InvalidOrigin`, `InvalidProtocol`,
`UnexpectedBody` (see
[`HandshakeError`](#handshakeerror)); `write_response` returns
`InvalidProtocol` for a protocol that was not offered.

```rust
use ws_net::{HandshakeError, ServerHandshake};

let request = b"GET /rpc HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUpgrade: websocket\r\n\
    Connection: keep-alive, Upgrade\r\nOrigin: http://127.0.0.1:8080\r\n\
    Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\
    Sec-WebSocket-Protocol: jsonrpc\r\n\r\n";
assert_eq!(ServerHandshake::from_head(&request[..20])?, None); // not all here yet
let (hs, len) = ServerHandshake::from_head(request)?.expect("complete");
assert_eq!(len, request.len());
assert_eq!((hs.target(), hs.host()), ("/rpc", "127.0.0.1:8080"));
assert_eq!(hs.origin(), Some("http://127.0.0.1:8080"));
assert_eq!(hs.protocols().collect::<Vec<_>>(), ["jsonrpc"]);

let mut out = Vec::new();
assert_eq!(hs.write_response(Some("other"), &mut out), Err(HandshakeError::InvalidProtocol));
hs.write_response(Some("jsonrpc"), &mut out)?;
assert!(out.ends_with(b"sec-websocket-protocol: jsonrpc\r\n\r\n"));

// The same request from an HTTP layer's parsed fields.
let fields = [
    ("Host", &b"127.0.0.1:8080"[..]), ("Upgrade", b"websocket"),
    ("Connection", b"keep-alive, Upgrade"), ("Origin", b"http://127.0.0.1:8080"),
    ("Sec-WebSocket-Key", b"dGhlIHNhbXBsZSBub25jZQ=="), ("Sec-WebSocket-Version", b"13"),
    ("Sec-WebSocket-Protocol", b"jsonrpc"),
];
assert_eq!(ServerHandshake::from_request("GET", "/rpc", fields)?, hs);
# Ok::<(), HandshakeError>(())
```

## `AcceptPolicy` and `Decision`

```rust,ignore
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AcceptPolicy { /* private */ }

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Decision<'a> { pub protocol: Option<&'a str>, pub extensions: Negotiated }
```

| Method | Description |
|---|---|
| `AcceptPolicy::new() -> AcceptPolicy` / `default()` | The Tier 1 policy: same-origin (a missing Origin accepted), no subprotocol, default `Limits`. |
| `with_origins(self, origins: OriginPolicy) -> AcceptPolicy` | The Origin rule. |
| `with_protocols(self, preference: &[&str]) -> Result<AcceptPolicy, HandshakeError>` | The server's subprotocols in preference order; `InvalidProtocol` for a non-token. |
| `require_protocol(self) -> AcceptPolicy` | Refuse a client that offers none of them (`ProtocolRequired`). |
| `with_limits(self, limits: Limits) -> AcceptPolicy` | The limits of accepted connections. |
| `with_keepalive(self, keepalive: Keepalive) -> AcceptPolicy`, `keepalive` | The keepalive of accepted connections. |
| `with_hosts(self, hosts: &[&str]) -> Result<AcceptPolicy, HandshakeError>`, `hosts` | `Host` allowlist (DNS rebinding): RFC 3986 authorities, compared case-insensitively, IP literals by value; `HostRefused` (403) otherwise. |
| `with_secure(self, secure: bool) -> AcceptPolicy` | The endpoint is (or is not) behind TLS: same-origin then pins the page's scheme, and a port-less host entry means 443 or 80. |
| `origins(&self) -> &OriginPolicy`, `limits(&self) -> &Limits` | Accessors. |
| `check<'h>(&self, handshake: &'h ServerHandshake) -> Result<Decision<'h>, HandshakeError>` | The decision without writing anything, for an HTTP layer that writes its own `101`. `OriginRefused` or `ProtocolRequired`. |

```rust
use ws_net::{AcceptPolicy, HandshakeError, OriginPolicy, ServerHandshake};

let fields = [
    ("Host", &b"api.example"[..]), ("Upgrade", b"websocket"), ("Connection", b"Upgrade"),
    ("Sec-WebSocket-Version", b"13"), ("Sec-WebSocket-Key", b"dGhlIHNhbXBsZSBub25jZQ=="),
    ("Origin", b"https://app.example"), ("Sec-WebSocket-Protocol", b"rpc.v1, rpc.v2"),
];
let handshake = ServerHandshake::from_request("GET", "/rpc", fields)?;
let policy = AcceptPolicy::new()
    .with_origins(OriginPolicy::allow(&["https://app.example"])?)
    .with_protocols(&["rpc.v2", "rpc.v1"])?;
assert_eq!(policy.check(&handshake)?.protocol, Some("rpc.v2")); // server's order wins

let mut out = Vec::new();
let conn = handshake.accept(&policy, &mut out)?;
assert!(out.ends_with(b"sec-websocket-protocol: rpc.v2\r\n\r\n"));
assert!(conn.is_open());

let other = AcceptPolicy::new().with_protocols(&["chat"])?.require_protocol();
assert_eq!(other.check(&handshake), Err(HandshakeError::OriginRefused));
# Ok::<(), HandshakeError>(())
```

## `OriginPolicy`

```rust,ignore
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OriginPolicy {
    SameOrigin { allow_missing: bool },
    AllowList { origins: Vec<String>, allow_missing: bool },
    Any,
}
```

| Item | Description |
|---|---|
| `OriginPolicy::same_origin() -> OriginPolicy` / `default()` | The Origin's host and port must be the request's `Host` (scheme not compared). A missing Origin is accepted. |
| `OriginPolicy::allow(origins: &[&str]) -> Result<OriginPolicy, HandshakeError>` | Exact serialized origins, each `http` or `https` with a host and optional port, no path, query, userinfo, trailing slash, or surrounding space; `InvalidRequest` otherwise. |
| `OriginPolicy::any_origin() -> OriginPolicy` | Every Origin. Loud on purpose. |
| `allow_missing(self, allow: bool) -> OriginPolicy` | Whether a request without `Origin` is accepted (no effect on `Any`). |
| `permits(&self, origin: Option<&str>, host: &str) -> bool` | The check. Fails closed: an Origin or Host that does not parse is refused. |

Origins are compared as RFC 6454 serialized origins (through `parse-net`):
scheme and host ASCII case-insensitively, IP literals by value, ports after
the scheme's default (80, 443) is filled in. Never by prefix, suffix, or
substring. `null` never matches, nor does a scheme other than `http` or
`https`. Under `SameOrigin`, a `Host` without a port matches an Origin on
its scheme's default port, and a `Host` with a port matches an Origin whose
effective port is that port.

```rust
use ws_net::OriginPolicy;

let list = OriginPolicy::allow(&["https://example.com"])?;
for evil in ["https://example.com.evil.net", "https://evilexample.com",
             "https://example.com@evil.net", "http://example.com", "null"] {
    assert!(!list.permits(Some(evil), "example.com"), "{evil}");
}
assert!(list.permits(Some("HTTPS://EXAMPLE.COM:443"), "example.com"));

let same = OriginPolicy::same_origin();
assert!(same.permits(Some("http://127.0.0.1:8080"), "127.0.0.1:8080"));
assert!(!same.permits(Some("http://127.0.0.1:8080"), "127.0.0.1:9090"));
assert!(same.permits(None, "127.0.0.1:8080"));
assert!(!same.allow_missing(false).permits(None, "127.0.0.1:8080"));
# Ok::<(), ws_net::HandshakeError>(())
```

## `HeadReader`

```rust,ignore
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct HeadReader { /* private */ }

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Verified<'a> { pub protocol: Option<&'a str>, pub extensions: Negotiated }
```

| Method | Description |
|---|---|
| `HeadReader::new() -> HeadReader` | A reader at the start of a head. |
| `server(&mut self, bytes: &[u8]) -> Result<Option<(ServerHandshake, usize)>, HandshakeError>` | As `ServerHandshake::from_head`, resuming where the last call stopped. |
| `client<'c>(&mut self, handshake: &'c ClientHandshake, bytes: &[u8]) -> Result<Option<(Verified<'c>, usize)>, HandshakeError>` | As `ClientHandshake::verify_head`, resuming. |
| `reset(&mut self)` | Start over for the next head. |

`from_head` and `verify_head` scan the whole buffer on every call, so a peer
that sends its head one byte per read makes them do quadratic work: up to
about 134 million byte visits for a 16 KiB head (the class of
CVE-2023-43669). A `HeadReader` keeps its scan position: pass the same
buffer each time, grown at the end, and the total work is linear in the
head. A buffer shorter than what was already scanned is `InvalidRequest`.

```rust
use ws_net::{ClientHandshake, HeadReader, ServerHandshake};

let client = ClientHandshake::with_nonce(*b"the sample nonce");
let mut request = Vec::new();
client.write_request("a.example", "/", &mut request)?;

let mut reader = HeadReader::new();
let mut buffer = Vec::new();
let mut found = None;
for &byte in &request {
    buffer.push(byte); // one byte per read
    if let Some(f) = reader.server(&buffer)? {
        found = Some(f);
    }
}
let (server, len) = found.expect("complete");
assert_eq!(len, request.len());

let mut response = Vec::new();
server.write_response(None, &mut response)?;
let (verified, _) = HeadReader::new().client(&client, &response)?.expect("complete");
assert_eq!(verified.protocol, None);
# Ok::<(), ws_net::HandshakeError>(())
```

## `ClientHandshake`

```rust,ignore
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientHandshake { /* private */ }
impl Default for ClientHandshake {} // feature `std`
```

The client side: the request to send, and the check of the response.

| Item | Description |
|---|---|
| `ClientHandshake::new() -> ClientHandshake` | A fresh 16-byte nonce from the OS cryptographic random source. If that source fails it fails closed: `write_request` returns `RandomUnavailable`. Feature `std`. |
| `ClientHandshake::try_new() -> Result<ClientHandshake, HandshakeError>` | As `new`, returning `RandomUnavailable` when the OS source fails. Feature `std`. |
| `with_nonce(nonce: [u8; 16]) -> ClientHandshake` | A caller-chosen nonce (RFC 6455 requires it to be random per connection). |
| `with_protocols(self, protocols: &[&str]) -> ClientHandshake` | Offers subprotocols, in preference order. |
| `with_origin(self, origin: &str) -> ClientHandshake` | Sends an `Origin` field, as browsers do. |
| `with_header(self, name: &str, value: &[u8]) -> ClientHandshake` | An extra request header (`Authorization`, `Cookie`), validated at write; reserved names refused. |
| `verify_full(&self, status, headers) -> Result<Verified<'_>, HandshakeError>` | As `verify`, returning the protocol and the negotiated extensions. |
| `connection(&self, verified: &Verified<'_>) -> Connection` (feature `std`), `connection_with_seed(&self, verified, seed: [u8; 32]) -> Connection` | The client connection for a verified response, with its extensions. `Verified::none()` builds one by hand. |
| `key(&self) -> &str` | The `Sec-WebSocket-Key` sent. |
| `write_request(&self, host: &str, path: &str, out: &mut Vec<u8>) -> Result<(), HandshakeError>` | Appends the request. `InvalidRequest` for an empty or non-visible-ASCII host, path, or origin, or a path without a leading `/`; `InvalidProtocol` for a non-token protocol. Nothing is written on error. |
| `verify(&self, status: u16, headers: impl IntoIterator<Item = (&str, &[u8])>) -> Result<Option<&str>, HandshakeError>` | Checks a response an HTTP layer parsed; returns the selected subprotocol. |
| `verify_head(&self, bytes: &[u8]) -> Result<Option<(Option<&str>, usize)>, HandshakeError>` | Checks a response from raw bytes: `Ok(None)` until the head is complete, then the selected subprotocol and the head's length. |

**What is checked.** Status 101 (else `NotSwitching(status)`); `Upgrade`
lists `websocket`; `Connection` lists `upgrade`; exactly one
`Sec-WebSocket-Accept`, equal to the expected value (`AcceptMismatch`); no
extension accepted (`UnexpectedExtension`); at most one
`Sec-WebSocket-Protocol`, naming an offered protocol (`InvalidProtocol`).
`verify_head` reads the head as strictly as `ServerHandshake::from_head`
(status line `HTTP/1.1 SP 3DIGIT [SP reason]`).

```rust
use ws_net::{ClientHandshake, HandshakeError, ServerHandshake};

let client = ClientHandshake::with_nonce(*b"the sample nonce").with_protocols(&["chat"]);
assert_eq!(client.key(), "dGhlIHNhbXBsZSBub25jZQ==");
let mut request = Vec::new();
client.write_request("server.example.com", "/chat", &mut request)?;

let (server, _) = ServerHandshake::from_head(&request)?.expect("complete");
let mut response = Vec::new();
server.write_response(Some("chat"), &mut response)?;
assert_eq!(client.verify_head(&response)?, Some((Some("chat"), response.len())));

assert_eq!(
    client.verify_head(b"HTTP/1.1 403 Forbidden\r\n\r\n"),
    Err(HandshakeError::NotSwitching(403))
);
# Ok::<(), HandshakeError>(())
```

## `HandshakeError`

```rust,ignore
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HandshakeError { /* variants below */ }
impl HandshakeError {
    pub const fn status(&self) -> u16;
    pub fn write_response(&self, out: &mut Vec<u8>);
}
impl Display for HandshakeError {}
impl core::error::Error for HandshakeError {}
```

| Variant | Meaning | `status()` |
|---|---|---|
| `NotGet` | The method is not `GET`. | 400 |
| `MalformedHead` | Not strict HTTP/1.1: a bad request or status line, a bare CR or LF, a malformed field line, or a bad target. | 400 |
| `HeadTooLarge` | The head did not end within `MAX_HEAD` bytes. | 431 |
| `InvalidHost` | No `Host`, more than one, or not visible ASCII. | 400 |
| `InvalidOrigin` | More than one `Origin`, or not visible ASCII. | 400 |
| `MissingUpgrade` | No `Upgrade` field listing `websocket`. | 400 |
| `MissingConnectionUpgrade` | No `Connection` field listing `upgrade`. | 400 |
| `MissingKey` | No `Sec-WebSocket-Key`, or more than one. | 400 |
| `InvalidKey` | The key is not the canonical base64 of 16 bytes. | 400 |
| `UnsupportedVersion` | `Sec-WebSocket-Version` missing, repeated, or not `13`. | 426 |
| `UnexpectedBody` | The upgrade request declares a body: `Transfer-Encoding`, or `Content-Length` other than `0` (request smuggling defense). | 400 |
| `OriginRefused` | The policy refused the `Origin` (or its absence). | 403 |
| `HostRefused` | The policy's `Host` allowlist refused the request (DNS rebinding). | 403 |
| `InvalidExtensions` | `Sec-WebSocket-Extensions` malformed, or over 16 offers or 16 parameters. | 400 |
| `ProtocolRequired` | The policy requires a subprotocol and none of the server's was offered. | 400 |
| `RandomUnavailable` | Client side: the OS random source failed, so no nonce exists; nothing was written. | 500 (not answered) |
| `InvalidProtocol` | A subprotocol that is not a token, more than 64, or a selection not offered. | 400 |
| `NotSwitching(u16)` | Client side: the status was not 101. | 400 |
| `AcceptMismatch` | Client side: `Sec-WebSocket-Accept` missing, repeated, or wrong. | 400 |
| `UnexpectedExtension` | Client side: the server accepted an extension. | 400 |
| `InvalidRequest` | Client side: a bad host, path, or origin given to `ClientHandshake`. | 400 |

`write_response` appends the complete refusal: the status line,
`sec-websocket-version: 13` for 426 (RFC 6455 section 4.4), an empty body,
and `connection: close`. Close the connection after writing it.

```rust
use ws_net::HandshakeError;
let mut out = Vec::new();
HandshakeError::UnsupportedVersion.write_response(&mut out);
assert_eq!(out, b"HTTP/1.1 426 Upgrade Required\r\nsec-websocket-version: 13\r\n\
content-length: 0\r\nconnection: close\r\n\r\n");
assert_eq!(HandshakeError::HeadTooLarge.status(), 431);
```

## `write_refusal`

```rust,ignore
pub fn write_refusal(status: u16, retry_after_seconds: Option<u32>, out: &mut Vec<u8>) -> Result<(), HandshakeError>;
```

A complete refusal (`content-length: 0`, `connection: close`, and
`retry-after` when given) for statuses a server decides itself: 403 by
policy, 429 for rate limits, 503 when shedding load. `InvalidRequest` for a
status outside 400 to 599; nothing is written then.

```rust
let mut out = Vec::new();
ws_net::write_refusal(429, Some(5), &mut out)?;
assert!(out.starts_with(b"HTTP/1.1 429 Too Many Requests\r\n"));
assert!(out.ends_with(b"retry-after: 5\r\n\r\n"));
# Ok::<(), ws_net::HandshakeError>(())
```

## The `extension` module

```rust,ignore
pub fn parse(value: &[u8]) -> Offers<'_>;             // Item = Result<Offer<'_>, HandshakeError>
pub struct Offer<'a>;                                  // name(), params() -> Params<'a>
pub struct Params<'a>;                                 // Iterator<Item = Param<'a>>
pub struct Param<'a> { pub name: &'a str, pub value: Option<&'a str> }
#[non_exhaustive] pub struct Negotiated;               // none(), is_empty(), deflate()
pub const MAX_OFFERS: usize = 16;
pub const MAX_PARAMS: usize = 16;
```

RFC 6455 section 9.1: `extension = token *( ";" param )`, `param = token [
"=" ( token / quoted-string ) ]`. The list and the parameters are read
with `parse-net` (commas inside quoted strings do not split); a value may
be absent; there is no whitespace around `=`; empty parameters (`a;;b`)
are skipped; a repeated name is kept, in order, for the extension's
negotiation to judge; a quoted value must be a token once unquoted, and one
with a backslash escape is refused.
`ServerHandshake::from_request` validates every offer (at most 16 over all
fields) and `extensions()` iterates them. The one extension ws-net
negotiates is [permessage-deflate](#permessage-deflate) (feature `deflate`);
every other offer is declined (RFC 6455 allows it), and a client refuses a
response that accepts one it did not offer.

```rust
use ws_net::extension;

let offers: Vec<_> = extension::parse(b"permessage-deflate; client_max_window_bits=\"10\"; server_no_context_takeover")
    .collect::<Result<_, _>>()?;
let params: Vec<_> = offers[0].params().map(|p| (p.name, p.value)).collect();
assert_eq!(params, [("client_max_window_bits", Some("10")), ("server_no_context_takeover", None)]);
# Ok::<(), ws_net::HandshakeError>(())
```

<a id="permessage-deflate"></a>
## permessage-deflate (feature `deflate`)

RFC 7692 on [compress-lib](https://crates.io/crates/compress-lib) (first
party, no dependencies). Off unless the feature is on and the policy or
the client asks for it.

```rust,ignore
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct DeflateConfig { /* private */ }

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DeflateParams {
    pub server_no_context_takeover: bool,
    pub client_no_context_takeover: bool,
    pub server_max_window_bits: u8,   // 8..=15
    pub client_max_window_bits: u8,   // 8..=15
}
```

| Item | Default | Description |
|---|---|---|
| `DeflateConfig::new()`, `Default` | | The defaults below: memory-lean and keeping secrets in one message from leaking through the next. |
| `with_server_context_takeover(bool)`, `with_client_context_takeover(bool)` | off, off | Whether each end may keep its compression window between messages: better ratios for similar messages, at the cost of the window per connection and of letting one message probe another (RFC 7692 section 8). |
| `with_server_max_window_bits(u8)`, `with_client_max_window_bits(u8)` | 15, 15 | The largest windows, clamped to 8 to 15. |
| `with_level(u8)`, `with_min_size(usize)` | 1, 256 | Compression level 0 to 9; messages shorter than `min_size` go uncompressed. |
| `server_context_takeover`, `client_context_takeover`, `server_max_window_bits`, `client_max_window_bits`, `level`, `min_size` | | The configured values. |
| `AcceptPolicy::with_deflate(DeflateConfig)` | | The server accepts the first offer, in the client's order, that the configuration can satisfy; offers with unknown, repeated, or invalid parameters are declined. A configuration asking for a client window under 15 bits declines a client that did not offer `client_max_window_bits` (the response may not limit it). |
| `ClientHandshake::with_deflate(DeflateConfig)` | | The client offers one element: `server_no_context_takeover` unless server takeover is allowed, `client_no_context_takeover` unless its own is, `server_max_window_bits` below 15, and `client_max_window_bits`. A response that breaks RFC 7692 section 7 is `HandshakeError::InvalidExtensions`. Read it with `verify_full`, `HeadReader::client`, or the `blocking` module, which return the agreement for `connection`. |
| `Negotiated::deflate(&self) -> Option<&DeflateParams>` | | The agreement. |
| `PreparedMessage::with_deflate(self, &DeflateConfig)` | | A broadcast compressed once (see [`PreparedMessage`](#preparedmessage)). |

On a connection that agreed:

- Sends compress by [`SendOptions`](#preparedmessage); a compressed
  message has RSV1 on its first frame and is split at `send_frame` like any
  other. Fragmented sends and control frames go uncompressed.
- Received messages with RSV1 are inflated into the reassembly buffer as
  their bytes arrive. The inflated size is capped at `max_message` while it
  is produced, so a small compressed bomb fails with `MessageTooLarge`
  (1009) at the budget, never past it; the compressed size of a message is
  capped too, at `max_message` plus a sixty-fourth plus 1 KiB. Inflated
  text is validated once, whole, when the message is complete (in pieces,
  which failure is reported would depend on how the bytes arrive; the
  budget bounds the work before the check). Undecodable data is
  `InvalidCompressedData` (1007); RSV1 on a continuation or a control frame
  is `ReservedBits` (1002).
- The compressor and decompressor are built on first use.
  `release_memory` drops each one that holds no context between messages;
  `memory_in_use` counts them; `wipe` zeroes their windows and drops them.

Memory per connection (compress-lib's figures): a decompressor without
takeover holds its decode tables, about 12 KiB, and adds the window
(`2^bits` bytes) with takeover; a level-1 compressor holds about 330 KiB at
15 bits and about 30 KiB at 9 bits. A server sending large volumes to many
clients picks its server window bits with that in mind.

```rust
# #[cfg(feature = "deflate")] {
use ws_net::{AcceptPolicy, ClientHandshake, DeflateConfig, HeadReader, OriginPolicy, ServerHandshake};

let client = ClientHandshake::with_nonce(*b"the sample nonce").with_deflate(DeflateConfig::new());
let mut request = Vec::new();
client.write_request("chat.example", "/", &mut request)?;

let (handshake, _) = ServerHandshake::from_head(&request)?.expect("complete");
let policy = AcceptPolicy::new()
    .with_origins(OriginPolicy::any_origin())
    .with_deflate(DeflateConfig::new());
let mut response = Vec::new();
let mut server = handshake.accept(&policy, &mut response)?;

let (verified, _) = HeadReader::new().client(&client, &response)?.expect("complete");
let mut conn = client.connection_with_seed(&verified, [7; 32]);
assert!(conn.negotiated().deflate().is_some());

let update = r#"{"jsonrpc":"2.0","method":"tick","params":[1,2,3]}"#.repeat(10);
server.send_text(&update)?;
assert_eq!(server.output()[0], 0xC1); // FIN, RSV1, text
let wire = server.output().to_vec();
let _ = conn.feed(&wire);
assert!(matches!(conn.poll()?, ws_net::Event::Text(t) if t == update));
# }
# Ok::<(), Box<dyn std::error::Error>>(())
```

## The `blocking` module

Feature `std`. A `Read + Write` adapter, comparable to tungstenite's
`WebSocket<Stream>`.

| Item | Description |
|---|---|
| `blocking::accept(stream) -> Result<WebSocket<S>, Error>` | Reads the head, applies the Tier 1 policy, writes the `101` or the refusal. |
| `blocking::accept_with(stream, policy: &AcceptPolicy) -> Result<(WebSocket<S>, ServerHandshake), Error>` | With a policy; returns the request for routing. |
| `blocking::connect(stream, host, path) -> Result<WebSocket<S>, Error>` | The client side, with a fresh OS-random nonce. |
| `blocking::connect_with(stream, host, path, handshake: &ClientHandshake) -> Result<(WebSocket<S>, Option<String>), Error>` | With protocols, Origin, headers; returns the selected protocol. |
| `WebSocket::from_upgraded(stream, leftover: &[u8], connection: Connection)` | Continues after an HTTP layer's upgrade (http-net's `Upgraded`). |
| `read(&mut self) -> Result<Message, Error>` | The next message, Ping, Pong, or Close; replies are written before it returns or blocks; `Error::Closed` after the closing handshake. |
| `send_text`, `send_binary`, `send`, `ping`, `close`, `flush` | Queue and write fully. |
| `send_text_with`, `send_binary_with` | With [`SendOptions`](#preparedmessage), as on `Connection`. |
| `with_keepalive(self, keepalive: Keepalive) -> WebSocket<S>` | The keepalive rules; connections from `accept`, `connect`, and their `_with` forms start with the 5 s close timeout only. |
| `connection`, `connection_mut`, `get_ref`, `get_mut`, `into_inner` | Access. |
| `Error { Io, Protocol(WsError), Handshake(HandshakeError), Closed }` | `#[non_exhaustive]`, `Display`, `std::error::Error`. |

The adapter calls `on_time` around every read. While blocked in `read`,
nothing ticks: give the stream a read timeout of at most the ping interval,
and a timed-out read ticks the keepalive and reads again.

```rust
use std::io::Cursor;
use ws_net::{Connection, Message, blocking::WebSocket};

// A masked "Hello" that arrived with the request head.
let leftover = [0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58];
let mut ws = WebSocket::from_upgraded(Cursor::new(Vec::new()), &leftover, Connection::server());
let message = ws.read()?;
assert_eq!(message, Message::from("Hello"));
ws.send(&message)?;
assert_eq!(ws.get_ref().get_ref(), &[0x81, 0x05, b'H', b'e', b'l', b'l', b'o']);
# Ok::<(), ws_net::blocking::Error>(())
```

## `accept_key` and `AcceptKey`

```rust,ignore
pub fn accept_key(key: &[u8]) -> AcceptKey;
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AcceptKey(/* [u8; 28] */);
impl AcceptKey { pub fn as_str(&self) -> &str; pub fn as_bytes(&self) -> &[u8]; }
impl Debug for AcceptKey {}
impl Display for AcceptKey {}
```

`accept_key` computes base64(SHA-1(key || "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")),
always 28 ASCII characters. It does not validate the key; `ServerHandshake`
does.

```rust
let accept = ws_net::accept_key(b"dGhlIHNhbXBsZSBub25jZQ==");
assert_eq!(accept.as_str(), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="); // RFC 6455 section 1.3
assert_eq!(accept.as_bytes().len(), 28);
assert_eq!(accept.to_string(), accept.as_str());
```

## The `frame` module

The frame layer that [`Connection`](#connection) is built on, for callers
that build or inspect raw frames.

### `Opcode`

```rust,ignore
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Opcode { Continuation, Text, Binary, Close, Ping, Pong }
```

| Method | Description |
|---|---|
| `Opcode::from_u8(value: u8) -> Option<Opcode>` | The opcode for a 4-bit value; `None` for reserved values. |
| `as_u8(&self) -> u8` | The wire value. |
| `is_control(&self) -> bool` | Close, Ping, or Pong. |
| `is_data(&self) -> bool` | Text, Binary, or Continuation. |

```rust
use ws_net::frame::Opcode;
assert_eq!(Opcode::from_u8(0x9), Some(Opcode::Ping));
assert_eq!(Opcode::from_u8(0xB), None);
assert_eq!(Opcode::Close.as_u8(), 0x8);
assert!(Opcode::Pong.is_control() && !Opcode::Text.is_control());
assert!(Opcode::Continuation.is_data());
```

Constants: `frame::MAX_HEADER_LEN` (14), `frame::MAX_CONTROL_PAYLOAD` (125),
`frame::MAX_PAYLOAD_LEN` (2^63 - 1).

```rust
use ws_net::frame::{FrameHeader, MAX_CONTROL_PAYLOAD, MAX_HEADER_LEN, MAX_PAYLOAD_LEN, Opcode};
let h = FrameHeader::new(Opcode::Binary, true, MAX_PAYLOAD_LEN).with_mask([0; 4]);
assert_eq!((h.encoded_len(), MAX_CONTROL_PAYLOAD), (MAX_HEADER_LEN, 125));
```

### `FrameHeader`

```rust,ignore
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FrameHeader {
    pub fin: bool,
    pub rsv: u8,              // RSV1-3 in the low three bits
    pub opcode: Opcode,
    pub mask: Option<[u8; 4]>,
    pub payload_len: u64,
}
```

| Method | Description |
|---|---|
| `FrameHeader::new(opcode: Opcode, fin: bool, payload_len: u64) -> FrameHeader` | No RSV bits, no mask. |
| `with_mask(self, key: [u8; 4]) -> FrameHeader` | Sets the masking key. |
| `with_rsv(self, rsv: u8) -> FrameHeader` | Sets RSV1-3 (low three bits), for an extension that defines them; above 7 is refused at encode. |
| `decode(bytes: &[u8]) -> Result<Option<(FrameHeader, usize)>, WsError>` | Decodes a header from the front of `bytes`: `Ok(None)` if more bytes are needed, else the header and its length (2 to 14). |
| `encoded_len(&self) -> usize` | The encoded length. |
| `encode(&self, out: &mut Vec<u8>) -> Result<(), WsError>` | Appends the header, length in its shortest encoding. |
| `encode_to_slice(&self, out: &mut [u8]) -> Result<usize, WsError>` | The same into a caller buffer, no allocation; `InvalidArgument` when too short. |

`decode` enforces the rules that hold whatever the role: `ReservedOpcode`,
`FragmentedControl`, `ControlTooLong`, `InvalidLength` (non-minimal, or the
high bit set). RSV bits and masking direction are the connection's to
judge. `encode` refuses what `decode` would (`FragmentedControl`,
`ControlTooLong`, `InvalidLength` above 2^63 - 1, `ReservedBits` for `rsv`
above 7) and writes nothing then, so every encoded header decodes.

```rust
use ws_net::{frame::{FrameHeader, Opcode}, WsError};

let header = FrameHeader::new(Opcode::Binary, true, 300).with_mask([1, 2, 3, 4]);
let mut wire = Vec::new();
header.encode(&mut wire)?;
assert_eq!(wire, [0x82, 0xFE, 0x01, 0x2C, 1, 2, 3, 4]);
assert_eq!(header.encoded_len(), wire.len());
assert_eq!(FrameHeader::decode(&wire)?, Some((header, 8)));
assert_eq!(FrameHeader::decode(&wire[..3])?, None);
// 5 bytes in a 16-bit length field: not the shortest encoding.
assert_eq!(FrameHeader::decode(&[0x82, 126, 0, 5]), Err(WsError::InvalidLength));
# Ok::<(), WsError>(())
```

### `apply_mask`

```rust,ignore
pub fn apply_mask(data: &mut [u8], key: [u8; 4], offset: usize);
```

XORs `data` with the masking key as if `data` began `offset` bytes into the
payload. Masking and unmasking are the same operation, a payload can be
processed in pieces by passing each piece's offset, and any offset is
accepted (only its value modulo 4 matters). Works eight bytes at a time.

```rust
use ws_net::frame::apply_mask;
let key = [0x37, 0xfa, 0x21, 0x3d];
let mut data = *b"Hello";
apply_mask(&mut data, key, 0);
assert_eq!(data, [0x7f, 0x9f, 0x4d, 0x51, 0x58]); // RFC 6455 section 5.7
apply_mask(&mut data[..2], key, 0);
apply_mask(&mut data[2..], key, 2);
assert_eq!(&data, b"Hello");
```

## Feature flags

| Feature | Default | Description |
|---|---|---|
| `std` | yes | Masking-key seeds and handshake nonces from the OS cryptographic random source through `mod-rand` (first party, no dependencies): `Connection::client`, `try_client`, `ClientHandshake::new`, `try_new`, `ClientHandshake: Default`, and the [`blocking`](#the-blocking-module) module. Without it the crate is `no_std` + `alloc` and clients take a seed (`client_with_seed`, `with_nonce`), which must come from a cryptographic source. |
| `deflate` | no | [permessage-deflate](#permessage-deflate) (RFC 7692) on `compress-lib` (first party, no dependencies, `no_std` + `alloc`). Works with or without `std`. |

Dependencies: `parse-net` (always; the shared RFC 9110 grammar, no
allocator, no dependencies of its own), `mod-rand` (feature `std`), and
`compress-lib` (feature `deflate`). No third-party runtime dependency.

## Limits reference

| Limit | Value | Where |
|---|---|---|
| Frame payload | 1 MiB default, at least 125 | [`Limits`](#limits) |
| Message | 16 MiB default | [`Limits`](#limits) |
| Control frame payload | 125 bytes | RFC 6455 |
| Close reason | 123 bytes | RFC 6455 |
| Input buffer | 64 KiB default, 256 B to 1 MiB | [`Limits`](#limits) |
| Pending output | 32 MiB default, plus 256 B for automatic Pong and Close | [`Limits`](#limits) |
| Capacity kept per buffer | 64 KiB default | [`Limits`](#limits) |
| Close timeout | 5 s default | [`Keepalive`](#keepalive-millis-tick) |
| Extension offers, parameters per offer | 16, 16 | [`extension`](#the-extension-module) |
| Reassembly reserved ahead of arrived bytes | 1 MiB | [Budgets and memory](#budgets-and-memory) |
| Handshake head | 16 KiB | [`ServerHandshake::MAX_HEAD`](#serverhandshake) |
| Offered subprotocols | 64 | [`ServerHandshake`](#serverhandshake) |

## The 1.0 API (design lock)

The whole 1.0 surface, with the version each item landed in. Every item
is shipped and documented above. Requirement and
item ids are those of [`../dev/PLAN.md`](../dev/PLAN.md).

**Tier 1** (the common case): `accept`, `Acceptor::new`, `Connection::server`,
`Connection::client`, `feed`, `poll`, `send_text`, `send_binary`, `send`,
`close`, `output`, `advance_output`, `feed_eof`, `is_open`,
`should_close_transport`, `Event`, `Message`, `ClientHandshake::new` +
`write_request` + `verify_head`, `blocking::accept`, `blocking::connect`,
`blocking::WebSocket::{read, send_text, send_binary, close}`.

| Item | Version |
|---|---|
| `Connection`: `server`, `client`, `client_with_seed`, `with_limits`, `limits`, `role`, `state`, `feed`, `read_buf`, `commit`, `feed_eof`, `poll`, `send_text`, `send_binary`, `send_text_fragment`, `send_binary_fragment`, `send_ping`, `send_pong`, `close`, `output`, `advance_output` | 0.2 |
| `Connection::try_client`, `is_open`, `can_send` | 0.3 |
| `Connection::with_keepalive(Keepalive)`, `on_time(Millis) -> Result<Tick, WsError>`, `next_deadline() -> Option<Millis>` | 0.4 |
| `Connection::should_close_transport`, `buffered_output`, `release_memory`, `memory_in_use`, `wipe`, `stats() -> Stats` | 0.4 |
| `Connection::poll_split() -> Result<(Event, Sender), WsError>`, `Sender` (`send_text`, `send_binary`, `send_ping`, `send_pong`, `close`, `send_prepared`) | 0.4 |
| `Connection::detach_message(&mut Vec<u8>) -> Option<MessageKind>`, `MessageKind` | 0.4 |
| `Connection::send(&Message)`, `Message` (`Text`, `Binary`, `Ping`, `Pong`, `Close`), `Event::to_message` | 0.4 |
| `PreparedMessage` (`text`, `binary`, `text_with`, `binary_with`, `as_bytes`, `len`, `is_empty`, `payload_len`), `Connection::send_prepared` | 0.4 |
| `Stats { bytes_in, bytes_out, frames_in, messages_in, messages_out, pings_in, pongs_in, closes_in }` | 0.4 |
| `Keepalive` (`new`, `with_ping_interval`, `with_idle_timeout`, `with_close_timeout`, `with_message_timeout`), `Millis`, `Tick` | 0.4 |
| `Limits`: `new`, `with_max_frame`, `with_max_message`, `max_frame`, `max_message` | 0.2 |
| `Limits::with_send_frame`, `send_frame` | 0.3 |
| `Limits::with_max_output` (32 MiB default), `with_input_buffer` (256 B to 1 MiB, default 64 KiB), `with_retain` (64 KiB), their accessors, `DEFAULT_*` constants | 0.4 |
| `WsError` 0.2 variants and `close_code`; `RandomUnavailable` | 0.2, 0.3 |
| `WsError::OutputFull`, `IdleTimeout` (1001), `CloseTimeout` (1006), `MessageTimeout` (1008) | 0.4 |
| `WsError::InvalidCompressedData` (1007; produced with feature `deflate`) | 0.9 |
| `WsError::AllocationFailed` (1011) | 0.6 |
| `CloseCode`, `CloseFrame` | 0.2 |
| `CloseCode::is_private_use`, `is_registered`, `is_reporting_only` | 0.4 |
| `ServerHandshake`: `from_request`, `from_head`, `accept_key`, `target`, `host`, `origin`, `protocols`, `write_response`, `MAX_HEAD` | 0.2 |
| `ServerHandshake::select_protocol`, `accept`, `MAX_PROTOCOLS` | 0.3 |
| `ServerHandshake::extensions`, `write_response_with` (negotiated extensions, extra headers), `response_fields` (the 101 field list for an HTTP layer), `MAX_EXTENSION_OFFERS` | 0.4 |
| `accept`, `Acceptor`, `Accepted`, `AcceptPolicy` (`new`, `with_origins`, `with_protocols`, `require_protocol`, `with_limits`, `check`), `Decision`, `OriginPolicy`, `HeadReader`, `Verified` | 0.3 |
| `AcceptPolicy::with_hosts`, `with_keepalive`, `with_secure`; `HandshakeError::HostRefused`; `write_refusal(status, retry_after, out)` (403, 429, 503) | 0.4 |
| `AcceptPolicy::with_deflate` (feature `deflate`) | 0.9 |
| `ClientHandshake`: `new`, `with_nonce`, `with_protocols`, `with_origin`, `key`, `write_request`, `verify`, `verify_head` | 0.2 |
| `ClientHandshake::try_new` | 0.3 |
| `ClientHandshake::with_header`, `verify_full` | 0.4 |
| `ClientHandshake::connection`, `connection_with_seed`; `Verified::none`; `Connection::with_extensions`, `negotiated` | 0.5 |
| `ClientHandshake::with_deflate` (feature `deflate`) | 0.9 |
| `HandshakeError` 0.2 variants, `status`, `write_response`; `UnexpectedBody`, `OriginRefused`, `ProtocolRequired`, `RandomUnavailable` | 0.2, 0.3 |
| `HandshakeError::InvalidExtensions` | 0.4 |
| `accept_key`, `AcceptKey` | 0.2 |
| `frame`: `Opcode`, `FrameHeader` (`new`, `with_mask`, `decode`, `encoded_len`, `encode`), `apply_mask` | 0.2 |
| `Opcode::is_data`, `MAX_HEADER_LEN`, `MAX_CONTROL_PAYLOAD`, `MAX_PAYLOAD_LEN` | 0.3 |
| `FrameHeader::encode_to_slice` | 0.4 |
| `FrameHeader::with_rsv` | 0.5 |
| `extension` module: `parse`, `Offers`, `Offer` (`name`, `params`), `Param`, `Negotiated` (`none`, `is_empty`), `MAX_OFFERS`, `MAX_PARAMS` | 0.4 |
| `blocking` module (feature `std`): `accept`, `accept_with`, `connect`, `connect_with`, `WebSocket` (`from_upgraded`, `read`, `send_text`, `send_binary`, `send`, `ping`, `close`, `flush`, `connection`, `connection_mut`, `get_ref`, `get_mut`, `into_inner`), `Error` | 0.4 |
| `Stats::data_frames_in` | 0.8 |
| `Sender::send_text_with`, `send_binary_with`; `blocking::WebSocket::send_text_with`, `send_binary_with`, `with_keepalive` | 0.9 |
| `SendOptions`, `send_text_with`, `send_binary_with` | 0.5 |
| permessage-deflate (feature `deflate`): `DeflateConfig`, `DeflateParams`, `PreparedMessage::with_deflate`, `compressed_len`, `Negotiated::deflate` | 0.9 (back from 1.1 once compress-lib was published; `dev/PLAN.md` D-056) |
| `VERSION` | 0.3 |
| After 1.0: shared-segment output, a public extension trait, RFC 8441 (`ExtendedConnect`), connection state export | 1.x |
