# ws-net &mdash; API Reference

> Complete reference for every public item in `ws-net`, with examples.
> **Status: pre-1.0 (0.2.0).** The surface is designed across the 0.x series
> and frozen at `1.0.0`, after LexerSketch Studio ships on it. See
> [`../dev/ROADMAP.md`](../dev/ROADMAP.md).

<sub>Copyright &copy; 2026 <strong>James Gober</strong>.</sub>

## Table of contents

- [Overview](#overview)
- [Installation](#installation)
- [Quick start](#quick-start)
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
  - [Accessors: `limits`, `role`, `state`](#accessors)
- [`Event`](#event)
- [`Limits`](#limits)
- [`Role`](#role)
- [`State`](#state)
- [`CloseCode`](#closecode)
- [`CloseFrame`](#closeframe)
- [`WsError`](#wserror)
- [`ServerHandshake`](#serverhandshake)
- [`ClientHandshake`](#clienthandshake)
- [`HandshakeError`](#handshakeerror)
- [`accept_key` and `AcceptKey`](#accept_key-and-acceptkey)
- [The `frame` module](#the-frame-module)
  - [`Opcode`](#opcode)
  - [`FrameHeader`](#frameheader)
  - [`apply_mask`](#apply_mask)
- [Feature flags](#feature-flags)
- [Limits reference](#limits-reference)

## Overview

`ws-net` is a WebSocket protocol engine that does no I/O. The caller owns
the socket: bytes go in, events come out, and frames to send accumulate in
an output queue the caller writes. The same code runs over `std::net`, an
async runtime, a test harness, or memory.

| Item | Kind | Purpose |
|---|---|---|
| [`Connection`](#connection) | struct | One WebSocket connection after the handshake. |
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

## Installation

```toml
[dependencies]
ws-net = "0.2"

# no_std (alloc only)
ws-net = { version = "0.2", default-features = false }
```

## Quick start

A server: validate the upgrade request from raw bytes, answer `101`, then
echo the first message.

```rust
use ws_net::{Connection, Event, ServerHandshake};

let mut wire = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\n\
    Upgrade: websocket\r\nConnection: Upgrade\r\n\
    Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n".to_vec();
// A masked "Hello" (RFC 6455 section 5.7) right behind the head.
wire.extend_from_slice(&[0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58]);

let (handshake, head_len) = ServerHandshake::from_head(&wire)?.expect("complete head");
let mut response = Vec::new();
handshake.write_response(None, &mut response)?; // write this to the socket

let mut conn = Connection::server();
let _ = conn.feed(&wire[head_len..]);
let reply = match conn.poll()? {
    Event::Text(text) => text.to_uppercase(),
    other => panic!("{other:?}"),
};
conn.send_text(&reply)?;
assert_eq!(conn.output(), [0x81, 0x05, b'H', b'E', b'L', b'L', b'O']);
# Ok::<(), Box<dyn std::error::Error>>(())
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

What the peer sends cannot grow a connection's memory past its budgets:

- The input buffer holds at most 64 KiB; [`feed`](#input) takes what fits.
- A frame's payload length is checked against [`Limits::max_frame`](#limits)
  from its header, before any payload is read; a fragmented message's total
  against [`Limits::max_message`](#limits) before each fragment is read.
  Either violation fails with 1009.
- Reassembly reserves at most 1 MiB ahead of the bytes that have arrived,
  even with the budgets lifted to `u64::MAX`: a length in a header is a
  claim, not an allocation.
- An automatic Pong still waiting, unwritten, at the end of the output is
  replaced by the next one, so a peer that pings without reading cannot
  grow the output. At most one Close is ever queued.

What the caller sends is the caller's to pace: the output queue holds every
frame you queue until you write it.

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

The crate validates the protocol; the policy is yours. A
[`ServerHandshake`](#serverhandshake) exposes:

- [`host`](#serverhandshake): compare it with your own authority to defeat
  DNS rebinding.
- [`origin`](#serverhandshake): compare it with the pages allowed to connect
  to defeat cross-site WebSocket hijacking (browsers always send it). A
  request with two `Origin` fields is refused outright.
- [`protocols`](#serverhandshake): the subprotocols offered, in the client's
  order of preference. Choose one (or none) in
  [`write_response`](#serverhandshake); choosing one that was not offered
  is refused. The client side refuses a response that selects a protocol
  it did not offer, or more than one. Extensions are never negotiated.

Refuse a policy failure with `HTTP/1.1 403 Forbidden`.

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
| `Connection::client() -> Connection` | The connecting end, masking keys from the OS random source. Feature `std`. |
| `Connection::client_with_seed(seed: [u8; 32]) -> Connection` | The connecting end, masking keys derived from a 32-byte secret seed. The seed must be unpredictable to the peer (RFC 6455 section 5.3); a fixed seed is for tests. |
| `Connection::with_limits(self, limits: Limits) -> Connection` | Replaces the [budgets](#limits). |

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
| `feed(&mut self, bytes: &[u8]) -> usize` | Copies as much of `bytes` as fits into the input buffer (64 KiB at most) and returns the count taken. Poll, then feed the rest. `#[must_use]`. |
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
### Accessors: `limits`, `role`, `state`

| Method | Returns |
|---|---|
| `limits(&self) -> &Limits` | The budgets. |
| `role(&self) -> Role` | Server or client. |
| `state(&self) -> State` | Open, Closing, or Closed. |

```rust
use ws_net::{Connection, Limits, Role, State};
let conn = Connection::server();
assert_eq!((conn.role(), conn.state(), *conn.limits()), (Role::Server, State::Open, Limits::new()));
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

## `Limits`

```rust,ignore
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Limits { /* private */ }
```

Budgets on incoming frames and messages, checked from frame headers.
Outgoing messages larger than the frame budget are split into frames of
that size, so a peer with the same limits accepts them.

| Method | Description |
|---|---|
| `Limits::new() -> Limits` / `Limits::default()` | 1 MiB frames, 16 MiB messages (LexerSketch Studio's budgets). |
| `with_max_frame(self, bytes: u64) -> Limits` | The largest frame payload; at least 125 (the largest control frame). |
| `with_max_message(self, bytes: u64) -> Limits` | The largest message, summed over its fragments. |
| `max_frame(&self) -> u64` | The frame budget. |
| `max_message(&self) -> u64` | The message budget. |

```rust
use ws_net::{Connection, Limits, WsError};

let limits = Limits::new().with_max_frame(1).with_max_message(4096);
assert_eq!(limits.max_frame(), 125); // clamped
let mut conn = Connection::server().with_limits(limits);
// A masked binary frame announcing 200 bytes: refused from the header.
let _ = conn.feed(&[0x82, 0xFE, 0x00, 0xC8, 1, 2, 3, 4]);
assert_eq!(conn.poll().unwrap_err(), WsError::FrameTooLarge);
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
| `ReservedBits` | RSV1-3 set. | 1002 |
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
| `from_head(bytes: &[u8]) -> Result<Option<(ServerHandshake, usize)>, HandshakeError>` | Validates a request from its raw bytes. `Ok(None)` until the blank line ending the head arrives; then the handshake and the head's length (bytes after it are the first frames). |
| `from_request(method: &str, target: &str, headers: impl IntoIterator<Item = (&str, &[u8])>) -> Result<ServerHandshake, HandshakeError>` | Validates a request an HTTP layer has parsed. |
| `accept_key(&self) -> &AcceptKey` | The `Sec-WebSocket-Accept` value. |
| `target(&self) -> &str` | The request target, for routing. |
| `host(&self) -> &str` | The `Host` field. |
| `origin(&self) -> Option<&str>` | The `Origin` field, if sent. |
| `protocols(&self) -> impl Iterator<Item = &str>` | The offered subprotocols, in preference order. |
| `write_response(&self, protocol: Option<&str>, out: &mut Vec<u8>) -> Result<(), HandshakeError>` | Appends the complete `101` response, selecting `protocol` or none. |

**What is checked.** The method is `GET`; the target is visible ASCII;
exactly one `Host` (visible ASCII); `Upgrade` lists `websocket` and
`Connection` lists `upgrade`, case-insensitively, in any field of that name;
exactly one `Sec-WebSocket-Version`, equal to `13`; exactly one
`Sec-WebSocket-Key`, the canonical base64 of 16 bytes; at most one `Origin`
(visible ASCII); every offered subprotocol a token, at most 64.
`from_head` also checks the HTTP/1.1 syntax strictly: CRLF line endings (a
bare CR or LF is refused as soon as it arrives), `METHOD SP target SP
HTTP/1.1`, token field names with no whitespace before the colon, no line
folding, no control bytes in values, and at most `MAX_HEAD` bytes. Each
call scans at most `MAX_HEAD` bytes, so calling it again after every read
costs bounded work per read.

**Errors.** `NotGet`, `MalformedHead`, `HeadTooLarge`, `InvalidHost`,
`MissingUpgrade`, `MissingConnectionUpgrade`, `UnsupportedVersion`,
`MissingKey`, `InvalidKey`, `InvalidOrigin`, `InvalidProtocol` (see
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

## `ClientHandshake`

```rust,ignore
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientHandshake { /* private */ }
impl Default for ClientHandshake {} // feature `std`
```

The client side: the request to send, and the check of the response.

| Item | Description |
|---|---|
| `ClientHandshake::new() -> ClientHandshake` | A fresh random nonce from the OS. Feature `std`. |
| `with_nonce(nonce: [u8; 16]) -> ClientHandshake` | A caller-chosen nonce (RFC 6455 requires it to be random per connection). |
| `with_protocols(self, protocols: &[&str]) -> ClientHandshake` | Offers subprotocols, in preference order. |
| `with_origin(self, origin: &str) -> ClientHandshake` | Sends an `Origin` field, as browsers do. |
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

```rust
use ws_net::frame::Opcode;
assert_eq!(Opcode::from_u8(0x9), Some(Opcode::Ping));
assert_eq!(Opcode::from_u8(0xB), None);
assert_eq!(Opcode::Close.as_u8(), 0x8);
assert!(Opcode::Pong.is_control() && !Opcode::Text.is_control());
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
| `decode(bytes: &[u8]) -> Result<Option<(FrameHeader, usize)>, WsError>` | Decodes a header from the front of `bytes`: `Ok(None)` if more bytes are needed, else the header and its length (2 to 14). |
| `encoded_len(&self) -> usize` | The encoded length. |
| `encode(&self, out: &mut Vec<u8>) -> Result<(), WsError>` | Appends the header, length in its shortest encoding. |

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
| `std` | yes | OS-seeded masking keys and handshake nonces: `Connection::client`, `ClientHandshake::new`, `ClientHandshake: Default`. Without it the crate is `no_std` + `alloc`; clients use `Connection::client_with_seed` and `ClientHandshake::with_nonce`. |

## Limits reference

| Limit | Value | Where |
|---|---|---|
| Frame payload | 1 MiB default, at least 125 | [`Limits`](#limits) |
| Message | 16 MiB default | [`Limits`](#limits) |
| Control frame payload | 125 bytes | RFC 6455 |
| Close reason | 123 bytes | RFC 6455 |
| Input buffer | 64 KiB | [`feed`](#input) |
| Reassembly reserved ahead of arrived bytes | 1 MiB | [Budgets and memory](#budgets-and-memory) |
| Handshake head | 16 KiB | [`ServerHandshake::MAX_HEAD`](#serverhandshake) |
| Offered subprotocols | 64 | [`ServerHandshake`](#serverhandshake) |
