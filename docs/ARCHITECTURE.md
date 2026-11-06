# ws-net - Architecture

How the engine is built: its modules, how bytes flow through a connection,
its state machines, its memory, and the algorithms on the hot paths.

<sub>Copyright &copy; 2026 <strong>James Gober</strong>.</sub>

## Principles

- **Sans-IO.** No socket, clock, thread, or allocation policy of its own
  beyond bounded buffers. The caller owns the transport and the time; the
  engine is a state machine over bytes and milliseconds. The same code
  runs over `std::net`, a reactor, a TLS session, or a test feeding one
  byte at a time.
- **Budgets before work.** Every size is checked against a configured
  budget before memory is reserved or work is done: frame and message
  lengths from the header, the head at 16 KiB, output against
  `max_output`, offers and parameters by count.
- **Failures and refusals are different.** A protocol violation fails the
  connection and queues a Close with its code; a call the protocol does not
  allow is refused and changes nothing.
- **No `unsafe`, no third-party runtime dependency, no reachable panic.**

## Modules

| Module | Public | Job |
|---|---|---|
| `lib.rs` | root | crate docs, lint wall, re-exports, `VERSION` |
| `conn.rs` | `Connection`, `Event`, `Role`, `State`, `Sender` | the reader and writer halves, the receive state machine, keepalive application, memory management |
| `limits.rs` | `Limits` | every size budget |
| `keepalive.rs` | `Keepalive`, `Millis`, `Tick` | timer settings and the compact clock state |
| `message.rs` | `Message`, `MessageKind`, `Stats` | owned messages and counters |
| `prepared.rs` | `PreparedMessage`, `SendOptions` | encode-once broadcast frames |
| `frame.rs` | `frame` module | the header codec, `apply_mask`, protocol constants |
| `handshake.rs` | `ServerHandshake`, `ClientHandshake`, `HeadReader`, `Verified`, `ResponseFields`, `accept_key` | the opening handshake, both roles |
| `head.rs` | (private) | the strict, resumable HTTP/1.1 head reader |
| `policy.rs` | `AcceptPolicy`, `OriginPolicy`, `Decision`, `accept`, `Acceptor`, `Accepted`, `write_refusal` | server policy and the Tier 1 entry points |
| `extension.rs` | `extension` module | `Sec-WebSocket-Extensions` parsing |
| `close.rs`, `error.rs` | `CloseCode`, `CloseFrame`, `WsError`, `HandshakeError` | codes and errors |
| `keys.rs` | (private) | masking keys: OS batches or SHA-1 counter mode |
| `sha1.rs`, `base64.rs` | (private) | the handshake's fixed primitives |
| `blocking.rs` | `blocking` module (feature `std`) | a `Read + Write` adapter |

Shared HTTP grammar (tokens, lists, field values, `Origin`, `Host`) comes
from `parse-net`; the OS random source from `mod-rand`.

## Receiving

```text
 transport bytes
   |  feed(&[u8]) copies in   -or-   read_buf() + commit(n) (read straight in)
   v
 input buffer [pos .. filled]       grows from 4 KiB to Limits::input_buffer
   |  poll()
   |   1. decode the header (2 to 14 bytes): opcode, control rules, minimal length
   |   2. reserved bits; masking direction for the role
   |   3. frame budget, then message budget, from the header
   |   4a. control frame: wait until whole (at most 139 bytes), unmask in place;
   |       Ping -> queue the Pong (an unwritten one is replaced);
   |       Close -> parse, echo, Closed
   |   4b. single-frame data message already buffered: unmask in place,
   |       validate UTF-8 if text, lend a slice of the input (no copy)
   |   4c. otherwise stream into the reassembly buffer: binary as bytes;
   |       text validated as it arrives, a cut sequence carried to the next
   |       read, assembled into a String; deliver at FIN
   v
 Event<'_> borrowing the input or the reassembly buffer until the next poll
```

Each `poll` does at most the work of the bytes buffered (at most the input
buffer) and returns at most one event. A reassembly buffer never grows past
`max_message`, and reserves at most 1 MiB ahead of arrived bytes.

## Sending

```text
 send_text / send_binary / fragments / ping / pong / close / send_prepared
   | checks: not after a Close, not interleaved with another data message,
   |         argument rules, then the output budget (one size comparison)
   v
 output [out_pos .. len]   header written directly, then the payload;
   |                       a client masks in place with the next key
   | output() returns the unwritten slice
   | advance_output(n): drained -> cleared (shrunk past retain);
   |                    compacted when more than 64 KiB and half is written
   v
 transport
```

Automatic Pongs and Close frames may use 256 bytes above `max_output`, so a
flooded queue can always answer and close.

## State machines

Closing handshake:

```text
            close() sent                        peer Close received
  Open ─────────────────────▶ Closing ─────────────────────────────▶ Closed
   │ peer Close received (echo queued, code kept)                       ▲
   ├────────────────────────────────────────────────────────────────────┤
   │ protocol violation (Close with its code queued unless one was sent) │
   ├────────────────────────────────────────────────────────────────────┤
   │ EOF before the handshake completes (1006, nothing sent)            │
   ├────────────────────────────────────────────────────────────────────┤
   │ IdleTimeout (1001 queued), MessageTimeout (1008 queued),           │
   │ CloseTimeout (from Closing; nothing more sent), wipe()             │
   └────────────────────────────────────────────────────────────────────┘
```

`State` is derived, never stored: `Closed` if the writer failed or a Close
was received, `Closing` if a Close was sent, else `Open`.

Receive state (internal): idle; a frame in progress (kind, FIN, remaining
length, mask phase); a message in progress awaiting continuations. Control
frames are handled from either without disturbing the message.

Keepalive, on the caller's clock (`on_time(now)`): any input since the last
tick restarts the idle clock and clears an outstanding keepalive Ping; then
the close timeout (if this end sent Close), the idle timeout, the message
timeout (from the first tick that saw the message in progress), and the
ping interval, in that order. `next_deadline()` is the minimum of the armed
deadlines, so a driver sleeps until there is work. Times saturate, and a
clock that goes backwards counts as no time passing.

## Memory

| Buffer | Bound | Released |
|---|---|---|
| input | `input_buffer` (64 KiB; 256 B to 1 MiB) | `release_memory` |
| reassembly (binary bytes, or a text `String`) | the message, at most `max_message`, plus up to 1 MiB reserved ahead | after delivery when larger than `retain`; `release_memory` |
| output | `max_output` + 256 B; capacity up to twice that, plus 64 KiB before compaction | drained and larger than `retain`; `release_memory` |
| client key batch | 1 KiB (256 keys) | `release_memory` (refilled on the next send) |
| handshake record | one exact allocation (target, Host, Origin, protocols, extensions) | with the `ServerHandshake` |
| inline | `size_of::<Connection>()`, at most 512 bytes | never |

An idle connection after `release_memory` holds no heap. In steady state no
message allocates (checked with a counting allocator).

## Algorithms

- **Masking:** the key is rotated by the payload offset and widened to an
  8-byte word; the payload is XORed 8 bytes per step, then the tail byte by
  byte. Any offset is accepted.
- **UTF-8:** every byte is validated once with `core::str::from_utf8`. A
  streamed chunk is validated up to its last complete character; a cut
  sequence (at most 3 bytes) is checked as a prefix at once and completed by
  the next chunk, so an invalid byte fails the moment it arrives.
- **Head reading:** the resumable reader keeps its scan position, the start
  of the current line, and the previous byte; total work is linear in the
  head however it is cut.
- **Automatic Pong:** encoded when the Ping is read; if the previous
  automatic Pong is still last in the queue and none of it is written, it is
  replaced (RFC 6455 section 5.5.3 allows answering only the latest Ping).
- **Masking keys:** `Connection::client` reads 1 KiB from the OS
  cryptographic source per 256 keys and zeroes each key once used;
  `client_with_seed` derives keys with SHA-1 in counter mode over its seed.
- **Origin policy:** origins are parsed (RFC 6454) and compared as values:
  scheme and host ASCII case-insensitively, IP literals by value, ports
  after the scheme's default is filled in.
