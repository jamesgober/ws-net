<h1 align="center">
    <img width="90px" height="auto" src="https://raw.githubusercontent.com/jamesgober/jamesgober/main/media/icons/hexagon-3.svg" alt="Triple Hexagon">
    <br><b>CHANGELOG</b>
</h1>
<p>
  All notable changes to <code>ws-net</code> will be documented in this file. The format is based on <a href="https://keepachangelog.com/en/1.1.0/">Keep a Changelog</a>,
  and this project adheres to <a href="https://semver.org/spec/v2.0.0.html/">Semantic Versioning</a>.
</p>

---

## [Unreleased]

### Changed

- **Breaking:** `ClientHandshake::verify` returns a `Verified` (the
  selected subprotocol and the negotiated extensions) instead of the
  subprotocol alone, and `ClientHandshake::verify_head` returns
  `(Verified, usize)`. `verify_full` is removed: `verify` is what it was.
  The old forms dropped the negotiated extensions, so a client that
  offered permessage-deflate could not build its connection from them.
  Migration: `verify(..)?` becomes `verify(..)?.protocol`;
  `verify_full(..)` becomes `verify(..)`; from `verify_head`, the protocol
  is `.0.protocol` (`docs/API.md`, "Migrating from 0.9").
- `docs/API.md`: a "Tier 1 at a glance" table (accept, connect, receive,
  send, close, sans-IO and blocking) with a socket example; the README's
  quick start adds the blocking client and server.
- `Keepalive::new` (and so every connection) times a data message out
  after 60 s (`MessageTimeout`, Close 1008); it was off. A peer that
  starts a message and stops sending no longer holds the reassembly buffer
  for as long as the TCP connection lives. `with_message_timeout` raises
  it; `Duration::MAX` turns it off.
- The `feed` examples check the count `feed` returns (they dropped it with
  `let _ =`), and `feed`'s docs show the loop for a read larger than the
  input buffer.

### Fixed

From the independent review of 0.9.0; a regression test for each.

- A frame header claiming a large payload reserved up to 1 MiB of
  reassembly space before any payload arrived, so 14 bytes per connection
  held 1 MiB that `release_memory` could not free. Reassembly now grows
  only as payload bytes arrive (at most eight times what arrived, or the input buffer)
  (`tests/review.rs`).
- Buffers that held message bytes went back to the allocator unzeroed
  when freed or regrown in normal operation (a message or send over
  `retain`, a buffer doubling, `release_memory`, the compression engines
  dropped by `release_memory`), so `wipe` could not reach those copies.
  They now move to a new allocation and the old one is zeroed first; the
  one exception is compress-lib growing the buffer itself when a piece
  inflates to more than four times its size (`tests/wipe.rs`).
- Compressed text was checked as UTF-8 only once the whole message was
  inflated, so a bad first byte held up to `max_message` of output until
  the last fragment. It is now checked as it is inflated, every KiB of
  compressed input and at each frame's end, points that do not depend on
  how the input was split (`tests/deflate.rs`).
- The README said a client's masking keys and nonce come from the standard
  library's hasher keys (they come from the OS cryptographic source) and
  that the crate has no dependencies (it has no third-party ones), and
  that a browser handshake allocates once (`ServerHandshake::from_head`
  does; the Tier 1 `accept` allocates the response too).
- `interop/net-io` on net-io 0.7.0 (its reactor fix for a reader that lost
  its place on the starved list, and the output-buffer reuse); no source
  change. The 24-hour reactor soak runs on it.
- `interop/net-io` on net-io 0.7.1 (an idle TLS connection on the reactor
  gives back its buffers, as a plaintext one does); no source change.
- compress-lib 1.0.0 for feature `deflate`, its stable release (the
  `message` API unchanged since 0.7, no breaking change before its 2.0);
  no source change. The `deflate_message` 72-hour run starts again on it.
- The 24-hour socket soak on net-io's reactor (Linux, 500 clients, net-io
  0.7.0) passed: 3.70 billion messages, heap flat (131 MiB in the first
  hour, 128 MiB in the last), no connect retried.

---

## [0.9.0] - 2026-11-08

Beta: permessage-deflate (RFC 7692), the 1.0 API surface final in
`docs/API.md`, a fresh security review, and the 0.9 performance pass. The
API is designed as it will freeze; changes from here need a reason in
`docs/STABILITY-1.0.md`.

### Added

- permessage-deflate (RFC 7692), feature `deflate`, on compress-lib (first
  party, no dependencies, `no_std` + `alloc`): `DeflateConfig`,
  `DeflateParams`, `AcceptPolicy::with_deflate`,
  `ClientHandshake::with_deflate`, `Negotiated::deflate`,
  `PreparedMessage::with_deflate` and `compressed_len`. Negotiation in
  both roles with all four parameters and window bits 8 to 15; compressed
  sends by `SendOptions` and a minimum size (256 bytes); inflation into the
  reassembly buffer capped at `max_message` while it runs (1009), text
  validated once inflated; no context takeover unless configured.
- `WsError::InvalidCompressedData` (1007) for compressed data that is not
  valid DEFLATE.
- Autobahn TestSuite sections 12 and 13 (permessage-deflate) in CI, both
  roles; the `deflate_message` fuzz target; `tests/deflate.rs` with the
  RFC 7692 section 7.2.3 examples and property tests.
- compress-lib 0.7: inflation is linear however the input is split, a
  compressed message that ends inside a DEFLATE block (or keeps the
  `00 00 FF FF` tail RFC 7692 removes) fails with 1007, and `wipe` zeroes
  the compression windows.

- `Sender::send_text_with` and `send_binary_with`;
  `blocking::WebSocket::send_text_with`, `send_binary_with`, and
  `with_keepalive`.

### Changed

- A connection's timers start with the 5 s close timeout armed, without
  `with_keepalive` (the documented default, which only held once a
  keepalive was set): a peer that never answers the Close no longer holds
  a connection made by `accept`, `Acceptor`, or the `blocking` module.
- The input buffer is compacted only when half of it is read or when what
  is left cannot be parsed, not on every feed once full.
- `detach_message` returns `None` once input was fed, whatever the buffer
  did.
- A client fails a response whose `Upgrade` names anything but
  `websocket`.
- `ServerHandshake::response_fields` borrows the `Negotiated` it is given
  for as long as the fields live (the extension value is written there).
  Pass the decision's extensions; a temporary `&Negotiated::none()` kept
  past its statement must be bound first.
- `ServerHandshake::accept` and `write_response_with` write the negotiated
  `sec-websocket-extensions` field.
- A single-frame text message is validated once, not twice: small-message
  receive 14 to 24% faster than 0.8.0 on the hosted runners.
- Every rustdoc example runs: the `blocking` module's accept and connect
  examples talk over loopback instead of needing a server.
- `docs/API.md` final for the 1.0 surface; `docs/STABILITY-1.0.md`, the
  1.0 readiness note; the 0.9 security review in `docs/SECURITY.md`.
- All eleven fuzz targets, `deflate_message` included, ran clean for 32
  hours (`deflate_message` 25) before a host restart cut the 72-hour runs
  short; the 72-hour runs are restarted for 1.0 (`docs/SECURITY.md`).
- Sockets: the blocking pool on net-io ran 24 hours on Linux, both drivers
  4 hours on Windows, flat heap (`interop/net-io/tests/soak.rs`).

### Fixed

- `blocking::connect_with` built the client connection without the
  negotiated extensions.

---

## [0.8.0] - 2026-11-06

Alpha: ws-net end to end on real transports (net-io's two drivers, tls-net)
and against tungstenite on three platforms, so consumers can adopt it. No
breaking API change.

### Added

- `interop/net-io/`: ws-net as a net-io 0.6 `Session` (the mapping in
  `docs/INTEGRATION.md`), end-to-end tests on both drivers in CI on three
  platforms, the end-to-end echo benchmark against tungstenite (payloads
  to 64 KiB), and a socket-level soak with a counting allocator.
- `interop/tls/`: a ws-net client and server through two tls-net 0.5
  sessions in memory, with the close order checked.
- `docs/PLATFORM-NOTES.md`; a net-io section in `docs/INTEGRATION.md`.

- `tests/budget_audit.rs`: every heap growth site in `src/` names the
  budget that bounds it in a `// budget:` note (78 sites: `max_message`,
  `max_output`, `input_buffer`, the head limit, fixed sizes, and the
  caller's own arguments); a new site without one fails CI.
- `Stats::data_frames_in`, for the fragments-per-message and
  Pings-per-message ratios.

### Fixed

- A Ping, Pong, or Close whose payload arrived in pieces was counted in
  `frames_in` once per `poll` until it was whole (a Ping fed a byte at a
  time counted about 130 times), which could trip a frame-flood limit. A
  frame now counts once, and the split property test checks every counter.

### Changed

- `parse-net` 0.9.1. Extension parameters are read with its
  optional-value parameter parser, which replaces ws-net's own loop. Empty
  parameters (`permessage-deflate;`, `a;;b`) are now skipped instead of
  refused; everything accepted before is still accepted, with the same
  parameters.
- `docs/PERFORMANCE.md`: the end-to-end echo benchmark over net-io's
  reactor and blocking pool against tungstenite, on three platforms, and
  the cause of the Linux 1 MiB receive rows (buffer placement on the hosted
  runner; `bench-compare/examples/faults.rs` measures it).
- Small sends: the exact frame size is worked out only near the output
  budget, and each frame reserves once (client sends on Linux from 14% to
  4 to 8% behind 0.2.0).

---

## [0.7.0] - 2026-11-05

Hardening: ten fuzz targets run for 24 hours each, one attack test per
threat, a 4-hour soak with 100,000 connection pairs, a big-endian check
under Miri, a security review with twelve fixes, and
`docs/SECURITY.md`.

### Added

- `fuzz/`: cargo-fuzz targets for the frame header, the connection in both
  roles under small, default, and lifted budgets (split invariance, valid
  output, memory bounds), API call sequences (a refused call changes
  nothing, state only moves forward), the server and client heads (the
  resumable reader equals the one-shot reader), extension parsing, the
  Origin policy, handshake keys, and a differential target against
  tungstenite 0.30.0. `fuzz/run-all.sh` runs them in parallel and replays
  WSL clock-step timeouts. A CI job builds them and runs each for 30
  seconds.
- `tests/attacks.rs`: one test per threat T-1 to T-29 (T-19 to T-21 wait for
  permessage-deflate).
- `tests/soak.rs`: in-memory connection pairs under a simulated clock with a
  counting allocator (ignored by default; `WS_NET_SOAK_PAIRS`,
  `WS_NET_SOAK_SECS`).
- `docs/SECURITY.md`: the threat model, every defense with its test and
  cost, what is not defended, the conformance and fuzzing record.

### Changed

- A server handshake refuses a request target that is not origin-form (a
  path starting with `/`, not `//`): absolute-form, authority-form, and `*`
  are `MalformedHead`. RFC 6455 section 4.1 sends the resource name; an
  absolute-form target carries an authority that would override the `Host`
  the policy checked.
- The output headroom above `max_output` for automatic Pongs and Close
  frames is 262 bytes (was 256), the size of a client's masked Pong and
  Close together.
- After `Closed` with output unwritten (or a client waiting for the
  server's EOF), the close timeout stays armed: `next_deadline` reports it
  and `on_time` sets `should_close_transport` when it passes.

### Fixed

- `should_close_transport` stayed false after a close timeout while the
  unanswered Close was still queued; it is now true at once (the peer
  stopped reading). Found by the new close-hang attack test.
- A connection that failed with output unwritten (an idle timeout, a
  protocol error) had no timer left, so a peer that never read kept the
  transport open forever.
- A keepalive Ping refused by a full output left the deadline in the past,
  so a timer loop woke on every tick.
- A client's full output could not take both its masked automatic Pong and
  a Close (131 bytes each, 262 in all, above the 256-byte headroom).
- A Text message that failed UTF-8 validation was still marked as lent, so
  `detach_message` handed out the invalid bytes as Text.
- A multi-frame send that failed part way (a masking-key refill error)
  left the first frames queued; it now changes nothing. A refused Close no
  longer marks the Close as sent.
- Streamed text reserved room for the new chunk but not the carried
  partial character, so the reservation could fall short and reallocate.
- Server extension offers spread over several fields with empty list
  elements were stored so that `extensions()` could fail to parse them
  again; only the non-empty elements are kept.

### Security

- `wipe` zeroes each buffer's whole allocation, spare capacity included
  (bytes a compaction or `clear` left behind).
- `ServerHandshake`'s `Debug` prints the path without the query string,
  and `ClientHandshake`'s prints header names only: a query or an
  `Authorization` header can carry a credential.
- `HeadReader` keeps its error until `reset`, instead of resuming the scan
  and parsing what follows a bad head as a fresh one.
- `accept`'s documentation warns that the Tier 1 policy accepts any `Host`,
  so a service on a private address is open to DNS rebinding without
  `AcceptPolicy::with_hosts`.

---

## [0.6.0] - 2026-11-04

Optimisation: measured against tungstenite 0.30.0 and against 0.2.0 on
hosted Linux, macOS, and Windows runners, with every hot path rechecked.
The numbers are in `docs/PERFORMANCE.md`.

### Added

- `WsError::AllocationFailed` (1011): reassembly memory is reserved with
  `try_reserve_exact`, so allocator exhaustion fails the connection instead
  of aborting the process.
- `bench-compare/`: ws-net against tungstenite on the same bytes (not
  published, not in ws-net's dependency graph), and a benchmark workflow
  on hosted runners (`.github/workflows/bench.yml`).
- Benchmark `send_100k/client_masked_os`; `docs/PERFORMANCE.md`.
- Counting-allocator checks: one allocation per handshake; none for
  fragmented messages, Ping floods, idle keepalive ticks, prepared sends,
  or the Close echo.

### Changed

- A streamed text message is validated once per byte: a sequence cut at a
  read boundary waits for the next read, and the message is assembled from
  validated pieces, so delivering it no longer validates it again.
  Receiving 1 MiB of text is about 50% faster than in 0.2.0.
- `Connection::client` draws masking keys from the OS cryptographic source
  in 1 KiB batches (256 keys), about 30 times cheaper per key than SHA-1
  counter mode over an OS seed; `client_with_seed` keeps SHA-1 counter
  mode. The batch is freed by `release_memory` and zeroed by `wipe`.
- The server handshake record is one allocation (target, `Host`, `Origin`,
  protocols, and extensions in one buffer).
- The frame writer writes headers directly on the send path.
- `PreparedMessage`'s `Debug` prints lengths only, never the payload.
- permessage-deflate moved out of 1.0 to 1.1: no first-party DEFLATE crate
  exists.

### Security

- Allocation failure under memory pressure no longer aborts the process
  (`AllocationFailed`, 1011).

---

## [0.5.0] - 2026-11-04

Feature complete, except permessage-deflate, which waits for a first-party
DEFLATE crate and moves to 0.6. The Autobahn TestSuite now runs in CI in
both roles, and every case of sections 1 to 10 passes strictly.

### Added

- `Connection::with_extensions` and `negotiated`; `ClientHandshake::connection`
  (feature `std`) and `connection_with_seed`; `Verified::none`.
- `SendOptions` (`new`, `uncompressed`, `compressed`, `is_uncompressed`) and
  `Connection::send_text_with`, `send_binary_with`. No effect on the wire
  until compression exists; `uncompressed()` keeps its meaning then.
- `FrameHeader::with_rsv`.
- The Autobahn TestSuite (`crossbario/autobahn-testsuite:25.10.1`) in CI for
  the server role (`fuzzingclient` against `examples/autobahn_server`) and
  the client role (`fuzzingserver` with `examples/autobahn_client`), with a
  strict report check (`autobahn/check.py`): 301 cases, 0 failures in each
  role; 7.1.6, 7.13.1, and 7.13.2 are informational.

### Changed

- Connections built by `accept`, `ServerHandshake::accept`, and
  `ClientHandshake::connection` carry what the handshake negotiated.
- permessage-deflate (feature `deflate`) moved from 0.5 to 0.6: no
  first-party raw DEFLATE crate exists yet.

---

## [0.4.0] - 2026-11-04

Extended: everything a server with many connections needs around the
protocol. Output budget, memory release, keepalive and timeouts on the
caller's clock, split borrows and detaching messages, counters and wiping,
owned and prepared messages, extension parsing, Host allowlists, the
blocking adapter, and the http-net integration.

### Added

- `Limits::with_max_output` (32 MiB default) and `WsError::OutputFull`: a
  send that would exceed the pending-output budget is refused and changes
  nothing; automatic Pong and Close frames use a 256-byte headroom.
  `Limits::with_input_buffer` (256 B to 1 MiB), `with_retain` (64 KiB), and
  `DEFAULT_*` constants. `Connection::buffered_output`.
- `Keepalive` (ping interval, idle, close, and message timeouts), `Millis`,
  `Tick`; `Connection::with_keepalive`, `on_time`, `next_deadline`,
  `should_close_transport`; `WsError::IdleTimeout` (1001),
  `CloseTimeout` (1006, not sent), `MessageTimeout` (1008).
- `Connection::poll_split` and `Sender`; `detach_message` and
  `MessageKind`; `stats` and `Stats`; `wipe`; `release_memory`,
  `memory_in_use`.
- `Message`, `Event::to_message`, `Connection::send`; `PreparedMessage`
  and `send_prepared`.
- The `extension` module (`parse`, `Offers`, `Offer`, `Param`,
  `Negotiated`, `MAX_OFFERS`, `MAX_PARAMS`); `ServerHandshake::extensions`,
  `MAX_EXTENSION_OFFERS`; `HandshakeError::InvalidExtensions`;
  `ClientHandshake::verify_full`; `Verified::extensions` and
  `Decision::extensions`.
- `AcceptPolicy::with_hosts` and `HandshakeError::HostRefused` (403, DNS
  rebinding), `with_secure`, `with_keepalive`; `write_refusal` (403, 429,
  503 with `retry-after`).
- `ServerHandshake::write_response_with` (extra response headers),
  `response_fields` and `ResponseFields` (the `101` field list for an HTTP
  layer); `ClientHandshake::with_header`.
- `FrameHeader::encode_to_slice`; `CloseCode::is_private_use`,
  `is_registered`, `is_reporting_only`.
- The `blocking` module (feature `std`): `accept`, `accept_with`,
  `connect`, `connect_with`, `WebSocket` (`from_upgraded`, `read`,
  `send_text`, `send_binary`, `send`, `ping`, `close`, `flush`, accessors),
  `Error`.
- `docs/INTEGRATION.md`; examples `keepalive`, `broadcast`,
  `blocking_echo`, `blocking_client`, `http_net_upgrade`.
- Tests: keepalive, output budget and headroom, detach, prepared messages,
  counters, wiping, memory per connection with a counting allocator,
  the blocking adapter over localhost, http-net's sans-IO and blocking
  upgrade (http-net is a dev-dependency only), extension and extra-header
  edge cases; properties for the output bound, detach, and keepalive
  deadlines. Benches `handshake/head_reader_bytewise`,
  `broadcast/prepared_10k`, `keepalive/on_time_idle`,
  `flood/empty_continuations`.

### Changed

- `Limits` moved to its own module (still `ws_net::Limits`).
- The automatic Pong is encoded into the output when the Ping is read, not
  on the next `output()` call, with the same rule: an unwritten Pong at the
  end of the queue is replaced by the next. Bytes on the wire are the same.
- A reassembly buffer is shrunk after delivery when it grew past `retain`
  (64 KiB; it was 1 MiB), and never grows past the message budget.
- The output buffer is released when drained and larger than `retain`.

### Security

- Slow consumers: the output budget bounds what a peer that stops reading
  can make this end hold.
- Slow messages and idle connections: the message and idle timeouts end
  them; a peer that never answers a Close is cut off by the close timeout.
- DNS rebinding: `AcceptPolicy::with_hosts`.

---

## [0.3.0] - 2026-11-04

Design lock and core corrections: a one-call server accept with the
same-origin policy, a resumable head reader with linear work, masking
seeds from the OS cryptographic random source, and the shared HTTP grammar
from `parse-net`. The whole 1.0 API is now listed in `docs/API.md` with the
version each item lands in.

### Added

- `accept(bytes)`, the Tier 1 server entry point: validates the request,
  applies the same-origin policy, writes the `101`, and returns an
  `Accepted { response, connection, consumed, handshake }` whose server
  `Connection` already holds the frames that followed the head.
- `Acceptor` (`new`, `with_policy`, `accept`): the resumable form, for a
  head read in pieces.
- `AcceptPolicy` (`new`, `with_origins`, `with_protocols`,
  `require_protocol`, `with_limits`, `origins`, `limits`, `check`) and
  `Decision`; `ServerHandshake::accept(policy, out)`.
- `OriginPolicy` (`same_origin`, `allow`, `any_origin`, `allow_missing`,
  `permits`): RFC 6454 origin comparison through `parse-net`, never by
  substring; `null` and non-web schemes never match.
- `HeadReader` (`new`, `server`, `client`, `reset`) and `Verified`: a
  resumable strict head reader whose total scanning work is linear in the
  head.
- `HandshakeError::UnexpectedBody`, `OriginRefused` (403),
  `ProtocolRequired`, `RandomUnavailable`; `WsError::RandomUnavailable`.
- `Connection::try_client`, `ClientHandshake::try_new`;
  `Connection::is_open`, `can_send`.
- `Limits::with_send_frame` and `send_frame`: the outgoing frame size,
  separate from the incoming frame budget (it follows the budget until set,
  so existing behaviour is unchanged).
- `ServerHandshake::select_protocol`, `ServerHandshake::MAX_PROTOCOLS`.
- `frame::Opcode::is_data`, `frame::MAX_HEADER_LEN`,
  `MAX_CONTROL_PAYLOAD`, `MAX_PAYLOAD_LEN`; `VERSION`.
- Example `accept_policy`; `echo_server` now accepts through an `Acceptor`.
- `tests/attacks.rs` (cross-site hijacking, smuggled bodies, slow heads,
  Pong and frame floods, close-reason log injection, HTTP bytes after the
  upgrade); every protocol case run in pieces of every size from 1 to 15
  bytes and split in two at every point; properties for `HeadReader`
  against `from_head` and `OriginPolicy` against a reference; a
  `size_of::<Connection>()` bound of 512 bytes.
- `dev/PLAN.md` with the requirements and the decision log; CI builds the
  docs with default features too, and checks a 32-bit target.

### Changed

- Tokens, OWS, field-value checks, and comma lists come from `parse-net`
  0.9 (first party, no dependencies of its own). Lists are RFC 9110 lists:
  a comma inside a quoted string does not split, and a value that does not
  parse holds nothing, so `Upgrade: websocket, "x` is not an upgrade. The
  browser handshake benchmark is 12.7% faster.
- Masking-key seeds and nonces come from `mod-rand`'s OS tier (feature
  `std`) instead of `RandomState`. If the OS source fails,
  `Connection::client` returns a connection that refuses every send and
  `ClientHandshake::new` one that refuses to write its request.
- `HandshakeError::status` and `write_response` cover 403 and 500.
- Test names follow `test_<subject>_<condition>_<expected>`.

### Security

- An upgrade request that declares a body (`Transfer-Encoding`, or any
  `Content-Length` but a lone `0`) is refused: the bytes after the head are
  frames, and a front proxy that read a body would disagree about where
  they start (request smuggling).
- The Tier 1 path refuses pages from other origins (cross-site WebSocket
  hijacking, CWE-1385) by default.
- A head sent one byte per read no longer costs quadratic scanning work
  when read through `HeadReader` or `Acceptor` (the class of
  CVE-2023-43669).
- The 0.2 masking seed was documented as OS-random but came from
  `RandomState` (one OS draw per thread, a counter, and the clock); it now
  comes from the OS cryptographic random source.

---

## [0.2.0] - 2026-10-12

The foundation: a complete sans-IO WebSocket (RFC 6455) engine. The opening
handshake (standalone over raw bytes, or behind an HTTP layer), frame
parsing and serialization, masking, fragmentation with incremental UTF-8
validation, ping/pong, and the closing handshake, with every size bounded
and no dependencies.

### Added

- `Connection`: one connection as a state machine, server or client role.
  Bytes in through `feed` (or `read_buf` + `commit`) and `feed_eof`;
  `poll` returns `Event::Text`, `Binary`, `Ping`, `Pong`, `Close`,
  `NeedInput`, or `Closed`; `send_text`, `send_binary`,
  `send_text_fragment`, `send_binary_fragment`, `send_ping`, `send_pong`,
  and `close` queue frames; `output` + `advance_output` drain them.
  `Connection::client` seeds masking keys from the OS (feature `std`);
  `client_with_seed` takes a seed (`no_std`, reproducible tests).
- Every RFC 6455 receive rule enforced, each failure closing with the right
  code: masking direction per role, RSV bits, reserved opcodes, control
  frames fragmented or over 125 bytes, payload lengths not minimally
  encoded (refused, by policy) or with the 64-bit high bit set,
  continuation order with control frames interleaved, UTF-8 validated
  incrementally across fragments (an invalid byte fails at once, 1007),
  Close payload, status code, and UTF-8 reason.
- `Limits`: frame (default 1 MiB) and message (default 16 MiB) budgets,
  checked from frame headers before any payload is read (1009).
  Outgoing messages larger than the frame budget are split.
- Automatic replies: a Pong for every Ping, the peer's Close echoed with its
  code; no frame may be sent after a Close.
- `ServerHandshake`: `from_head` (raw request bytes through a strict,
  bounded HTTP/1.1 head reader, 16 KiB `MAX_HEAD`) and `from_request`
  (method, target, and `(name, value)` fields, the shape `http-net`
  yields); `target`, `host`, `origin`, `protocols`, `accept_key`; and
  `write_response` with subprotocol selection.
- `ClientHandshake`: `new` / `with_nonce`, `with_protocols`,
  `with_origin`, `key`, `write_request`, `verify`, `verify_head`.
- `HandshakeError` with `status` (400, 426, 431) and `write_response` for
  the refusal (including `sec-websocket-version: 13` on 426).
- `accept_key` and `AcceptKey`; `CloseCode` (named codes, `is_sendable`);
  `CloseFrame`; `WsError` with `close_code`; `Role`; `State`.
- `frame` module: `Opcode`, `FrameHeader` (`decode`, `encode`,
  `encoded_len`), `apply_mask` (eight bytes at a time, any offset).
- Private SHA-1 (RFC 3174) and strict canonical base64 (RFC 4648) for the
  handshake, until the owner's crypto and codec libraries provide them.
- Examples: `sans_io` (both ends in memory) and `echo_server` (a
  localhost echo server over `std::net` with no HTTP library).
- Tests: 111 Autobahn-style cases as data, closing-handshake tests, socket
  echo tests (including a protocol failure and an Origin refusal),
  handshake tests over raw heads, review regression tests, and property
  tests for every invariant in `dev/DIRECTIVES.md` section 4. Criterion
  benchmarks at 100,000-message scale.

### Fixed

Found by the adversarial review before release; each has a regression test.

- Usage errors (a Ping over 125 bytes, an unsendable close code, a close
  reason over 123 bytes) reported a close code as if the connection had
  failed. They are now `WsError::InvalidArgument` with no close code, and
  the connection is unchanged. `WsError::CloseReasonTooLong` is gone.
- `apply_mask` with an offset near `usize::MAX`, and `commit` /
  `advance_output` with very large counts, panicked on overflow in debug
  builds.
- The echo server example (and the socket test's loop) returned on a
  protocol error before sending the queued Close frame, so the peer never
  learned the close code.

### Security

- With the budgets lifted (`u64::MAX`), a 14-byte header announcing a
  terabyte made the connection reserve that much memory up front and abort
  the process. Reassembly now reserves at most 1 MiB ahead of the bytes
  that have arrived.
- A peer that sent Pings but never read could grow the output queue without
  bound (one Pong per Ping). An unwritten automatic Pong at the end of the
  output is now replaced by the next one.
- The handshake now exposes `Origin` and `Host` for the server's policy
  (cross-site WebSocket hijacking and DNS-rebinding defenses), and refuses
  a request with two `Origin` or `Host` fields rather than pick one.

---

## [0.1.0] - 2026-10-08

Initial scaffold and repository bootstrap. No domain logic yet: this release establishes the structure, tooling, and quality gates the implementation will be built on.

### Added

- `Cargo.toml` with crate metadata, Rust 2024 edition, MSRV 1.85.
- Dual `Apache-2.0 OR MIT` license files.
- `README.md`, `CHANGELOG.md`, and a documentation skeleton.
- `REPS.md` compliance baseline.
- `.github/workflows/ci.yml` CI matrix; `deny.toml`, `clippy.toml`, `rustfmt.toml`.
- `dev/DIRECTIVES.md` and `dev/ROADMAP.md` (committed engineering standards + plan).

[Unreleased]: https://github.com/jamesgober/ws-net/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/jamesgober/ws-net/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/jamesgober/ws-net/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/jamesgober/ws-net/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/jamesgober/ws-net/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/jamesgober/ws-net/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/jamesgober/ws-net/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/jamesgober/ws-net/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jamesgober/ws-net/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesgober/ws-net/releases/tag/v0.1.0
