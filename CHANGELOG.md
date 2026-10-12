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

### Added

### Changed

### Fixed

### Security

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

Initial scaffold and repository bootstrap. No domain logic yet &mdash; this release establishes the structure, tooling, and quality gates the implementation will be built on.

### Added

- `Cargo.toml` with crate metadata, Rust 2024 edition, MSRV 1.85.
- Dual `Apache-2.0 OR MIT` license files.
- `README.md`, `CHANGELOG.md`, and a documentation skeleton.
- `REPS.md` compliance baseline.
- `.github/workflows/ci.yml` CI matrix; `deny.toml`, `clippy.toml`, `rustfmt.toml`.
- `dev/DIRECTIVES.md` and `dev/ROADMAP.md` (committed engineering standards + plan).

[Unreleased]: https://github.com/jamesgober/ws-net/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/jamesgober/ws-net/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesgober/ws-net/releases/tag/v0.1.0
