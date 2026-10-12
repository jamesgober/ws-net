# ws-net - Roadmap

> Path from scaffold to a stable 1.0. Hard parts are front-loaded; each phase has hard exit criteria.
> Master plan: C:/Dev/libraries/Rust/lang-collection/_lexersketch/ROADMAP.md and NEW-LIBS.md
>
> **Anti-deferral rule:** no listed hard task moves to a later phase unless this file records the move and the reason.

## v0.1.0 - Scaffold (DONE)
Compiles, CI green, structure correct, no domain logic.
- [x] Manifest, README, CHANGELOG, REPS, dual license, CI, deny, clippy, rustfmt, DIRECTIVES, ROADMAP.

## v0.2.0 - Foundation (DONE)
- [x] Handshake (SHA-1 + base64 implemented in-crate until the owner's crypto library lands), framing, masking, fragmentation, ping/pong, close; Autobahn-style cases as data.

Delivered:
- `Connection` (sans-IO, server and client roles): `feed` / `read_buf` +
  `commit` / `feed_eof` in, `poll` -> `Event` out, `send_text` /
  `send_binary`, `send_text_fragment` / `send_binary_fragment`, `send_ping` /
  `send_pong`, `close`, `output` + `advance_output`; `Limits` (1 MiB frames,
  16 MiB messages by default, Studio's budgets), `Role`, `State`, `Event`.
- Every RFC 6455 receive rule: masking direction per role, RSV bits,
  reserved opcodes, control frames fragmented or over 125 bytes (including
  any control frame using an extended length field), payload lengths not
  minimally encoded or with the 64-bit high bit set, fragmentation order
  with control frames interleaved, UTF-8 validated incrementally across
  fragment boundaries (fail-fast), Close payload, code, and reason rules.
  A violation fails the connection with the right close code (1002, 1007,
  1009; 1006 reported, never sent).
- Policy for non-minimal length encodings: **refused** (1002). RFC 6455
  section 5.2 says the minimal number of bytes MUST be used; accepting both
  forms would give one frame two encodings.
- Budgets checked from frame headers before any payload is read;
  reassembly reserves at most 1 MiB ahead of arrived bytes even with the
  budgets lifted; the input buffer is capped at 64 KiB; an unwritten
  automatic Pong at the end of the output is replaced by the next one.
- Closing handshake: automatic echo of the peer's Close (code kept),
  automatic Pong, no sends after Close (`InvalidState`), refused calls
  (`InvalidArgument`) that leave the connection unchanged.
- Opening handshake: `ServerHandshake::from_head` (raw bytes, strict
  bounded HTTP/1.1 head reader, 16 KiB) and `from_request` (method, target,
  `(name, value)` fields from an HTTP layer); exposes `target`, `host`,
  `origin`, offered `protocols`; `write_response` with subprotocol
  selection; `HandshakeError::write_response` for refusals (400, 426 with
  `sec-websocket-version: 13`, 431). `ClientHandshake` (`new`,
  `with_nonce`, `with_protocols`, `with_origin`, `write_request`, `verify`,
  `verify_head`). `accept_key`, `AcceptKey`.
- `frame` module: `Opcode`, `FrameHeader` (`decode` / `encode` /
  `encoded_len`), `apply_mask` (8 bytes at a time, any offset).
- Private SHA-1 (RFC 3174 vectors) and strict canonical base64 (RFC 4648
  vectors); client masking keys from SHA-1 in counter mode over an
  OS-seeded secret.
- Tests: 111 Autobahn-style cases as data (each run whole, byte by byte,
  and in 7-byte pieces), closing-handshake and socket echo tests,
  regression tests from the adversarial review, properties for every
  DIRECTIVES section 4 invariant; criterion benches at 100k-message scale;
  examples `sans_io` and `echo_server`.

Dependency wiring (decided here, recorded per the anti-deferral rule):
- **No runtime dependencies.** SHA-1 and base64 are private modules
  (`src/sha1.rs`, `src/base64.rs`): the owner's crypto library
  (crypt-collection) has no SHA-1 yet, and `wire-codec` 1.0 has no base64.
  Swap each in, without an API change, when it is published.
- **http-net: composed, not depended on.** `ServerHandshake::from_request`
  takes `(method, target, headers)` in exactly the shape `http-net`'s
  `RequestHead` yields (`method_str()`, `target()`, `headers()` items of
  `(&str, &[u8])`), and `ClientHandshake::verify` takes `ResponseHead`'s
  `status()` and `headers()`, so the two compose with no glue and ws-net
  stays usable behind any HTTP layer. http-net 0.2 is not on crates.io yet
  (path dependencies are not allowed), so the standalone raw-head path
  (`from_head`, `verify_head`) carries the examples and socket tests. **Move
  (reason: unpublished dependency):** an example and an integration test
  over http-net's upgrade hand-off (`ServerConn::into_upgraded`, as a
  dev-dependency) land in v0.5.0, once http-net 0.2 is published.
- Masking-key seeding uses the standard library's OS-seeded `RandomState`
  under `std`, and a caller seed without it; the owner's random library
  replaces it when published.

## v0.5.0 - Implementation
- Note (coordinator, 2026-10-12): permessage-deflate stays an optional library feature for other consumers; LexerSketch Studio never negotiates it (STUDIO.md §6.6, by decision). http-net 0.2.0 is now on crates.io, so the composition example and integration test can land here as a dev-dependency.
- [ ] permessage-deflate (with the owner's DEFLATE library), backpressure helpers.
- [ ] http-net upgrade example + integration test (moved from v0.2.0: http-net 0.2 unpublished; see above).

## v0.9.0 - Hardening
- [ ] Fuzzing; full Autobahn conformance as a dev-only oracle.

## v1.0.0 - Stable
- [ ] Frozen after Studio ships on it (D18).
