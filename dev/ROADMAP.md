# ws-net - Roadmap

> Path from scaffold to a stable 1.0. Hard parts are front-loaded; each phase has hard exit criteria.
> The plan behind it, with requirement ids and the decision log, is `dev/PLAN.md`.
>
> **Anti-deferral rule:** no listed hard task moves to a later phase unless this file records the move and the reason.

Milestones follow the library standard: 0.3 core, 0.4 extended, 0.5 feature complete, 0.6 optimisation, 0.7 hardening, 0.8 alpha, 0.9 beta, 1.0 stable. No series is skipped.

Recorded moves (each with its reason):

1. **Design lock in 0.3, not 0.2.** 0.2.0 shipped as "Foundation" before the full API was written down, and a published version cannot be re-cut. The lock happens in 0.3 with the core corrections.
2. **http-net integration test: 0.5 to 0.4.** It left 0.2.0 because http-net was unpublished; http-net is published now (0.9.2), so it belongs with the other composition work in 0.4.
3. **Full Autobahn TestSuite: 0.9 to 0.7.** Conformance is part of hardening; 0.9 is the beta.
4. **permessage-deflate depends on an unpublished crate.** It stays in 0.5 if the first-party compression crate (raw DEFLATE, sans-IO, no dependencies, no `unsafe`) is published by then; otherwise it moves to 0.6, and at the latest out of 1.0 to 1.1, each move recorded here with that reason. Checked 2026-11-04: no such crate exists yet.

## v0.1.0 - Scaffold (DONE)
Compiles, CI green, structure correct, no domain logic.
- [x] Manifest, README, CHANGELOG, REPS, dual license, CI, deny, clippy, rustfmt, DIRECTIVES, ROADMAP.

## v0.2.0 - Foundation (DONE)
- [x] Handshake (SHA-1 + base64 in-crate), framing, masking, fragmentation, ping/pong, close; Autobahn-style cases as data.

Delivered: `Connection` (sans-IO, both roles) with every RFC 6455 receive rule and its close code; budgets checked from frame headers; reassembly reservation capped at 1 MiB; automatic Pong (latest replaces an unwritten one) and Close echo; `ServerHandshake` (`from_head`, `from_request`), `ClientHandshake`, `HandshakeError` refusals (400, 426, 431); the `frame` module; 111 Autobahn-style cases as data, property tests for every invariant, criterion benches at 100k-message scale. Policy recorded then: non-minimal length encodings are refused (1002).

## v0.3.0 - Design lock and core corrections
- [x] parse-net 0.9 for the shared RFC 9110 grammar: tokens, OWS, field-value checks, comma lists (quote- and comment-aware, fail closed).
- [ ] `dev/PLAN.md` with the requirements and the decision log; `docs/API.md` rewritten to the whole 1.0 API, each item with the version it lands in (the design lock).
- [ ] Tier 1 server accept: `accept(bytes)`, `Acceptor` (resumable, linear scanning), `Accepted { response, connection, consumed, handshake }`.
- [ ] `HeadReader`: resumable strict head reader for both roles; total scan work linear in the head (closes the slow-head CPU amplification, same class as CVE-2023-43669).
- [ ] `AcceptPolicy` (`new`, `with_origins`, `with_protocols`, `require_protocol`, `with_limits`, `check`) and `OriginPolicy` (`same_origin`, `allow`, `any_origin`, `allow_missing`, `permits`), using parse-net's `Origin`; same-origin is the Tier 1 default; `ServerHandshake::accept` and `select_protocol`.
- [ ] `HandshakeError::UnexpectedBody` (refuse `Transfer-Encoding` and a non-zero `Content-Length` on the upgrade), `OriginRefused` (403), `ProtocolRequired`.
- [ ] `Limits::with_send_frame` (outgoing frame size separate from the incoming budget).
- [ ] Masking seeds and handshake nonces from the OS CSPRNG through `mod-rand` 1.0 (feature `std`); fallible `try_client` and `ClientHandshake::try_new`; the infallible forms fail closed.
- [ ] `Connection::is_open`, `can_send`; `Opcode::is_data`; `frame::MAX_HEADER_LEN`, `MAX_CONTROL_PAYLOAD`, `MAX_PAYLOAD_LEN`; `ServerHandshake::MAX_PROTOCOLS`; `pub const VERSION`.
- [ ] Bounded work per `poll` stated and tested.
- [ ] Tests: CSWSH, smuggling body, byte-at-a-time head, Pong flood, close-reason log injection, HTTP bytes after the upgrade; every chunk size 1 to 15 over the data cases; test names in the `test_<subject>_<condition>_<expected>` form; `size_of::<Connection>()` at most 512 bytes; an `i686` build check.
- [ ] CI documents with default and all features; `.editorconfig`; em dashes out of `docs/release/v0.2.0.md`; DIRECTIVES wording ("first-party crates by published version").
- [ ] Example `accept_policy`.

Exit: every item implemented, documented with an example, and tested; local gate and CI green on all platforms.

## v0.4.0 - Extended
- [ ] Output budget `Limits::with_max_output` (default 32 MiB) with `WsError::OutputFull` and 256 bytes of headroom kept for automatic Pong and Close; `buffered_output`.
- [ ] Memory: `Limits::with_input_buffer`, `with_retain`, `release_memory`, `memory_in_use`; the per-connection memory formula confirmed by counting-allocator peaks.
- [ ] Keepalive: `Millis`, `Keepalive` (ping interval, idle, close, message timeouts), `Tick`, `on_time`, `next_deadline`; `IdleTimeout`, `CloseTimeout`, `MessageTimeout`; `should_close_transport`.
- [ ] `poll_split` and `Sender`; `detach_message` and `MessageKind`; `Stats`; `wipe`.
- [ ] Owned `Message`, `Event::to_message`, `Connection::send`.
- [ ] `PreparedMessage` and `send_prepared` (encode once, broadcast).
- [ ] `extension` module: `Sec-WebSocket-Extensions` parsed with parse-net (`list`, then parameters), `Offer`, `Param`, `Negotiated`, at most 16 offers of 16 parameters; `ServerHandshake::extensions`; `ClientHandshake::verify_full`.
- [ ] Host allowlist `AcceptPolicy::with_hosts` (RFC 3986 authority through parse-net), `HostRefused`; `with_secure`; `write_refusal` (403, 429, 503 with `retry-after`).
- [ ] `write_response_with`, `response_fields` (the 101 field list for an HTTP layer); `ClientHandshake::with_header`; `FrameHeader::encode_to_slice`; `CloseCode` classification.
- [ ] `blocking` module (feature `std`): `accept`, `accept_with`, `connect`, `connect_with`, `WebSocket::{from_upgraded, read, send_*, ping, close, flush}`.
- [ ] http-net integration test (dev-dependency): the sans-IO upgrade and the blocking `Upgraded` hand-off; example `http_net_upgrade`; examples `keepalive`, `broadcast`, `blocking_echo`, `blocking_client`.
- [ ] `docs/INTEGRATION.md`.

Exit: all items tested; memory formula confirmed; http-net test green.

## v0.5.0 - Feature complete
- [ ] permessage-deflate behind the non-default `deflate` feature (RFC 7692): negotiation both roles, all four parameters, window bits 8 to 15; decompression bounded during inflation; per-message `SendOptions`; context takeover memory counted; prepared messages with a compressed form. Needs the compression crate (move 4 above).
- [ ] `Connection::with_extensions`, `negotiated`; `ClientHandshake::with_deflate`, `connection`; `FrameHeader::with_rsv`.
- [ ] Preliminary Autobahn run, sections 1 to 10 (and 12, 13 with deflate), both roles.

Exit: every P0 to P2 API item exists; no API addition after this version except fixes found by testing.

## v0.6.0 - Optimisation
- [ ] Competitor harness outside the crate's dependency graph: tungstenite, fastwebsockets, tokio-websockets, ratchet; frame-level receive, send, handshake.
- [ ] 32-byte masking lanes (autovectorised, no `unsafe`); UTF-8 ASCII fast path; masking-key generator measured (SHA-1 counter mode against bulk OS refills).
- [ ] Single-allocation handshake record; counting-allocator suite (no allocation per message in steady state); `try_reserve` on every growth.
- [ ] `docs/PERFORMANCE.md` with Linux, macOS, and Windows numbers.

Exit: no per-message allocation; NFR targets met or each shortfall published with its cause.

## v0.7.0 - Hardening
- [ ] cargo-fuzz targets: frame header, connection (both roles), connection API sequences, server and client heads, extension parsing, Origin policy, base64; 24 hours each; differential fuzzing against tungstenite.
- [ ] Autobahn TestSuite in CI for both roles (strict: every case of sections 1 to 10 OK); `examples/autobahn_server`, `autobahn_client`.
- [ ] `tests/attacks.rs`: one test per threat in the plan.
- [ ] Soak: 100,000 in-memory connection pairs for 4 hours with no memory growth beyond the configured bounds.
- [ ] Big-endian check; tls-net example if tls-net is published (otherwise recorded and moved).
- [ ] `docs/SECURITY.md`.

Exit: Autobahn strict pass, fuzz 24 hours clean, soak 4 hours, every threat test passing.

## v0.8.0 - Alpha
- [ ] Real consumers end to end: LexerSketch Studio with keepalive; serve-net's WebSocket upgrade route; a gateway consumer using the policy, counters, wipe, and close-on-revocation contract.
- [ ] Socket-level soak with net-io.
- [ ] `docs/ARCHITECTURE.md`, `docs/PLATFORM-NOTES.md`.

Exit: two consumers end to end with no open P0 or P1 defect; API changes from feedback recorded in the decision log.

## v0.9.0 - Beta
- [ ] API review against the plan and the parity matrix; every rustdoc example runnable; `docs/API.md` final.
- [ ] Fuzzing 72 hours per target; soak 24 hours.

### v0.9.x - Pre-1.0 polish (before any release candidate)
- [ ] Revisit every accepted gap, deferred item, and missed target recorded in this file and the decision log; close it or record why it stays open.
- [ ] Fresh performance pass against tungstenite and the other competitors on the current versions.
- [ ] Fresh security review of the whole crate.
- [ ] `docs/STABILITY-1.0.md` draft as the 1.0 readiness note: what is done, what is open, the go/no-go list.
- [ ] Release candidates with no API change for two weeks before 1.0.

## v1.0.0 - Stable
- [ ] Full audit recorded in `docs/STABILITY-1.0.md` (API, docs, tests, benchmarks, security).
- [ ] Frozen after Studio ships on it (D18). 1.0 needs the owner's explicit go.
