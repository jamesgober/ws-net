# ws-net - Plan

> The plan from 0.2.0 to 1.0: what the crate is for, what it must do, how each requirement is checked, and every design decision with its reason. `dev/ROADMAP.md` is the per-version checklist; `docs/API.md` lists the whole 1.0 API (the design lock, made in 0.3). This file is updated in the same change as every decision.

## 1. Purpose

`ws-net` is a WebSocket protocol engine that performs no I/O. It turns bytes from a transport into WebSocket messages and control events, and messages into bytes, enforcing every rule of RFC 6455 (and, with the `deflate` feature, RFC 7692) with every size, count, and time budget bounded by configuration. It does the opening handshake standalone over raw bytes or behind any HTTP layer, in both roles. The same engine runs over a blocking `std::net` socket, a reactor, a TLS stream, an HTTP/2 stream (RFC 8441, after 1.0), or an in-memory harness fed one byte at a time.

It is not a socket owner, an event loop, an HTTP parser beyond the one strict upgrade head, TLS, authentication, rate limiting across connections, pub/sub routing, a message schema, DEFLATE itself, or a clock. Those live in net-io, serve-net, http-net, tls-net, gate-net, bouncer-io and rate-net, the application, a first-party compression crate, and the caller.

Consumers: LexerSketch Studio (one WebSocket per window, JSON-RPC text and binary frames; first consumer, D18), serve-net (generic upgrade route), a gateway that holds one `Connection` per upgraded socket (policy helpers, counters, wipe, close on revocation), fetch-net and back-channel clients (client role over tls-net).

## 2. Requirements

Status: **S** shipped (version), **P** planned (version). The full API, item by item, is in `docs/API.md` section "The 1.0 API (design lock)".

### 2.1 Functional

| Id | Requirement | Status |
|---|---|---|
| FR-1 | Validate a client's request per RFC 6455 section 4.2.1 (method, target, one Host, Upgrade/Connection tokens, one Version 13, one canonical 16-byte Key, at most one Origin, at most 64 token subprotocols). | S 0.2 |
| FR-2 | Strict bounded raw head reader (CRLF only, token names, no folding, no controls, 16 KiB). | S 0.2 |
| FR-2a | Resumable `HeadReader`: total scan work linear in the head. | S 0.3 |
| FR-3 | Refuse `Transfer-Encoding` and `Content-Length` other than `0` on the upgrade (`UnexpectedBody`). | S 0.3 |
| FR-4 | Expose target, Host, Origin, offered subprotocols; offered extensions. | S 0.2; extensions P 0.4 |
| FR-5 | Origin policy: exact allowlist after normalisation, same-origin default, `any_origin` opt-out, `null` never matches; refusal 403. | S 0.3 |
| FR-6 | Host allowlist with RFC 3986 authority syntax (DNS rebinding). | P 0.4 |
| FR-7 | Subprotocol selection by server preference; `require_protocol`. | S 0.3 |
| FR-8 | Extension negotiation (`Sec-WebSocket-Extensions` grammar, at most 16 offers of 16 parameters). | P 0.4 (see D-017) |
| FR-9 | Refusals 400, 403, 426, 431; 503 with `retry-after` through `write_refusal`. | S 0.2/0.3; 503 helper P 0.4 |
| FR-10 | The 101 as a field list for HTTP layers; extra response headers. | P 0.4 |
| FR-11 | At most one allocation per handshake. | P 0.6 |
| FR-12 | Client request, with extra headers and extension offers. | S 0.2; extras P 0.4/0.5 |
| FR-13 | Client response verification, extensions included. | S 0.2; extensions P 0.4/0.5 |
| FR-14 to FR-26 | Every frame rule, masking direction, RSV, opcodes, control frames, fragmentation, incremental UTF-8, close rules, closing handshake, automatic Pong (latest replaces unwritten), EOF, budgets from headers, 1 MiB reservation cap. | S 0.2 |
| FR-27 | Outgoing frame size separate from the incoming budget (`Limits::with_send_frame`). | S 0.3 |
| FR-28 | Sending fragmented messages. | S 0.2 |
| FR-29 to FR-32 | Output budget with 256 B control headroom; `buffered_output`; `release_memory` and retain threshold; configurable input buffer. | P 0.4 |
| FR-33 to FR-37 | Keepalive and timeouts driven by the caller's monotonic milliseconds; `next_deadline`. | P 0.4 |
| FR-38, FR-39 | `PreparedMessage`, `send_prepared` (server only). | P 0.4 |
| FR-40 to FR-44 | permessage-deflate. | P 0.5 (D-015) |
| FR-45 | http-net integration test. | P 0.4 |
| FR-46 | tls-net example. | P 0.7 |
| FR-47, FR-48 | Blocking adapter; owned `Message`. | P 0.4 |
| FR-49 to FR-52 | Split borrow; detach; counters; wipe. | P 0.4 |
| FR-53 | Bounded work per `poll`. | S 0.2, tested 0.3 |
| FR-54, FR-55 | RFC 8441; state export. | P 1.x |
| FR-56 | `no_std` + `alloc` core. | S 0.2 |
| FR-57 | Tier 1 `accept(bytes)` reporting `consumed`. | S 0.3 |
| FR-58 | Nonces and masking seeds from the OS CSPRNG through `mod-rand`. | S 0.3 |
| FR-59 | Close with a policy reason at any time. | S 0.2 |
| FR-60 | `pub const VERSION`. | S 0.3 |

### 2.2 Non-functional

| Id | Requirement | Measure |
|---|---|---|
| NFR-1 | Zero third-party runtime dependencies; first-party by published version only. | `cargo tree -e normal`; `deny.toml` |
| NFR-2 | `#![forbid(unsafe_code)]`. | crate root |
| NFR-3 | No reachable panic; no unchecked arithmetic on peer-derived values. | lint wall, proptest, fuzzing (0.7) |
| NFR-4 | No allocation per message in steady state. | counting-allocator tests (0.6) |
| NFR-5, NFR-6 | Memory per connection bounded by configuration; `size_of::<Connection>()` at most 512 bytes. | `size_of` test (0.3); counting allocator (0.4) |
| NFR-8 | Throughput at least 20% above the best Rust competitor at equal or stronger security. | competitor harness (0.6) |
| NFR-12 | Deterministic for every split of the input. | proptest split invariance; every piece size 1 to 15 and every two-piece split of the data cases (0.3) |
| NFR-13 | Autobahn TestSuite strict pass, both roles. | CI job (0.7) |
| NFR-14 | Fuzzing: 24 hours per target before 0.7, 72 before 1.0. | `docs/SECURITY.md` |
| NFR-15 | MSRV 1.85, edition 2024; Linux, macOS, Windows; `no_std` build; 32-bit check. | CI |
| NFR-16 | Public types `Send + Sync`, checked at compile time. | `lib.rs` test |
| NFR-19 | No payload, key, seed, or nonce in `Debug` or `Display`. | Debug tests |
| NFR-21 | Soak: 4 hours before 0.8, 24 before 1.0. | soak harness (0.7) |

## 3. Threats

The threat table (cross-site hijacking, DNS rebinding, smuggled bodies, slow heads, header floods, proxy cache poisoning, predictable masking keys, oversized frames and length lies, frame, Ping, and Pong floods, slow messages, idle exhaustion, slow consumers, decompression bombs, compression side channels, invalid UTF-8, log injection, close-handshake hangs, panics, revoked sessions, cross-protocol bytes, allocation failure, information leaks) is kept with its tests in `tests/attacks.rs`, one `test_attack_<threat>_<expected>` per defense, and published in `docs/SECURITY.md` in 0.7. In 0.3: cross-site hijacking, smuggled bodies, slow heads, Pong flood, frame flood, log injection, cross-protocol bytes.

Defence idea per version (hypothesis, method, cost):

| Version | Hypothesis | Method | Cost |
|---|---|---|---|
| 0.3 | Linear head scanning removes the slow-head CPU amplification. | `HeadReader` keeps scan state; a unit test counts examined bytes (each once for a 16 KiB head fed bytewise). | none at runtime; 24 bytes of state per pending handshake |
| 0.4 | A reserved control headroom above the output budget lets a flooded queue still close cleanly. | 256 bytes above `max_output` usable only by Pong and Close. | 256 bytes per connection worst case |
| 0.5 | Inflating into the reassembly buffer with the budget checked per chunk bounds bombs by the message budget. | write-into-message inflater; peak-memory test. | none beyond the budget |
| 0.6 | `try_reserve` on every growth turns allocator exhaustion into a clean failure. | failing test allocator. | one branch per growth |
| 0.7 | Differential fuzzing against tungstenite finds acceptance mismatches. | same bytes into both; compare accept or reject per frame. | CI time |
| 0.8 | Per-connection ratios (Pings per message, fragments per message) flag abusive peers earlier than byte rates. | ratios from `Stats`; shadow-mode false-positive measurement. | two counters |
| 0.9 | A budget audit test lists every `Vec` growth site with its guard. | source-level test in CI. | CI time |

## 4. Decision log

| Id | Date | Decision | Reason |
|---|---|---|---|
| D-001 | 2026-11-04 | The design lock is 0.3, not 0.2 (OD-1). | 0.2.0 shipped as "Foundation" before the full API was written down; a published version cannot be re-cut. |
| D-002 | 2026-11-04 | The Tier 1 Origin rule is same-origin with a missing Origin accepted (OD-2). | Browsers always send Origin and a page cannot remove it, so cross-site hijacking is blocked; non-browser clients carry no ambient browser credentials and keep working. |
| D-003 | 2026-11-04 | parse-net 0.9 (`default-features = false`) replaces the private token, OWS, field-value, visible-ASCII, and list helpers. Lists are RFC 9110 lists: quote- and comment-aware, and a value that does not parse holds nothing (fail closed: `Upgrade: websocket, "x` is not an upgrade). | One grammar across the stack; the private split-on-comma read `"a,b"` as two elements. Measured: the browser handshake benchmark is 12.7% faster. |
| D-004 | 2026-11-04 | Masking seeds and nonces come from `mod-rand` 1.0's OS tier (`tier3::fill_bytes`, feature `std`). It can fail, so `Connection::try_client` and `ClientHandshake::try_new` are added; `client()` and `new()` fail closed (a connection that refuses every send with `WsError::RandomUnavailable`, a handshake whose `write_request` returns `HandshakeError::RandomUnavailable`), never a weaker source, never a panic (OD-12). | The 0.2 seed came from `RandomState`, which is one OS draw per thread plus a counter and the clock, not a specified CSPRNG (gap G-2). |
| D-005 | 2026-11-04 | `OriginPolicy` matches only `http` and `https` origins, under every policy except `Any`. | A web page's origin has one of these schemes; anything else (`chrome-extension://`, `file://`) is refused rather than compared. Fail closed. |
| D-006 | 2026-11-04 | Same-origin port rule: a `Host` with a port matches an Origin whose effective port (explicit, or the scheme's default) is that port; a `Host` without one matches an Origin on its scheme's default port. The scheme is not compared, so an `http` page passes for a `wss` endpoint on the same authority. | The endpoint's own scheme is not known to a sans-IO handshake; `AcceptPolicy::with_secure` (0.4, OD-20) pins it. |
| D-007 | 2026-11-04 | Only a lone `Content-Length: 0` counts as no body; `00`, `0, 0`, and repeated fields are `UnexpectedBody`. | Never interpret a body length on a request that must have none; refuse what another parser could read differently. |
| D-008 | 2026-11-04 | `HeadReader` returns `InvalidRequest` when the buffer is shorter than what it scanned; it cannot detect a changed prefix, and the docs say the buffer must only grow. `Verified` is introduced in 0.3 with `protocol` only, `#[non_exhaustive]`, so 0.4 adds `extensions` without a break. | Linear scanning needs the caller's buffer discipline; checking the prefix would cost the linearity it buys. |
| D-009 | 2026-11-04 | `HandshakeError::RandomUnavailable` reports status 500 (client side, never answered); `WsError::RandomUnavailable` is a refused call (`close_code() == None`). | Neither is a protocol failure; both say what to do (retry or fail the attempt). |
| D-010 | 2026-11-04 | SHA-1 and base64 stay private modules. | RFC 6455 fixes SHA-1 as a protocol requirement, not a security primitive; crypt-io ships no SHA-1 by design and the owner's codec library has no base64. Swapping them later changes no API. |
| D-011 | 2026-11-04 | Recorded exception: the REPS "MUST use tokio" clause does not apply. | ws-net is sans-IO and uses no runtime; no async runtime is allowed in the stack. |
| D-012 | 2026-10-12 | Non-minimal payload length encodings are refused with 1002 (OD-9). | RFC 6455 section 5.2: the minimal encoding MUST be used; accepting both would give one frame two encodings. |
| D-013 | 2026-11-04 | Open-decision recommendations adopted for the plan: output budget 32 MiB default (OD-3); no public extension trait in 1.0 (OD-5); 1007 for undecodable compressed data, to confirm against Autobahn 12 and 13 (OD-6); keep SHA-1 counter-mode masking keys, measure bulk OS refills in 0.6 (OD-7); autovectorised lanes, no `unsafe` (OD-8); a test-only counting allocator if `mod-alloc` does not fit (OD-10); fan-out by one copy per recipient in 1.0 (OD-11); close with 1012 on restart, state export after 1.0 (OD-13); a separate `ExtendedConnect` type for RFC 8441 (OD-14); best-effort wipe through `black_box` (OD-15); two weeks without API change before 1.0 (OD-16); `on_time(Millis)` (OD-17); refuse with `OutputFull`, the caller decides (OD-18); queue Close 1001 on idle timeout (OD-19); `with_secure` in 0.4 (OD-20). | Technical calls delegated for the 0.x series; each is revisited in the 0.9.x polish pass. |
| D-014 | 2026-11-04 | `REPS.md` keeps its em dashes. | It must stay a byte-identical copy of the shared REPS file; the no-em-dash rule applies to the crate's own documents. |
| D-015 | 2026-11-04 | permessage-deflate needs a first-party raw DEFLATE crate (sans-IO, no dependencies, no `unsafe`). If none is published when 0.5 is otherwise done, deflate moves to 0.6, then at the latest out of 1.0 to 1.1, each move recorded in `dev/ROADMAP.md`. | Zero third-party dependencies; DEFLATE also serves HTTP content coding, so it belongs in its own crate. None exists on 2026-11-04. |
| D-016 | 2026-11-04 | `tests/autobahn.rs` runs every case in pieces of every size from 1 to 15 bytes and split in two at every point (for the 64 KiB cases, every point near a header or buffer boundary and a stride). | Determinism for every split (NFR-12) at the boundaries where streaming parsers break. |
| D-017 | 2026-11-04 | API gap reported to parse-net: RFC 6455 extension parameters may have no value (`client_max_window_bits`, `server_no_context_takeover`), and `parse_net::param::parse` refuses a name with no `=`. The 0.4 extension parser waits for an optional-value form in parse-net; if parse-net 1.0 does not add one, ws-net parses parameters itself on top of `parse_net::text` (token and quoted-string), recorded here. | The adoption rule moves shared grammar out of ws-net; this piece is not yet expressible with parse-net. |
