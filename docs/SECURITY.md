# ws-net - Security

The threat model, every defense with the test that proves it and what it
costs, what ws-net does not defend, and the fuzzing and conformance
record.

<sub>Copyright &copy; 2026 <strong>James Gober</strong>.</sub>

## Threat model

The peer is hostile in both roles. For a server, the peer is any Internet
client, including a browser running an attacker's page with the victim's
cookies. For a client, the peer is a server that may be compromised or
impersonated (TLS authenticity is tls-net's job, not this crate's). The
caller (the application) is trusted to pass correct arguments: wrong
arguments are refused (`WsError::InvalidArgument`, `InvalidState`), never
undefined behavior. At risk: CPU, memory, the application's session
authority, intermediaries (proxy caches), and secrets inside messages.

The crate forbids `unsafe` code (`#![forbid(unsafe_code)]`), has no
third-party runtime dependency (parse-net and mod-rand are first party with
no dependencies of their own), and has no reachable panic: `unwrap`,
`expect`, `panic!`, `unreachable!`, and indexing that can fail are denied by
the lint wall, and the fuzz targets check it.

## Threats, defenses, tests

Every test named `test_attack_*` is in `tests/attacks.rs`.

| Id | Threat | Defense | Test | Cost |
|---|---|---|---|---|
| T-1 | Cross-site WebSocket hijacking: another site's page opens a socket with the user's cookies (CWE-1385) | The Tier 1 path (`accept`, `Acceptor`, `blocking::accept`) applies the same-origin rule; `OriginPolicy::allow` compares parsed origins, never substrings; `null` and non-web schemes never match; two `Origin` fields are refused | `test_attack_cswsh_*`, a property against a reference comparison, the `origin_policy` fuzz target | one origin parse per handshake |
| T-2 | DNS rebinding: the attacker's name resolves to the server | `AcceptPolicy::with_hosts`; same-origin ties the Origin to `Host` | `test_attack_dns_rebinding_foreign_host_refused_403` | one host parse per entry |
| T-3 | Request smuggling through a body on the upgrade request | `Transfer-Encoding` and any `Content-Length` but a lone `0` refused (`UnexpectedBody`) | `test_attack_smuggled_body_*` | two comparisons per field |
| T-4 | Slow-head CPU amplification (the class of CVE-2023-43669) | `HeadReader` and `Acceptor` resume where they stopped: linear total work | `test_attack_slow_head_*`; a unit test counts each byte examined once | none |
| T-5 | Handshake header floods | 16 KiB head, 64 subprotocols, 16 extension offers of 16 parameters | `test_attack_header_flood_refused` | constant |
| T-6 | Proxy cache poisoning by unmasked client data | a server fails on any unmasked frame (1002), no opt-out | `test_attack_unmasked_client_frame_fails_1002`, Autobahn | one branch |
| T-7 | Predictable masking keys | keys from the OS cryptographic source in 1 KiB batches (`Connection::client`); each key is zeroed once used; no key material in `Debug` | `test_attack_masking_keys_unpredictable_across_connections` | about 1.4 ns per key |
| T-8 | Masked frames from a server | a client fails (1002) | `test_attack_masked_server_frame_fails_1002` | one branch |
| T-9, T-10 | Oversized frames; a header claiming a terabyte | frame and message budgets from the header, before any payload (1009); reassembly reserves at most 1 MiB ahead of arrived bytes; a message buffer never grows past its budget | `test_attack_length_lie_fails_before_payload_1009`, the budget property | two comparisons per frame |
| T-11 | 64-bit length with the high bit set; overflow | refused (1002); saturating arithmetic on every peer-derived value; 32-bit build in CI | `test_attack_length_high_bit_fails_1002`, the i686 job | none |
| T-12 | Frame floods (millions of empty frames) | work linear in bytes, no memory per frame; counters for rate limits; the message timeout | `test_attack_frame_flood_*`, `flood/empty_continuations` | 10 to 18 ns per frame on hosted runners |
| T-13 | Ping floods without reading | an unwritten automatic Pong is replaced by the next; `pings_in` counter | `test_attack_ping_flood_output_bounded_one_pong` | none |
| T-14 | Unsolicited Pong floods | Pongs produce events, never output | `test_attack_pong_flood_output_stays_empty` | none |
| T-15 | Slow messages holding a budget | `Keepalive::with_message_timeout` (1008) | `test_attack_slow_message_idle_and_close_hang_time_out` | 4 to 9 ns per tick |
| T-16 | Idle connections | `with_idle_timeout` (1001); `release_memory` frees all heap | the same test; `test_attack_many_idle_connections_hold_no_heap` | 0 heap when idle |
| T-17 | Slow consumers | `Limits::with_max_output` refuses a send past the budget (`OutputFull`); 262 bytes kept for Pong and Close | `test_attack_slow_consumer_refused_at_budget_close_still_fits`, a property under random sends | one comparison per send (about 2.4 ns, `docs/PERFORMANCE.md`) |
| T-18 | Memory per connection across many connections | inline size at most 512 bytes; idle heap 0 after `release_memory`; every buffer budgeted | `test_attack_many_idle_connections_hold_no_heap`, `tests/memory.rs`, the soak | none |
| T-19 to T-21 | Decompression bombs, compression side channels, compression context memory | permessage-deflate is not implemented; a client refuses a response that accepts an extension, and a server declines every offer | the extension tests | none (planned for 1.1 with its own defenses) |
| T-22 | Invalid UTF-8 passed downstream | validated once per byte, failing at the first bad byte (1007), across fragments and reads | `test_attack_invalid_utf8_fails_1007`, Autobahn section 6, the UTF-8 property | linear |
| T-23 | Log injection through close reasons | the reason is delivered verbatim and documented as peer text | `test_attack_close_reason_control_characters_delivered_verbatim` | none |
| T-24 | Close-handshake hangs | `with_close_timeout` (5 s default); `should_close_transport` | the timeout test | 4 to 9 ns per tick |
| T-25 | Panics as denial of service | no panic by construction; fuzzing with small, default, and lifted budgets | `test_attack_extreme_arguments_never_panic`, all fuzz targets | none |
| T-26 | A revoked session keeps its socket | `close(POLICY_VIOLATION, ..)` at any time, even mid-message; `wipe()` | `test_attack_revoked_session_close_1008_mid_message_then_input_ignored` | none |
| T-27 | Cross-protocol bytes after the upgrade | strict frame rules fail at the first bad byte (1002) | `test_attack_http_bytes_after_upgrade_fail_1002` | none |
| T-28 | Allocator exhaustion aborting the process | `try_reserve_exact` on reassembly growth: `AllocationFailed` (1011) | `tests/memory.rs` scenario 7 with a failing allocator; `test_attack_allocation_failure_closes_1011` | one branch per growth |
| T-29 | Information leaks through `Debug`, `Display`, or errors | no payload, key, or seed in either; `PreparedMessage` prints lengths only | `test_attack_debug_and_display_leak_no_payload` | none |
| T-30 | Message-content attacks (JSON bombs) | out of scope (the application); ws-net bounds the size | n/a | n/a |

## What ws-net does not defend

Authentication and authorization, cross-connection rate limiting, message
schema validation, TLS, and amplification through application broadcasts
belong to other layers (gate-net, bouncer-io and rate-net, the
application, tls-net). `wipe()` zeroes buffers through
`core::hint::black_box`, which Rust documents as best effort: it is a
strong hint against removing the writes, not a guarantee. A guaranteed
wipe needs volatile writes, which need `unsafe`. Secrets that need a
guarantee belong in a key vault, not in WebSocket buffers.

## Conformance

The Autobahn TestSuite (`crossbario/autobahn-testsuite:25.10.1`) runs in CI
on every change, in both roles, sections 1 to 10, with a strict check
(`autobahn/check.py`: every case OK in behavior and close behavior;
NON-STRICT counts as a failure). Result since 0.5.0: 301 cases, 0 failures
as a server and as a client. Cases 7.1.6, 7.13.1, and 7.13.2 are
informational by the suite's own design.

## Fuzzing

Ten cargo-fuzz targets (`fuzz/`), the corpus outside the repository:

| Target | Input | Oracle |
|---|---|---|
| `frame_header` | arbitrary bytes | no panic; every accepted header re-encodes to the same bytes; every prefix asks for more |
| `connection_server`, `connection_client` | bytes, budgets small, default, or lifted | no panic; split invariance; output is whole valid frames; memory within the configured bound |
| `connection_api` | a sequence of calls, input, and clock ticks | a refused call changes neither state nor output; state only moves forward; output within budget plus headroom |
| `server_head` | head bytes, cut points | `HeadReader` equals `from_head`; an accepted head answers a 101 |
| `client_head` | response bytes | the one-shot and resumable readers agree; an accepted response names an offered protocol |
| `extension_parse` | `Sec-WebSocket-Extensions` values | token names and values; caps hold |
| `origin_policy` | allowlist entry, Origin, Host | an identical origin is permitted; nothing but http or https is |
| `handshake_key` | `Sec-WebSocket-Key` values | accepted exactly when canonical base64 of 16 bytes |
| `differential_tungstenite` | client bytes | what ws-net and tungstenite 0.30.0 deliver agrees as far as both go |

Run: `fuzz/run-all.sh 24` (WSL or Linux, nightly). The record of each run
is below; every crash becomes a regression test before it is fixed.

### 0.7.0: 2026-11-04 to 2026-11-05

All ten targets, 24 hours each, at once on one shared machine (WSL,
nightly, one libFuzzer process per target), on the code after the
review fixes. No crash, no timeout, no out-of-memory, no artifact.
35.32 billion inputs in all.

| Target | Inputs run | Findings |
|---|---:|---|
| `frame_header` | 12.29 billion | none |
| `extension_parse` | 7.27 billion | none |
| `handshake_key` | 5.59 billion | none |
| `origin_policy` | 4.53 billion | none |
| `server_head` | 2.38 billion | none |
| `client_head` | 1.82 billion | none |
| `connection_client` | 486 million | none |
| `connection_api` | 446 million | none |
| `connection_server` | 245 million | none |
| `differential_tungstenite` | 245 million | none |

## Review

Before 0.7.0 two independent reviews read the engine and the handshake
against this threat model. They found twelve defects, none reachable for
code execution or a crash (the crate forbids `unsafe`), all fixed in 0.7.0
with a regression test each (`tests/regressions.rs`):

| Area | Defect | Effect before the fix |
|---|---|---|
| close | a failed connection with output unwritten had no timer left | a peer that never read held the transport open |
| close | a client's masked Pong and Close (131 bytes each) did not both fit the 256-byte headroom | a flooded client could answer but not close |
| keepalive | a Ping refused by full output left its deadline in the past | a timer loop woke on every tick |
| frames | a failed UTF-8 message was still marked as lent | `detach_message` returned invalid bytes as Text |
| frames | a send that failed part way (key refill) left frames queued; a refused Close counted as sent | a refused call changed state |
| memory | `wipe` zeroed the length, not the capacity | bytes left by compaction survived the wipe |
| memory | streamed text did not reserve for the carried partial character | an extra reallocation, outside `try_reserve_exact` |
| handshake | absolute-form targets were accepted | the target's authority could differ from the `Host` the policy checked |
| handshake | `HeadReader` resumed after an error | bytes after a bad head could parse as a fresh head |
| handshake | empty extension list elements across fields were stored as is | `extensions()` could fail on a head that was accepted |
| logging | `ServerHandshake`'s `Debug` printed the query; `ClientHandshake`'s printed header values | a token in a query or `Authorization` could reach logs |
| docs | `accept` did not warn that Tier 1 accepts any `Host` | a private-address service was open to DNS rebinding by default |

## Reporting a vulnerability

Open a private security advisory on the repository
(https://github.com/jamesgober/ws-net/security/advisories/new), or write to
the address in `Cargo.toml`'s `authors`.
