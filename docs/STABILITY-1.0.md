# 1.0 readiness

What must be true before any `1.0.0` release candidate, what is done, and
what still stands in the way. This is the draft written in 0.9; the full
audit (API, docs, tests, benchmarks, security) replaces it at the v0.9.x
polish exit (`dev/ROADMAP.md`). 1.0 itself needs the owner's explicit go.

## Done

| Area | State | Record |
|---|---|---|
| Protocol | every RFC 6455 receive rule with its close code, both roles; permessage-deflate (RFC 7692, feature `deflate`) with all four parameters | `docs/API.md` |
| Conformance | Autobahn TestSuite sections 1 to 13, 517 cases, both roles, strict (OK or INFORMATIONAL only), in CI on every push | `autobahn/` |
| Dependencies | no third-party runtime dependency; parse-net, mod-rand, and compress-lib 1 (optional) by published version | `deny.toml`, NFR-1 |
| Safety | `#![forbid(unsafe_code)]`; no reachable panic on peer input; a lint wall on arithmetic and indexing | NFR-2, NFR-3 |
| Security | a threat model with a test per threat (T-1 to T-29, the deflate threats included); two reviews before 0.7, a fresh one in 0.9, an independent one of 0.9.0 (one medium, four low, fixed in 0.10, D-081), every finding fixed with a test | `docs/SECURITY.md` |
| Fuzzing | ten targets 24 hours each before 0.7, clean; all eleven again in 0.9 (32 hours, `deflate_message` 25), clean, before WSL cut the 72-hour runs short | `docs/SECURITY.md`, D-071 |
| Memory | `size_of::<Connection>()` at most 512 bytes; idle heap 0 after `release_memory`; every heap growth site names its budget | `tests/memory.rs`, `tests/budget_audit.rs` |
| Allocation | no allocation per message in steady state; one to read a browser handshake (`ServerHandshake::from_head`) | counting-allocator tests, NFR-4 |
| Determinism | the same events for every split of the input | proptest, every piece size 1 to 15 |
| Soak, in memory | 100,000 connection pairs for 4 hours | `tests/soak.rs` |
| Soak, sockets | on net-io, 500 clients: Linux 4 hours per driver (0.8), both drivers 24 hours (the blocking pool in 0.9, the reactor on net-io 0.7.0 in 0.9.x, 3.70 billion messages, heap flat); Windows 4 hours per driver (0.9) | `interop/net-io/tests/soak.rs`, D-068, D-077 |
| Platforms | Linux, macOS, Windows on stable and 1.85; `no_std`; 32-bit; big-endian under Miri | CI |
| Integration | http-net (sans-IO and blocking hand-off), net-io (both drivers), tls-net, end to end in CI | `docs/INTEGRATION.md` |
| Consumers | serve-net's upgrade route and LexerSketch Studio build and pass on the 0.9 API unchanged | D-069 |
| API | every public item in `docs/API.md`; every rustdoc example runs | `docs/API.md` |
| Performance | against tungstenite 0.30.0 (its latest) and 0.8.0 on hosted runners, three platforms, each shortfall named with its cause; every accepted gap revisited | `docs/PERFORMANCE.md`, D-070 |

## Open

| Item | What closes it |
|---|---|
| 72-hour fuzzing per target (NFR-14) | the runs on the 0.10.0 code end clean on all eleven targets, `deflate_message` on compress-lib 1.0.0; the runs before them reached 38 to 64 hours clean before WSL restarts cut them (D-071, D-076, D-078, D-079) |
| A gateway consumer | a gateway using the policy, counters, `wipe`, and close on revocation runs end to end (serve-net and the Studio already pass on 0.9 unchanged, D-069) |
| Release candidates | two weeks of release candidates with no API change |
| Freeze | after the Studio ships on ws-net (D18) |

## Accepted shortfalls

Each was revisited in 0.9 (D-070) and stays, with its reason:

- NFR-8 (20% above the best Rust competitor) holds for small receives and
  sends, not for the handshake on Linux and macOS (1.02 and 1.12 against
  tungstenite), where ws-net checks more (the strict head grammar, the Host
  and Origin policy), nor for one 1 MiB message (level), a single copy and
  validation in both and bound by memory.
- NFR-10's 1.5x ASCII validation target: `core::str::from_utf8` already
  checks ASCII a word at a time; more needs SIMD intrinsics, which
  `forbid(unsafe_code)` rules out (D-029).
- Small server sends cost about 2.5 ns more than 0.2.0 on Linux: the
  output budget (the slow-consumer defense) and the counters (D-053).
- The Linux 1 MiB rows of the hosted harness move with the runner's heap
  placement, 0.19 to 0.93 against tungstenite on the same code (D-052).

## Go / no-go

1.0 goes when every row of "Open" is closed, no P0 or P1 defect is open,
the local gate and CI are green on the release commit, and the owner says
go.
