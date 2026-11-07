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
| Dependencies | no third-party runtime dependency; parse-net, mod-rand, and compress-lib (optional) by published version | `deny.toml`, NFR-1 |
| Safety | `#![forbid(unsafe_code)]`; no reachable panic on peer input; a lint wall on arithmetic and indexing | NFR-2, NFR-3 |
| Security | a threat model with a test per threat (T-1 to T-29, the deflate threats included); two reviews before 0.7, a fresh one in 0.9, every finding fixed with a test | `docs/SECURITY.md` |
| Fuzzing | ten targets 24 hours each before 0.7, clean | `docs/SECURITY.md` |
| Memory | `size_of::<Connection>()` at most 512 bytes; idle heap 0 after `release_memory`; every heap growth site names its budget | `tests/memory.rs`, `tests/budget_audit.rs` |
| Allocation | no allocation per message in steady state; one per handshake | counting-allocator tests, NFR-4 |
| Determinism | the same events for every split of the input | proptest, every piece size 1 to 15 |
| Soak, in memory | 100,000 connection pairs for 4 hours | `tests/soak.rs` |
| Soak, sockets | on net-io, 500 clients: Linux 4 hours per driver (0.8), the blocking pool 24 hours (0.9); Windows 4 hours per driver (0.9) | `interop/net-io/tests/soak.rs`, D-068 |
| Platforms | Linux, macOS, Windows on stable and 1.85; `no_std`; 32-bit; big-endian under Miri | CI |
| Integration | http-net (sans-IO and blocking hand-off), net-io (both drivers), tls-net, end to end in CI | `docs/INTEGRATION.md` |
| Consumers | serve-net's upgrade route and LexerSketch Studio build and pass on the 0.9 API unchanged | D-069 |
| API | every public item in `docs/API.md`; every rustdoc example runs | `docs/API.md` |
| Performance | against tungstenite 0.30.0 on hosted runners, three platforms, each shortfall named with its cause | `docs/PERFORMANCE.md` |

## Open

| Item | What closes it |
|---|---|
| 72-hour fuzzing per target (NFR-14) | the runs started 2026-11-06 on all eleven targets, `deflate_message` included, end clean |
| 24-hour socket soak on net-io's reactor (NFR-21) | a clean 24-hour Linux run on net-io 0.7.0; on 0.6.1 seven connections stopped receiving after 15 hours, a read the reactor did not deliver (D-068) |
| A gateway consumer | a gateway using the policy, counters, `wipe`, and close on revocation runs end to end (serve-net and the Studio already pass on 0.9 unchanged, D-069) |
| Accepted gaps | every accepted gap, deferred item, and missed target in `dev/ROADMAP.md` and the decision log closed or recorded as staying open |
| Performance pass | a fresh comparison on current versions of tungstenite and the others |
| Release candidates | two weeks of release candidates with no API change |
| Freeze | after the Studio ships on ws-net (D18) |

## Known shortfalls carried into the audit

- Small sends cost about 2.5 ns more than 0.2.0 on Linux servers: the
  output budget (the slow-consumer defense) and the counters (D-053).
- ASCII text is validated by `core::str::from_utf8` once per byte, without
  the separate fast path of NFR-10's 1.5x target (D-029).
- The Linux 1 MiB receive rows of the hosted harness depend on where the
  runner's heap places the buffer, not on ws-net (D-052).

## Go / no-go

1.0 goes when every row of "Open" is closed, no P0 or P1 defect is open,
the local gate and CI are green on the release commit, and the owner says
go.
