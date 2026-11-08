# ws-net - Performance

Measured numbers, how they were taken, and how to reproduce them. Every table comes from one run
of `.github/workflows/bench.yml` on GitHub's hosted runners, so the three platforms ran the same
commit at the same time; each section names its run. The 0.9 pass is first; the tables after it
are the 0.6 to 0.8 record (commit `4359c49`, run 41899339504). Hosted runners are shared virtual
machines: compare rows within one run and one platform, never across runs. The development
machine (shared by many builds, load near 40 on 32 cores) was too noisy to publish from.

<sub>Copyright &copy; 2026 <strong>James Gober</strong>.</sub>

## Method

- Rust stable, `cargo bench` with the release profile (`opt-level = 3`, `lto = "fat"`, `codegen-units = 1`).
- Criterion medians. Baselines: v0.2.0 built from its tag in the same job, then this commit with
  `--baseline-lenient v020` (benchmarks newer than 0.2.0 have no baseline).
- Competitor: tungstenite 0.30.0 (`bench-compare/`, outside ws-net's dependency graph), on the
  same wire bytes at each library's lowest public layer: ws-net's `Connection`, tungstenite's
  `WebSocket` over an in-memory stream. UTF-8 validation on, unmasked client frames refused,
  default budgets except where a workload needs more. Libraries that need an async runtime
  (fastwebsockets, tokio-websockets, ratchet) are not compared: no async runtime is used anywhere
  in this repository.
- Reproduce: `cargo bench --bench bench` in the crate; `cargo bench --bench compare` in `bench-compare/`;
  `python3 bench-compare/summary.py <criterion dir> [baseline]` prints the tables.

## 0.9.0

Run 42403822331 on commit `9067ecd`: this commit against v0.8.0 built in the
same job (`gh workflow run bench.yml -f baseline=v0.8.0`), then against
tungstenite 0.30.0, still its latest release.

| Benchmark | Linux x86_64 | macOS arm64 | Windows x86_64 |
|---|---:|---:|---:|
| `receive_100k/small_messages` | 2.46 ms (-13.8%) | 1.79 ms (-23.5%) | 2.18 ms (-13.6%) |
| `receive_1mib/text_utf8` | 553 µs (-9.4%) | 560 µs (-0.2%) | 482 µs (-45.9%) |
| `receive_1mib/binary` | 76.1 µs (+1.8%) | 59.8 µs (+0.3%) | 484 µs (-0.8%) |
| `send_100k/server_unmasked` | 1.31 ms (+5.4%) | 1.6 ms (-4.0%) | 2.97 ms (+1.1%) |
| `send_100k/client_masked_os` | 3.21 ms (-0.4%) | 3.44 ms (+0.4%) | 4.1 ms (-0.1%) |
| `handshake/from_head_100k` | 272 ms (-2.8%) | 243 ms (+0.5%) | 225 ms (+5.0%) |
| `keepalive/on_time_idle` | 903 µs (-17.1%) | 402 µs (+8.8%) | 763 µs (-0.0%) |
| `flood/empty_continuations` | 20.5 ms (+11.0%) | 12.2 ms (+2.3%) | 14.1 ms (+2.8%) |
| `broadcast/prepared_10k` | 93.2 µs (+2.4%) | 79.4 µs (-4.3%) | 151 µs (+1.7%) |
| `mask_1mib/in_place` | 21.3 µs (-0.5%) | 22.1 µs (-12.0%) | 18.3 µs (-1.3%) |

Small-message receive is 14 to 24% faster than 0.8.0: a single-frame text
message is validated once (since 0.7's lending fix it was validated twice,
once to decide and once to build the event). permessage-deflate costs a
connection without it a few branches per frame and nothing measurable.
The flood row is up 11% on Linux and within 3% elsewhere; it is watched in
the next run rather than read as a cost.

Against tungstenite in the same run (tungstenite's median over ws-net's):

| Workload | Linux | macOS | Windows |
|---|---:|---:|---:|
| Receive 100,000 small masked messages | 2.13 | 1.75 | 2.44 |
| Send 100,000 small messages (server) | 2.42 | 2.49 | 4.85 |
| Send 100,000 small messages (client) | 1.61 | 1.80 | 3.47 |
| Accept 10,000 browser upgrade requests | 1.02 | 1.12 | 1.48 |
| Receive one 1 MiB binary message | 0.19 | 1.00 | 1.23 |
| Receive one 1 MiB text message | 0.66 | 0.99 | 1.08 |

The Linux 1 MiB rows are the runner's heap placement (below): in run
42401336990, an hour earlier on the same code but the validation fix, the
same rows were 0.93 and 0.89.

## ws-net against tungstenite 0.30.0

The ratio is tungstenite's median over ws-net's: above 1.00, ws-net is faster.

| Workload | Linux x86_64 | macOS arm64 | Windows x86_64 |
|---|---:|---:|---:|
| Receive 100,000 small masked messages (server) | 1.89 ms vs 4.41 ms (2.34) | 1.43 ms vs 2.8 ms (1.95) | 1.95 ms vs 4.55 ms (2.34) |
| Receive one 1 MiB binary message | 414 µs vs 77.5 µs (0.19) | 67 µs vs 68.2 µs (1.02) | 468 µs vs 548 µs (1.17) |
| Receive one 1 MiB text message (mixed UTF-8) | 1.02 ms vs 650 µs (0.64) | 672 µs vs 723 µs (1.08) | 1.19 ms vs 1.28 ms (1.08) |
| Send 100,000 small messages (server, unmasked) | 1.32 ms vs 3.37 ms (2.55) | 1.88 ms vs 3.99 ms (2.12) | 1.16 ms vs 5.61 ms (4.83) |
| Send 100,000 small messages (client, masked) | 3.5 ms vs 5.15 ms (1.47) | 3.61 ms vs 6.95 ms (1.93) | 2.25 ms vs 7.9 ms (3.52) |
| Accept 10,000 browser upgrade requests | 25.5 ms vs 27.3 ms (1.07) | 20.5 ms vs 22.8 ms (1.11) | 23.1 ms vs 32 ms (1.38) |

## This release against 0.2.0

| Benchmark | Linux x86_64 | macOS arm64 | Windows x86_64 |
|---|---:|---:|---:|
| `broadcast/prepared_10k` | 88.1 µs | 88 µs | 159 µs |
| `flood/empty_continuations` | 18.6 ms | 10.9 ms | 14.1 ms |
| `handshake/from_head_100k` | 265 ms (-18.6%) | 230 ms (-33.4%) | 247 ms (-0.6%) |
| `handshake/head_reader_bytewise` | 3.93 µs | 2.76 µs | 3.4 µs |
| `keepalive/on_time_idle` | 905 µs | 383 µs | 873 µs |
| `mask_1mib/in_place` | 21.4 µs (+0.3%) | 23.3 µs (-1.8%) | 20.6 µs (-2.6%) |
| `receive_100k/small_messages` | 2.32 ms (+2.4%) | 2.32 ms (+35.2%) | 2.34 ms (+4.5%) |
| `receive_1mib/binary` | 75.7 µs (-0.5%) | 77.9 µs (-7.2%) | 545 µs (+4.6%) |
| `receive_1mib/text_utf8` | 543 µs (-59.9%) | 635 µs (-41.3%) | 686 µs (-41.9%) |
| `send_100k/client_masked` | 7.35 ms (+9.2%) | 9.06 ms (-1.6%) | 8.73 ms (+7.0%) |
| `send_100k/client_masked_os` | 3.52 ms | 3.32 ms | 4.44 ms |
| `send_100k/server_unmasked` | 1.24 ms (+24.2%) | 1.74 ms (-22.4%) | 3.32 ms (+12.5%) |

## Reading the tables

**Where ws-net leads tungstenite** (on all three platforms): receiving many
small messages (1.9 to 2.3 times), sending as a server (2.1 to 4.8 times)
and as a client (1.5 to 3.5 times), and accepting upgrade requests (1.07 to
1.38 times). Small-message receive is zero-copy (a single-frame message is
unmasked in place and lent from the input buffer); sends write headers
straight into the output; client masking keys come from the OS in 1 KiB
batches (about 1.4 ns per key on Windows x86_64, against about 40 ns for
SHA-1 counter mode); the handshake record is one allocation.

**Where they are level:** one 1 MiB message, binary or text, on macOS and
Windows (0.98 to 1.17). Both copy the payload once and validate text once;
the remaining cost is memory bandwidth.

**Shortfalls, with their cause and plan:**

- *1 MiB receive on Linux in the comparison harness* (ws-net 414 µs against
  77 µs binary, 1.02 ms against 650 µs text). This is where the hosted
  Linux runner places the buffers, not ws-net's cost.
  `bench-compare/examples/faults.rs` (in the benchmark workflow) times one
  message with its allocations and minor page faults. On the Linux runner
  (run 42167760017) the same code path, one allocation of the same 1 MiB,
  took 753 µs in one case and 78 µs in the next, where earlier live
  allocations had moved the heap. tungstenite took 82 µs, and 75 µs with
  the reassembly buffer kept. None of these cases page-faults, and plain
  `memcpy` into a fresh 1 MiB buffer takes 24 µs. tungstenite's text row
  moves the same way between runs (676 µs and 1000 µs). macOS, Windows,
  and a WSL Linux machine show no gap. No change is planned.
  On every platform, a fresh 1 MiB buffer per message is the dearest part
  of a large receive (Windows: 94 µs kept against 310 µs fresh, for ws-net
  and tungstenite alike). A connection that receives a stream of large
  messages keeps its buffer with `Limits::with_retain`, at the cost of
  holding that much memory between messages.
- *Small sends against 0.2.0:* the price of the 0.4 output budget (the
  slow-consumer defense) and the counters, about 2.5 ns per send on Linux.
  In 0.8 the exact frame size is only worked out near the budget, and each
  frame makes one capacity check instead of two (`dev/PLAN.md` D-047,
  D-053). Against 0.2.0 built in the same job, client sends moved from
  +14% to +4 to +8% on Linux, and from +12% to +2% and -20% on macOS. Server
  sends are still +38 to +52% on Linux, +4 to +21% on Windows, and -3 to
  +18% on macOS. These runners move the untouched small-receive row by
  +15 to +33% between runs, so a few percent either way is noise. Against
  tungstenite in the same runs, ws-net sends 2.1 to 5.2 times as fast as a
  server and 1.4 to 4.6 times as fast as a client.
- *Small-message receive on macOS against 0.2.0* moved between +7.6% and
  +35% across runs while Linux and Windows stayed within 5%; treated as
  runner noise until a quieter measurement says otherwise.

**Improvements over 0.2.0:** 1 MiB text receive 42 to 60% faster (one
UTF-8 pass instead of two), the raw-head handshake 1 to 33% faster
(parse-net's list and token scanning, one allocation), and client sends
through `Connection::client` about 2 to 2.6 times faster (OS key batches;
`client_masked` uses a fixed seed and SHA-1 counter mode for
reproducibility, `client_masked_os` the OS batches).

## End to end over net-io

`interop/net-io/examples/e2e.rs`: echo servers over loopback, and one
client for all of them, each connection a thread doing round trips (send a
message, read its echo). ws-net runs as a net-io 0.6 `Session` on the
reactor (one worker per CPU) and on the blocking pool (80 workers);
tungstenite 0.30.0 runs one thread per connection on `std::net`. Messages
per second, 3 seconds per cell; the ratio is reactor over tungstenite.
Hosted run 41917369553 on commit `cb2b264`.

| Connections | Payload | Linux reactor | Linux pool | Linux tungstenite | Ratio | macOS ratio | Windows ratio |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 16 B | 27,611 | 29,718 | 29,923 | 0.92 | 0.90 | 0.95 |
| 1 | 1 KiB | 26,333 | 28,826 | 28,637 | 0.92 | 1.14 | 0.96 |
| 16 | 16 B | 129,444 | 123,170 | 120,961 | 1.07 | 1.17 | 0.85 |
| 16 | 1 KiB | 124,875 | 119,056 | 119,348 | 1.05 | 0.85 | 0.85 |
| 64 | 16 B | 132,747 | 121,454 | 116,190 | 1.14 | 1.13 | 0.84 |
| 64 | 1 KiB | 127,217 | 116,972 | 115,483 | 1.10 | 0.96 | 0.78 |

A round trip is two loopback system calls and two thread wake-ups each way,
and ws-net's share of it is well under a microsecond (the tables above), so
this measures the driver more than the engine. On Linux the reactor leads
from 16 connections on (5 to 14%) and trails by 8% at one connection,
where a thread blocked in `read` wakes sooner than a readiness loop. The
blocking pool is level with tungstenite (0.99 to 1.05), as both are a
thread in `read` per connection. On Windows the reactor runs at 0.78 to
0.96 of thread-per-connection tungstenite; the gap is in the driver, since
ws-net leads tungstenite on Windows in every engine row above. On macOS the cells move both ways (0.85 to 1.17) between
neighboring rows, which reads as runner noise.
With net-io 0.6.1 the benchmark includes 64 KiB messages (hosted run
42175335960; the 16 B and 1 KiB rows of that run agree with the table above
within runner noise). Messages per second at 64 connections:

| 64 KiB, 64 connections | Linux | macOS | Windows |
|---|---:|---:|---:|
| ws-net on reactor, defaults | 33,209 | 19,729 | 33,418 |
| ws-net on reactor, 256 KiB net-io output budget | 42,305 | 23,508 | 42,105 |
| ws-net on blocking pool | 47,015 | 23,064 | 54,015 |
| tungstenite, thread per connection | 53,518 | 25,100 | 63,851 |

net-io's default output budget is 64 KiB per connection, so a 64 KiB echo
(plus its frame header) leaves in two flushes with a writable wake-up
between them. Raising it to 256 KiB is worth 19 to 27%. A 256 KiB ws-net
input buffer alone, so that the message is lent whole instead of
reassembled, changed nothing (run 42175181790: 21,936 against 22,244
on Linux). The rest of the gap, 8 to 15% on the blocking pool, is the copy
between each driver buffer and ws-net's, which a driver that owns its
buffers pays. A server for large messages should size net-io's
`output_budget` above its largest message.

## Memory

From `tests/memory.rs` (a counting allocator, every platform in CI):
receiving and sending small messages, fragmented messages, Ping floods,
idle keepalive ticks, prepared sends, and the Close echo allocate nothing
once the buffers have grown; a browser handshake allocates once; an idle
connection after `release_memory` holds no heap, and its inline size is at
most 512 bytes.
