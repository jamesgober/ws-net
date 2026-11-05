//! The soak: many in-memory connection pairs exchanging messages under a
//! simulated clock for a long time, with memory sampled by a counting
//! allocator. It passes when memory stays within the configured bounds and
//! shows no growth trend.
//!
//! Ignored by default. Run it with, for example, 100,000 pairs for 4 hours:
//!
//! ```sh
//! WS_NET_SOAK_PAIRS=100000 WS_NET_SOAK_SECS=14400 \
//!     cargo test --release --test soak -- --ignored --nocapture
//! ```
//!
//! Every pair is a client and a server joined in memory. Each step picks a
//! pair at random and does one thing: send a message (sizes from a
//! heavy-tailed distribution up to the budget), ping, deliver some of the
//! bytes in flight (slow readers take a little at a time), close and
//! replace the pair, release memory, or advance the clock.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

use ws_net::{CloseCode, Connection, Event, Keepalive, Limits, Millis};

struct Counting;

static CURRENT: AtomicUsize = AtomicUsize::new(0);

// SAFETY: forwards every call to the system allocator unchanged; the
// counter never affects the result.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract is passed on unchanged.
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            let _ = CURRENT.fetch_add(layout.size(), Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: as for `alloc`.
        unsafe { System.dealloc(ptr, layout) };
        let _ = CURRENT.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: as for `alloc`.
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            let _ = CURRENT.fetch_sub(layout.size(), Ordering::Relaxed);
            let _ = CURRENT.fetch_add(new_size, Ordering::Relaxed);
        }
        p
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// xorshift64*: a small deterministic generator for the workload.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }

    /// Heavy-tailed sizes: mostly small, sometimes up to `max`.
    fn size(&mut self, max: u64) -> usize {
        let bits = self.below(18);
        (self.next() % (1u64 << bits).min(max).max(1)) as usize
    }
}

const MAX_MESSAGE: u64 = 128 * 1024;
const MAX_OUTPUT: u64 = 256 * 1024;
const INPUT: usize = 4096;
const RETAIN: usize = 4096;

fn limits() -> Limits {
    Limits::new()
        .with_max_frame(MAX_MESSAGE)
        .with_max_message(MAX_MESSAGE)
        .with_max_output(MAX_OUTPUT)
        .with_input_buffer(INPUT)
        .with_retain(RETAIN)
}

fn keepalive() -> Keepalive {
    Keepalive::new()
        .with_ping_interval(Duration::from_secs(30))
        .with_idle_timeout(Duration::from_secs(600))
        .with_message_timeout(Duration::from_secs(120))
}

struct Pair {
    client: Connection,
    server: Connection,
}

fn pair(seed: u64) -> Pair {
    let mut s = [0u8; 32];
    s[..8].copy_from_slice(&seed.to_le_bytes());
    Pair {
        client: Connection::client_with_seed(s)
            .with_limits(limits())
            .with_keepalive(keepalive()),
        server: Connection::server()
            .with_limits(limits())
            .with_keepalive(keepalive()),
    }
}

/// Moves up to `budget` bytes from `from`'s output into `to`, and lets
/// `to` read them.
fn deliver(from: &mut Connection, to: &mut Connection, budget: usize) {
    let out = from.output();
    let take = out.len().min(budget);
    let mut chunk = out[..take].to_vec();
    from.advance_output(take);
    let mut rest = &mut chunk[..];
    while !rest.is_empty() {
        let n = to.feed(rest);
        rest = &mut rest[n..];
        loop {
            match to.poll() {
                Ok(Event::NeedInput) | Ok(Event::Closed) | Err(_) => break,
                Ok(_) => {}
            }
        }
        if n == 0 {
            break;
        }
    }
}

fn env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[test]
#[ignore = "long-running: set WS_NET_SOAK_SECS and WS_NET_SOAK_PAIRS"]
fn test_soak_memory_bounded_no_growth() {
    let pairs_n = env("WS_NET_SOAK_PAIRS", 10_000) as usize;
    let secs = env("WS_NET_SOAK_SECS", 60);
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let base = CURRENT.load(Ordering::Relaxed);
    let mut pairs: Vec<Pair> = (0..pairs_n).map(|i| pair(i as u64)).collect();
    let payload = vec![b'x'; MAX_MESSAGE as usize];
    let started = Instant::now();
    let mut clock = 0u64;
    let mut samples: Vec<usize> = Vec::new();
    let mut last_sample = Instant::now();
    let mut steps = 0u64;
    let mut replaced = 0u64;
    // At most this many pairs can be busy at their peak at once (the rest
    // drain or idle); every busy pair holds at most two input buffers, two
    // messages, and two outputs with growth slack.
    let per_busy =
        2 * (INPUT + 2 * MAX_MESSAGE as usize + 2 * (MAX_OUTPUT as usize + 262) + 64 * 1024);
    let inline = pairs_n * 2 * std::mem::size_of::<Connection>();
    while started.elapsed() < Duration::from_secs(secs) {
        for _ in 0..10_000 {
            steps += 1;
            let i = rng.below(pairs_n as u64) as usize;
            let p = &mut pairs[i];
            match rng.below(100) {
                0..=39 => {
                    let n = rng.size(MAX_MESSAGE);
                    let text = rng.below(2) == 0;
                    let c = &mut p.client;
                    let _ = if text {
                        c.send_text(std::str::from_utf8(&payload[..n]).unwrap_or(""))
                    } else {
                        c.send_binary(&payload[..n])
                    };
                }
                40..=49 => {
                    let n = rng.size(MAX_MESSAGE);
                    let _ = p.server.send_binary(&payload[..n]);
                }
                50..=54 => {
                    let _ = p.client.send_ping(b"soak");
                }
                55..=79 => {
                    // Slow readers take a little; fast ones take it all.
                    let budget = if rng.below(4) == 0 { 512 } else { usize::MAX };
                    deliver(&mut p.client, &mut p.server, budget);
                    deliver(&mut p.server, &mut p.client, budget);
                }
                80..=89 => {
                    p.client.release_memory();
                    p.server.release_memory();
                }
                90..=94 => {
                    clock += rng.below(5_000);
                    let _ = p.client.on_time(Millis(clock));
                    let _ = p.server.on_time(Millis(clock));
                }
                95..=96 => {
                    let _ = p.client.close(CloseCode::NORMAL, "soak");
                    deliver(&mut p.client, &mut p.server, usize::MAX);
                    deliver(&mut p.server, &mut p.client, usize::MAX);
                }
                _ => {
                    if p.server.state() == ws_net::State::Closed || rng.below(8) == 0 {
                        *p = pair(steps);
                        replaced += 1;
                    }
                }
            }
        }
        if last_sample.elapsed() >= Duration::from_secs(1) || samples.is_empty() {
            last_sample = Instant::now();
            let used = CURRENT.load(Ordering::Relaxed).saturating_sub(base);
            let held: usize = pairs
                .iter()
                .map(|p| p.client.memory_in_use() + p.server.memory_in_use())
                .sum();
            // Every byte the connections hold is within their budgets.
            for p in &pairs {
                assert!(p.client.memory_in_use() <= per_busy / 2);
                assert!(p.server.memory_in_use() <= per_busy / 2);
                assert!(p.client.buffered_output() as u64 <= MAX_OUTPUT + 262);
                assert!(p.server.buffered_output() as u64 <= MAX_OUTPUT + 262);
            }
            samples.push(used);
            if samples.len() % 60 == 1 {
                println!(
                    "{:>6} s: heap {:>8} KiB (connections {:>8} KiB, inline {} KiB), {} steps, {} replaced",
                    started.elapsed().as_secs(),
                    used / 1024,
                    held / 1024,
                    inline / 1024,
                    steps,
                    replaced
                );
            }
        }
    }
    // No growth trend: the mean of the last tenth of the samples is within
    // 10% (plus 1 MiB of noise) of the mean of the second tenth, after
    // warm-up.
    let n = samples.len();
    if n >= 20 {
        let tenth = n / 10;
        let mean = |s: &[usize]| s.iter().sum::<usize>() / s.len().max(1);
        let early = mean(&samples[tenth..2 * tenth]);
        let late = mean(&samples[n - tenth..]);
        println!(
            "early mean {} KiB, late mean {} KiB",
            early / 1024,
            late / 1024
        );
        assert!(
            late <= early + early / 10 + (1 << 20),
            "memory grew: {early} -> {late}"
        );
    }
}
