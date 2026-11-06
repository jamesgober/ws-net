//! Where the time goes in the 1 MiB receive rows: time, heap allocations,
//! and minor page faults (Linux, from `/proc/self/stat`) per message, for
//! ws-net on a fresh connection each time (as `compare` measures it), ws-net
//! on one connection reused, and tungstenite on a fresh socket each time.
//!
//! ```sh
//! cargo run --release --example faults
//! ```

use std::{
    alloc::{GlobalAlloc, Layout, System},
    hint::black_box,
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

use tungstenite::{
    Message,
    protocol::{Role, WebSocket, WebSocketConfig},
};
use ws_net::{Connection, Event, Limits};
use ws_net_bench_compare::{Memory, large_binary, large_text};

struct Counting;

static ALLOCS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// Minor page faults so far (Linux only).
fn minor_faults() -> Option<u64> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    // Fields after the parenthesized command; minflt is field 10 overall.
    let rest = stat.rsplit_once(')')?.1;
    rest.split_whitespace().nth(7)?.parse().ok()
}

fn receive(conn: &mut Connection, wire: &[u8]) -> usize {
    let mut rest = wire;
    loop {
        match conn.poll() {
            Ok(Event::Text(t)) => return black_box(t.len()),
            Ok(Event::Binary(b)) => return black_box(b.len()),
            Ok(Event::NeedInput) if !rest.is_empty() => {
                let n = conn.feed(&rest[..rest.len().min(64 * 1024)]);
                rest = &rest[n..];
            }
            _ => return 0,
        }
    }
}

fn limits() -> Limits {
    Limits::new().with_max_message(64 << 20)
}

fn tungstenite(wire: &[u8]) -> usize {
    let mut ws = WebSocket::from_raw_socket(
        Memory {
            input: wire,
            output: Vec::new(),
        },
        Role::Server,
        Some(WebSocketConfig::default()),
    );
    match ws.read() {
        Ok(Message::Text(t)) => black_box(t.len()),
        Ok(Message::Binary(b)) => black_box(b.len()),
        _ => 0,
    }
}

fn measure(name: &str, iters: u32, mut f: impl FnMut() -> usize) {
    for _ in 0..20 {
        assert_eq!(f(), 1 << 20, "{name}");
    }
    let (a0, b0, f0) = (
        ALLOCS.load(Ordering::Relaxed),
        BYTES.load(Ordering::Relaxed),
        minor_faults(),
    );
    let start = Instant::now();
    for _ in 0..iters {
        assert!(f() > 0);
    }
    let per = start.elapsed().as_secs_f64() * 1e6 / f64::from(iters);
    let allocs = (ALLOCS.load(Ordering::Relaxed) - a0) as f64 / f64::from(iters);
    let kib = (BYTES.load(Ordering::Relaxed) - b0) as f64 / 1024.0 / f64::from(iters);
    let faults = match (f0, minor_faults()) {
        (Some(a), Some(b)) => format!("{:.1}", (b - a) as f64 / f64::from(iters)),
        _ => "n/a".into(),
    };
    println!("| {name} | {per:.0} µs | {allocs:.1} | {kib:.0} KiB | {faults} |");
}

/// Plain memory, no WebSocket: 1 MiB copied in 64 KiB pieces from one
/// 64 KiB buffer into a destination made by `dest`, as ws-net reassembles.
fn copy_into(src: &[u8], mut dest: impl FnMut() -> Vec<u8>) -> usize {
    let mut out = dest();
    for _ in 0..16 {
        out.extend_from_slice(src);
    }
    black_box(out.len())
}

fn main() {
    let iters = 300;
    println!("| Case | Time per message | Allocations | Bytes allocated | Minor faults |");
    println!("|---|---:|---:|---:|---:|");
    let src = vec![0x5a_u8; 64 * 1024];
    measure("memcpy: fresh 1 MiB each time", iters, || {
        copy_into(&src, || Vec::with_capacity(1 << 20))
    });
    measure("memcpy: fresh 1 MiB + 4 KiB each time", iters, || {
        copy_into(&src, || Vec::with_capacity((1 << 20) + 4096))
    });
    measure("memcpy: fresh 1 MiB + 64 B each time", iters, || {
        copy_into(&src, || Vec::with_capacity((1 << 20) + 64))
    });
    let mut kept = Vec::with_capacity(1 << 20);
    measure("memcpy: one 1 MiB buffer kept", iters, || {
        kept.clear();
        for _ in 0..16 {
            kept.extend_from_slice(&src);
        }
        black_box(kept.len())
    });
    for (kind, wire) in [("binary", large_binary()), ("text", large_text())] {
        // Each case must deliver the whole message every time.
        let len = receive(&mut Connection::server().with_limits(limits()), &wire);
        let check = move |n: usize| n == len;
        measure(&format!("{kind}: ws-net, fresh connection"), iters, || {
            let n = receive(&mut Connection::server().with_limits(limits()), &wire);
            if check(n) { 1 << 20 } else { 0 }
        });
        let mut conn = Connection::server().with_limits(limits());
        measure(
            &format!("{kind}: ws-net, one connection reused"),
            iters,
            || {
                let n = receive(&mut conn, &wire);
                if check(n) { 1 << 20 } else { 0 }
            },
        );
        // Retain lifted: the reassembly buffer is kept, so this is the
        // parse alone (no allocation, no fresh pages).
        let mut kept = Connection::server().with_limits(limits().with_retain(2 << 20));
        measure(
            &format!("{kind}: ws-net, reused, buffer kept"),
            iters,
            || {
                let n = receive(&mut kept, &wire);
                if check(n) { 1 << 20 } else { 0 }
            },
        );
        // One factor at a time against the crate's own benchmark (default
        // limits, the wire cloned per iteration).
        measure(
            &format!("{kind}: ws-net, default limits, fresh"),
            iters,
            || {
                let n = receive(&mut Connection::server(), &wire);
                if check(n) { 1 << 20 } else { 0 }
            },
        );
        measure(
            &format!("{kind}: ws-net, fresh, wire cloned each time"),
            iters,
            || {
                let copy = wire.clone();
                let n = receive(&mut Connection::server().with_limits(limits()), &copy);
                if check(n) { 1 << 20 } else { 0 }
            },
        );
        measure(&format!("{kind}: tungstenite, fresh socket"), iters, || {
            let n = tungstenite(&wire);
            if check(n) { 1 << 20 } else { 0 }
        });
    }
}
