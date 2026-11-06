//! The socket-level soak: clients over loopback against ws-net on net-io's
//! reactor, each sending messages of random size (heavy-tailed, up to
//! 256 KiB), Pings, and now and then closing and reconnecting. The heap of
//! the whole process (server and clients) is sampled by a counting
//! allocator. Pass: every echo intact, no growth between the second tenth
//! and the last tenth of the samples, every connection closed at the end.
//!
//! Ignored by default:
//!
//! ```sh
//! WS_NET_NETIO_SOAK_CONNS=500 WS_NET_NETIO_SOAK_SECS=3600 \
//!     cargo test --release --test soak -- --ignored --nocapture
//! ```
//!
//! More knobs: `WS_NET_NETIO_SOAK_DRIVER=blocking` (the reactor otherwise),
//! `WS_NET_NETIO_SOAK_TOP_BITS` (largest message 2^bits, 18 by default),
//! `WS_NET_NETIO_SOAK_RECONNECT=0` (no close-and-reconnect).

use std::{
    alloc::{GlobalAlloc, Layout, System},
    net::{SocketAddr, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use net_io::{DriverKind, Limits, PrefixPolicy};
use ws_net::{ClientHandshake, CloseCode, Message, blocking};
use ws_net_interop_net_io::start_with;

struct Counting;

static HEAP: AtomicUsize = AtomicUsize::new(0);

/// The longest a 50 ms sleep overslept since the last sample, in ms: a gap
/// of seconds means the process was not scheduled (the host, not net-io).
static SCHED_GAP: AtomicU64 = AtomicU64::new(0);

// SAFETY: forwards to the system allocator and only counts.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        HEAP.fetch_add(layout.size(), Ordering::Relaxed);
        // SAFETY: the caller's contract is passed through.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        HEAP.fetch_sub(layout.size(), Ordering::Relaxed);
        // SAFETY: the caller's contract is passed through.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new: usize) -> *mut u8 {
        HEAP.fetch_add(new, Ordering::Relaxed);
        HEAP.fetch_sub(layout.size(), Ordering::Relaxed);
        // SAFETY: the caller's contract is passed through.
        unsafe { System.realloc(ptr, layout, new) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// xorshift64*: reproducible per client.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// Mostly small, sometimes large: 16 B to 256 KiB.
    fn size(&mut self) -> usize {
        let top = env("WS_NET_NETIO_SOAK_TOP_BITS", 18).clamp(4, 24);
        let bits = 4 + self.next() % (top - 3);
        (self.next() % (1 << bits)) as usize
    }
}

fn connect(addr: SocketAddr) -> blocking::WebSocket<TcpStream> {
    let stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    let host = addr.to_string();
    blocking::connect_with(stream, &host, "/", &ClientHandshake::new())
        .unwrap()
        .0
}

/// Reads until the closing handshake ends; anything but `Closed` is a
/// failure of the run.
fn finish_close(ws: &mut blocking::WebSocket<TcpStream>) {
    loop {
        match ws.read() {
            Ok(_) => {}
            Err(blocking::Error::Closed) => return,
            Err(e) => panic!("closing: {e}"),
        }
    }
}

/// What one client is doing, for the stall report.
#[derive(Default)]
struct Progress {
    /// The operation (1 close, 2 Ping, 3 message) and its length.
    op: AtomicU64,
    /// Milliseconds since the start when the last operation finished.
    done_at: AtomicU64,
}

fn client(
    addr: SocketAddr,
    seed: u64,
    stop: &AtomicBool,
    messages: &AtomicU64,
    progress: &Progress,
    epoch: Instant,
) {
    let mut rng = Rng(seed | 1);
    let mut ws = connect(addr);
    while !stop.load(Ordering::Relaxed) {
        let ms = epoch.elapsed().as_millis() as u64;
        progress.done_at.store(ms, Ordering::Relaxed);
        match rng.next() % 1000 {
            0 if env("WS_NET_NETIO_SOAK_RECONNECT", 1) == 1 => {
                // Close and come back.
                progress.op.store(1 << 32, Ordering::Relaxed);
                ws.close(CloseCode::NORMAL, "").unwrap();
                finish_close(&mut ws);
                ws = connect(addr);
            }
            1..=20 => {
                progress.op.store(2 << 32, Ordering::Relaxed);
                let payload = rng.next().to_be_bytes();
                ws.ping(&payload).unwrap();
                assert_eq!(ws.read().unwrap(), Message::Pong(payload.to_vec()));
            }
            _ => {
                let len = rng.size();
                progress.op.store(3 << 32 | len as u64, Ordering::Relaxed);
                let fill = rng.next() as u8;
                let data: Vec<u8> = (0..len).map(|i| fill.wrapping_add(i as u8)).collect();
                ws.send_binary(&data).unwrap();
                assert_eq!(ws.read().unwrap(), Message::Binary(data));
                messages.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    ws.close(CloseCode::NORMAL, "").unwrap();
    finish_close(&mut ws);
}

#[test]
#[ignore = "long: run with --ignored, sized by WS_NET_NETIO_SOAK_CONNS and WS_NET_NETIO_SOAK_SECS"]
fn soak_reactor_over_loopback() {
    let conns = env("WS_NET_NETIO_SOAK_CONNS", 200);
    let secs = env("WS_NET_NETIO_SOAK_SECS", 60);
    let driver = if std::env::var("WS_NET_NETIO_SOAK_DRIVER").as_deref() == Ok("blocking") {
        DriverKind::Blocking
    } else {
        DriverKind::Reactor
    };
    // The blocking pool holds one connection per worker, and a closing
    // connection keeps its worker while its client already reconnects:
    // twice the clients leaves room for the churn.
    let workers = if driver == DriverKind::Blocking {
        (conns as u16).saturating_mul(2)
    } else {
        8
    };
    // A loaded machine can leave a client quiet for seconds: net-io's idle
    // timeout (5 s on the blocking driver) must not end a soak connection.
    let limits = Limits::builder()
        .max_connections(4096)
        .max_per_source(4096, PrefixPolicy::DEFAULT)
        .idle_timeout(Duration::from_secs(600))
        // 128 KiB per blocking worker at least; the reactor's default.
        .buffer_budget(512 << 20)
        .build()
        .unwrap();
    let (server, addr) = start_with(driver, workers, limits).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let messages = Arc::new(AtomicU64::new(0));
    // net-io reserves its buffer pool up front (512 MiB on the reactor by
    // default): that is the baseline, not the connections.
    let baseline = HEAP.load(Ordering::Relaxed);
    println!(
        "baseline {} KiB, {conns} connections, {secs} s",
        baseline / 1024
    );
    let progress: Arc<Vec<Progress>> = Arc::new((0..conns).map(|_| Progress::default()).collect());
    let start = Instant::now();
    let clients: Vec<_> = (0..conns)
        .map(|c| {
            let (stop, messages, progress) = (
                Arc::clone(&stop),
                Arc::clone(&messages),
                Arc::clone(&progress),
            );
            thread::Builder::new()
                .stack_size(256 * 1024)
                .spawn(move || {
                    let p = &progress[c as usize];
                    client(addr, 0x9e37_79b9 * (c + 1), &stop, &messages, p, start);
                })
                .unwrap()
        })
        .collect();

    {
        let stop = Arc::clone(&stop);
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let t = Instant::now();
                thread::sleep(Duration::from_millis(50));
                let over = (t.elapsed().as_millis() as u64).saturating_sub(50);
                SCHED_GAP.fetch_max(over, Ordering::Relaxed);
            }
        });
    }
    let every = Duration::from_secs((secs / 20).clamp(1, 60));
    let mut samples = Vec::new();
    while start.elapsed() < Duration::from_secs(secs) {
        thread::sleep(every);
        let heap = HEAP.load(Ordering::Relaxed);
        let stats = server.stats();
        println!(
            "{:6} s: heap {:8} KiB, open {:5}, accepted {:7}, messages {:10}, sched gap {:5} ms",
            start.elapsed().as_secs(),
            heap / 1024,
            stats.open,
            stats.accepted,
            messages.load(Ordering::Relaxed),
            SCHED_GAP.swap(0, Ordering::Relaxed)
        );
        samples.push(heap);
        let now = start.elapsed().as_millis() as u64;
        for (c, p) in progress.iter().enumerate() {
            let since = now.saturating_sub(p.done_at.load(Ordering::Relaxed));
            if since > 5_000 {
                let op = p.op.load(Ordering::Relaxed);
                println!(
                    "  client {c} stalled {since} ms in op {} len {}",
                    op >> 32,
                    op as u32
                );
            }
        }
    }
    stop.store(true, Ordering::Relaxed);
    for c in clients {
        c.join().expect("a client failed");
    }

    let wait = Instant::now();
    while server.stats().open > 0 {
        assert!(
            wait.elapsed() < Duration::from_secs(30),
            "connections left open"
        );
        thread::sleep(Duration::from_millis(50));
    }
    let tenth = (samples.len() / 10).max(1);
    let early = samples[tenth..2 * tenth].iter().max().copied().unwrap_or(0);
    let late = samples[samples.len() - tenth..]
        .iter()
        .max()
        .copied()
        .unwrap_or(0);
    println!(
        "early {} KiB, late {} KiB, after close {} KiB (baseline {} KiB), {} messages",
        early / 1024,
        late / 1024,
        HEAP.load(Ordering::Relaxed) / 1024,
        baseline / 1024,
        messages.load(Ordering::Relaxed)
    );
    // Heavy-tailed sizes make single samples noisy: allow a margin of one
    // large message per connection, not a trend.
    let margin = conns as usize * 2 * 256 * 1024;
    assert!(late <= early + margin, "heap grew: {early} -> {late}");
    let _ = server.shutdown(Instant::now() + Duration::from_secs(5));
}
