//! The end-to-end echo benchmark (the plan's row 4): echo servers over
//! loopback, driven by one client for all of them, each client connection a
//! thread doing round trips (send one message, read its echo).
//!
//! - ws-net on net-io's reactor,
//! - ws-net on net-io's blocking pool,
//! - tungstenite 0.30.0, one thread per connection on `std::net`.
//!
//! ```sh
//! cargo run --release --example e2e            # 3 s per cell
//! E2E_SECS=10 cargo run --release --example e2e
//! ```
//!
//! Round trips measure latency as much as throughput; on a shared machine
//! compare within one run only.

use std::{
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use net_io::{DriverKind, Limits, PrefixPolicy};
use ws_net::{ClientHandshake, CloseCode, Message, blocking};
use ws_net_interop_net_io::start_with;

/// A tungstenite echo server: one thread per connection.
fn tungstenite_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || {
                let _ = stream.set_nodelay(true);
                let Ok(mut ws) = tungstenite::accept(stream) else {
                    return;
                };
                while let Ok(msg) = ws.read() {
                    if msg.is_close() {
                        break;
                    }
                    if (msg.is_binary() || msg.is_text()) && ws.send(msg).is_err() {
                        break;
                    }
                }
                let _ = ws.flush();
            });
        }
    });
    addr
}

fn client(addr: SocketAddr, payload: usize, stop: &AtomicBool, count: &AtomicU64, go: &Barrier) {
    let stream = TcpStream::connect(addr).unwrap();
    stream.set_nodelay(true).unwrap();
    let host = addr.to_string();
    let (mut ws, _) = blocking::connect_with(stream, &host, "/", &ClientHandshake::new()).unwrap();
    let data = vec![0x5a; payload];
    go.wait();
    let mut n = 0u64;
    while !stop.load(Ordering::Relaxed) {
        ws.send_binary(&data).unwrap();
        match ws.read().unwrap() {
            Message::Binary(echo) => assert_eq!(echo.len(), payload),
            other => panic!("{other:?}"),
        }
        n += 1;
    }
    count.fetch_add(n, Ordering::Relaxed);
    let _ = ws.close(CloseCode::NORMAL, "");
    while ws.read().is_ok() {}
}

/// Messages per second over `conns` connections for `secs`.
fn run(addr: SocketAddr, conns: usize, payload: usize, secs: u64) -> f64 {
    let stop = Arc::new(AtomicBool::new(false));
    let count = Arc::new(AtomicU64::new(0));
    let go = Arc::new(Barrier::new(conns + 1));
    let threads: Vec<_> = (0..conns)
        .map(|_| {
            let (stop, count, go) = (Arc::clone(&stop), Arc::clone(&count), Arc::clone(&go));
            thread::spawn(move || client(addr, payload, &stop, &count, &go))
        })
        .collect();
    go.wait();
    let start = Instant::now();
    thread::sleep(Duration::from_secs(secs));
    stop.store(true, Ordering::Relaxed);
    let elapsed = start.elapsed().as_secs_f64();
    for t in threads {
        t.join().unwrap();
    }
    count.load(Ordering::Relaxed) as f64 / elapsed
}

fn main() {
    let secs = std::env::var("E2E_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);
    let cpus = thread::available_parallelism().map_or(4, |n| n.get()) as u16;
    // A connection waits at the start barrier while the others connect, and
    // a busy runner may starve one for seconds: net-io's idle timeout (5 s
    // on the blocking driver) must not end a benchmark connection.
    let limits = || {
        Limits::builder()
            .max_connections(4096)
            .max_per_source(4096, PrefixPolicy::DEFAULT)
            .idle_timeout(Duration::from_secs(600))
            .build()
            .unwrap()
    };
    let (reactor, reactor_addr) = start_with(DriverKind::Reactor, cpus, limits()).unwrap();
    let (pool, pool_addr) = start_with(DriverKind::Blocking, 80, limits()).unwrap();
    let tung_addr = tungstenite_server();

    println!(
        "| Connections | Payload | ws-net on reactor | ws-net on blocking pool | tungstenite | reactor / tungstenite |"
    );
    println!("|---:|---:|---:|---:|---:|---:|");
    for conns in [1, 16, 64] {
        for payload in [16, 1024, 64 * 1024] {
            let r = run(reactor_addr, conns, payload, secs);
            let b = run(pool_addr, conns, payload, secs);
            let t = run(tung_addr, conns, payload, secs);
            println!(
                "| {conns} | {payload} B | {r:.0}/s | {b:.0}/s | {t:.0}/s | {:.2} |",
                r / t
            );
        }
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    let _ = reactor.shutdown(deadline);
    let _ = pool.shutdown(deadline);
}
