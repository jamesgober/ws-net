//! ws-net against tungstenite on the same bytes (spec workloads 1 to 3):
//! receiving 100,000 small masked messages and 1 MiB messages as a server,
//! sending 100,000 small messages in both roles, and accepting 10,000
//! browser-sized upgrade requests. UTF-8 validation is on and unmasked
//! client frames are refused in both.

use std::hint::black_box;

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use tungstenite::{
    Message,
    protocol::{Role, WebSocket, WebSocketConfig},
};
use ws_net::{Connection, Event, Limits, ServerHandshake};
use ws_net_bench_compare::{BROWSER_REQUEST, Memory, large_binary, large_text, small_messages};

fn ws_net_receive(wire: &[u8]) -> usize {
    let mut conn = Connection::server().with_limits(Limits::new().with_max_message(64 << 20));
    let mut rest = wire;
    let mut messages = 0;
    loop {
        match conn.poll() {
            Ok(Event::Text(t)) => {
                messages += 1;
                let _ = black_box(t.len());
            }
            Ok(Event::Binary(b)) => {
                messages += 1;
                let _ = black_box(b.len());
            }
            Ok(Event::NeedInput) if !rest.is_empty() => {
                let n = conn.feed(&rest[..rest.len().min(64 * 1024)]);
                rest = &rest[n..];
            }
            _ => return messages,
        }
    }
}

fn tungstenite_receive(wire: &[u8]) -> usize {
    let config = WebSocketConfig::default();
    let mut ws = WebSocket::from_raw_socket(
        Memory {
            input: wire,
            output: Vec::new(),
        },
        Role::Server,
        Some(config),
    );
    let mut messages = 0;
    loop {
        match ws.read() {
            Ok(Message::Text(t)) => {
                messages += 1;
                let _ = black_box(t.len());
            }
            Ok(Message::Binary(b)) => {
                messages += 1;
                let _ = black_box(b.len());
            }
            Ok(_) => {}
            Err(_) => return messages,
        }
    }
}

fn bench_receive(c: &mut Criterion) {
    let small = small_messages();
    let mut group = c.benchmark_group("receive_100k");
    group.sample_size(20);
    group.throughput(Throughput::Elements(100_000));
    group.bench_function("ws_net", |b| {
        b.iter(|| assert_eq!(ws_net_receive(black_box(&small)), 100_000))
    });
    group.bench_function("tungstenite", |b| {
        b.iter(|| assert_eq!(tungstenite_receive(black_box(&small)), 100_000))
    });
    group.finish();

    for (name, wire) in [
        ("receive_1mib_binary", large_binary()),
        ("receive_1mib_text", large_text()),
    ] {
        let mut group = c.benchmark_group(name);
        group.throughput(Throughput::Bytes(1 << 20));
        group.bench_function("ws_net", |b| {
            b.iter(|| assert_eq!(ws_net_receive(black_box(&wire)), 1))
        });
        group.bench_function("tungstenite", |b| {
            b.iter(|| assert_eq!(tungstenite_receive(black_box(&wire)), 1))
        });
        group.finish();
    }
}

const REPLY: &str = r#"{"jsonrpc":"2.0","result":true}"#;

fn bench_send(c: &mut Criterion) {
    for (name, server) in [("send_100k_server", true), ("send_100k_client", false)] {
        let mut group = c.benchmark_group(name);
        group.sample_size(20);
        group.throughput(Throughput::Elements(100_000));
        group.bench_function("ws_net", |b| {
            b.iter(|| {
                let mut conn = if server {
                    Connection::server()
                } else {
                    Connection::client()
                };
                let mut written = 0;
                for i in 0..100_000 {
                    let _ = conn.send_text(REPLY);
                    if i % 64 == 63 {
                        let n = conn.output().len();
                        written += n;
                        conn.advance_output(n);
                    }
                }
                black_box(written + conn.output().len())
            })
        });
        group.bench_function("tungstenite", |b| {
            b.iter(|| {
                let role = if server { Role::Server } else { Role::Client };
                let mut ws = WebSocket::from_raw_socket(
                    Memory {
                        input: &[],
                        output: Vec::new(),
                    },
                    role,
                    None,
                );
                for i in 0..100_000 {
                    let _ = ws.write(Message::text(REPLY));
                    if i % 64 == 63 {
                        let _ = ws.flush();
                        ws.get_mut().output.clear();
                    }
                }
                let _ = ws.flush();
                black_box(ws.get_ref().output.len())
            })
        });
        group.finish();
    }
}

fn bench_handshake(c: &mut Criterion) {
    let mut group = c.benchmark_group("handshake_10k");
    group.sample_size(10);
    group.throughput(Throughput::Elements(10_000));
    group.bench_function("ws_net_from_head", |b| {
        b.iter(|| {
            let mut out = Vec::with_capacity(256);
            for _ in 0..10_000 {
                out.clear();
                if let Ok(Some((h, _))) = ServerHandshake::from_head(black_box(BROWSER_REQUEST)) {
                    let _ = h.write_response(None, &mut out);
                }
            }
            black_box(out.len())
        })
    });
    group.bench_function("ws_net_accept", |b| {
        b.iter(|| {
            let mut n = 0;
            for _ in 0..10_000 {
                if let Ok(Some(a)) = ws_net::accept(black_box(BROWSER_REQUEST)) {
                    n += a.response.len();
                }
            }
            black_box(n)
        })
    });
    group.bench_function("tungstenite_accept", |b| {
        b.iter_batched(
            || (),
            |()| {
                let mut n = 0;
                for _ in 0..10_000 {
                    let stream = Memory {
                        input: black_box(BROWSER_REQUEST),
                        output: Vec::new(),
                    };
                    if let Ok(ws) = tungstenite::accept(stream) {
                        n += ws.get_ref().output.len();
                    }
                }
                black_box(n)
            },
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

criterion_group!(benches, bench_receive, bench_send, bench_handshake);
criterion_main!(benches);
