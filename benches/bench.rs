//! Criterion benchmarks at realistic scale.
//!
//! - `receive_100k`: a server parsing 100,000 small masked messages (half
//!   text, half binary) in 64 KiB reads.
//! - `receive_1mib`: one 1 MiB masked binary message, and one 1 MiB text
//!   message (UTF-8 validated), in 64 KiB reads.
//! - `send_100k`: a client serializing and masking 100,000 small messages.
//! - `mask_1mib`: masking 1 MiB in place.
//! - `accept_key`: the handshake's SHA-1 + base64.
//! - `handshake/from_head`: validating a browser-sized upgrade request from
//!   raw bytes, 100,000 times (one per connection a busy server accepts).
//! - `handshake/head_reader_bytewise`: the same request fed one byte per
//!   call to a `HeadReader` (linear, not quadratic).
//! - `broadcast/prepared_10k`: one prepared message appended to 10,000
//!   server connections.
//! - `keepalive/on_time_idle`: `on_time` with nothing due, 100,000 times.
//! - `flood/empty_continuations`: 1,000,000 empty continuation frames
//!   inside one message.

use std::{hint::black_box, time::Duration};

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use ws_net::{
    Connection, Event, HeadReader, Keepalive, Millis, PreparedMessage, ServerHandshake, accept_key,
    frame::apply_mask,
};

fn client_wire(build: impl FnOnce(&mut Connection)) -> Vec<u8> {
    let mut client = Connection::client_with_seed([7; 32]);
    build(&mut client);
    client.output().to_vec()
}

/// Feeds `wire` in 64 KiB reads and counts delivered messages.
fn receive_all(conn: &mut Connection, wire: &[u8]) -> usize {
    let mut pending = wire;
    let mut messages = 0;
    loop {
        match conn.poll() {
            Ok(Event::Text(t)) => {
                black_box(t);
                messages += 1;
            }
            Ok(Event::Binary(b)) => {
                black_box(b);
                messages += 1;
            }
            Ok(Event::NeedInput) => {
                if pending.is_empty() {
                    return messages;
                }
                let n = conn.feed(&pending[..pending.len().min(64 * 1024)]);
                pending = &pending[n..];
            }
            _ => return messages,
        }
    }
}

fn bench_receive_small(c: &mut Criterion) {
    let wire = client_wire(|client| {
        for i in 0..100_000u32 {
            if i % 2 == 0 {
                client
                    .send_text("{\"jsonrpc\":\"2.0\",\"method\":\"ping\"}")
                    .unwrap_or_default();
            } else {
                client
                    .send_binary(&[1, 0, 0, 0, 7, 0, 0, 0, 42, 42])
                    .unwrap_or_default();
            }
        }
    });
    let mut group = c.benchmark_group("receive_100k");
    group.sample_size(20);
    group.throughput(Throughput::Elements(100_000));
    group.bench_function("small_messages", |b| {
        b.iter_batched(
            || (Connection::server(), wire.clone()),
            |(mut conn, wire)| assert_eq!(receive_all(&mut conn, &wire), 100_000),
            BatchSize::LargeInput,
        )
    });
    group.finish();
}

fn bench_receive_large(c: &mut Criterion) {
    let binary = client_wire(|client| client.send_binary(&vec![0x5a; 1 << 20]).unwrap_or_default());
    let text = client_wire(|client| {
        client
            .send_text(&"é-ascii-mix ".repeat(1 << 20 >> 4))
            .unwrap_or_default()
    });
    let mut group = c.benchmark_group("receive_1mib");
    group.throughput(Throughput::Bytes(1 << 20));
    group.bench_function("binary", |b| {
        b.iter_batched(
            || (Connection::server(), binary.clone()),
            |(mut conn, wire)| assert_eq!(receive_all(&mut conn, &wire), 1),
            BatchSize::LargeInput,
        )
    });
    group.bench_function("text_utf8", |b| {
        b.iter_batched(
            || (Connection::server(), text.clone()),
            |(mut conn, wire)| assert_eq!(receive_all(&mut conn, &wire), 1),
            BatchSize::LargeInput,
        )
    });
    group.finish();
}

fn bench_send(c: &mut Criterion) {
    let mut group = c.benchmark_group("send_100k");
    group.sample_size(20);
    group.throughput(Throughput::Elements(100_000));
    group.bench_function("client_masked", |b| {
        b.iter(|| {
            let mut client = Connection::client_with_seed([1; 32]);
            for _ in 0..100_000 {
                client
                    .send_text("{\"jsonrpc\":\"2.0\",\"result\":true}")
                    .unwrap_or_default();
            }
            black_box(client.output().len())
        })
    });
    #[cfg(feature = "std")]
    group.bench_function("client_masked_os", |b| {
        b.iter(|| {
            let mut client = Connection::client();
            for _ in 0..100_000 {
                client
                    .send_text("{\"jsonrpc\":\"2.0\",\"result\":true}")
                    .unwrap_or_default();
            }
            black_box(client.output().len())
        })
    });
    group.bench_function("server_unmasked", |b| {
        b.iter(|| {
            let mut server = Connection::server();
            for _ in 0..100_000 {
                server
                    .send_text("{\"jsonrpc\":\"2.0\",\"result\":true}")
                    .unwrap_or_default();
            }
            black_box(server.output().len())
        })
    });
    group.finish();
}

fn bench_mask(c: &mut Criterion) {
    let mut data = vec![0u8; 1 << 20];
    let mut group = c.benchmark_group("mask_1mib");
    group.throughput(Throughput::Bytes(1 << 20));
    group.bench_function("in_place", |b| {
        b.iter(|| apply_mask(black_box(&mut data), [1, 2, 3, 4], 1))
    });
    group.finish();
}

fn bench_accept_key(c: &mut Criterion) {
    c.bench_function("accept_key", |b| {
        b.iter(|| accept_key(black_box(b"dGhlIHNhbXBsZSBub25jZQ==")))
    });
}

/// A request head the size a browser sends (about 500 bytes, 12 fields).
const BROWSER_REQUEST: &[u8] = b"GET /rpc HTTP/1.1\r\n\
Host: 127.0.0.1:53817\r\n\
Connection: Upgrade\r\n\
Pragma: no-cache\r\n\
Cache-Control: no-cache\r\n\
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36\r\n\
Upgrade: websocket\r\n\
Origin: http://127.0.0.1:53817\r\n\
Sec-WebSocket-Version: 13\r\n\
Accept-Encoding: gzip, deflate, br, zstd\r\n\
Accept-Language: en-US,en;q=0.9\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\r\n";

fn bench_handshake(c: &mut Criterion) {
    let mut group = c.benchmark_group("handshake");
    group.sample_size(20);
    group.throughput(Throughput::Elements(100_000));
    group.bench_function("from_head_100k", |b| {
        b.iter(|| {
            let mut out = Vec::with_capacity(256);
            for _ in 0..100_000 {
                out.clear();
                if let Ok(Some((hs, _))) = ServerHandshake::from_head(black_box(BROWSER_REQUEST)) {
                    let _ = hs.write_response(None, &mut out);
                }
            }
            black_box(out.len())
        })
    });
    group.finish();
}

fn bench_head_reader(c: &mut Criterion) {
    let mut group = c.benchmark_group("handshake");
    group.sample_size(20);
    group.throughput(Throughput::Bytes(BROWSER_REQUEST.len() as u64));
    group.bench_function("head_reader_bytewise", |b| {
        b.iter(|| {
            let mut reader = HeadReader::new();
            let mut done = 0;
            for end in 1..=BROWSER_REQUEST.len() {
                if let Ok(Some((_, len))) = reader.server(black_box(&BROWSER_REQUEST[..end])) {
                    done = len;
                    break;
                }
            }
            black_box(done)
        })
    });
    group.finish();
}

fn bench_broadcast(c: &mut Criterion) {
    let mut group = c.benchmark_group("broadcast");
    group.sample_size(20);
    group.throughput(Throughput::Elements(10_000));
    let message = PreparedMessage::text(r#"{"jsonrpc":"2.0","method":"tick","params":[1]}"#);
    let mut conns: Vec<Connection> = (0..10_000).map(|_| Connection::server()).collect();
    group.bench_function("prepared_10k", |b| {
        b.iter(|| {
            for conn in &mut conns {
                let _ = conn.send_prepared(black_box(&message));
                let n = conn.output().len();
                conn.advance_output(n);
            }
        })
    });
    group.finish();
}

fn bench_keepalive(c: &mut Criterion) {
    let mut group = c.benchmark_group("keepalive");
    group.throughput(Throughput::Elements(100_000));
    let k = Keepalive::new()
        .with_ping_interval(Duration::from_secs(30))
        .with_idle_timeout(Duration::from_secs(75));
    let mut conn = Connection::server().with_keepalive(k);
    let _ = conn.on_time(Millis(0));
    group.bench_function("on_time_idle", |b| {
        b.iter(|| {
            for t in 0..100_000u64 {
                let _ = black_box(conn.on_time(Millis(black_box(t % 1000))));
            }
        })
    });
    group.finish();
}

fn bench_flood(c: &mut Criterion) {
    let mut group = c.benchmark_group("flood");
    group.sample_size(10);
    let mut wire = client_wire(|c| c.send_text_fragment("a", false).unwrap());
    // An empty masked continuation: 0x00 0x80 + a 4-byte key.
    let cont = [0x00u8, 0x80, 1, 2, 3, 4];
    for _ in 0..1_000_000 {
        wire.extend_from_slice(&cont);
    }
    wire.extend_from_slice(&[0x80, 0x80, 1, 2, 3, 4]);
    group.throughput(Throughput::Elements(1_000_000));
    group.bench_function("empty_continuations", |b| {
        b.iter_batched(
            Connection::server,
            |mut conn| black_box(receive_all(&mut conn, &wire)),
            BatchSize::LargeInput,
        )
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_receive_small,
    bench_receive_large,
    bench_send,
    bench_mask,
    bench_accept_key,
    bench_handshake,
    bench_head_reader,
    bench_broadcast,
    bench_keepalive,
    bench_flood
);
criterion_main!(benches);
