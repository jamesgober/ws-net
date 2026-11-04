//! Memory per connection, measured by a counting allocator: the peak heap
//! of each scenario against the formula in `docs/API.md` (Budgets and
//! memory), zero heap for an idle connection after `release_memory`, and
//! no allocation per message in steady state.
//!
//! The allocator counts every allocation of the process, so all scenarios
//! run in one test function, one after another.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicUsize, Ordering},
};

use ws_net::{
    CloseCode, Connection, Event, Keepalive, Limits, Millis, PreparedMessage, ServerHandshake,
    WsError,
};

struct Counting;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
/// Allocations larger than this fail (`usize::MAX`: none fail).
static FAIL_ABOVE: AtomicUsize = AtomicUsize::new(usize::MAX);

// SAFETY: every call forwards to the system allocator with the same layout
// and pointer; the counters are atomics and never affect the result.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract for `alloc` is passed on unchanged.
        if layout.size() > FAIL_ABOVE.load(Ordering::SeqCst) {
            return core::ptr::null_mut();
        }
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            let now = CURRENT.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
            let _ = PEAK.fetch_max(now, Ordering::SeqCst);
            let _ = ALLOCATIONS.fetch_add(1, Ordering::SeqCst);
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: as for `alloc`.
        unsafe { System.dealloc(ptr, layout) };
        let _ = CURRENT.fetch_sub(layout.size(), Ordering::SeqCst);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: as for `alloc`.
        if new_size > FAIL_ABOVE.load(Ordering::SeqCst) {
            return core::ptr::null_mut();
        }
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            let _ = CURRENT.fetch_sub(layout.size(), Ordering::SeqCst);
            let now = CURRENT.fetch_add(new_size, Ordering::SeqCst) + new_size;
            let _ = PEAK.fetch_max(now, Ordering::SeqCst);
            let _ = ALLOCATIONS.fetch_add(1, Ordering::SeqCst);
        }
        p
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// Starts a measurement: the peak restarts from the current use.
fn begin() -> usize {
    let now = CURRENT.load(Ordering::SeqCst);
    PEAK.store(now, Ordering::SeqCst);
    now
}

fn peak_since(base: usize) -> usize {
    PEAK.load(Ordering::SeqCst).saturating_sub(base)
}

fn allocations() -> usize {
    ALLOCATIONS.load(Ordering::SeqCst)
}

/// A masked client frame, built without allocating during measurement.
fn frame_into(out: &mut Vec<u8>, b0: u8, payload: &[u8]) {
    out.push(b0);
    let len = payload.len();
    if len < 126 {
        out.push(0x80 | len as u8);
    } else if len <= 0xFFFF {
        out.push(0x80 | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0x80 | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.extend_from_slice(&[0, 0, 0, 0]); // zero key: payload unchanged
    out.extend_from_slice(payload);
}

fn drive(conn: &mut Connection, wire: &[u8]) -> usize {
    let mut events = 0;
    let mut rest = wire;
    loop {
        let n = conn.feed(rest);
        rest = &rest[n..];
        loop {
            match conn.poll() {
                Ok(Event::NeedInput) => break,
                Ok(Event::Closed) | Err(_) => return events,
                Ok(_) => events += 1,
            }
        }
        if rest.is_empty() {
            return events;
        }
    }
}

#[test]
fn test_memory_per_connection_matches_formula() {
    // 1. Reassembly: a 4 MiB message in 64 KiB frames. Peak is the input
    //    buffer plus at most the message budget.
    let limits = Limits::new().with_max_message(4 << 20);
    let mut wire = Vec::new();
    let piece = vec![b'a'; 64 * 1024];
    for i in 0..64 {
        let b0 = match (i, i == 63) {
            (0, _) => 0x02,
            (_, true) => 0x80,
            _ => 0x00,
        };
        frame_into(&mut wire, b0, &piece);
    }
    let base = begin();
    let mut conn = Connection::server().with_limits(limits);
    assert_eq!(drive(&mut conn, &wire), 1);
    let peak = peak_since(base);
    let bound = limits.input_buffer() + (4 << 20);
    assert!(peak <= bound, "reassembly peak {peak} > {bound}");
    assert!(conn.memory_in_use() <= bound);
    drop(conn);

    // 2. Slow consumer: send until the output budget refuses. Peak is at
    //    most twice the budget plus headroom (vector doubling) and the
    //    64 KiB compaction slack.
    let limits = Limits::new().with_max_output(1 << 20);
    let base = begin();
    let mut conn = Connection::server().with_limits(limits);
    let chunk = [7u8; 1000];
    let mut sent = 0;
    while conn.send_binary(&chunk).is_ok() {
        sent += 1;
    }
    assert!(conn.buffered_output() as u64 <= limits.max_output());
    let peak = peak_since(base);
    let bound = 2 * ((1 << 20) + 256) + 64 * 1024;
    assert!(
        peak <= bound,
        "output peak {peak} > {bound} after {sent} sends"
    );
    drop(conn);

    // 3. Idle after release_memory: no heap held at all.
    let mut small = Vec::new();
    frame_into(&mut small, 0x81, b"hello");
    let base = begin();
    let mut conn = Connection::server();
    assert_eq!(drive(&mut conn, &small), 1);
    conn.send_text("reply").unwrap();
    let n = conn.output().len();
    conn.advance_output(n);
    conn.release_memory();
    assert_eq!(conn.memory_in_use(), 0);
    assert_eq!(CURRENT.load(Ordering::SeqCst), base);
    drop(conn);

    // 4. Steady state: after warm-up, receiving and sending small messages
    //    allocates nothing.
    let mut wire = Vec::new();
    for _ in 0..1000 {
        frame_into(&mut wire, 0x81, br#"{"jsonrpc":"2.0","id":1}"#);
        frame_into(&mut wire, 0x82, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        frame_into(&mut wire, 0x89, b"");
    }
    let mut conn = Connection::server();
    // Warm-up: one full round grows every buffer to its working size.
    let _ = drive(&mut conn, &wire);
    for _ in 0..100 {
        conn.send_text("ok").unwrap();
    }
    let n = conn.output().len();
    conn.advance_output(n);
    let before = allocations();
    for _ in 0..10 {
        let _ = drive(&mut conn, &wire);
        for _ in 0..100 {
            conn.send_text("ok").unwrap();
        }
        let n = conn.output().len();
        conn.advance_output(n);
    }
    assert_eq!(allocations() - before, 0, "allocations in steady state");

    // 5. The handshake record takes one allocation (FR-11): a browser's
    //    request, validated from raw bytes, and the 101 written into a
    //    buffer that already has room.
    let request: &[u8] = b"GET /chat HTTP/1.1\r\nHost: 127.0.0.1:53817\r\nConnection: Upgrade\r\n\
        Pragma: no-cache\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\
        Upgrade: websocket\r\nOrigin: http://127.0.0.1:53817\r\nSec-WebSocket-Version: 13\r\n\
        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: rpc.v1, rpc.v2\r\n\
        Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\r\n";
    let mut response = Vec::with_capacity(512);
    let before = allocations();
    let (handshake, _) = ServerHandshake::from_head(request).unwrap().unwrap();
    handshake.write_response(None, &mut response).unwrap();
    assert_eq!(allocations() - before, 1, "allocations per handshake");
    drop(handshake);

    // 6. More steady-state paths that allocate nothing once warm:
    //    fragmented messages after the reassembly buffer grew, automatic
    //    Pong replacement under a Ping flood, idle keepalive ticks, and
    //    prepared sends.
    let mut fragments = Vec::new();
    for _ in 0..100 {
        frame_into(&mut fragments, 0x01, b"part one, ");
        frame_into(&mut fragments, 0x89, b"ping");
        frame_into(&mut fragments, 0x80, b"part two");
    }
    let prepared = PreparedMessage::text("broadcast");
    let mut conn = Connection::server()
        .with_keepalive(Keepalive::new().with_ping_interval(core::time::Duration::from_secs(60)));
    let _ = conn.on_time(Millis(0));
    let _ = drive(&mut conn, &fragments);
    for _ in 0..100 {
        conn.send_prepared(&prepared).unwrap();
    }
    let n = conn.output().len();
    conn.advance_output(n);
    let before = allocations();
    for round in 0..10 {
        let _ = drive(&mut conn, &fragments);
        let _ = conn.on_time(Millis(round));
        for _ in 0..100 {
            conn.send_prepared(&prepared).unwrap();
        }
        let n = conn.output().len();
        conn.advance_output(n);
    }
    assert_eq!(
        allocations() - before,
        0,
        "allocations on fragments, pings, ticks, prepared"
    );

    //    And the Close echo.
    let mut close = Vec::new();
    frame_into(&mut close, 0x88, &[0x03, 0xE8]);
    let before = allocations();
    let _ = drive(&mut conn, &close);
    assert_eq!(conn.output(), [0x88, 0x02, 0x03, 0xE8]);
    assert_eq!(allocations() - before, 0, "allocations on the Close echo");
    drop(conn);

    // 7. Allocation failure fails the connection with 1011 instead of
    //    aborting the process (try_reserve on every reassembly growth).
    let limits = Limits::new()
        .with_max_frame(64 << 20)
        .with_max_message(64 << 20);
    let mut big = Vec::new();
    frame_into(&mut big, 0x82, &vec![1u8; 8 << 20]);
    let mut conn = Connection::server().with_limits(limits);
    FAIL_ABOVE.store(512 * 1024, Ordering::SeqCst);
    let mut result = Ok(Event::NeedInput);
    let mut rest = &big[..];
    while !rest.is_empty() && result.is_ok() {
        let n = conn.feed(rest);
        rest = &rest[n..];
        result = conn.poll().map(|_| Event::NeedInput);
    }
    FAIL_ABOVE.store(usize::MAX, Ordering::SeqCst);
    assert_eq!(result.unwrap_err(), WsError::AllocationFailed);
    assert_eq!(
        WsError::AllocationFailed.close_code(),
        Some(CloseCode::INTERNAL_ERROR)
    );
    assert_eq!(conn.output(), [0x88, 0x02, 0x03, 0xF3]);
}
