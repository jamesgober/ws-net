//! A buffer that held message bytes went back to the
//! allocator with them still in it whenever it was freed or regrown in
//! normal operation (a message over `retain`, a large send once written,
//! a reassembly buffer doubling, `release_memory`), so [`wipe`] could not
//! reach those copies. Now every such buffer is zeroed first.
//!
//! A global allocator scans every block freed while the test runs for a
//! marker. `realloc` is not overridden, so a reallocation is an allocation,
//! a copy, and a scanned free of the old block. One test only: the scan is
//! global to this binary.
//!
//! [`wipe`]: ws_net::Connection::wipe

mod common;

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use common::client_frame;
use ws_net::{Connection, Event};

const MARKER: &[u8] = b"SECRET-SESSION-TOKEN-7f3a";

static ARMED: AtomicBool = AtomicBool::new(false);
static FOUND: AtomicUsize = AtomicUsize::new(0);

struct Scan;

// SAFETY: every call forwards to `System` with the same arguments; the
// scan only reads the block being freed, which is valid for
// `layout.size()` bytes until it is handed back.
unsafe impl GlobalAlloc for Scan {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::SeqCst) && layout.size() >= MARKER.len() {
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            if block.windows(MARKER.len()).any(|w| w == MARKER) {
                FOUND.fetch_add(1, Ordering::SeqCst);
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Scan = Scan;

/// `len` bytes of letters (compressible about twice, not more) with the
/// marker in the middle.
fn secret(len: usize) -> String {
    let mut x = 7u32;
    let mut text: Vec<u8> = (0..len)
        .map(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            b'a' + ((x >> 16) % 26) as u8
        })
        .collect();
    let mid = len / 2;
    text[mid..mid + MARKER.len()].copy_from_slice(MARKER);
    String::from_utf8(text).unwrap()
}

/// Feeds `wire` in 4 KiB reads and returns the length of the one text
/// message it holds.
fn receive(conn: &mut Connection, wire: &[u8]) -> usize {
    let mut got = 0;
    for read in wire.chunks(4096) {
        let mut rest = read;
        while !rest.is_empty() {
            let n = conn.feed(rest);
            rest = &rest[n..];
            loop {
                match conn.poll().unwrap() {
                    Event::Text(t) => got = t.len(),
                    Event::NeedInput => break,
                    other => panic!("{other:?}"),
                }
            }
        }
    }
    got
}

#[test]
fn test_freed_buffers_hold_no_message_bytes() {
    // Everything the test itself holds is built before the scan starts and
    // freed after it ends.
    let big = secret(100 * 1024);
    let small = secret(2 * 1024);
    let mut fragmented = Vec::new();
    for (i, piece) in big.as_bytes().chunks(40 * 1024).enumerate() {
        let opcode = if i == 0 { 0x1 } else { 0x0 };
        fragmented.extend(client_frame(opcode, i == 2, piece));
    }
    let single = client_frame(0x1, true, small.as_bytes());

    ARMED.store(true, Ordering::SeqCst);

    let mut conn = Connection::server();
    // A message over `retain` in three fragments: the reassembly buffer
    // doubles as it arrives, then is freed by the next poll.
    assert_eq!(receive(&mut conn, &fragmented), big.len());
    assert!(matches!(conn.poll(), Ok(Event::NeedInput)));
    // A send over `retain`: the output buffer doubles as the frame is
    // written, then is freed once the output is.
    conn.send_text(&big).unwrap();
    let n = conn.output().len();
    conn.advance_output(n);
    // A small message kept for reuse, then `release_memory`.
    assert_eq!(receive(&mut conn, &single), small.len());
    conn.send_text(&small).unwrap();
    let n = conn.output().len();
    conn.advance_output(n);
    conn.release_memory();
    // The current buffers, at the end.
    assert_eq!(receive(&mut conn, &single), small.len());
    conn.wipe();
    drop(conn);

    #[cfg(feature = "deflate")]
    deflate(&big);

    ARMED.store(false, Ordering::SeqCst);
    assert_eq!(
        FOUND.load(Ordering::SeqCst),
        0,
        "blocks freed with the marker"
    );
}

/// The same with permessage-deflate: the inflated message, the compressed
/// scratch buffer, and the engines' windows (dropped by `release_memory`).
#[cfg(feature = "deflate")]
fn deflate(text: &str) {
    use ws_net::{
        AcceptPolicy, ClientHandshake, DeflateConfig, HeadReader, OriginPolicy, ServerHandshake,
    };

    let hs = ClientHandshake::with_nonce(*b"the sample nonce").with_deflate(DeflateConfig::new());
    let mut req = Vec::new();
    hs.write_request("a.example", "/", &mut req).unwrap();
    let (h, _) = ServerHandshake::from_head(&req).unwrap().unwrap();
    let policy = AcceptPolicy::new()
        .with_origins(OriginPolicy::any_origin())
        .with_deflate(DeflateConfig::new());
    let mut response = Vec::new();
    let mut srv = h.accept(&policy, &mut response).unwrap();
    let (verified, _) = HeadReader::new().client(&hs, &response).unwrap().unwrap();
    let mut cli = hs.connection_with_seed(&verified, [9; 32]);
    assert!(srv.negotiated().deflate().is_some());

    cli.send_text(text).unwrap();
    // Compressed and masked: the marker is not in these bytes.
    let wire = cli.output().to_vec();
    let n = cli.output().len();
    cli.advance_output(n);
    assert_eq!(receive(&mut srv, &wire), text.len());
    assert!(matches!(srv.poll(), Ok(Event::NeedInput)));
    srv.send_text(text).unwrap();
    let n = srv.output().len();
    srv.advance_output(n);
    srv.release_memory();
    cli.release_memory();
    srv.wipe();
    cli.wipe();
}
