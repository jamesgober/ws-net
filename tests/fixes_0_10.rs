//! Regression tests for the bugs fixed in 0.10.0 (D-081). Each test
//! failed on 0.9.0; the name says what is now true. The zeroing of
//! freed buffers is in `tests/wipe.rs` (it needs its own allocator), and
//! the incremental check of compressed text in `tests/deflate.rs`.

mod common;

use common::client_frame;
use core::time::Duration;
use std::{fs, path::Path};
use ws_net::{Connection, Event, Keepalive, Millis, WsError, frame::FrameHeader, frame::Opcode};

/// A masked binary frame header announcing `len` bytes, with no payload.
fn header_only(opcode: Opcode, fin: bool, len: u64) -> Vec<u8> {
    let mut out = Vec::new();
    FrameHeader::new(opcode, fin, len)
        .with_mask([1, 2, 3, 4])
        .encode(&mut out)
        .unwrap();
    out
}

/// A header claiming a 1 MiB payload reserved 1 MiB before any of it
/// arrived, so 14 bytes per connection held a frame budget of memory.
/// Reassembly now grows only as payload bytes arrive.
#[test]
fn test_header_alone_reserves_nothing() {
    let mut held = 0;
    for _ in 0..64 {
        let mut conn = Connection::server();
        let h = header_only(Opcode::Binary, true, 1 << 20);
        assert_eq!(conn.feed(&h), h.len());
        assert!(matches!(conn.poll(), Ok(Event::NeedInput)));
        held += conn.memory_in_use();
    }
    // Only the input buffer's first allocation (4 KiB) each.
    assert!(held <= 64 * 4096, "64 headers hold {held} bytes");
}

/// The same for each fragment's header: after 1 MiB of real data,
/// a continuation header alone added a second 1 MiB.
#[test]
fn test_fragment_header_reserves_nothing() {
    let mut conn = Connection::server();
    let first = client_frame(0x2, false, &vec![7u8; 1 << 20]);
    let mut rest = &first[..];
    while !rest.is_empty() {
        let n = conn.feed(rest);
        rest = &rest[n..];
        assert!(matches!(conn.poll(), Ok(Event::NeedInput)));
    }
    let after_data = conn.memory_in_use();
    let h = header_only(Opcode::Continuation, true, 1 << 20);
    assert_eq!(conn.feed(&h), h.len());
    assert!(matches!(conn.poll(), Ok(Event::NeedInput)));
    assert_eq!(conn.memory_in_use(), after_data);
    // The claim ends at 1 MiB, so at most that, plus
    // the input buffer.
    assert!(after_data <= (2 << 20) + 64 * 1024, "{after_data}");
}

/// No default timer ended a message that stopped arriving, so the
/// peer held its reassembly buffer for as long as the TCP connection
/// lived. The default `Keepalive` now times a message out after 60 s.
#[test]
fn test_stalled_message_times_out_by_default() {
    assert_eq!(
        Keepalive::new().message_timeout(),
        Some(Duration::from_secs(60))
    );
    let mut conn = Connection::server();
    let part = client_frame(0x2, false, b"part of a message");
    assert_eq!(conn.feed(&part), part.len());
    assert!(matches!(conn.poll(), Ok(Event::NeedInput)));
    assert!(conn.on_time(Millis(1_000)).is_ok());
    assert_eq!(conn.next_deadline(), Some(Millis(61_000)));
    assert!(conn.on_time(Millis(60_999)).is_ok());
    assert_eq!(conn.on_time(Millis(61_000)), Err(WsError::MessageTimeout));
    // Close 1008 is queued.
    assert_eq!(conn.output(), [0x88, 0x02, 0x03, 0xF0]);

    // `Duration::MAX` turns it off.
    let mut conn =
        Connection::server().with_keepalive(Keepalive::new().with_message_timeout(Duration::MAX));
    assert_eq!(conn.feed(&part), part.len());
    assert!(matches!(conn.poll(), Ok(Event::NeedInput)));
    assert!(conn.on_time(Millis(0)).is_ok());
    assert!(conn.on_time(Millis(u64::MAX / 2)).is_ok());
}

/// The files whose examples users copy: the crate's sources (doc
/// examples), the README, the docs, and the examples. Release notes are
/// left as they shipped.
fn documented_files() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    let mut dirs = vec![root.join("src"), root.join("docs"), root.join("examples")];
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n != "release") {
                    dirs.push(path);
                }
            } else if path.extension().is_some_and(|e| e == "rs" || e == "md") {
                files.push(path);
            }
        }
    }
    files.push(root.join("README.md"));
    files
        .into_iter()
        .map(|p| {
            let text = fs::read_to_string(&p).unwrap();
            (p.display().to_string(), text)
        })
        .collect()
}

/// The examples dropped `feed`'s count with `let _ =`, which loses
/// whatever did not fit the input buffer when copied into a socket loop.
/// Every example now checks it or feeds the rest.
#[test]
fn test_examples_never_drop_the_feed_count() {
    for (path, text) in documented_files() {
        for (i, line) in text.lines().enumerate() {
            let code = line.trim_start().trim_start_matches("///").trim_start();
            let code = code.trim_start_matches("//!").trim_start();
            if code.starts_with("let _ =") && code.contains(".feed(") {
                panic!("{path}:{}: {}", i + 1, line.trim());
            }
        }
    }
}

/// The README said a client's masking keys and nonce came from the
/// standard library's hasher keys (they come from the OS cryptographic
/// source), and that the crate has no dependencies (it has three
/// first-party ones).
#[test]
fn test_readme_states_the_key_source_and_dependencies() {
    let readme =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md")).unwrap();
    assert!(
        !readme.contains("hasher keys"),
        "README names the hasher keys"
    );
    assert!(
        readme.contains("cryptographic"),
        "README names the key source"
    );
    assert!(
        !readme.contains("no dependencies"),
        "README claims no dependencies"
    );
    assert!(readme.contains("no third-party dependencies"));
}
