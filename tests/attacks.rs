//! One test per threat in the plan's threat table, named
//! `test_attack_<threat>_<expected>`. Each asserts the defense's observable
//! effect: a refusal, a close code, or bounded work. This file grows with
//! every version; 0.7.0 completed it. The permessage-deflate threats T-19
//! to T-21 are tested in `tests/deflate.rs`, behind the `deflate` feature.

mod common;

use common::{Ev, client_frame, drive, server_frame};
use ws_net::{
    AcceptPolicy, Acceptor, CloseCode, Connection, Event, HandshakeError, HeadReader, Keepalive,
    Limits, Millis, OriginPolicy, ServerHandshake, WsError, accept, frame,
};

trait ReplaceHost {
    fn replace_host(&self, host: &str) -> Vec<u8>;
}

impl ReplaceHost for Vec<u8> {
    fn replace_host(&self, host: &str) -> Vec<u8> {
        String::from_utf8_lossy(self)
            .replace("Host: chat.example", &format!("Host: {host}"))
            .into_bytes()
    }
}

fn request(extra: &str) -> Vec<u8> {
    format!(
        "GET /chat HTTP/1.1\r\nHost: chat.example\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n{extra}\r\n"
    )
    .into_bytes()
}

// T-1: cross-site WebSocket hijacking.

#[test]
fn test_attack_cswsh_foreign_origin_refused_403() {
    let wire = request("Origin: https://evil.example\r\n");
    let refused = accept(&wire).unwrap_err();
    assert_eq!(refused, HandshakeError::OriginRefused);
    assert_eq!(refused.status(), 403);
    let mut out = Vec::new();
    refused.write_response(&mut out);
    assert!(out.starts_with(b"HTTP/1.1 403 Forbidden\r\n"));
    assert!(out.ends_with(b"content-length: 0\r\nconnection: close\r\n\r\n"));
}

#[test]
fn test_attack_cswsh_lookalike_origins_refused() {
    for origin in [
        "https://chat.example.evil.net",
        "https://evilchat.example",
        "https://chat.example@evil.net",
        "https://chat.example:8443",
        "null",
        "https://chat.example/path",
        "https://chat.example/",
    ] {
        let wire = request(&format!("Origin: {origin}\r\n"));
        assert_eq!(
            accept(&wire).unwrap_err(),
            HandshakeError::OriginRefused,
            "{origin}"
        );
    }
}

#[test]
fn test_attack_cswsh_same_origin_forms_accepted() {
    for origin in [
        "https://chat.example",
        "HTTPS://CHAT.EXAMPLE",
        "https://chat.example:443",
    ] {
        let wire = request(&format!("Origin: {origin}\r\n"));
        assert!(accept(&wire).unwrap().is_some(), "{origin}");
    }
    // No Origin: not a browser, so no ambient credentials; accepted by the
    // default policy, refused when the policy says so.
    assert!(accept(&request("")).unwrap().is_some());
    let strict = AcceptPolicy::new().with_origins(OriginPolicy::same_origin().allow_missing(false));
    assert_eq!(
        Acceptor::with_policy(strict)
            .accept(&request(""))
            .unwrap_err(),
        HandshakeError::OriginRefused
    );
}

#[test]
fn test_attack_cswsh_two_origins_refused() {
    let wire = request("Origin: https://chat.example\r\nOrigin: https://evil.example\r\n");
    assert_eq!(accept(&wire).unwrap_err(), HandshakeError::InvalidOrigin);
}

// T-3: request smuggling through a body on the upgrade request.

#[test]
fn test_attack_smuggled_body_refused_400() {
    for extra in [
        "Content-Length: 5\r\n",
        "Transfer-Encoding: chunked\r\n",
        "Content-Length: 0\r\nContent-Length: 5\r\n",
        "Content-Length: 00\r\n",
        "Content-Length: 0, 0\r\n",
        "transfer-encoding: identity\r\n",
    ] {
        let wire = request(extra);
        assert_eq!(
            ServerHandshake::from_head(&wire).unwrap_err(),
            HandshakeError::UnexpectedBody,
            "{extra:?}"
        );
        assert_eq!(HandshakeError::UnexpectedBody.status(), 400);
    }
    let fields = [
        ("Host", &b"chat.example"[..]),
        ("Upgrade", b"websocket"),
        ("Connection", b"Upgrade"),
        ("Sec-WebSocket-Version", b"13"),
        ("Sec-WebSocket-Key", b"dGhlIHNhbXBsZSBub25jZQ=="),
        ("Transfer-Encoding", b"chunked"),
    ];
    assert_eq!(
        ServerHandshake::from_request("GET", "/", fields),
        Err(HandshakeError::UnexpectedBody)
    );
}

#[test]
fn test_attack_smuggled_body_zero_length_accepted() {
    assert!(
        ServerHandshake::from_head(&request("Content-Length: 0\r\n"))
            .unwrap()
            .is_some()
    );
}

// T-4: algorithmic complexity in the head reader.

#[test]
fn test_attack_slow_head_bytewise_matches_one_shot() {
    let mut wire =
        request(&"X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n".repeat(200));
    wire.extend_from_slice(b"\x81\x80\x00\x00\x00\x00");
    let one_shot = ServerHandshake::from_head(&wire).unwrap().unwrap();
    let mut reader = HeadReader::new();
    let mut found = None;
    for end in 1..=wire.len() {
        if let Some(f) = reader.server(&wire[..end]).unwrap() {
            found = Some(f);
            break;
        }
    }
    assert_eq!(found.unwrap(), one_shot);
}

#[test]
fn test_attack_slow_head_oversized_refused_431() {
    // 16 KiB with no blank line, one byte per read.
    let mut wire = b"GET / HTTP/1.1\r\n".to_vec();
    while wire.len() < ServerHandshake::MAX_HEAD {
        wire.extend_from_slice(b"X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
    }
    let mut acceptor = Acceptor::new();
    let mut result = Ok(None);
    for end in 1..=wire.len() {
        result = acceptor.accept(&wire[..end]);
        if result.is_err() {
            break;
        }
    }
    assert_eq!(result.unwrap_err(), HandshakeError::HeadTooLarge);
}

#[test]
fn test_attack_slow_head_shrunk_buffer_refused() {
    let wire = request("");
    let mut reader = HeadReader::new();
    assert_eq!(reader.server(&wire[..30]).unwrap(), None);
    assert_eq!(
        reader.server(&wire[..10]).unwrap_err(),
        HandshakeError::InvalidRequest
    );
}

// T-14: unsolicited Pong flood.

#[test]
fn test_attack_pong_flood_output_stays_empty() {
    let mut conn = Connection::server();
    let mut wire = Vec::new();
    for _ in 0..10_000 {
        wire.extend_from_slice(&client_frame(0xA, true, b"pong"));
    }
    let pieces: Vec<&[u8]> = wire.chunks(4096).collect();
    let (events, out) = drive(&mut conn, &pieces, false);
    assert_eq!(events.len(), 10_000);
    assert!(events.iter().all(|e| *e == Ev::Pong(b"pong".to_vec())));
    assert!(out.is_empty());
    assert!(conn.output().is_empty());
}

// T-23: log injection through close reasons.

#[test]
fn test_attack_close_reason_control_characters_delivered_verbatim() {
    let mut conn = Connection::client_with_seed([9; 32]);
    let mut payload = 1000u16.to_be_bytes().to_vec();
    payload.extend_from_slice("bye\n\u{1b}[31mred".as_bytes());
    let _ = conn.feed(&server_frame(0x8, true, &payload));
    match conn.poll().unwrap() {
        Event::Close(Some(frame)) => {
            assert_eq!(frame.code, CloseCode::NORMAL);
            assert_eq!(frame.reason, "bye\n\u{1b}[31mred");
            // What a caller logs: the escaped form.
            assert_eq!(
                frame.reason.escape_debug().to_string(),
                "bye\\n\\u{1b}[31mred"
            );
        }
        other => panic!("{other:?}"),
    }
}

// T-27: cross-protocol bytes after the upgrade.

#[test]
fn test_attack_http_bytes_after_upgrade_fail_1002() {
    let mut conn = Connection::server();
    let _ = conn.feed(b"GET / HTTP/1.1\r\nHost: chat.example\r\n\r\n");
    let e = conn.poll().unwrap_err();
    assert_eq!(e.close_code(), Some(CloseCode::PROTOCOL_ERROR));
    assert!(matches!(conn.poll(), Ok(Event::Closed)));
    // The Close with 1002 is queued.
    assert_eq!(conn.output(), [0x88, 0x02, 0x03, 0xEA]);
    // And every later send is refused.
    assert!(matches!(conn.send_text("x"), Err(WsError::InvalidState(_))));
}

// T-12: frame flood. Work per poll is bounded by the buffered bytes (FR-53).

#[test]
fn test_attack_frame_flood_empty_continuations_delivered_once() {
    let mut conn = Connection::server();
    let mut wire = client_frame(0x1, false, b"a");
    let empty = client_frame(0x0, false, b"");
    for _ in 0..200_000 {
        wire.extend_from_slice(&empty);
    }
    wire.extend_from_slice(&client_frame(0x0, true, b"b"));
    let pieces: Vec<&[u8]> = wire.chunks(64 * 1024).collect();
    let (events, out) = drive(&mut conn, &pieces, false);
    assert_eq!(events, [Ev::Text("ab".to_string())]);
    assert!(out.is_empty());
}

#[test]
fn test_attack_bounded_work_one_event_per_poll() {
    let mut conn = Connection::server();
    let mut wire = Vec::new();
    for _ in 0..1000 {
        wire.extend_from_slice(&client_frame(0xA, true, b""));
    }
    assert_eq!(conn.feed(&wire), wire.len());
    // One poll returns one event and leaves the rest buffered.
    assert!(matches!(conn.poll(), Ok(Event::Pong(b""))));
    let mut count = 1;
    while let Ok(Event::Pong(_)) = conn.poll() {
        count += 1;
    }
    assert_eq!(count, 1000);
}

// T-2: DNS rebinding.

#[test]
fn test_attack_dns_rebinding_foreign_host_refused_403() {
    let policy = AcceptPolicy::new()
        .with_origins(OriginPolicy::any_origin())
        .with_hosts(&["chat.example"])
        .unwrap();
    let wire = request("").replace_host("attacker.example");
    let e = Acceptor::with_policy(policy).accept(&wire).unwrap_err();
    assert_eq!((e, e.status()), (HandshakeError::HostRefused, 403));
}

// T-5: header flood.

#[test]
fn test_attack_header_flood_refused() {
    let many = "Sec-WebSocket-Protocol: p\r\n".repeat(65);
    assert_eq!(
        accept(&request(&many)).unwrap_err(),
        HandshakeError::InvalidProtocol
    );
    let offers = "Sec-WebSocket-Extensions: e\r\n".repeat(17);
    assert_eq!(
        accept(&request(&offers)).unwrap_err(),
        HandshakeError::InvalidExtensions
    );
    let huge = format!("X-Pad: {}\r\n", "a".repeat(ServerHandshake::MAX_HEAD));
    assert_eq!(
        accept(&request(&huge)).unwrap_err(),
        HandshakeError::HeadTooLarge
    );
}

// T-6: unmasked client data (proxy cache poisoning).

#[test]
fn test_attack_unmasked_client_frame_fails_1002() {
    let mut conn = Connection::server();
    let _ = conn.feed(&server_frame(0x1, true, b"GET /poison HTTP/1.1"));
    assert_eq!(conn.poll().unwrap_err(), WsError::UnmaskedFrame);
    assert_eq!(conn.output(), [0x88, 0x02, 0x03, 0xEA]);
}

// T-7: predictable masking keys.

#[cfg(feature = "std")]
#[test]
fn test_attack_masking_keys_unpredictable_across_connections() {
    let key = |conn: &mut Connection| {
        conn.send_binary(b"x").unwrap();
        let out = conn.output().to_vec();
        [out[2], out[3], out[4], out[5]]
    };
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..1000 {
        let mut conn = Connection::client();
        let _ = seen.insert(key(&mut conn));
    }
    assert!(seen.len() > 990, "{} distinct first keys", seen.len());
    // No seed or key material in Debug.
    let conn = Connection::client();
    let text = format!("{conn:?}");
    assert!(!text.contains("seed") && !text.contains("pool"), "{text}");
}

// T-8: masked frames from a server.

#[test]
fn test_attack_masked_server_frame_fails_1002() {
    let mut conn = Connection::client_with_seed([1; 32]);
    let _ = conn.feed(&client_frame(0x1, true, b"x"));
    assert_eq!(conn.poll().unwrap_err(), WsError::MaskedFrame);
}

// T-9 and T-10: oversized frames and length lies.

#[test]
fn test_attack_length_lie_fails_before_payload_1009() {
    let mut conn = Connection::server();
    // A header announcing 2^40 bytes, then nothing.
    let _ = conn.feed(&[0x82, 0xFF, 0, 0, 0x01, 0, 0, 0, 0, 0, 1, 2, 3, 4]);
    assert_eq!(conn.poll().unwrap_err(), WsError::FrameTooLarge);
    assert!(conn.memory_in_use() < 128 * 1024);
}

// T-11: the 64-bit length's high bit.

#[test]
fn test_attack_length_high_bit_fails_1002() {
    let mut conn = Connection::server();
    let _ = conn.feed(&[0x82, 0xFF, 0x80, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4]);
    assert_eq!(conn.poll().unwrap_err(), WsError::InvalidLength);
}

// T-13: Ping flood without reading.

#[test]
fn test_attack_ping_flood_output_bounded_one_pong() {
    let mut conn = Connection::server();
    let mut wire = Vec::new();
    for i in 0..10_000u32 {
        wire.extend_from_slice(&client_frame(0x9, true, &i.to_be_bytes()));
    }
    let mut rest = &wire[..];
    while !rest.is_empty() {
        let n = conn.feed(rest);
        rest = &rest[n..];
        while let Ok(Event::Ping(_)) = conn.poll() {}
    }
    assert_eq!(conn.output(), [0x8A, 0x04, 0, 0, 0x27, 0x0F]);
    assert_eq!(conn.stats().pings_in, 10_000);
}

// T-15, T-16, T-24: slow message, idle connection, close hang.

#[test]
fn test_attack_slow_message_idle_and_close_hang_time_out() {
    use core::time::Duration;
    let k = Keepalive::new()
        .with_message_timeout(Duration::from_secs(10))
        .with_idle_timeout(Duration::from_secs(60))
        .with_close_timeout(Duration::from_secs(5));
    let mut slow = Connection::server().with_keepalive(k);
    let _ = slow.on_time(Millis(0));
    let _ = slow.feed(&client_frame(0x2, false, b"1"));
    let _ = slow.poll();
    // A driver ticks after every read: the message's clock starts here.
    let _ = slow.on_time(Millis(1));
    assert_eq!(slow.on_time(Millis(10_001)), Err(WsError::MessageTimeout));
    let mut idle = Connection::server().with_keepalive(k);
    let _ = idle.on_time(Millis(0));
    assert_eq!(idle.on_time(Millis(60_000)), Err(WsError::IdleTimeout));
    let mut hang = Connection::server().with_keepalive(k);
    let _ = hang.on_time(Millis(0));
    hang.close(CloseCode::NORMAL, "").unwrap();
    let _ = hang.on_time(Millis(1));
    assert_eq!(hang.on_time(Millis(5_001)), Err(WsError::CloseTimeout));
    assert!(hang.should_close_transport());
}

// T-17: slow consumer.

#[test]
fn test_attack_slow_consumer_refused_at_budget_close_still_fits() {
    let mut conn = Connection::server().with_limits(Limits::new().with_max_output(4096));
    while conn.send_binary(&[0; 100]).is_ok() {}
    assert_eq!(conn.send_binary(&[0; 100]), Err(WsError::OutputFull));
    conn.close(CloseCode::TRY_AGAIN_LATER, "slow").unwrap();
    assert!(conn.buffered_output() <= 4096 + 262);
}

// T-18: many connections, memory per connection.

#[test]
fn test_attack_many_idle_connections_hold_no_heap() {
    let mut conns: Vec<Connection> = (0..10_000).map(|_| Connection::server()).collect();
    for c in &mut conns {
        let _ = c.feed(&client_frame(0x1, true, b"hello"));
        let _ = c.poll();
        c.release_memory();
    }
    assert!(conns.iter().all(|c| c.memory_in_use() == 0));
    assert!(core::mem::size_of::<Connection>() <= 512);
}

// T-22: invalid UTF-8 for downstream parsers.

#[test]
fn test_attack_invalid_utf8_fails_1007() {
    for bad in [
        &[0xC0u8, 0x80][..],
        &[0xED, 0xA0, 0x80],
        &[0xF4, 0x90, 0x80, 0x80],
        &[0xFF],
    ] {
        let mut conn = Connection::server();
        let _ = conn.feed(&client_frame(0x1, true, bad));
        let e = conn.poll().unwrap_err();
        assert_eq!(
            (e, e.close_code()),
            (WsError::InvalidUtf8, Some(CloseCode::INVALID_PAYLOAD))
        );
    }
}

// T-25: panics as denial of service (the fuzz targets cover arbitrary
// bytes; here, the extreme values every API accepts).

#[test]
fn test_attack_extreme_arguments_never_panic() {
    let mut conn = Connection::server().with_limits(
        Limits::new()
            .with_max_frame(u64::MAX)
            .with_max_message(u64::MAX)
            .with_max_output(0)
            .with_input_buffer(usize::MAX)
            .with_retain(usize::MAX),
    );
    conn.commit(usize::MAX);
    conn.advance_output(usize::MAX);
    let _ = conn.on_time(Millis(u64::MAX));
    let _ = conn.send_binary(&[]);
    let _ = conn.close(CloseCode::new(u16::MAX), "");
    let _ = conn.poll();
    frame::apply_mask(&mut [0; 7], [1, 2, 3, 4], usize::MAX);
}

// T-26: a revoked session keeps a long-lived socket.

#[test]
fn test_attack_revoked_session_close_1008_mid_message_then_input_ignored() {
    let mut conn = Connection::server();
    let _ = conn.feed(&client_frame(0x1, false, b"half"));
    let _ = conn.poll();
    conn.close(CloseCode::POLICY_VIOLATION, "session ended")
        .unwrap();
    assert_eq!(&conn.output()[..4], [0x88, 0x0F, 0x03, 0xF0]);
    conn.wipe();
    let _ = conn.feed(&client_frame(0x0, true, b" rest"));
    assert!(matches!(conn.poll(), Ok(Event::Closed)));
}

// T-28: allocation failure (the counting allocator test in
// tests/memory.rs fails an 8 MiB reassembly; here, the error's contract).

#[test]
fn test_attack_allocation_failure_closes_1011() {
    assert_eq!(
        WsError::AllocationFailed.close_code(),
        Some(CloseCode::INTERNAL_ERROR)
    );
}

// T-29: information leaks through Debug and Display.

#[test]
fn test_attack_debug_and_display_leak_no_payload() {
    let mut conn = Connection::server();
    let _ = conn.feed(&client_frame(0x1, true, b"secret-token-123"));
    let _ = conn.poll();
    conn.send_text("another-secret").unwrap();
    let debug = format!("{conn:?}");
    assert!(!debug.contains("secret"), "{debug}");
    for e in [
        WsError::InvalidUtf8,
        WsError::OutputFull,
        WsError::AllocationFailed,
    ] {
        assert!(!e.to_string().contains("secret"));
    }
    let message = ws_net::PreparedMessage::text("secret");
    assert!(format!("{message:?}").len() < 200);
}
