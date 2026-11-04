//! One test per threat in the plan's threat table, named
//! `test_attack_<threat>_<expected>`. Each asserts the defense's observable
//! effect: a refusal, a close code, or bounded work. This file grows with
//! every version; 0.7.0 completes it.

mod common;

use common::{Ev, client_frame, drive, server_frame};
use ws_net::{
    AcceptPolicy, Acceptor, CloseCode, Connection, Event, HandshakeError, HeadReader, OriginPolicy,
    ServerHandshake, WsError, accept,
};

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
