//! Regression tests for the defects fixed from 0.2.0 to 0.9.0. Each test
//! was written failing before its fix; the name says what was wrong.

mod common;

use common::{Ev, client_frame, drive};
use core::time::Duration;
use ws_net::{
    ClientHandshake, CloseCode, Connection, Event, HandshakeError, HeadReader, Keepalive, Limits,
    Millis, ServerHandshake, State, Tick, WsError, frame::apply_mask,
};

#[test]
fn test_apply_mask_any_offset_no_overflow() {
    // The offset is only meaningful modulo 4; a caller tracking a 64-bit
    // stream position must not hit an arithmetic overflow.
    let key = [1, 2, 3, 4];
    let mut a = [0u8; 13];
    apply_mask(&mut a, key, usize::MAX);
    let mut b = [0u8; 13];
    apply_mask(&mut b, key, usize::MAX % 4);
    assert_eq!(a, b);
}

#[test]
fn test_commit_and_advance_huge_counts_saturate() {
    let mut conn = Connection::server();
    let _ = conn.read_buf();
    conn.commit(1);
    conn.commit(usize::MAX);
    assert!(conn.read_buf().is_empty() || conn.state() == State::Open);

    let mut conn = Connection::server();
    conn.send_text("abc").unwrap();
    conn.advance_output(1);
    conn.advance_output(usize::MAX);
    assert!(conn.output().is_empty());
}

#[test]
fn test_usage_errors_no_close_code() {
    // A refused call leaves the connection open, so it must not look like
    // a connection failure to a caller that checks `close_code()`.
    let mut conn = Connection::server();
    let err = conn.send_ping(&[0; 126]).unwrap_err();
    assert_eq!(err.close_code(), None, "{err:?}");
    let err = conn.send_pong(&[0; 126]).unwrap_err();
    assert_eq!(err.close_code(), None, "{err:?}");
    let err = conn.close(CloseCode::NO_STATUS, "").unwrap_err();
    assert_eq!(err.close_code(), None, "{err:?}");
    let err = conn.close(CloseCode::NORMAL, &"x".repeat(124)).unwrap_err();
    assert_eq!(err.close_code(), None, "{err:?}");
    assert_eq!(conn.state(), State::Open);
    assert!(conn.output().is_empty());
    conn.send_text("still open").unwrap();
}

#[test]
fn test_ping_flood_unread_output_bounded() {
    // A peer that sends Pings but never reads our output must not make the
    // output queue grow: only the latest automatic Pong stays unsent.
    let mut conn = Connection::server();
    let ping = client_frame(0x9, true, &[0xab; 125]);
    for _ in 0..1000 {
        assert_eq!(conn.feed(&ping), ping.len());
        assert!(matches!(conn.poll().unwrap(), Event::Ping(_)));
        // The caller looks at the output (as an I/O loop does) but the
        // socket accepts nothing.
        let _ = conn.output();
    }
    assert_eq!(conn.output().len(), 2 + 125);
}

#[test]
fn test_pong_behind_user_frame_kept() {
    // Replacing an unsent Pong is only allowed while it is the last thing
    // queued; a Pong behind a data frame must stay in order.
    let mut conn = Connection::server();
    let _ = conn.feed(&client_frame(0x9, true, b"1"));
    assert!(matches!(conn.poll().unwrap(), Event::Ping(b"1")));
    let _ = conn.output();
    conn.send_text("x").unwrap();
    let _ = conn.feed(&client_frame(0x9, true, b"2"));
    assert!(matches!(conn.poll().unwrap(), Event::Ping(b"2")));
    assert_eq!(
        conn.output(),
        [0x8A, 0x01, b'1', 0x81, 0x01, b'x', 0x8A, 0x01, b'2']
    );
    // A partly written Pong is never rewritten either.
    conn.advance_output(7);
    let _ = conn.feed(&client_frame(0x9, true, b"3"));
    assert!(matches!(conn.poll().unwrap(), Event::Ping(b"3")));
    assert_eq!(conn.output(), [0x01, b'2', 0x8A, 0x01, b'3']);
}

#[test]
fn test_reserve_lifted_budgets_capped_at_one_mib() {
    // With the budgets lifted, a header announcing 1 TiB must not make the
    // connection reserve 1 TiB up front (an allocation failure aborts the
    // process). Memory follows the bytes that actually arrive.
    let limits = Limits::new()
        .with_max_frame(u64::MAX)
        .with_max_message(u64::MAX);
    let mut conn = Connection::server().with_limits(limits);
    let mut header = vec![0x82, 0x80 | 127];
    header.extend_from_slice(&(1u64 << 40).to_be_bytes());
    header.extend_from_slice(&[0, 0, 0, 0]);
    header.extend_from_slice(b"some bytes");
    let _ = conn.feed(&header);
    assert!(matches!(conn.poll().unwrap(), Event::NeedInput));
}

#[test]
fn test_budget_maximum_length_header_fails_before_payload() {
    // 2^63 - 1 bytes announced: refused from the header alone.
    let mut wire = vec![0x82, 0x80 | 127];
    wire.extend_from_slice(&(i64::MAX as u64).to_be_bytes());
    wire.extend_from_slice(&[1, 2, 3, 4]);
    let (events, out) = drive(&mut Connection::server(), &[&wire], false);
    assert_eq!(events, vec![Ev::Err(WsError::FrameTooLarge)]);
    assert_eq!(out, [0x88, 0x02, 0x03, 0xF1]);
}

// 0.6: streamed text is validated once, with a cut sequence carried into
// the next chunk. Fail-fast must hold at every cut, and the delivered text
// must equal the input for every cut.

fn streamed_text(payload: &[u8], cut: usize) -> Result<Vec<String>, ws_net::WsError> {
    // One text frame larger than the input buffer, so it streams; the
    // payload's first `cut` bytes arrive in the first read.
    let limits = ws_net::Limits::new().with_input_buffer(256);
    let mut conn = ws_net::Connection::server().with_limits(limits);
    let wire = common::client_frame(0x1, true, payload);
    let header = wire.len() - payload.len();
    let (first, second) = wire.split_at(header + cut);
    let mut got = Vec::new();
    for piece in [first, second] {
        let mut rest = piece;
        loop {
            let n = conn.feed(rest);
            rest = &rest[n..];
            loop {
                match conn.poll()? {
                    ws_net::Event::Text(t) => got.push(t.to_string()),
                    ws_net::Event::NeedInput => break,
                    other => panic!("{other:?}"),
                }
            }
            if rest.is_empty() {
                break;
            }
        }
    }
    Ok(got)
}

#[test]
fn test_streamed_text_every_cut_delivers_whole() {
    let text = "a€𝄞é".repeat(100);
    for cut in 0..=text.len() {
        let got = streamed_text(text.as_bytes(), cut).unwrap();
        assert_eq!(got, std::slice::from_ref(&text), "cut {cut}");
    }
}

#[test]
fn test_streamed_text_invalid_prefix_fails_before_rest_arrives() {
    // F4 90 starts no valid sequence (above U+10FFFF): it must fail when the
    // first part arrives, not when the message completes.
    let mut payload = vec![b'a'; 300];
    payload.extend_from_slice(&[0xF4, 0x90, 0x80, 0x80]);
    payload.extend_from_slice(&[b'b'; 300]);
    let limits = ws_net::Limits::new().with_input_buffer(256);
    let mut conn = ws_net::Connection::server().with_limits(limits);
    let wire = common::client_frame(0x1, true, &payload);
    let header = wire.len() - payload.len();
    let upto = header + 302; // ... 'a' F4 90 | 80 80 'b' ...
    let mut rest = &wire[..upto];
    let mut failed = None;
    while failed.is_none() && !rest.is_empty() {
        let n = conn.feed(rest);
        rest = &rest[n..];
        match conn.poll() {
            Ok(ws_net::Event::NeedInput) => {}
            Err(e) => failed = Some(e),
            Ok(other) => panic!("{other:?}"),
        }
    }
    assert_eq!(failed, Some(ws_net::WsError::InvalidUtf8));
}

#[test]
fn test_streamed_text_truncated_at_end_fails() {
    let mut payload = vec![b'a'; 300];
    payload.extend_from_slice(&[0xE2, 0x82]); // a cut euro sign, then the end
    for cut in [0, 299, 300, 301, 302] {
        assert_eq!(
            streamed_text(&payload, cut).unwrap_err(),
            ws_net::WsError::InvalidUtf8,
            "cut {cut}"
        );
    }
}

#[test]
fn test_streamed_text_detach_moves_without_copy() {
    let text = "κόσμε".repeat(200);
    let limits = ws_net::Limits::new().with_input_buffer(256);
    let mut conn = ws_net::Connection::server().with_limits(limits);
    let wire = common::client_frame(0x1, true, text.as_bytes());
    let mut rest = &wire[..];
    let mut owned = Vec::new();
    while !rest.is_empty() {
        let n = conn.feed(rest);
        rest = &rest[n..];
        while let Ok(ev) = conn.poll() {
            match ev {
                ws_net::Event::NeedInput => break,
                ws_net::Event::Text(_) => {
                    assert_eq!(
                        conn.detach_message(&mut owned),
                        Some(ws_net::MessageKind::Text)
                    );
                }
                other => panic!("{other:?}"),
            }
        }
    }
    assert_eq!(owned, text.as_bytes());
}

// Fixed in 0.7.0.

const REQUEST: &str = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n";

fn request(target: &str, extra: &str) -> Vec<u8> {
    let mut head = REQUEST.replacen("/chat", target, 1);
    if !extra.is_empty() {
        head.push_str(extra);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    head.into_bytes()
}

#[test]
fn test_invalid_text_not_lent_for_detach() {
    // A Text message that fails UTF-8 validation must not be left for
    // `detach_message` to hand out as Text.
    let mut conn = Connection::server();
    let _ = conn.feed(&[0x81, 0x82, 0, 0, 0, 0, 0xc0, 0x80]);
    assert_eq!(conn.poll().err(), Some(WsError::InvalidUtf8));
    let mut owned = Vec::new();
    assert_eq!(conn.detach_message(&mut owned), None);
    assert!(owned.is_empty());
}

#[test]
fn test_close_timeout_bounds_unwritten_output_after_idle_timeout() {
    // After an idle timeout the Close 1001 is queued; a peer that never
    // reads it must not keep the transport open forever.
    let k = Keepalive::new().with_idle_timeout(Duration::from_secs(75));
    let mut conn = Connection::server().with_keepalive(k);
    assert_eq!(conn.on_time(Millis(0)), Ok(Tick::Nothing));
    assert_eq!(conn.on_time(Millis(75_000)), Err(WsError::IdleTimeout));
    assert!(!conn.should_close_transport());
    assert_eq!(conn.next_deadline(), Some(Millis(80_000)));
    assert_eq!(conn.on_time(Millis(79_999)), Ok(Tick::Nothing));
    assert!(!conn.should_close_transport());
    assert_eq!(conn.on_time(Millis(80_000)), Ok(Tick::Nothing));
    assert!(conn.should_close_transport());
    assert_eq!(conn.next_deadline(), None);
}

#[test]
fn test_keepalive_ping_refused_by_full_output_moves_deadline_on() {
    // A Ping that does not fit must not leave the deadline in the past,
    // which would make a timer loop spin.
    let k = Keepalive::new()
        .with_ping_interval(Duration::from_secs(30))
        .with_idle_timeout(Duration::from_secs(75));
    let mut conn = Connection::server()
        .with_limits(Limits::new().with_max_output(100))
        .with_keepalive(k);
    conn.send_binary(&[0; 98]).unwrap();
    assert_eq!(conn.buffered_output(), 100);
    assert_eq!(conn.on_time(Millis(0)), Ok(Tick::Nothing));
    assert_eq!(conn.on_time(Millis(30_000)), Ok(Tick::Nothing));
    assert_eq!(conn.next_deadline(), Some(Millis(75_000)));
}

#[test]
fn test_client_full_output_fits_masked_pong_and_close() {
    // A client's masked Pong and Close are 131 bytes each: both must fit
    // above a full output budget.
    let mut conn =
        Connection::client_with_seed([7; 32]).with_limits(Limits::new().with_max_output(1000));
    conn.send_binary(&[0; 992]).unwrap();
    assert_eq!(conn.buffered_output(), 1000);
    let mut ping = vec![0x89, 125];
    ping.extend_from_slice(&[0xab; 125]);
    let _ = conn.feed(&ping);
    let _ = conn.poll().unwrap();
    assert_eq!(conn.buffered_output(), 1131);
    conn.close(CloseCode::NORMAL, &"x".repeat(123)).unwrap();
    assert_eq!(conn.buffered_output(), 1262);
}

#[test]
fn test_server_target_origin_form_only() {
    // An absolute-form target carries its own authority, which would
    // override the Host the policy checked.
    for target in [
        "http://evil.example/chat",
        "//evil.example/chat",
        "*",
        "chat",
    ] {
        let head = request(target, "");
        assert_eq!(
            ServerHandshake::from_head(&head).err(),
            Some(HandshakeError::MalformedHead),
            "{target}"
        );
    }
    assert!(
        ServerHandshake::from_head(&request("/chat?x=1", ""))
            .unwrap()
            .is_some()
    );
}

#[test]
fn test_extensions_empty_elements_reparse() {
    // Empty list elements and spacing across several fields must not make
    // the stored offers fail to parse again.
    let head = request(
        "/",
        "Sec-WebSocket-Extensions: , foo ,,\r\nSec-WebSocket-Extensions:   bar; x=1 ,",
    );
    let (h, _) = ServerHandshake::from_head(&head).unwrap().unwrap();
    let offers: Vec<_> = h.extensions().collect::<Result<_, _>>().unwrap();
    let names: Vec<_> = offers.iter().map(|o| o.name()).collect();
    assert_eq!(names, ["foo", "bar"]);
}

#[test]
fn test_debug_omits_query_and_header_values() {
    let (h, _) = ServerHandshake::from_head(&request("/chat?token=s3cret", ""))
        .unwrap()
        .unwrap();
    let text = format!("{h:?}");
    assert!(text.contains("/chat") && !text.contains("s3cret"), "{text}");

    let c = ClientHandshake::with_nonce([7; 16]).with_header("Authorization", b"Bearer s3cret");
    let text = format!("{c:?}");
    assert!(
        text.contains("Authorization") && !text.contains("s3cret"),
        "{text}"
    );
}

#[test]
fn test_head_reader_error_sticky_until_reset() {
    // After an error the reader must not resume scanning mid-stream and
    // parse what follows as a fresh head.
    let mut reader = HeadReader::new();
    let bad = request("http://evil.example/", "");
    assert_eq!(
        reader.server(&bad).err(),
        Some(HandshakeError::MalformedHead)
    );
    let good = request("/chat", "");
    assert_eq!(
        reader.server(&good).err(),
        Some(HandshakeError::MalformedHead)
    );
    reader.reset();
    assert!(reader.server(&good).unwrap().is_some());
}

#[test]
fn test_close_wait_after_failed_read_starts_at_next_tick() {
    // A read that fails after a quiet period must still give the peer the
    // whole close timeout to read the Close, not one measured from the
    // last tick before the read.
    let mut conn = Connection::server().with_keepalive(Keepalive::new());
    assert_eq!(conn.on_time(Millis(0)), Ok(Tick::Nothing));
    let _ = conn.feed(&[0x81, 0x00]); // unmasked: a protocol error
    assert!(conn.poll().is_err());
    assert!(conn.buffered_output() > 0); // Close 1002 queued
    assert_eq!(conn.on_time(Millis(20_000)), Ok(Tick::Nothing));
    assert!(!conn.should_close_transport());
    assert_eq!(conn.next_deadline(), Some(Millis(25_000)));
    assert_eq!(conn.on_time(Millis(25_000)), Ok(Tick::Nothing));
    assert!(conn.should_close_transport());
}

#[test]
fn test_control_frame_split_counted_once() {
    // A control frame waits for its whole payload, decoding its header on
    // every poll; each wait counted it again in `frames_in`.
    let mut wire = client_frame(0x9, true, b"ping payload");
    wire.extend(client_frame(0x2, false, b"ab"));
    wire.extend(client_frame(0x0, true, b"cd"));
    let mut conn = Connection::server();
    for byte in &wire {
        assert_eq!(conn.feed(core::slice::from_ref(byte)), 1);
        while !matches!(conn.poll(), Ok(Event::NeedInput)) {}
    }
    let stats = conn.stats();
    assert_eq!(
        (stats.frames_in, stats.pings_in, stats.messages_in),
        (3, 1, 1)
    );
    assert_eq!(stats.data_frames_in(), 2);
}

/// Fixed in 0.9: a connection with no keepalive set still has the 5 s close
/// timeout, so a peer that never answers the Close releases the transport.
#[test]
fn test_close_timeout_without_keepalive() {
    use ws_net::{CloseCode, Millis};
    let mut conn = Connection::server();
    conn.close(CloseCode::NORMAL, "").unwrap();
    let n = conn.output().len();
    conn.advance_output(n);
    assert_eq!(conn.on_time(Millis(0)), Ok(ws_net::Tick::Nothing));
    assert_eq!(conn.next_deadline(), Some(Millis(5_000)));
    assert_eq!(conn.on_time(Millis(5_000)), Err(WsError::CloseTimeout));
    assert!(conn.should_close_transport());
    // An open connection with nothing armed costs no wake-ups.
    let idle = Connection::server();
    assert_eq!(idle.next_deadline(), None);
}

/// Fixed in 0.9: a full input buffer is parsed, not copied, while it holds
/// more than a frame header or a control frame: feeding after every event
/// stays linear.
#[test]
fn test_full_input_not_compacted_per_event() {
    let limits = Limits::new().with_input_buffer(256);
    let mut conn = Connection::server().with_limits(limits);
    let mut wire = Vec::new();
    while wire.len() < 600 {
        wire.extend_from_slice(&client_frame(0x2, true, b""));
    }
    let mut rest = &wire[..];
    let mut events = 0;
    let n = conn.feed(rest);
    assert_eq!(n, 256);
    rest = &rest[n..];
    assert!(matches!(conn.poll(), Ok(Event::Binary(b"")))); // one 6-byte frame read
    events += 1;
    // 250 bytes unread: nothing fits yet, and nothing is copied.
    assert_eq!(conn.feed(rest), 0);
    loop {
        match conn.poll().unwrap() {
            Event::Binary(_) => events += 1,
            Event::NeedInput => {
                if rest.is_empty() {
                    break;
                }
                let n = conn.feed(rest);
                assert!(n > 0, "room once the buffer is parsed");
                rest = &rest[n..];
            }
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(events, wire.len() / 6);
}

/// Fixed in 0.9: `detach_message` gives nothing once input was fed, however
/// the buffer moved.
#[test]
fn test_detach_none_after_feed() {
    let mut conn = Connection::server();
    let _ = conn.feed(&client_frame(0x1, true, b"abc"));
    assert!(matches!(conn.poll(), Ok(Event::Text("abc"))));
    let _ = conn.feed(&client_frame(0x9, true, b""));
    assert_eq!(conn.detach_message(&mut Vec::new()), None);
}

/// Fixed in 0.9: the largest time does not switch the idle timeout off.
#[test]
fn test_idle_timeout_at_largest_time() {
    use ws_net::{Keepalive, Millis};
    let mut conn = Connection::server()
        .with_keepalive(Keepalive::new().with_idle_timeout(Duration::from_secs(1)));
    assert!(conn.on_time(Millis(0)).is_ok());
    assert_eq!(conn.on_time(Millis(u64::MAX)), Err(WsError::IdleTimeout));
}

/// Fixed in 0.9: a client fails a response whose `Upgrade` names more than
/// `websocket` (RFC 6455 section 4.1).
#[test]
fn test_client_upgrade_must_be_websocket_alone() {
    use ws_net::{ClientHandshake, HandshakeError};
    let client = ClientHandshake::with_nonce(*b"the sample nonce");
    let fields = |upgrade: &'static [u8]| {
        [
            ("Upgrade", upgrade),
            ("Connection", &b"Upgrade"[..]),
            ("Sec-WebSocket-Accept", b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
        ]
    };
    assert_eq!(
        client.verify(101, fields(b"WebSocket")).map(|v| v.protocol),
        Ok(None)
    );
    assert_eq!(
        client.verify(101, fields(b"websocket, h2c")),
        Err(HandshakeError::MissingUpgrade)
    );
}
