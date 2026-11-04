//! Regression tests from the v0.2.0 adversarial review. Each test was
//! written failing before its fix; the name says what was wrong.

mod common;

use common::{Ev, client_frame, drive};
use ws_net::{CloseCode, Connection, Event, Limits, State, WsError, frame::apply_mask};

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
