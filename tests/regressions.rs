//! Regression tests from the v0.2.0 adversarial review. Each test was
//! written failing before its fix; the name says what was wrong.

mod common;

use common::{Ev, client_frame, drive};
use ws_net::{CloseCode, Connection, Event, Limits, State, WsError, frame::apply_mask};

#[test]
fn test_apply_mask_with_any_offset_does_not_overflow() {
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
fn test_commit_and_advance_output_saturate() {
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
fn test_usage_errors_do_not_report_a_close_code() {
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
fn test_unanswered_pings_do_not_grow_the_output() {
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
fn test_pong_after_user_frame_is_not_overwritten() {
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
fn test_huge_limits_do_not_reserve_announced_length() {
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
fn test_header_announcing_maximum_length_fails_before_payload() {
    // 2^63 - 1 bytes announced: refused from the header alone.
    let mut wire = vec![0x82, 0x80 | 127];
    wire.extend_from_slice(&(i64::MAX as u64).to_be_bytes());
    wire.extend_from_slice(&[1, 2, 3, 4]);
    let (events, out) = drive(&mut Connection::server(), &[&wire], false);
    assert_eq!(events, vec![Ev::Err(WsError::FrameTooLarge)]);
    assert_eq!(out, [0x88, 0x02, 0x03, 0xF1]);
}
