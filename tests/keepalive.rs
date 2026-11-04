//! Keepalive and timeouts driven by the caller's clock (`on_time`,
//! `next_deadline`), the slow-message and close-hang defenses, and
//! `should_close_transport`.

mod common;

use core::time::Duration;

use common::{client_frame, decode_frames};
use ws_net::{
    CloseCode, Connection, Event, Keepalive, Millis, State, Tick, WsError, frame::Opcode,
};

fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

fn studio() -> Keepalive {
    Keepalive::new()
        .with_ping_interval(secs(30))
        .with_idle_timeout(secs(75))
}

fn drain(conn: &mut Connection) -> Vec<(Opcode, bool, Vec<u8>)> {
    let out = conn.output().to_vec();
    conn.advance_output(out.len());
    decode_frames(&out)
}

#[test]
fn test_keepalive_unset_no_deadlines() {
    let mut conn = Connection::server();
    assert_eq!(conn.on_time(Millis(1_000_000)), Ok(Tick::Nothing));
    assert_eq!(conn.next_deadline(), None);
    let conn = Connection::server().with_keepalive(studio());
    // No tick yet: the timers have no start.
    assert_eq!(conn.next_deadline(), None);
}

#[test]
fn test_keepalive_ping_carries_tick_and_is_sent_once() {
    let mut conn = Connection::server().with_keepalive(studio());
    assert_eq!(conn.on_time(Millis(5)), Ok(Tick::Nothing));
    assert_eq!(conn.next_deadline(), Some(Millis(30_005)));
    assert_eq!(conn.on_time(Millis(30_004)), Ok(Tick::Nothing));
    assert_eq!(conn.on_time(Millis(30_005)), Ok(Tick::PingQueued));
    let frames = drain(&mut conn);
    assert_eq!(
        frames,
        [(Opcode::Ping, true, 30_005u64.to_be_bytes().to_vec())]
    );
    // Outstanding: no second Ping, the next deadline is the idle timeout.
    assert_eq!(conn.on_time(Millis(60_010)), Ok(Tick::Nothing));
    assert_eq!(conn.next_deadline(), Some(Millis(75_005)));
}

#[test]
fn test_keepalive_input_resets_idle_and_ping() {
    let mut conn = Connection::server().with_keepalive(studio());
    let _ = conn.on_time(Millis(0));
    let _ = conn.feed(&client_frame(0xA, true, b""));
    assert!(matches!(conn.poll(), Ok(Event::Pong(_))));
    assert_eq!(conn.on_time(Millis(29_000)), Ok(Tick::Nothing));
    assert_eq!(conn.next_deadline(), Some(Millis(59_000)));
    assert_eq!(conn.on_time(Millis(74_999)), Ok(Tick::PingQueued));
    // Idle counts from the last input, at 29 s: due at 104 s.
    assert_eq!(conn.on_time(Millis(103_999)), Ok(Tick::Nothing));
    assert_eq!(conn.on_time(Millis(104_000)), Err(WsError::IdleTimeout));
}

#[test]
fn test_keepalive_idle_timeout_queues_close_1001_once() {
    let mut conn =
        Connection::server().with_keepalive(Keepalive::new().with_idle_timeout(secs(10)));
    let _ = conn.on_time(Millis(0));
    let e = conn.on_time(Millis(10_000)).unwrap_err();
    assert_eq!(
        (e, e.close_code()),
        (WsError::IdleTimeout, Some(CloseCode::GOING_AWAY))
    );
    assert_eq!(drain(&mut conn), [(Opcode::Close, true, vec![0x03, 0xE9])]);
    assert_eq!(conn.state(), State::Closed);
    assert_eq!(conn.on_time(Millis(20_000)), Ok(Tick::Nothing));
    assert_eq!(conn.next_deadline(), None);
    assert!(matches!(conn.poll(), Ok(Event::Closed)));
    assert!(conn.should_close_transport());
}

#[test]
fn test_keepalive_close_timeout_sends_nothing_more() {
    let mut conn = Connection::client_with_seed([1; 32]).with_keepalive(Keepalive::new());
    let _ = conn.on_time(Millis(100));
    conn.close(CloseCode::NORMAL, "").unwrap();
    let _ = drain(&mut conn);
    // The Close is first seen at 200 ms: due 5 s later, inclusive.
    assert_eq!(conn.on_time(Millis(200)), Ok(Tick::Nothing));
    assert_eq!(conn.next_deadline(), Some(Millis(5_200)));
    assert!(!conn.should_close_transport());
    assert_eq!(conn.on_time(Millis(5_199)), Ok(Tick::Nothing));
    assert_eq!(conn.on_time(Millis(5_200)), Err(WsError::CloseTimeout));
    assert!(conn.output().is_empty());
    // A client may now close the transport itself.
    assert!(conn.should_close_transport());
}

#[test]
fn test_keepalive_slow_message_fails_1008() {
    let k = Keepalive::new().with_message_timeout(secs(10));
    let mut conn = Connection::server().with_keepalive(k);
    let _ = conn.on_time(Millis(0));
    let _ = conn.feed(&client_frame(0x1, false, b"part"));
    assert!(matches!(conn.poll(), Ok(Event::NeedInput)));
    assert_eq!(conn.on_time(Millis(1_000)), Ok(Tick::Nothing));
    assert_eq!(conn.next_deadline(), Some(Millis(11_000)));
    // Trickling bytes does not extend the message deadline.
    let _ = conn.feed(&client_frame(0x0, false, b"more"));
    assert!(matches!(conn.poll(), Ok(Event::NeedInput)));
    let e = conn.on_time(Millis(11_000)).unwrap_err();
    assert_eq!(
        (e, e.close_code()),
        (WsError::MessageTimeout, Some(CloseCode::POLICY_VIOLATION))
    );
    assert_eq!(drain(&mut conn), [(Opcode::Close, true, vec![0x03, 0xF0])]);
}

#[test]
fn test_keepalive_completed_message_clears_deadline() {
    let k = Keepalive::new().with_message_timeout(secs(10));
    let mut conn = Connection::server().with_keepalive(k);
    let _ = conn.on_time(Millis(0));
    let _ = conn.feed(&client_frame(0x1, false, b"a"));
    let _ = conn.poll();
    let _ = conn.on_time(Millis(1));
    let _ = conn.feed(&client_frame(0x0, true, b"b"));
    assert!(matches!(conn.poll(), Ok(Event::Text("ab"))));
    assert_eq!(conn.on_time(Millis(20_000)), Ok(Tick::Nothing));
    // A new message gets a fresh deadline.
    let _ = conn.feed(&client_frame(0x1, false, b"c"));
    let _ = conn.poll();
    assert_eq!(conn.on_time(Millis(25_000)), Ok(Tick::Nothing));
    assert_eq!(conn.next_deadline(), Some(Millis(35_000)));
}

#[test]
fn test_keepalive_clock_backwards_and_saturation() {
    let mut conn =
        Connection::server().with_keepalive(Keepalive::new().with_idle_timeout(secs(10)));
    let _ = conn.on_time(Millis(50_000));
    // Time going backwards is no time passing.
    assert_eq!(conn.on_time(Millis(0)), Ok(Tick::Nothing));
    assert_eq!(conn.next_deadline(), Some(Millis(60_000)));
    let mut conn =
        Connection::server().with_keepalive(Keepalive::new().with_idle_timeout(Duration::MAX));
    let _ = conn.on_time(Millis(u64::MAX - 1));
    assert_eq!(conn.on_time(Millis(u64::MAX - 1)), Ok(Tick::Nothing));
}

#[test]
fn test_should_close_transport_server_after_exchange() {
    let mut conn = Connection::server();
    assert!(!conn.should_close_transport());
    let mut close = 1000u16.to_be_bytes().to_vec();
    close.extend_from_slice(b"bye");
    let _ = conn.feed(&client_frame(0x8, true, &close));
    assert!(matches!(conn.poll(), Ok(Event::Close(Some(_)))));
    assert!(!conn.should_close_transport()); // the echo is not written
    let _ = drain(&mut conn);
    assert!(conn.should_close_transport());
}

#[test]
fn test_should_close_transport_client_waits_for_eof() {
    let mut conn = Connection::client_with_seed([2; 32]);
    let _ = conn.feed(&common::server_frame(0x8, true, &1000u16.to_be_bytes()));
    assert!(matches!(conn.poll(), Ok(Event::Close(Some(_)))));
    let _ = drain(&mut conn);
    assert!(!conn.should_close_transport());
    conn.feed_eof();
    assert!(conn.should_close_transport());
}
