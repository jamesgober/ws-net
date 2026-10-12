//! The closing handshake (RFC 6455 sections 5.5.1 and 7) from both ends,
//! in both orders, and the rules around it: no data after Close, no Pong
//! after Close, data still delivered while closing, and EOF handling.

mod common;

use common::{Ev, client_frame, close_payload, decode_frames, drive, server_frame};
use ws_net::{CloseCode, Connection, Event, State, WsError, frame::Opcode};

#[test]
fn test_server_initiated_close() {
    let mut server = Connection::server();
    server.close(CloseCode::GOING_AWAY, "restart").unwrap();
    assert_eq!(server.state(), State::Closing);
    assert_eq!(
        decode_frames(server.output()),
        [(Opcode::Close, true, close_payload(1001, "restart"))]
    );
    server.advance_output(usize::MAX);
    // Nothing may follow a Close frame.
    assert!(matches!(
        server.send_text("x"),
        Err(WsError::InvalidState(_))
    ));
    assert!(matches!(
        server.send_binary(b"x"),
        Err(WsError::InvalidState(_))
    ));
    assert!(matches!(
        server.send_text_fragment("x", true),
        Err(WsError::InvalidState(_))
    ));
    assert!(matches!(
        server.send_pong(b""),
        Err(WsError::InvalidState(_))
    ));
    assert!(matches!(
        server.close(CloseCode::NORMAL, ""),
        Err(WsError::InvalidState(_))
    ));
    // The peer may still send data and pings before its Close: data is
    // delivered, pings are not answered, and its Close ends the handshake
    // without an echo.
    let wire = [
        client_frame(0x1, true, b"late"),
        client_frame(0x9, true, b"p"),
        client_frame(0x8, true, &close_payload(1001, "")),
    ]
    .concat();
    let (events, out) = drive(&mut server, &[&wire], false);
    assert_eq!(
        events,
        [
            Ev::Text("late".into()),
            Ev::Ping(b"p".to_vec()),
            Ev::Close(Some((1001, String::new())))
        ]
    );
    assert!(out.is_empty(), "{out:?}");
    assert_eq!(server.state(), State::Closed);
}

#[test]
fn test_client_answers_server_close_with_masked_close() {
    let mut client = Connection::client_with_seed([4; 32]);
    let wire = server_frame(0x8, true, &close_payload(1000, "bye"));
    let (events, out) = drive(&mut client, &[&wire], false);
    assert_eq!(events, [Ev::Close(Some((1000, "bye".into())))]);
    // The echo is masked, like every client frame, and carries the code.
    assert_eq!(out[1] & 0x80, 0x80);
    assert_eq!(
        decode_frames(&out),
        [(Opcode::Close, true, 1000u16.to_be_bytes().to_vec())]
    );
    assert_eq!(client.state(), State::Closed);
    assert!(matches!(
        client.send_text("x"),
        Err(WsError::InvalidState(_))
    ));
}

#[test]
fn test_client_initiated_close_completes() {
    let mut client = Connection::client_with_seed([5; 32]);
    let mut server = Connection::server();
    client.close(CloseCode::NORMAL, "done").unwrap();
    let wire = client.output().to_vec();
    client.advance_output(wire.len());
    let (events, reply) = drive(&mut server, &[&wire], false);
    assert_eq!(events, [Ev::Close(Some((1000, "done".into())))]);
    let (events, out) = drive(&mut client, &[&reply], false);
    assert_eq!(events, [Ev::Close(Some((1000, String::new())))]);
    assert!(out.is_empty());
    assert_eq!(
        (client.state(), server.state()),
        (State::Closed, State::Closed)
    );
}

#[test]
fn test_close_during_outgoing_fragmented_message() {
    // A Close may interrupt our own fragmented message; nothing may follow.
    let mut server = Connection::server();
    server.send_text_fragment("par", false).unwrap();
    server.close(CloseCode::NORMAL, "").unwrap();
    assert!(matches!(
        server.send_text_fragment("t", true),
        Err(WsError::InvalidState(_))
    ));
    let frames = decode_frames(server.output());
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[1].0, Opcode::Close);
}

#[test]
fn test_pending_pong_goes_out_before_close() {
    // A Ping answered before this end closes: the Pong precedes the Close.
    let mut server = Connection::server();
    let _ = server.feed(&client_frame(0x9, true, b"hb"));
    assert!(matches!(server.poll().unwrap(), Event::Ping(b"hb")));
    server.close(CloseCode::NORMAL, "").unwrap();
    let frames = decode_frames(server.output());
    assert_eq!(
        frames,
        [
            (Opcode::Pong, true, b"hb".to_vec()),
            (Opcode::Close, true, 1000u16.to_be_bytes().to_vec())
        ]
    );
}

#[test]
fn test_eof_while_closing_is_abnormal() {
    let mut server = Connection::server();
    server.close(CloseCode::NORMAL, "").unwrap();
    server.advance_output(usize::MAX);
    let (events, out) = drive(&mut server, &[], true);
    assert_eq!(events, [Ev::Err(WsError::UnexpectedEof)]);
    assert!(out.is_empty());
    assert_eq!(server.state(), State::Closed);
}

#[test]
fn test_eof_after_close_is_clean() {
    let mut server = Connection::server();
    let wire = client_frame(0x8, true, b"");
    let (events, _) = drive(&mut server, &[&wire], true);
    assert_eq!(events, [Ev::Close(None)]);
    assert!(matches!(server.poll().unwrap(), Event::Closed));
}

#[test]
fn test_failure_after_close_sent_queues_nothing_more() {
    // Once this end has sent its Close, a protocol error must not queue a
    // second Close frame.
    let mut server = Connection::server();
    server.close(CloseCode::NORMAL, "").unwrap();
    server.advance_output(usize::MAX);
    let (events, out) = drive(&mut server, &[&server_frame(0x1, true, b"x")], false);
    assert_eq!(events, [Ev::Err(WsError::UnmaskedFrame)]);
    assert!(out.is_empty());
}

#[test]
fn test_failure_reports_once_then_closed() {
    let mut server = Connection::server();
    let _ = server.feed(&[0x83, 0x80, 0, 0, 0, 0]);
    assert_eq!(server.poll().unwrap_err(), WsError::ReservedOpcode);
    assert!(matches!(server.poll().unwrap(), Event::Closed));
    assert!(matches!(server.poll().unwrap(), Event::Closed));
    assert_eq!(server.state(), State::Closed);
    assert_eq!(server.output(), [0x88, 0x02, 0x03, 0xEA]);
    assert!(matches!(
        server.send_text("x"),
        Err(WsError::InvalidState(_))
    ));
}
