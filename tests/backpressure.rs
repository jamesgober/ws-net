//! The output budget and its control headroom (slow consumers), split
//! borrows, detaching messages, prepared messages, counters, and wiping.

mod common;

use common::{client_frame, decode_frames, drive};
use ws_net::{
    CloseCode, Connection, Event, Limits, Message, MessageKind, PreparedMessage, State, WsError,
    frame::Opcode,
};

fn budgeted(bytes: u64) -> Connection {
    Connection::server().with_limits(Limits::new().with_max_output(bytes))
}

#[test]
fn test_output_budget_exact_fit_accepted_one_more_refused() {
    let mut conn = budgeted(1000);
    // 2-byte header + 126-byte payload uses the 16-bit length: 4 + 996.
    conn.send_binary(&[0; 996]).unwrap();
    assert_eq!(conn.buffered_output(), 1000);
    let before = conn.output().to_vec();
    assert_eq!(conn.send_binary(&[]), Err(WsError::OutputFull));
    assert_eq!(conn.send_text("x"), Err(WsError::OutputFull));
    assert_eq!(conn.send_ping(b""), Err(WsError::OutputFull));
    assert_eq!(WsError::OutputFull.close_code(), None);
    assert_eq!(conn.output(), before, "a refused send changes nothing");
    assert!(conn.is_open());
}

#[test]
fn test_output_budget_close_and_pong_use_headroom() {
    let mut conn = budgeted(1000);
    conn.send_binary(&[0; 996]).unwrap();
    // A Ping arrives: its Pong is queued in the headroom.
    let _ = conn.feed(&client_frame(0x9, true, &[7; 125]));
    assert!(matches!(conn.poll(), Ok(Event::Ping(_))));
    assert_eq!(conn.buffered_output(), 1000 + 127);
    // A Close with the longest reason still fits.
    conn.close(CloseCode::TRY_AGAIN_LATER, &"r".repeat(123)).unwrap();
    assert_eq!(conn.buffered_output(), 1000 + 127 + 127);
    let frames = decode_frames(conn.output());
    assert_eq!(frames.len(), 3);
    assert_eq!(frames[1].0, Opcode::Pong);
    assert_eq!(frames[2].0, Opcode::Close);
}

#[test]
fn test_output_budget_ping_flood_unread_stays_bounded() {
    let mut conn = budgeted(1000);
    conn.send_binary(&[0; 996]).unwrap();
    let mut wire = Vec::new();
    for i in 0..10_000u32 {
        wire.extend_from_slice(&client_frame(0x9, true, &i.to_be_bytes()));
    }
    let pieces: Vec<&[u8]> = wire.chunks(4096).collect();
    for piece in pieces {
        let mut rest = piece;
        while !rest.is_empty() {
            let n = conn.feed(rest);
            rest = &rest[n..];
            while let Ok(Event::Ping(_)) = conn.poll() {}
        }
    }
    // One Pong, the latest, after the data.
    let frames = decode_frames(conn.output());
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[1], (Opcode::Pong, true, 9_999u32.to_be_bytes().to_vec()));
    assert!(conn.buffered_output() <= 1000 + 256);
}

#[test]
fn test_output_budget_drain_then_send_again() {
    let mut conn = budgeted(1000);
    conn.send_binary(&[0; 996]).unwrap();
    assert_eq!(conn.send_text("x"), Err(WsError::OutputFull));
    conn.advance_output(500);
    conn.send_text("x").unwrap();
    // Fragments are refused whole too.
    assert_eq!(conn.send_binary_fragment(&[0; 600], false), Err(WsError::OutputFull));
    assert!(conn.can_send());
}

#[test]
fn test_output_budget_lifted_accepts_anything() {
    let mut conn = budgeted(u64::MAX);
    conn.send_binary(&vec![0; 1 << 20]).unwrap();
    conn.send_binary(&vec![0; 1 << 20]).unwrap();
}

#[test]
fn test_poll_split_reply_while_holding_message() {
    let mut conn = Connection::server();
    let _ = conn.feed(&client_frame(0x1, true, b"ping me"));
    let (event, mut sender) = conn.poll_split().unwrap();
    match event {
        Event::Text(text) => sender.send_text(text).unwrap(),
        other => panic!("{other:?}"),
    }
    assert_eq!(decode_frames(conn.output()), [(Opcode::Text, true, b"ping me".to_vec())]);
}

#[test]
fn test_detach_message_matches_event_both_paths() {
    // Single frame, lent from the input buffer: copied.
    let mut conn = Connection::server();
    let _ = conn.feed(&client_frame(0x2, true, &[1, 2, 3]));
    assert!(matches!(conn.poll(), Ok(Event::Binary(_))));
    let mut owned = vec![9; 10];
    assert_eq!(conn.detach_message(&mut owned), Some(MessageKind::Binary));
    assert_eq!(owned, [1, 2, 3]);
    // Reassembled: swapped, no copy.
    let mut conn = Connection::server();
    let mut wire = client_frame(0x1, false, b"Hel");
    wire.extend_from_slice(&client_frame(0x0, true, b"lo"));
    let _ = conn.feed(&wire);
    assert!(matches!(conn.poll(), Ok(Event::Text("Hello"))));
    let mut owned = Vec::with_capacity(1000);
    let old = owned.as_ptr();
    assert_eq!(conn.detach_message(&mut owned), Some(MessageKind::Text));
    assert_eq!(owned, b"Hello");
    assert_ne!(owned.as_ptr(), old);
    // Not after a control frame, and not twice.
    let _ = conn.feed(&client_frame(0x9, true, b""));
    assert!(matches!(conn.poll(), Ok(Event::Ping(_))));
    assert_eq!(conn.detach_message(&mut owned), None);
    assert_eq!(owned, b"Hello", "nothing changes on None");
    // The next message still arrives whole after a swap.
    let _ = conn.feed(&client_frame(0x1, false, b"a"));
    let _ = conn.feed(&client_frame(0x0, true, b"b"));
    let mut got = None;
    for _ in 0..4 {
        if let Ok(Event::Text(t)) = conn.poll() {
            got = Some(t.to_string());
            break;
        }
    }
    assert_eq!(got.as_deref(), Some("ab"));
}

#[test]
fn test_detach_message_after_feed_refused() {
    let mut conn = Connection::server().with_limits(Limits::new().with_input_buffer(256));
    let frame = client_frame(0x2, true, &[5; 100]);
    let _ = conn.feed(&frame);
    assert!(matches!(conn.poll(), Ok(Event::Binary(_))));
    // Feeding may compact the buffer under the lent bytes.
    let _ = conn.feed(&[0; 200]);
    let mut owned = Vec::new();
    assert_eq!(conn.detach_message(&mut owned), None);
}

#[test]
fn test_prepared_message_broadcast_and_refusals() {
    let msg = PreparedMessage::text_with(&"x".repeat(300), &Limits::new().with_send_frame(125));
    let mut a = Connection::server();
    let mut b = Connection::server();
    a.send_prepared(&msg).unwrap();
    b.send_prepared(&msg).unwrap();
    assert_eq!(a.output(), b.output());
    // A client reading it gets the whole text.
    let mut client = Connection::client_with_seed([3; 32]);
    let (events, _) = drive(&mut client, &[a.output()], false);
    assert_eq!(events, [common::Ev::Text("x".repeat(300))]);
    // Refused for a client, during fragments, past the budget.
    assert!(matches!(client.send_prepared(&msg), Err(WsError::InvalidState(_))));
    let mut c = Connection::server();
    c.send_text_fragment("a", false).unwrap();
    assert!(matches!(c.send_prepared(&msg), Err(WsError::InvalidState(_))));
    let mut d = budgeted(100);
    assert_eq!(d.send_prepared(&msg), Err(WsError::OutputFull));
    assert_eq!(a.stats().messages_out, 1);
}

#[test]
fn test_send_owned_messages_and_to_message() {
    let mut conn = Connection::server();
    for m in [
        Message::from("t"),
        Message::from(&[1u8][..]),
        Message::Ping(vec![2]),
        Message::Pong(vec![3]),
        Message::Close(Some((CloseCode::NORMAL, "bye".into()))),
    ] {
        conn.send(&m).unwrap();
    }
    let ops: Vec<_> = decode_frames(conn.output()).into_iter().map(|f| f.0).collect();
    assert_eq!(ops, [Opcode::Text, Opcode::Binary, Opcode::Ping, Opcode::Pong, Opcode::Close]);
    assert!(matches!(conn.send(&Message::Close(None)), Err(WsError::InvalidState(_))));

    let mut server = Connection::server();
    let _ = server.feed(&client_frame(0x8, true, &[0x03, 0xE8, b'o', b'k']));
    let event = server.poll().unwrap();
    assert_eq!(
        event.to_message(),
        Some(Message::Close(Some((CloseCode::NORMAL, "ok".into()))))
    );
}

#[test]
fn test_stats_count_both_directions() {
    let mut conn = Connection::server();
    let mut wire = client_frame(0x1, true, b"a");
    wire.extend_from_slice(&client_frame(0x9, true, b""));
    wire.extend_from_slice(&client_frame(0xA, true, b""));
    wire.extend_from_slice(&client_frame(0x2, false, b"b"));
    wire.extend_from_slice(&client_frame(0x0, true, b"c"));
    let (events, out) = drive(&mut conn, &[&wire], false);
    assert_eq!(events.len(), 4);
    conn.send_text("reply").unwrap();
    let n = conn.output().len();
    conn.advance_output(n);
    let s = conn.stats();
    assert_eq!(s.bytes_in, wire.len() as u64);
    assert_eq!((s.frames_in, s.messages_in, s.pings_in, s.pongs_in), (5, 2, 1, 1));
    assert_eq!(s.messages_out, 1);
    assert_eq!(s.bytes_out, (out.len() + n) as u64);
}

#[test]
fn test_wipe_zeroes_and_fails() {
    let mut conn = Connection::client_with_seed([4; 32]);
    conn.send_text("secret").unwrap();
    let _ = conn.feed(&common::server_frame(0x1, false, b"half a secr"));
    let _ = conn.poll();
    conn.wipe();
    assert_eq!(conn.state(), State::Closed);
    assert!(conn.output().is_empty());
    assert!(matches!(conn.poll(), Ok(Event::Closed)));
    assert!(conn.send_text("x").is_err());
    // A server's wipe in the middle of a message, then input is ignored.
    let mut server = Connection::server();
    let _ = server.feed(&client_frame(0x1, false, b"a"));
    let _ = server.poll();
    server.wipe();
    let _ = server.feed(&client_frame(0x0, true, b"b"));
    assert!(matches!(server.poll(), Ok(Event::Closed)));
}

#[test]
fn test_release_memory_keeps_pending_frees_idle() {
    let mut conn = Connection::server();
    assert_eq!(conn.memory_in_use(), 0);
    let _ = conn.feed(&client_frame(0x1, false, &[b'a'; 1000]));
    let _ = conn.poll();
    conn.send_binary(&[0; 5000]).unwrap();
    conn.release_memory();
    // A partial message and pending output are kept.
    assert!(conn.memory_in_use() >= 1000 + 5000);
    let _ = conn.feed(&client_frame(0x0, true, b"b"));
    assert!(matches!(conn.poll(), Ok(Event::Text(_))));
    let n = conn.output().len();
    conn.advance_output(n);
    conn.release_memory();
    assert_eq!(conn.memory_in_use(), 0);
    // And the connection still works afterwards.
    let _ = conn.feed(&client_frame(0x1, true, b"again"));
    assert!(matches!(conn.poll(), Ok(Event::Text("again"))));
}

#[test]
fn test_retain_shrinks_buffers_after_burst() {
    let limits = Limits::new().with_retain(4096);
    let mut conn = Connection::server().with_limits(limits);
    conn.send_binary(&[0; 100_000]).unwrap();
    let n = conn.output().len();
    conn.advance_output(n);
    assert!(conn.memory_in_use() <= 64 * 1024, "output shrunk after drain");
    let mut wire = client_frame(0x2, false, &[1; 50_000]);
    wire.extend_from_slice(&client_frame(0x0, true, &[1; 50_000]));
    let (events, _) = drive(&mut conn, &wire.chunks(4096).collect::<Vec<_>>(), false);
    assert_eq!(events.len(), 1);
    let _ = conn.poll();
    assert!(conn.memory_in_use() <= 2 * 64 * 1024, "{}", conn.memory_in_use());
}

#[test]
fn test_input_buffer_limit_bounds_feed() {
    let mut conn = Connection::server().with_limits(Limits::new().with_input_buffer(256));
    assert_eq!(conn.feed(&[0x81; 1000]), 256);
    // A 125-byte control frame still fits whole.
    let mut conn = Connection::server().with_limits(Limits::new().with_input_buffer(1));
    let ping = client_frame(0x9, true, &[1; 125]);
    let (events, _) = drive(&mut conn, &[&ping], false);
    assert_eq!(events, [common::Ev::Ping(vec![1; 125])]);
}
