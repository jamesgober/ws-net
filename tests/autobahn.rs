//! Autobahn-style protocol cases as data.
//!
//! Each case mirrors a section of the Autobahn|Testsuite fuzzing client
//! (framing, ping/pong, reserved bits, opcodes, fragmentation, UTF-8,
//! close handling, limits) plus the RFC 6455 rules Autobahn does not
//! cover from the server side (masking direction, length encoding). A case
//! is the bytes a peer sends, the events the connection must report, and
//! the frames it must write back. Every case runs fed whole, one byte at a
//! time, and in 7-byte pieces; all three runs must agree exactly.
//!
//! The full Autobahn suite as a dev-only oracle is part of v0.9.0 (see
//! `dev/ROADMAP.md`); these cases are its behaviour written down as data.

mod common;

use common::{Ev, KEY, client_frame, close_payload, decode_frames, drive, raw, server_frame};
use ws_net::{Connection, Limits, WsError, frame::Opcode};

struct Case {
    id: &'static str,
    client: bool,
    limits: Limits,
    input: Vec<u8>,
    eof: bool,
    events: Vec<Ev>,
    replies: Vec<(Opcode, Vec<u8>)>,
}

fn case(
    id: &'static str,
    input: Vec<u8>,
    events: Vec<Ev>,
    replies: Vec<(Opcode, Vec<u8>)>,
) -> Case {
    Case {
        id,
        client: false,
        limits: Limits::new(),
        input,
        eof: false,
        events,
        replies,
    }
}

fn concat(frames: &[Vec<u8>]) -> Vec<u8> {
    frames.concat()
}

fn text(s: &str) -> Ev {
    Ev::Text(s.to_string())
}

fn close_reply(code: u16) -> (Opcode, Vec<u8>) {
    (Opcode::Close, code.to_be_bytes().to_vec())
}

/// A failure case: the events before the failure, the error, and the Close
/// frame with `code` the connection must send.
fn fail(id: &'static str, input: Vec<u8>, before: Vec<Ev>, e: WsError, code: u16) -> Case {
    let mut events = before;
    events.push(Ev::Err(e));
    case(id, input, events, vec![close_reply(code)])
}

fn cases() -> Vec<Case> {
    let mut c = Vec::new();

    // 1.1 / 1.2: text and binary messages at the length-encoding boundaries.
    for &len in &[0usize, 125, 126, 127, 128, 65_535, 65_536] {
        let t = "*".repeat(len);
        c.push(case(
            "1.1 text",
            client_frame(0x1, true, t.as_bytes()),
            vec![text(&t)],
            vec![],
        ));
        let b = vec![0xfe; len];
        c.push(case(
            "1.2 binary",
            client_frame(0x2, true, &b),
            vec![Ev::Binary(b.clone())],
            vec![],
        ));
    }

    // 2: ping / pong.
    c.push(case(
        "2.1 empty ping",
        client_frame(0x9, true, b""),
        vec![Ev::Ping(vec![])],
        vec![(Opcode::Pong, vec![])],
    ));
    c.push(case(
        "2.2 ping with text payload",
        client_frame(0x9, true, b"Hello, world!"),
        vec![Ev::Ping(b"Hello, world!".to_vec())],
        vec![(Opcode::Pong, b"Hello, world!".to_vec())],
    ));
    let bin = vec![0x00, 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0x00, 0xff];
    c.push(case(
        "2.3 ping with binary payload",
        client_frame(0x9, true, &bin),
        vec![Ev::Ping(bin.clone())],
        vec![(Opcode::Pong, bin)],
    ));
    let p125 = vec![0xfe; 125];
    c.push(case(
        "2.4 ping with 125-byte payload",
        client_frame(0x9, true, &p125),
        vec![Ev::Ping(p125.clone())],
        vec![(Opcode::Pong, p125)],
    ));
    c.push(fail(
        "2.5 ping with 126-byte payload",
        client_frame(0x9, true, &[0xfe; 126]),
        vec![],
        WsError::ControlTooLong,
        1002,
    ));
    // A control frame using the 16-bit length field is over 125 bytes by
    // construction, whatever length the field holds.
    let mut ext16_ping = vec![0x89, 0x80 | 126, 0, 100];
    ext16_ping.extend_from_slice(&KEY);
    ext16_ping.extend_from_slice(&[0; 100]);
    c.push(fail(
        "2.6 ping with a 16-bit length field",
        ext16_ping,
        vec![],
        WsError::ControlTooLong,
        1002,
    ));
    let mut ext64_close = vec![0x88, 0x80 | 127, 0, 0, 0, 0, 0, 0, 0, 2];
    ext64_close.extend_from_slice(&KEY);
    c.push(fail(
        "2.6 close with a 64-bit length field",
        ext64_close,
        vec![],
        WsError::ControlTooLong,
        1002,
    ));
    c.push(case(
        "2.7 unsolicited pong",
        client_frame(0xA, true, b""),
        vec![Ev::Pong(vec![])],
        vec![],
    ));
    c.push(case(
        "2.8 unsolicited pong with payload",
        client_frame(0xA, true, b"unsolicited"),
        vec![Ev::Pong(b"unsolicited".to_vec())],
        vec![],
    ));
    c.push(case(
        "2.9 pong then ping",
        concat(&[client_frame(0xA, true, b"p"), client_frame(0x9, true, b"q")]),
        vec![Ev::Pong(b"p".to_vec()), Ev::Ping(b"q".to_vec())],
        vec![(Opcode::Pong, b"q".to_vec())],
    ));
    let ten: Vec<Vec<u8>> = (0..10)
        .map(|i| client_frame(0x9, true, format!("ping {i}").as_bytes()))
        .collect();
    c.push(case(
        "2.10 ten pings, each answered",
        concat(&ten),
        (0..10)
            .map(|i| Ev::Ping(format!("ping {i}").into_bytes()))
            .collect(),
        (0..10)
            .map(|i| (Opcode::Pong, format!("ping {i}").into_bytes()))
            .collect(),
    ));

    // 3: reserved bits.
    c.push(fail(
        "3.1 RSV1 on text",
        raw(0x80 | 0x40 | 0x1, true, b"x"),
        vec![],
        WsError::ReservedBits,
        1002,
    ));
    c.push(fail(
        "3.2 RSV2 after a valid message",
        concat(&[
            client_frame(0x1, true, b"ok"),
            raw(0x80 | 0x20 | 0x1, true, b"x"),
        ]),
        vec![text("ok")],
        WsError::ReservedBits,
        1002,
    ));
    c.push(fail(
        "3.4 RSV1+RSV2 on ping",
        raw(0x80 | 0x60 | 0x9, true, b""),
        vec![],
        WsError::ReservedBits,
        1002,
    ));
    c.push(fail(
        "3.5 RSV3 on binary",
        raw(0x80 | 0x10 | 0x2, true, b"x"),
        vec![],
        WsError::ReservedBits,
        1002,
    ));
    c.push(fail(
        "3.7 all RSV bits on close",
        raw(0x80 | 0x70 | 0x8, true, b""),
        vec![],
        WsError::ReservedBits,
        1002,
    ));

    // 4: reserved opcodes.
    for op in [0x3u8, 0x4, 0x5, 0x6, 0x7, 0xB, 0xC, 0xD, 0xE, 0xF] {
        c.push(fail(
            "4 reserved opcode",
            raw(0x80 | op, true, b"x"),
            vec![],
            WsError::ReservedOpcode,
            1002,
        ));
    }
    c.push(fail(
        "4.1.3 reserved opcode after a valid message",
        concat(&[client_frame(0x1, true, b"ok"), raw(0x85, true, b"")]),
        vec![text("ok")],
        WsError::ReservedOpcode,
        1002,
    ));

    // 5: fragmentation.
    c.push(fail(
        "5.1 fragmented ping",
        client_frame(0x9, false, b"a"),
        vec![],
        WsError::FragmentedControl,
        1002,
    ));
    c.push(fail(
        "5.2 fragmented pong",
        client_frame(0xA, false, b"a"),
        vec![],
        WsError::FragmentedControl,
        1002,
    ));
    c.push(case(
        "5.3 text in two fragments",
        concat(&[
            client_frame(0x1, false, b"frag"),
            client_frame(0x0, true, b"ment"),
        ]),
        vec![text("fragment")],
        vec![],
    ));
    c.push(case(
        "5.6 ping between fragments",
        concat(&[
            client_frame(0x1, false, b"frag"),
            client_frame(0x9, true, b"in between"),
            client_frame(0x0, true, b"ment"),
        ]),
        vec![Ev::Ping(b"in between".to_vec()), text("fragment")],
        vec![(Opcode::Pong, b"in between".to_vec())],
    ));
    c.push(fail(
        "5.9 continuation with no message",
        client_frame(0x0, true, b"x"),
        vec![],
        WsError::UnexpectedContinuation,
        1002,
    ));
    c.push(fail(
        "5.10 non-final continuation with no message",
        client_frame(0x0, false, b"x"),
        vec![],
        WsError::UnexpectedContinuation,
        1002,
    ));
    c.push(fail(
        "5.15 new message inside a fragmented one",
        concat(&[
            client_frame(0x1, false, b"a"),
            client_frame(0x1, true, b"b"),
        ]),
        vec![],
        WsError::ExpectedContinuation,
        1002,
    ));
    c.push(fail(
        "5.18 binary start inside a text message",
        concat(&[
            client_frame(0x1, false, b"a"),
            client_frame(0x2, false, b"b"),
        ]),
        vec![],
        WsError::ExpectedContinuation,
        1002,
    ));
    let many: Vec<Vec<u8>> = (0..20)
        .map(|i| match i {
            0 => client_frame(0x2, false, &[i]),
            19 => client_frame(0x0, true, &[i]),
            _ if i % 5 == 0 => [
                client_frame(0x9, true, &[i]),
                client_frame(0x0, false, &[i]),
            ]
            .concat(),
            _ => client_frame(0x0, false, &[i]),
        })
        .collect();
    c.push(case(
        "5.19 many fragments with pings interleaved",
        concat(&many),
        vec![
            Ev::Ping(vec![5]),
            Ev::Ping(vec![10]),
            Ev::Ping(vec![15]),
            Ev::Binary((0..20).collect()),
        ],
        vec![
            (Opcode::Pong, vec![5]),
            (Opcode::Pong, vec![10]),
            (Opcode::Pong, vec![15]),
        ],
    ));

    // 6: UTF-8.
    c.push(case(
        "6.1 empty text",
        client_frame(0x1, true, b""),
        vec![text("")],
        vec![],
    ));
    let s = "Hello-µ@ßöäüàá-UTF-8!!";
    c.push(case(
        "6.2 valid UTF-8",
        client_frame(0x1, true, s.as_bytes()),
        vec![text(s)],
        vec![],
    ));
    let kosme = "κόσμε";
    let per_byte: Vec<Vec<u8>> = kosme
        .bytes()
        .enumerate()
        .map(|(i, b)| {
            let op = if i == 0 { 0x1 } else { 0x0 };
            client_frame(op, i + 1 == kosme.len(), &[b])
        })
        .collect();
    c.push(case(
        "6.4 valid UTF-8 split inside code points",
        concat(&per_byte),
        vec![text(kosme)],
        vec![],
    ));
    c.push(case(
        "6.5 four-byte sequences",
        client_frame(0x1, true, "\u{1F600}\u{10FFFF}".as_bytes()),
        vec![text("\u{1F600}\u{10FFFF}")],
        vec![],
    ));
    let surrogate =
        b"\xce\xba\xe1\xbd\xb9\xcf\x83\xce\xbc\xce\xb5\xed\xa0\x80\x65\x64\x69\x74\x65\x64";
    c.push(fail(
        "6.3 surrogate in text",
        client_frame(0x1, true, surrogate),
        vec![],
        WsError::InvalidUtf8,
        1007,
    ));
    for (id, bad) in [
        ("6.8 code point above U+10FFFF", &b"\xf4\x90\x80\x80"[..]),
        ("6.9 overlong encoding", b"\xc0\xaf"),
        ("6.10 lone continuation byte", b"\x80"),
        ("6.11 invalid lead byte", b"a\xffb"),
        ("6.12 truncated at the end of the message", b"\xe2\x82"),
    ] {
        c.push(fail(
            id,
            client_frame(0x1, true, bad),
            vec![],
            WsError::InvalidUtf8,
            1007,
        ));
    }
    // Fail fast: the invalid byte is reported before the message ends; the
    // final fragment never needs to arrive.
    c.push(fail(
        "6.4.1 fail fast inside a fragmented message",
        concat(&[
            client_frame(0x1, false, b"ok\xed\xa0\x80more"),
            client_frame(0x0, false, b"tail"),
        ]),
        vec![],
        WsError::InvalidUtf8,
        1007,
    ));
    c.push(fail(
        "6.4.2 fail fast across fragments",
        concat(&[
            client_frame(0x1, false, b"\xed"),
            client_frame(0x0, false, b"\xa0"),
        ]),
        vec![],
        WsError::InvalidUtf8,
        1007,
    ));
    c.push(fail(
        "6.4.3 truncated sequence at the final fragment",
        concat(&[
            client_frame(0x1, false, b"\xe2"),
            client_frame(0x0, true, b"\x82"),
        ]),
        vec![],
        WsError::InvalidUtf8,
        1007,
    ));

    // 7: closing handshake.
    c.push(case(
        "7.1.1 close with 1000",
        client_frame(0x8, true, &close_payload(1000, "")),
        vec![Ev::Close(Some((1000, String::new())))],
        vec![close_reply(1000)],
    ));
    c.push(case(
        "7.1.3 frames after close are ignored",
        concat(&[
            client_frame(0x8, true, &close_payload(1000, "")),
            client_frame(0x9, true, b"late"),
            client_frame(0x1, true, b"late"),
        ]),
        vec![Ev::Close(Some((1000, String::new())))],
        vec![close_reply(1000)],
    ));
    c.push(case(
        "7.1.5 close inside a fragmented message",
        concat(&[
            client_frame(0x1, false, b"part"),
            client_frame(0x8, true, &close_payload(1000, "")),
        ]),
        vec![Ev::Close(Some((1000, String::new())))],
        vec![close_reply(1000)],
    ));
    c.push(case(
        "7.3.1 close with empty payload",
        client_frame(0x8, true, b""),
        vec![Ev::Close(None)],
        vec![(Opcode::Close, vec![])],
    ));
    c.push(fail(
        "7.3.2 close with one-byte payload",
        client_frame(0x8, true, &[0x03]),
        vec![],
        WsError::InvalidClosePayload,
        1002,
    ));
    c.push(case(
        "7.3.4 close with reason",
        client_frame(0x8, true, &close_payload(1000, "Hello World!")),
        vec![Ev::Close(Some((1000, "Hello World!".into())))],
        vec![close_reply(1000)],
    ));
    let r123 = "*".repeat(123);
    c.push(case(
        "7.3.5 close with 123-byte reason",
        client_frame(0x8, true, &close_payload(1000, &r123)),
        vec![Ev::Close(Some((1000, r123)))],
        vec![close_reply(1000)],
    ));
    c.push(fail(
        "7.3.6 close with 124-byte reason",
        client_frame(0x8, true, &close_payload(1000, &"*".repeat(124))),
        vec![],
        WsError::ControlTooLong,
        1002,
    ));
    c.push(fail(
        "7.5.1 close reason not UTF-8",
        client_frame(
            0x8,
            true,
            b"\x03\xe8\xce\xba\xe1\xbd\xb9\xcf\x83\xce\xbc\xce\xb5\xed\xa0\x80",
        ),
        vec![],
        WsError::InvalidUtf8,
        1007,
    ));
    for code in [
        1000u16, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 3000, 3999,
        4000, 4999,
    ] {
        c.push(case(
            "7.7 valid close code echoed",
            client_frame(0x8, true, &close_payload(code, "")),
            vec![Ev::Close(Some((code, String::new())))],
            vec![close_reply(code)],
        ));
    }
    for code in [
        0u16, 999, 1004, 1005, 1006, 1015, 1016, 1100, 2000, 2999, 5000, 65_535,
    ] {
        c.push(fail(
            "7.9 invalid close code",
            client_frame(0x8, true, &close_payload(code, "")),
            vec![],
            WsError::InvalidCloseCode,
            1002,
        ));
    }

    // 9: limits (frame and message budgets, checked from headers).
    let small = Limits::new().with_max_frame(1000).with_max_message(2500);
    let mut over_frame = fail(
        "9.1 frame over the budget",
        client_frame(0x2, true, &[0; 1001]),
        vec![],
        WsError::FrameTooLarge,
        1009,
    );
    over_frame.limits = small;
    c.push(over_frame);
    let mut at_frame = case(
        "9.1 frame at the budget",
        client_frame(0x2, true, &[1; 1000]),
        vec![Ev::Binary(vec![1; 1000])],
        vec![],
    );
    at_frame.limits = small;
    c.push(at_frame);
    let mut over_msg = fail(
        "9.2 message over the budget",
        concat(&[
            client_frame(0x2, false, &[0; 1000]),
            client_frame(0x0, false, &[0; 1000]),
            client_frame(0x0, true, &[0; 501]),
        ]),
        vec![],
        WsError::MessageTooLarge,
        1009,
    );
    over_msg.limits = small;
    c.push(over_msg);
    let mut at_msg = case(
        "9.2 message at the budget",
        concat(&[
            client_frame(0x2, false, &[2; 1000]),
            client_frame(0x0, false, &[2; 1000]),
            client_frame(0x0, true, &[2; 500]),
        ]),
        vec![Ev::Binary(vec![2; 2500])],
        vec![],
    );
    at_msg.limits = small;
    c.push(at_msg);

    // RFC 6455 rules outside Autobahn's server-side cases.
    c.push(fail(
        "5.1 unmasked frame to a server",
        server_frame(0x1, true, b"x"),
        vec![],
        WsError::UnmaskedFrame,
        1002,
    ));
    let mut masked_to_client = fail(
        "5.1 masked frame to a client",
        client_frame(0x1, true, b"x"),
        vec![],
        WsError::MaskedFrame,
        1002,
    );
    masked_to_client.client = true;
    c.push(masked_to_client);
    let mut to_client = case(
        "5.1 unmasked frames to a client",
        concat(&[
            server_frame(0x1, true, b"hi"),
            server_frame(0x9, true, b"p"),
        ]),
        vec![text("hi"), Ev::Ping(b"p".to_vec())],
        vec![(Opcode::Pong, b"p".to_vec())],
    );
    to_client.client = true;
    c.push(to_client);
    let mut noncanonical16 = vec![0x82, 0x80 | 126, 0, 100];
    noncanonical16.extend_from_slice(&KEY);
    noncanonical16.extend_from_slice(&[0; 100]);
    c.push(fail(
        "5.2 16-bit length for a short payload",
        noncanonical16,
        vec![],
        WsError::InvalidLength,
        1002,
    ));
    let mut noncanonical64 = vec![0x82, 0x80 | 127, 0, 0, 0, 0, 0, 0, 0, 200];
    noncanonical64.extend_from_slice(&KEY);
    c.push(fail(
        "5.2 64-bit length for a short payload",
        noncanonical64,
        vec![],
        WsError::InvalidLength,
        1002,
    ));
    let mut msb = vec![0x82, 0x80 | 127, 0x80, 0, 0, 0, 0, 0, 0, 0];
    msb.extend_from_slice(&KEY);
    c.push(fail(
        "5.2 64-bit length with the top bit set",
        msb,
        vec![],
        WsError::InvalidLength,
        1002,
    ));
    let mut eof = case(
        "7.1.7 transport closed mid-frame",
        client_frame(0x1, true, b"cut short")[..8].to_vec(),
        vec![Ev::Err(WsError::UnexpectedEof)],
        vec![],
    );
    eof.eof = true;
    c.push(eof);
    c
}

fn run(case: &Case, pieces: &[&[u8]]) -> (Vec<Ev>, Vec<(Opcode, Vec<u8>)>) {
    let mut conn = if case.client {
        Connection::client_with_seed([3; 32])
    } else {
        Connection::server()
    }
    .with_limits(case.limits);
    let (events, out) = drive(&mut conn, pieces, case.eof);
    let replies = decode_frames(&out)
        .into_iter()
        .map(|(op, fin, payload)| {
            assert!(fin, "{}: replies are single frames", case.id);
            (op, payload)
        })
        .collect();
    (events, replies)
}

#[test]
fn test_autobahn_style_cases() {
    let all = cases();
    assert!(all.len() >= 111, "{} cases", all.len());
    for case in &all {
        let whole = run(case, &[&case.input]);
        assert_eq!(whole.0, case.events, "{}: events", case.id);
        assert_eq!(whole.1, case.replies, "{}: replies", case.id);
        let bytes: Vec<&[u8]> = case.input.chunks(1).collect();
        assert_eq!(
            run(case, &bytes),
            whole,
            "{}: byte-at-a-time differs",
            case.id
        );
        let sevens: Vec<&[u8]> = case.input.chunks(7).collect();
        assert_eq!(
            run(case, &sevens),
            whole,
            "{}: 7-byte pieces differ",
            case.id
        );
    }
}
