//! Property tests for the invariants in `dev/DIRECTIVES.md` section 4.
//!
//! - Frames follow RFC 6455: the header codec round-trips every valid
//!   header; masking in pieces equals masking whole.
//! - Messages survive any fragmentation and any split of the wire bytes,
//!   in both directions, with control frames interleaved.
//! - Text is validated incrementally: a text message is accepted exactly
//!   when `std::str::from_utf8` accepts its bytes, however it is
//!   fragmented and split.
//! - Sizes are bounded: a message is refused exactly when a frame exceeds
//!   the frame budget or the message exceeds the message budget (checked
//!   against a direct computation).
//! - Hostile bytes never panic (with the default budgets, small ones, and
//!   the budgets lifted entirely) and the parse does not depend on splits.
//! - Every frame shape round-trips through encode and decode, and masking
//!   is its own inverse at any offset.

mod common;

use common::{Ev, client_frame, drive, split};
use proptest::prelude::*;
use ws_net::{
    Connection, Event, Limits, WsError,
    frame::{FrameHeader, Opcode, apply_mask},
};

fn opcode() -> impl Strategy<Value = Opcode> {
    prop_oneof![
        Just(Opcode::Continuation),
        Just(Opcode::Text),
        Just(Opcode::Binary),
        Just(Opcode::Close),
        Just(Opcode::Ping),
        Just(Opcode::Pong),
    ]
}

fn payload_len() -> impl Strategy<Value = u64> {
    prop_oneof![0u64..=125, 126u64..=65_535, 65_536u64..=(i64::MAX as u64)]
}

#[derive(Clone, Debug)]
enum Msg {
    Text(String, Vec<usize>),
    Binary(Vec<u8>, Vec<usize>),
    Ping(Vec<u8>),
}

fn msg() -> impl Strategy<Value = Msg> {
    prop_oneof![
        (".{0,40}", proptest::collection::vec(any::<usize>(), 0..4))
            .prop_map(|(s, c)| Msg::Text(s, c)),
        (
            proptest::collection::vec(any::<u8>(), 0..300),
            proptest::collection::vec(any::<usize>(), 0..4)
        )
            .prop_map(|(b, c)| Msg::Binary(b, c)),
        proptest::collection::vec(any::<u8>(), 0..=125).prop_map(Msg::Ping),
    ]
}

/// Sends `msgs` from `sender`, fragmenting at the given cuts (text cuts are
/// moved to the nearest char boundary at or below), with each ping placed
/// between the first and second fragment of the next data message if there
/// is one.
fn send_all(sender: &mut Connection, msgs: &[Msg]) -> Vec<u8> {
    for m in msgs {
        match m {
            Msg::Ping(p) => sender.send_ping(p).unwrap(),
            Msg::Text(s, cuts) => {
                let mut points: Vec<usize> = cuts
                    .iter()
                    .map(|c| {
                        let mut p = c % (s.len() + 1);
                        while !s.is_char_boundary(p) {
                            p -= 1;
                        }
                        p
                    })
                    .collect();
                points.sort_unstable();
                points.dedup();
                if points.is_empty() {
                    sender.send_text(s).unwrap();
                } else {
                    let mut last = 0;
                    for p in points {
                        sender.send_text_fragment(&s[last..p], false).unwrap();
                        last = p;
                    }
                    sender.send_text_fragment(&s[last..], true).unwrap();
                }
            }
            Msg::Binary(b, cuts) => {
                if cuts.is_empty() {
                    sender.send_binary(b).unwrap();
                } else {
                    let pieces = split(b, cuts);
                    let n = pieces.len();
                    for (i, piece) in pieces.into_iter().enumerate() {
                        sender.send_binary_fragment(piece, i + 1 == n).unwrap();
                    }
                }
            }
        }
    }
    let wire = sender.output().to_vec();
    sender.advance_output(wire.len());
    wire
}

fn expected(msgs: &[Msg]) -> Vec<Ev> {
    msgs.iter()
        .map(|m| match m {
            Msg::Text(s, _) => Ev::Text(s.clone()),
            Msg::Binary(b, _) => Ev::Binary(b.clone()),
            Msg::Ping(p) => Ev::Ping(p.clone()),
        })
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn prop_header_round_trip(
        op in opcode(),
        fin in any::<bool>(),
        len in payload_len(),
        mask in proptest::option::of(any::<[u8; 4]>()),
    ) {
        let (fin, len) = if op.is_control() { (true, len % 126) } else { (fin, len) };
        let mut header = FrameHeader::new(op, fin, len);
        if let Some(k) = mask {
            header = header.with_mask(k);
        }
        let mut wire = Vec::new();
        header.encode(&mut wire).unwrap();
        prop_assert_eq!(wire.len(), header.encoded_len());
        let (decoded, n) = FrameHeader::decode(&wire).unwrap().unwrap();
        prop_assert_eq!(decoded, header);
        prop_assert_eq!(n, wire.len());
        // Every proper prefix asks for more input.
        for cut in 0..wire.len() {
            prop_assert_eq!(FrameHeader::decode(&wire[..cut]), Ok(None));
        }
    }

    #[test]
    fn prop_frame_round_trip(
        op in opcode(),
        fin in any::<bool>(),
        payload in prop_oneof![
            proptest::collection::vec(any::<u8>(), 0..=125),
            proptest::collection::vec(any::<u8>(), 126..300),
            proptest::collection::vec(any::<u8>(), 65_536..65_600),
        ],
        mask in proptest::option::of(any::<[u8; 4]>()),
    ) {
        // A whole frame: header, then the payload masked under its key.
        let (fin, payload) = if op.is_control() {
            (true, payload[..payload.len().min(125)].to_vec())
        } else {
            (fin, payload)
        };
        let mut header = FrameHeader::new(op, fin, payload.len() as u64);
        if let Some(k) = mask {
            header = header.with_mask(k);
        }
        let mut wire = Vec::new();
        header.encode(&mut wire).unwrap();
        let start = wire.len();
        wire.extend_from_slice(&payload);
        if let Some(k) = mask {
            apply_mask(&mut wire[start..], k, 0);
        }
        let (decoded, n) = FrameHeader::decode(&wire).unwrap().unwrap();
        prop_assert_eq!(decoded, header);
        prop_assert_eq!(n, start);
        let mut body = wire[n..].to_vec();
        prop_assert_eq!(body.len() as u64, decoded.payload_len);
        if let Some(k) = decoded.mask {
            apply_mask(&mut body, k, 0);
        }
        prop_assert_eq!(body, payload);
    }

    #[test]
    fn prop_masking_is_an_involution_at_any_offset(
        data in proptest::collection::vec(any::<u8>(), 0..64),
        key in any::<[u8; 4]>(),
        offset in any::<usize>(),
    ) {
        let mut masked = data.clone();
        apply_mask(&mut masked, key, offset);
        // Against a byte-by-byte reference.
        for (i, (m, d)) in masked.iter().zip(&data).enumerate() {
            prop_assert_eq!(*m, d ^ key[(offset % 4 + i) % 4]);
        }
        apply_mask(&mut masked, key, offset);
        prop_assert_eq!(masked, data);
    }

    #[test]
    fn prop_masking_in_pieces_matches_whole(
        data in proptest::collection::vec(any::<u8>(), 0..200),
        key in any::<[u8; 4]>(),
        cuts in proptest::collection::vec(any::<usize>(), 0..5),
    ) {
        let mut whole = data.clone();
        apply_mask(&mut whole, key, 0);
        let mut pieces = data.clone();
        let mut offset = 0;
        let mut points: Vec<usize> = cuts.iter().map(|c| c % (data.len() + 1)).collect();
        points.sort_unstable();
        points.push(data.len());
        for p in points {
            apply_mask(&mut pieces[offset..p], key, offset);
            offset = p;
        }
        prop_assert_eq!(&pieces, &whole);
        apply_mask(&mut pieces, key, 0);
        prop_assert_eq!(pieces, data);
    }

    #[test]
    fn prop_client_to_server_round_trip(
        msgs in proptest::collection::vec(msg(), 0..8),
        cuts in proptest::collection::vec(any::<usize>(), 0..10),
        seed in any::<[u8; 32]>(),
        frame_limit in prop_oneof![Just(1u64 << 20), 125u64..400],
    ) {
        let limits = Limits::new().with_max_frame(frame_limit);
        let mut client = Connection::client_with_seed(seed).with_limits(limits);
        let wire = send_all(&mut client, &msgs);
        let mut server = Connection::server().with_limits(limits);
        let (events, _) = drive(&mut server, &split(&wire, &cuts), false);
        prop_assert_eq!(events, expected(&msgs));
    }

    #[test]
    fn prop_server_to_client_round_trip(
        msgs in proptest::collection::vec(msg(), 0..8),
        cuts in proptest::collection::vec(any::<usize>(), 0..10),
    ) {
        let mut server = Connection::server();
        let wire = send_all(&mut server, &msgs);
        let mut client = Connection::client_with_seed([9; 32]);
        let (events, _) = drive(&mut client, &split(&wire, &cuts), false);
        prop_assert_eq!(events, expected(&msgs));
    }

    #[test]
    fn prop_utf8_validation_matches_std(
        bytes in prop_oneof![
            proptest::collection::vec(any::<u8>(), 0..40),
            ".{0,12}".prop_map(String::into_bytes),
            // Valid text with one byte changed: errors near real sequences.
            (".{1,12}", any::<usize>(), any::<u8>()).prop_map(|(s, i, b)| {
                let mut v = s.into_bytes();
                let n = v.len();
                v[i % n] = b;
                v
            }),
        ],
        frags in proptest::collection::vec(any::<usize>(), 0..5),
        cuts in proptest::collection::vec(any::<usize>(), 0..6),
    ) {
        let pieces = split(&bytes, &frags);
        let n = pieces.len();
        let wire: Vec<u8> = pieces
            .iter()
            .enumerate()
            .flat_map(|(i, p)| client_frame(if i == 0 { 0x1 } else { 0x0 }, i + 1 == n, p))
            .collect();
        let mut server = Connection::server();
        let (events, _) = drive(&mut server, &split(&wire, &cuts), false);
        match std::str::from_utf8(&bytes) {
            Ok(s) => prop_assert_eq!(events, vec![Ev::Text(s.to_string())]),
            Err(_) => prop_assert_eq!(events, vec![Ev::Err(WsError::InvalidUtf8)]),
        }
    }

    #[test]
    fn prop_size_budgets_match_direct_computation(
        sizes in proptest::collection::vec(0usize..600, 1..6),
        frame_limit in 125u64..500,
        message_limit in 0u64..1500,
    ) {
        let limits = Limits::new().with_max_frame(frame_limit).with_max_message(message_limit);
        let n = sizes.len();
        let wire: Vec<u8> = sizes
            .iter()
            .enumerate()
            .flat_map(|(i, &len)| client_frame(if i == 0 { 0x2 } else { 0x0 }, i + 1 == n, &vec![7; len]))
            .collect();
        // Reference: walk the frames as the headers announce them.
        let mut total = 0u64;
        let mut verdict = Ok(());
        for &len in &sizes {
            if len as u64 > frame_limit {
                verdict = Err(WsError::FrameTooLarge);
                break;
            }
            total += len as u64;
            if total > message_limit {
                verdict = Err(WsError::MessageTooLarge);
                break;
            }
        }
        let mut server = Connection::server().with_limits(limits);
        let (events, _) = drive(&mut server, &[&wire], false);
        match verdict {
            Ok(()) => prop_assert_eq!(events, vec![Ev::Binary(vec![7; total as usize])]),
            Err(e) => prop_assert_eq!(events, vec![Ev::Err(e)]),
        }
    }
}

/// Frame-shaped noise: real headers with random bits flipped, random
/// lengths, and random payloads, so the parser reaches deep states.
fn frame_soup() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(
        (
            any::<u8>(),
            any::<bool>(),
            proptest::collection::vec(any::<u8>(), 0..140),
            any::<u8>(),
        ),
        0..12,
    )
    .prop_map(|frames| {
        let mut out = Vec::new();
        for (b0, mask, payload, noise) in frames {
            let b0 = if noise % 4 == 0 {
                b0
            } else {
                (b0 & 0x8F) | [0x1, 0x2, 0x0, 0x9, 0xA, 0x8][noise as usize % 6]
            };
            out.extend(common::raw(b0, mask || noise % 7 != 0, &payload));
            if noise % 11 == 0 {
                out.push(noise);
            }
        }
        out
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn prop_never_panics_on_arbitrary_bytes(
        input in proptest::collection::vec(any::<u8>(), 0..600),
        cuts in proptest::collection::vec(any::<usize>(), 0..8),
        client in any::<bool>(),
        eof in any::<bool>(),
        budgets in 0u8..3,
    ) {
        let limits = match budgets {
            0 => Limits::new().with_max_frame(200).with_max_message(500),
            1 => Limits::new(),
            // Lifted entirely: a hostile length must still cost nothing.
            _ => Limits::new().with_max_frame(u64::MAX).with_max_message(u64::MAX),
        };
        let mut conn = if client { Connection::client_with_seed([1; 32]) } else { Connection::server() }
            .with_limits(limits);
        let _ = drive(&mut conn, &split(&input, &cuts), eof);
    }

    #[test]
    fn prop_never_panics_on_frame_soup_with_lifted_budgets(
        input in frame_soup(),
        cuts in proptest::collection::vec(any::<usize>(), 0..10),
        eof in any::<bool>(),
    ) {
        let limits = Limits::new().with_max_frame(u64::MAX).with_max_message(u64::MAX);
        let mut conn = Connection::server().with_limits(limits);
        let _ = drive(&mut conn, &split(&input, &cuts), eof);
    }

    #[test]
    fn prop_split_invariant(
        input in frame_soup(),
        cuts in proptest::collection::vec(any::<usize>(), 0..10),
        eof in any::<bool>(),
    ) {
        let limits = Limits::new().with_max_frame(200).with_max_message(600);
        let mut a = Connection::server().with_limits(limits);
        let mut b = Connection::server().with_limits(limits);
        let whole = drive(&mut a, &[&input], eof);
        let pieces = drive(&mut b, &split(&input, &cuts), eof);
        prop_assert_eq!(whole, pieces);
        // The frame and message counters do not depend on splits either (a
        // control frame whose payload arrives late counts once). `bytes_in`
        // may: after a failure, `feed` takes nothing more.
        let counts = |s: ws_net::Stats| {
            (s.frames_in, s.messages_in, s.pings_in, s.pongs_in, s.closes_in, s.bytes_out)
        };
        prop_assert_eq!(counts(a.stats()), counts(b.stats()));
    }
}

#[test]
fn test_receive_hundred_thousand_frames_delivered() {
    // Scale check: 100,000 masked messages in 64 KiB reads.
    let mut client = Connection::client_with_seed([5; 32]);
    for i in 0..100_000u32 {
        if i % 2 == 0 {
            client.send_text("message").unwrap();
        } else {
            client.send_binary(&i.to_le_bytes()).unwrap();
        }
    }
    let wire = client.output().to_vec();
    let mut server = Connection::server();
    let (events, _) = drive(
        &mut server,
        &wire.chunks(64 * 1024).collect::<Vec<_>>(),
        false,
    );
    assert_eq!(events.len(), 100_000);
    assert_eq!(events[0], Ev::Text("message".into()));
    assert_eq!(events[99_999], Ev::Binary(99_999u32.to_le_bytes().to_vec()));
}

#[test]
fn test_receive_sixteen_mib_in_one_mib_frames_delivered() {
    // The largest default message, streamed through the 64 KiB input buffer.
    let data: Vec<u8> = (0..16 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
    let mut client = Connection::client_with_seed([6; 32]);
    client.send_binary(&data).unwrap();
    let wire = client.output().to_vec();
    let mut server = Connection::server();
    let (events, _) = drive(
        &mut server,
        &wire.chunks(1 << 16).collect::<Vec<_>>(),
        false,
    );
    assert_eq!(events, vec![Ev::Binary(data)]);
}

/// A request head close to a real one, with fields drawn from a small
/// pool so that valid, refused, and malformed heads all occur.
fn head_bytes() -> impl Strategy<Value = Vec<u8>> {
    let field = prop_oneof![
        Just(&b"Host: a.example\r\n"[..]),
        Just(&b"Upgrade: websocket\r\n"[..]),
        Just(&b"Connection: Upgrade\r\n"[..]),
        Just(&b"Sec-WebSocket-Version: 13\r\n"[..]),
        Just(&b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"[..]),
        Just(&b"Origin: https://a.example\r\n"[..]),
        Just(&b"Sec-WebSocket-Protocol: a, \"b\"\r\n"[..]),
        Just(&b"Content-Length: 1\r\n"[..]),
        Just(&b"X: \r\n"[..]),
        Just(&b"Bad Name: x\r\n"[..]),
        Just(&b"X: a\rb\r\n"[..]),
        Just(&b"X: a\nb\r\n"[..]),
    ];
    (prop::collection::vec(field, 0..12), any::<bool>()).prop_map(|(fields, end)| {
        let mut wire = b"GET /x HTTP/1.1\r\n".to_vec();
        for f in fields {
            wire.extend_from_slice(f);
        }
        if end {
            wire.extend_from_slice(b"\r\n\x81\x80\0\0\0\0");
        }
        wire
    })
}

/// A reference same-origin test over the structured parts.
fn reference_same(a: &(String, String, Option<u16>), b: &(String, String, Option<u16>)) -> bool {
    let port = |(scheme, _, port): &(String, String, Option<u16>)| {
        port.unwrap_or(if scheme.eq_ignore_ascii_case("https") {
            443
        } else {
            80
        })
    };
    a.0.eq_ignore_ascii_case(&b.0) && a.1.eq_ignore_ascii_case(&b.1) && port(a) == port(b)
}

fn origin_parts() -> impl Strategy<Value = (String, String, Option<u16>)> {
    (
        prop_oneof![
            Just("http"),
            Just("HTTP"),
            Just("https"),
            Just("Https"),
            Just("ftp")
        ],
        prop_oneof![
            Just("a.example"),
            Just("A.Example"),
            Just("b.example"),
            Just("a.example.evil")
        ],
        prop_oneof![
            Just(None),
            Just(Some(80)),
            Just(Some(443)),
            Just(Some(8080))
        ],
    )
        .prop_map(|(s, h, p)| (s.to_string(), h.to_string(), p))
}

fn serialize((scheme, host, port): &(String, String, Option<u16>)) -> String {
    match port {
        Some(p) => format!("{scheme}://{host}:{p}"),
        None => format!("{scheme}://{host}"),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn prop_head_reader_matches_from_head_for_every_cut(
        wire in head_bytes(),
        cuts in prop::collection::vec(1usize..40, 1..20),
    ) {
        let mut reader = ws_net::HeadReader::new();
        let mut end = 0;
        let mut got = None;
        for step in cuts.iter().cycle().take(wire.len() + 1) {
            end = (end + step).min(wire.len());
            let r = reader.server(&wire[..end]);
            if !matches!(r, Ok(None)) || end == wire.len() {
                got = Some(r);
                break;
            }
        }
        let got = got.unwrap();
        prop_assert_eq!(got, ws_net::ServerHandshake::from_head(&wire[..end]));
    }

    #[test]
    fn prop_origin_allowlist_matches_reference(
        allowed in prop::collection::vec(origin_parts(), 1..4),
        origin in origin_parts(),
    ) {
        let web = |p: &(String, String, Option<u16>)| p.0.eq_ignore_ascii_case("http") || p.0.eq_ignore_ascii_case("https");
        let entries: Vec<String> = allowed.iter().filter(|p| web(p)).map(serialize).collect();
        let refs: Vec<&str> = entries.iter().map(String::as_str).collect();
        let policy = ws_net::OriginPolicy::allow(&refs).unwrap();
        let expect = web(&origin) && allowed.iter().filter(|p| web(p)).any(|a| reference_same(a, &origin));
        prop_assert_eq!(policy.permits(Some(&serialize(&origin)), "unused.example"), expect);
    }
}

#[derive(Clone, Debug)]
enum Op {
    Text(usize),
    Binary(usize),
    Ping,
    Close,
    Drain(usize),
    PeerPing,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (0usize..3000).prop_map(Op::Text),
        (0usize..70_000).prop_map(Op::Binary),
        Just(Op::Ping),
        Just(Op::Close),
        (0usize..5000).prop_map(Op::Drain),
        Just(Op::PeerPing),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn prop_output_never_exceeds_budget_plus_headroom(
        budget in 0u64..200_000,
        ops in prop::collection::vec(op(), 1..60),
        client in any::<bool>(),
    ) {
        let limits = Limits::new().with_max_output(budget);
        let mut conn = if client {
            Connection::client_with_seed([8; 32])
        } else {
            Connection::server()
        }
        .with_limits(limits);
        let ping = if client {
            common::server_frame(0x9, true, &[1; 125])
        } else {
            client_frame(0x9, true, &[1; 125])
        };
        for op in ops {
            let before = conn.output().to_vec();
            let r = match op {
                Op::Text(n) => conn.send_text(&"t".repeat(n)),
                Op::Binary(n) => conn.send_binary(&vec![0; n]),
                Op::Ping => conn.send_ping(b"p"),
                Op::Close => conn.close(ws_net::CloseCode::NORMAL, "bye"),
                Op::Drain(n) => {
                    conn.advance_output(n);
                    Ok(())
                }
                Op::PeerPing => {
                    let _ = conn.feed(&ping);
                    let _ = conn.poll();
                    Ok(())
                }
            };
            if r == Err(WsError::OutputFull) {
                prop_assert_eq!(conn.output(), &before[..], "a refused send changes nothing");
            }
            prop_assert!(conn.buffered_output() as u64 <= budget + 262);
        }
    }

    #[test]
    fn prop_detach_message_matches_event(msgs in prop::collection::vec(msg(), 1..8), cuts in prop::collection::vec(1usize..300, 1..6)) {
        let mut client = Connection::client_with_seed([9; 32]);
        let wire = send_all(&mut client, &msgs);
        let mut server = Connection::server();
        let mut got = Vec::new();
        let mut rest = &wire[..];
        let mut i = 0;
        while !rest.is_empty() {
            let take = cuts[i % cuts.len()].min(rest.len());
            i += 1;
            let mut chunk = &rest[..take];
            rest = &rest[take..];
            while !chunk.is_empty() {
                let n = server.feed(chunk);
                chunk = &chunk[n..];
                loop {
                    let seen = match server.poll() {
                        Ok(Event::Text(t)) => Some(t.as_bytes().to_vec()),
                        Ok(Event::Binary(b)) => Some(b.to_vec()),
                        Ok(Event::NeedInput) | Ok(Event::Closed) | Err(_) => break,
                        Ok(_) => None,
                    };
                    if let Some(bytes) = seen {
                        let mut owned = Vec::new();
                        prop_assert!(server.detach_message(&mut owned).is_some());
                        prop_assert_eq!(&owned, &bytes);
                        got.push(owned);
                    }
                }
            }
        }
        let want: Vec<Vec<u8>> = expected(&msgs)
            .into_iter()
            .filter_map(|e| match e {
                Ev::Text(t) => Some(t.into_bytes()),
                Ev::Binary(b) => Some(b),
                _ => None,
            })
            .collect();
        prop_assert_eq!(got, want);
    }

    #[test]
    fn prop_keepalive_deadline_monotone_and_progresses(
        ping in 1u64..10_000, idle in 1u64..20_000, steps in prop::collection::vec((0u64..5_000, any::<bool>()), 1..40),
    ) {
        use core::time::Duration;
        let k = ws_net::Keepalive::new()
            .with_ping_interval(Duration::from_millis(ping))
            .with_idle_timeout(Duration::from_millis(idle));
        let mut conn = Connection::server().with_keepalive(k);
        let mut now = 0u64;
        prop_assert_eq!(conn.on_time(ws_net::Millis(now)), Ok(ws_net::Tick::Nothing));
        for (advance, input) in steps {
            if input {
                let _ = conn.feed(&client_frame(0xA, true, b""));
                let _ = conn.poll();
            }
            now += advance;
            let deadline = conn.next_deadline();
            match conn.on_time(ws_net::Millis(now)) {
                Err(_) => {
                    // Closed: only the wait for the unsent Close stays
                    // armed, and it lies in the future.
                    match conn.next_deadline() {
                        None => prop_assert_eq!(conn.buffered_output(), 0),
                        Some(d) => {
                            prop_assert!(conn.buffered_output() > 0);
                            prop_assert!(d.as_u64() > now);
                        }
                    }
                    break;
                }
                Ok(_) => {
                    if let (Some(before), Some(after)) = (deadline, conn.next_deadline()) {
                        // A tick at or past a deadline moves it on.
                        if before.as_u64() <= now && !input {
                            prop_assert!(after > before || after.as_u64() > now);
                        }
                    }
                }
            }
        }
    }
}
