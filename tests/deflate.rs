//! permessage-deflate (RFC 7692): negotiation in both roles, the RFC's
//! example payloads, the receive rules, the budget during inflation, and
//! round trips with and without context takeover.

#![cfg(feature = "deflate")]

use ws_net::{
    AcceptPolicy, ClientHandshake, CloseCode, Connection, DeflateConfig, Event, HandshakeError,
    HeadReader, Limits, MessageKind, OriginPolicy, PreparedMessage, SendOptions, ServerHandshake,
    WsError, extension::Negotiated,
};

const KEY: &[u8] = b"dGhlIHNhbXBsZSBub25jZQ==";

/// A server handshake whose request offered `extensions`.
fn request(extensions: &[u8]) -> ServerHandshake {
    ServerHandshake::from_request(
        "GET",
        "/",
        [
            ("Host", &b"a.example"[..]),
            ("Upgrade", b"websocket"),
            ("Connection", b"Upgrade"),
            ("Sec-WebSocket-Version", b"13"),
            ("Sec-WebSocket-Key", KEY),
            ("Sec-WebSocket-Extensions", extensions),
        ],
    )
    .unwrap()
}

fn policy(config: DeflateConfig) -> AcceptPolicy {
    AcceptPolicy::new()
        .with_origins(OriginPolicy::any_origin())
        .with_deflate(config)
}

/// What the server answers for `offer`, as its header value.
fn answer(config: DeflateConfig, offer: &[u8]) -> Option<String> {
    let h = request(offer);
    let decision = policy(config).check(&h).unwrap();
    let fields: Vec<(&str, &[u8])> = h
        .response_fields(None, &decision.extensions)
        .unwrap()
        .collect();
    fields
        .iter()
        .find(|(n, _)| *n == "sec-websocket-extensions")
        .map(|(_, v)| String::from_utf8(v.to_vec()).unwrap())
}

/// A client and a server that negotiated through real handshake bytes.
fn pair(server: DeflateConfig, client: DeflateConfig) -> (Connection, Connection) {
    let hs = ClientHandshake::with_nonce(*b"the sample nonce").with_deflate(client);
    let mut req = Vec::new();
    hs.write_request("a.example", "/", &mut req).unwrap();
    let (h, _) = ServerHandshake::from_head(&req).unwrap().unwrap();
    let mut response = Vec::new();
    let srv = h.accept(&policy(server), &mut response).unwrap();
    let mut reader = HeadReader::new();
    let (verified, _) = reader.client(&hs, &response).unwrap().unwrap();
    let cli = hs.connection_with_seed(&verified, [9; 32]);
    // Both ends read the same agreement (their own level and minimum
    // size aside).
    assert_eq!(srv.negotiated().deflate(), cli.negotiated().deflate());
    (srv, cli)
}

fn drain(conn: &mut Connection) {
    let n = conn.buffered_output();
    conn.advance_output(n);
}

fn shuttle(from: &mut Connection, to: &mut Connection) {
    let bytes = from.output().to_vec();
    from.advance_output(bytes.len());
    let mut rest = &bytes[..];
    while !rest.is_empty() {
        let n = to.feed(rest);
        assert!(n > 0, "input full");
        rest = &rest[n..];
    }
}

/// The next data message, skipping control frames.
fn next(conn: &mut Connection) -> Result<Option<(MessageKind, Vec<u8>)>, WsError> {
    loop {
        match conn.poll()? {
            Event::Text(t) => return Ok(Some((MessageKind::Text, t.as_bytes().to_vec()))),
            Event::Binary(b) => return Ok(Some((MessageKind::Binary, b.to_vec()))),
            Event::NeedInput | Event::Closed => return Ok(None),
            _ => {}
        }
    }
}

/// A masked client frame (key 0, so the payload reads as given).
fn frame(first: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![first];
    if payload.len() < 126 {
        f.push(0x80 | payload.len() as u8);
    } else {
        f.push(0x80 | 126);
        f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    }
    f.extend_from_slice(&[0, 0, 0, 0]);
    f.extend_from_slice(payload);
    f
}

/// A server connection that negotiated the defaults.
fn server() -> Connection {
    pair(DeflateConfig::new(), DeflateConfig::new()).0
}

const HELLO: [u8; 7] = [0xF2, 0x48, 0xCD, 0xC9, 0xC9, 0x07, 0x00];

#[test]
fn test_negotiation_default_offer_accepted_with_no_takeover() {
    let v = answer(
        DeflateConfig::new(),
        b"permessage-deflate; client_max_window_bits",
    );
    assert_eq!(
        v.as_deref(),
        Some("permessage-deflate; server_no_context_takeover; client_no_context_takeover")
    );
    let h = request(b"permessage-deflate");
    let d = policy(DeflateConfig::new()).check(&h).unwrap();
    let p = d.extensions.deflate().unwrap();
    assert_eq!(
        (p.server_max_window_bits, p.client_max_window_bits),
        (15, 15)
    );
}

#[test]
fn test_negotiation_without_policy_declines() {
    let h = request(b"permessage-deflate");
    let d = AcceptPolicy::new()
        .with_origins(OriginPolicy::any_origin())
        .check(&h)
        .unwrap();
    assert!(d.extensions.is_empty());
    let mut out = Vec::new();
    h.write_response_with(None, &d.extensions, &[], &mut out)
        .unwrap();
    assert!(
        !out.windows(10)
            .any(|w| w.eq_ignore_ascii_case(b"extensions"))
    );
}

#[test]
fn test_negotiation_bad_offers_declined_next_accepted() {
    for bad in [
        &b"permessage-deflate; x=1, permessage-deflate"[..],
        b"permessage-deflate; server_no_context_takeover; server_no_context_takeover, permessage-deflate",
        b"permessage-deflate; server_max_window_bits=08, permessage-deflate",
        b"permessage-deflate; server_max_window_bits=16, permessage-deflate",
        b"permessage-deflate; server_max_window_bits, permessage-deflate",
        b"permessage-deflate; client_max_window_bits=7, permessage-deflate",
        b"permessage-deflate; server_no_context_takeover=1, permessage-deflate",
    ] {
        let v = answer(DeflateConfig::new(), bad);
        assert_eq!(
            v.as_deref(),
            Some("permessage-deflate; server_no_context_takeover; client_no_context_takeover"),
            "{}",
            String::from_utf8_lossy(bad)
        );
    }
    assert_eq!(answer(DeflateConfig::new(), b"permessage-deflate; x"), None);
    assert_eq!(
        answer(DeflateConfig::new(), b"x-webkit-deflate-frame"),
        None
    );
}

#[test]
fn test_negotiation_window_bits_and_takeover() {
    let roomy = DeflateConfig::new()
        .with_server_context_takeover(true)
        .with_client_context_takeover(true);
    // Takeover allowed and not refused: no takeover parameters.
    assert_eq!(
        answer(roomy, b"permessage-deflate").as_deref(),
        Some("permessage-deflate")
    );
    // The client refuses server takeover and limits the server window.
    assert_eq!(
        answer(
            roomy,
            b"permessage-deflate; server_no_context_takeover; server_max_window_bits=10"
        )
        .as_deref(),
        Some("permessage-deflate; server_no_context_takeover; server_max_window_bits=10")
    );
    // A smaller server window than offered is stated.
    let small = DeflateConfig::new().with_server_max_window_bits(9);
    assert!(
        answer(small, b"permessage-deflate; server_max_window_bits=12")
            .unwrap()
            .ends_with("server_max_window_bits=9")
    );
    // Quoted values are read unquoted.
    assert!(
        answer(small, b"permessage-deflate; server_max_window_bits=\"12\"")
            .unwrap()
            .ends_with("server_max_window_bits=9")
    );
    // A client window limit needs the client to have offered the parameter.
    let tight = DeflateConfig::new().with_client_max_window_bits(10);
    assert_eq!(answer(tight, b"permessage-deflate"), None);
    assert!(
        answer(
            tight,
            b"permessage-deflate, permessage-deflate; client_max_window_bits"
        )
        .unwrap()
        .ends_with("client_max_window_bits=10")
    );
    // The client's own hint lowers it further.
    assert!(
        answer(tight, b"permessage-deflate; client_max_window_bits=9")
            .unwrap()
            .ends_with("client_max_window_bits=9")
    );
}

#[test]
fn test_client_offer_follows_config() {
    let write = |c: DeflateConfig| {
        let mut out = Vec::new();
        ClientHandshake::with_nonce([0; 16])
            .with_deflate(c)
            .write_request("a", "/", &mut out)
            .unwrap();
        let text = String::from_utf8(out).unwrap();
        let line = text
            .lines()
            .find(|l| l.starts_with("sec-websocket-extensions: "))
            .unwrap()
            .to_owned();
        line["sec-websocket-extensions: ".len()..].to_owned()
    };
    assert_eq!(
        write(DeflateConfig::new()),
        "permessage-deflate; server_no_context_takeover; client_no_context_takeover; client_max_window_bits"
    );
    assert_eq!(
        write(
            DeflateConfig::new()
                .with_server_context_takeover(true)
                .with_client_context_takeover(true)
                .with_server_max_window_bits(10)
                .with_client_max_window_bits(11)
        ),
        "permessage-deflate; server_max_window_bits=10; client_max_window_bits=11"
    );
}

fn verify(config: DeflateConfig, value: &[u8]) -> Result<Negotiated, HandshakeError> {
    let hs = ClientHandshake::with_nonce(*b"the sample nonce").with_deflate(config);
    let fields = [
        ("Upgrade", &b"websocket"[..]),
        ("Connection", b"Upgrade"),
        ("Sec-WebSocket-Accept", b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
        ("Sec-WebSocket-Extensions", value),
    ];
    hs.verify(101, fields).map(|v| v.extensions)
}

#[test]
fn test_client_verify_response_rules() {
    let ok = verify(
        DeflateConfig::new(),
        b"permessage-deflate; server_no_context_takeover; client_max_window_bits=10",
    )
    .unwrap();
    let p = ok.deflate().unwrap();
    assert!(p.server_no_context_takeover && p.client_no_context_takeover);
    assert_eq!(p.client_max_window_bits, 10);
    assert_eq!(p.server_max_window_bits, 15);
    let invalid = Err(HandshakeError::InvalidExtensions);
    // The offer asked for server_no_context_takeover; the server must agree.
    assert_eq!(verify(DeflateConfig::new(), b"permessage-deflate"), invalid);
    for bad in [
        &b"permessage-deflate; server_no_context_takeover; x"[..],
        b"permessage-deflate; server_no_context_takeover; server_no_context_takeover",
        b"permessage-deflate; server_no_context_takeover; client_max_window_bits",
        b"permessage-deflate; server_no_context_takeover; server_max_window_bits=16",
        b"permessage-deflate; server_no_context_takeover, permessage-deflate; server_no_context_takeover",
    ] {
        assert_eq!(
            verify(DeflateConfig::new(), bad),
            invalid,
            "{}",
            String::from_utf8_lossy(bad)
        );
    }
    // A server window larger than the offer allowed.
    let small = DeflateConfig::new()
        .with_server_context_takeover(true)
        .with_server_max_window_bits(10);
    assert_eq!(verify(small, b"permessage-deflate"), invalid);
    assert_eq!(
        verify(small, b"permessage-deflate; server_max_window_bits=12"),
        invalid
    );
    assert!(verify(small, b"permessage-deflate; server_max_window_bits=9").is_ok());
    // Anything but permessage-deflate was not offered.
    assert_eq!(
        verify(DeflateConfig::new(), b"x-other"),
        Err(HandshakeError::UnexpectedExtension)
    );
    // Without an offer, an acceptance is unexpected.
    let plain = ClientHandshake::with_nonce(*b"the sample nonce");
    let fields = [
        ("Upgrade", &b"websocket"[..]),
        ("Connection", b"Upgrade"),
        ("Sec-WebSocket-Accept", b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
        ("Sec-WebSocket-Extensions", b"permessage-deflate"),
    ];
    assert_eq!(
        plain.verify(101, fields),
        Err(HandshakeError::UnexpectedExtension)
    );
}

#[test]
fn test_rfc7692_hello_examples_inflate() {
    // 7.2.3.1 one block; 7.2.3.3 stored; 7.2.3.4 BFINAL with padding;
    // 7.2.3.5 two blocks; 7.2.3.6 an empty message.
    let cases: [(&[u8], &str); 5] = [
        (&HELLO, "Hello"),
        (
            &[
                0x00, 0x05, 0x00, 0xFA, 0xFF, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x00,
            ],
            "Hello",
        ),
        (&[0xF3, 0x48, 0xCD, 0xC9, 0xC9, 0x07, 0x00, 0x00], "Hello"),
        (
            &[
                0xF2, 0x48, 0x05, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xCA, 0xC9, 0xC9, 0x07, 0x00,
            ],
            "Hello",
        ),
        (&[0x00], ""),
    ];
    for (payload, text) in cases {
        let mut srv = server();
        assert_eq!(srv.feed(&frame(0xC1, payload)), payload.len() + 6);
        match srv.poll().unwrap() {
            Event::Text(t) => assert_eq!(t, text),
            other => panic!("{other:?}"),
        }
    }
    // The fragmented form of 7.2.3.1: RSV1 on the first frame only.
    let mut srv = server();
    let _ = srv.feed(&frame(0x41, &HELLO[..3]));
    let _ = srv.feed(&frame(0x80, &HELLO[3..]));
    assert!(matches!(srv.poll().unwrap(), Event::Text("Hello")));
}

#[test]
fn test_rsv1_rules() {
    // On a continuation.
    let mut srv = server();
    let _ = srv.feed(&frame(0x41, &HELLO[..3]));
    let _ = srv.feed(&frame(0xC0, &HELLO[3..]));
    assert_eq!(srv.poll().unwrap_err(), WsError::ReservedBits);
    // On a control frame.
    let mut srv = server();
    let _ = srv.feed(&frame(0xC9, b""));
    assert_eq!(srv.poll().unwrap_err(), WsError::ReservedBits);
    // RSV2 is never defined.
    let mut srv = server();
    let _ = srv.feed(&frame(0xA1, b"x"));
    assert_eq!(srv.poll().unwrap_err(), WsError::ReservedBits);
    // Without negotiation.
    let mut plain = Connection::server();
    let _ = plain.feed(&frame(0xC1, &HELLO));
    assert_eq!(plain.poll().unwrap_err(), WsError::ReservedBits);
    // An uncompressed message on a deflate connection is valid.
    let mut srv = server();
    let _ = srv.feed(&frame(0x81, b"plain"));
    assert!(matches!(srv.poll().unwrap(), Event::Text("plain")));
}

#[test]
fn test_invalid_deflate_fails_1007() {
    for bad in [
        &[0x07][..],                                       // block type 3
        &[0x00, 0x05, 0x00, 0x00, 0x00, b'H'],             // stored length and complement mismatch
        &[0xF3, 0x48, 0xCD, 0xC9, 0xC9, 0x07, 0x00, 0x01], // data after BFINAL
        // A message that ends inside a block: a stored block of 1000 bytes
        // with 5 sent, and "Hello" cut after its first code. The appended
        // 00 00 FF FF must not complete either one.
        &[0x00, 0xE8, 0x03, 0x17, 0xFC, b'h', b'e', b'l', b'l', b'o'],
        &[0xF2, 0x48],
        // "Hello" with the 00 00 FF FF tail left on (RFC 7692 section 7.2.1
        // removes it): with the receiver's own tail, a stored block cut short.
        &[
            0xF2, 0x48, 0xCD, 0xC9, 0xC9, 0x07, 0x00, 0x00, 0x00, 0xFF, 0xFF,
        ],
    ] {
        let mut srv = server();
        let _ = srv.feed(&frame(0xC2, bad));
        assert_eq!(srv.poll().unwrap_err(), WsError::InvalidCompressedData);
        assert_eq!(srv.output(), [0x88, 0x02, 0x03, 0xEF]);
    }
    // Inflated text that is not UTF-8 fails as text does.
    let mut srv = server();
    let _ = srv.feed(&frame(0xC1, &[0x00, 0x01, 0x00, 0xFE, 0xFF, 0xFF, 0x00]));
    assert_eq!(srv.poll().unwrap_err(), WsError::InvalidUtf8);
}

#[test]
fn test_no_takeover_back_reference_into_previous_message_fails() {
    // 7.2.3.2: the second "Hello" refers back to the first, which a
    // connection without client context takeover does not keep.
    let mut srv = server();
    let _ = srv.feed(&frame(0xC1, &HELLO));
    assert!(matches!(srv.poll().unwrap(), Event::Text("Hello")));
    let _ = srv.feed(&frame(0xC1, &[0xF2, 0x00, 0x11, 0x00, 0x00]));
    assert_eq!(srv.poll().unwrap_err(), WsError::InvalidCompressedData);
    // With takeover agreed, it is the same message again.
    let takeover = DeflateConfig::new().with_client_context_takeover(true);
    let (mut srv, _) = pair(takeover, takeover);
    let _ = srv.feed(&frame(0xC1, &HELLO));
    assert!(matches!(srv.poll().unwrap(), Event::Text("Hello")));
    let _ = srv.feed(&frame(0xC1, &[0xF2, 0x00, 0x11, 0x00, 0x00]));
    assert!(matches!(srv.poll().unwrap(), Event::Text("Hello")));
}

/// `len` bytes that do not compress (xorshift).
fn noise(len: usize) -> Vec<u8> {
    let mut x: u32 = 0x9E37_79B9;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

/// A compressed message of `len` zeros.
fn zeros(len: usize) -> Vec<u8> {
    let (_, mut cli) = pair(DeflateConfig::new(), DeflateConfig::new());
    cli.send_binary(&vec![0; len]).unwrap();
    cli.output().to_vec()
}

#[test]
fn test_inflated_size_budget_exact_and_one_over() {
    for (len, ok) in [(4096, true), (4097, false)] {
        let wire = zeros(len);
        let (mut srv, _) = pair(DeflateConfig::new(), DeflateConfig::new());
        srv = srv.with_limits(Limits::new().with_max_message(4096));
        let _ = srv.feed(&wire);
        match srv.poll() {
            Ok(Event::Binary(b)) => assert!(ok && b.len() == len),
            Err(e) => {
                assert!(!ok);
                assert_eq!(e, WsError::MessageTooLarge);
                assert_eq!(e.close_code(), Some(CloseCode::MESSAGE_TOO_BIG));
            }
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn test_detach_after_invalid_inflated_text_gives_nothing() {
    let mut srv = server();
    let _ = srv.feed(&frame(0xC1, &[0x00, 0x01, 0x00, 0xFE, 0xFF, 0xFF, 0x00]));
    assert_eq!(srv.poll().unwrap_err(), WsError::InvalidUtf8);
    assert_eq!(srv.detach_message(&mut Vec::new()), None);
    assert_eq!(srv.stats().messages_in, 0);
}

#[test]
fn test_window_bits_8_agreed_accepts_9_bit_peer() {
    // A zlib peer told 8 compresses with 9; the decoder allows it.
    let eight = DeflateConfig::new().with_client_max_window_bits(8);
    let nine = DeflateConfig::new().with_client_max_window_bits(9);
    let (mut srv, _) = pair(eight, DeflateConfig::new());
    let (_, mut peer) = pair(nine, nine);
    let text: String = noise(3000)
        .iter()
        .map(|b| char::from(b'a' + b % 3))
        .collect();
    let text = text.clone() + &text;
    peer.send_text(&text).unwrap();
    shuttle(&mut peer, &mut srv);
    assert_eq!(
        next(&mut srv).unwrap(),
        Some((MessageKind::Text, text.into_bytes()))
    );
}

#[test]
fn test_inflate_fed_byte_by_byte_is_linear() {
    // 4 MiB of one byte compresses to about 18 KB; inflating it one byte
    // per poll must cost about what one poll does, not one pass over the
    // output per byte.
    let wire = zeros(4 << 20);
    let mut srv = server();
    let start = std::time::Instant::now();
    let mut got = 0;
    for b in &wire {
        assert_eq!(srv.feed(&[*b]), 1);
        if let Some((_, m)) = next(&mut srv).unwrap() {
            got = m.len();
        }
    }
    assert_eq!(got, 4 << 20);
    let took = start.elapsed();
    assert!(took < std::time::Duration::from_secs(3), "{took:?}");
}

#[test]
fn test_bomb_stops_at_the_budget() {
    // About 70 KiB of compressed zeros expand to 16 MiB; the budget is 1 MiB.
    let wire = zeros(16 << 20);
    assert!(wire.len() < 128 * 1024, "{}", wire.len());
    let mut srv = server().with_limits(Limits::new().with_max_message(1 << 20));
    let mut rest = &wire[..];
    let err = loop {
        let n = srv.feed(rest);
        rest = &rest[n..];
        match srv.poll() {
            Err(e) => break e,
            Ok(Event::NeedInput) => assert!(!rest.is_empty()),
            Ok(other) => panic!("{other:?}"),
        }
        assert!(
            srv.memory_in_use() < (1 << 20) + (1 << 20),
            "{}",
            srv.memory_in_use()
        );
    };
    assert_eq!(err, WsError::MessageTooLarge);
}

#[test]
fn test_round_trip_both_ways_split_every_byte() {
    let text = "{\"jsonrpc\":\"2.0\",\"method\":\"update\",\"params\":[1,2,3]} ".repeat(20);
    let (mut srv, mut cli) = pair(DeflateConfig::new(), DeflateConfig::new());
    // The server's frame is unmasked: its payload is the compressed message.
    srv.send_text(&text).unwrap();
    let wire = srv.output().to_vec();
    drain(&mut srv);
    assert_eq!(wire[0], 0xC1, "compressed text");
    assert!(wire.len() < text.len() / 4);
    shuttle_bytes(&wire, &mut cli);
    assert_eq!(
        next(&mut cli).unwrap(),
        Some((MessageKind::Text, text.clone().into_bytes()))
    );
    let payload = &wire[2..];
    assert_eq!(usize::from(wire[1]), payload.len());
    // The same payload from a client in 7-byte fragments with a Ping
    // between them, fed one byte at a time.
    let mut input = Vec::new();
    let pieces: Vec<&[u8]> = payload.chunks(7).collect();
    for (i, piece) in pieces.iter().enumerate() {
        let fin = if i + 1 == pieces.len() { 0x80 } else { 0 };
        let first = if i == 0 { 0x41 } else { 0x00 };
        input.extend_from_slice(&frame(fin | first, piece));
        input.extend_from_slice(&frame(0x89, b"p"));
    }
    let mut got = None;
    for b in &input {
        assert_eq!(srv.feed(&[*b]), 1);
        loop {
            match srv.poll().unwrap() {
                Event::Text(t) => got = Some(t.to_owned()),
                Event::NeedInput => break,
                _ => {}
            }
        }
    }
    assert_eq!(got.as_deref(), Some(text.as_str()));
    // And a masked client message the other way.
    cli.send_text(&text).unwrap();
    shuttle(&mut cli, &mut srv);
    assert_eq!(
        next(&mut srv).unwrap(),
        Some((MessageKind::Text, text.into_bytes()))
    );
}

/// Feeds `bytes` one at a time.
fn shuttle_bytes(bytes: &[u8], to: &mut Connection) {
    for b in bytes {
        assert_eq!(to.feed(&[*b]), 1);
    }
}

#[test]
fn test_send_options_and_min_size() {
    let (mut srv, _) = pair(DeflateConfig::new(), DeflateConfig::new());
    let big = "a".repeat(300);
    srv.send_text("small").unwrap();
    assert_eq!(srv.output()[0], 0x81, "under min_size");
    drain(&mut srv);
    srv.send_text_with(&big, SendOptions::uncompressed())
        .unwrap();
    assert_eq!(srv.output()[0], 0x81, "opted out");
    drain(&mut srv);
    srv.send_text_with("small", SendOptions::compressed())
        .unwrap();
    assert_eq!(srv.output()[0], 0xC1, "forced");
    drain(&mut srv);
    srv.send_text(&big).unwrap();
    assert_eq!(srv.output()[0], 0xC1, "default");
    drain(&mut srv);
    // Incompressible data goes uncompressed unless forced.
    let noise = noise(4096);
    srv.send_binary(&noise).unwrap();
    assert_eq!(srv.output()[0], 0x82);
    drain(&mut srv);
    // Fragments are never compressed.
    srv.send_text_fragment(&big, true).unwrap();
    assert_eq!(srv.output()[0], 0x81);
}

#[test]
fn test_compressed_send_split_at_send_frame() {
    let (mut srv, mut cli) = pair(DeflateConfig::new(), DeflateConfig::new());
    srv = srv.with_limits(Limits::new().with_send_frame(125));
    let text: String = noise(2000)
        .iter()
        .map(|b| char::from(b'a' + b % 4))
        .collect();
    srv.send_text_with(&text, SendOptions::compressed())
        .unwrap();
    let out = srv.output();
    assert_eq!(out[0], 0x41, "first frame: RSV1, not final");
    assert_eq!(out[127], 0x00, "a continuation without RSV1");
    shuttle(&mut srv, &mut cli);
    assert_eq!(
        next(&mut cli).unwrap(),
        Some((MessageKind::Text, text.into_bytes()))
    );
}

#[test]
fn test_takeover_round_trip_shrinks_repeats() {
    let both = DeflateConfig::new()
        .with_server_context_takeover(true)
        .with_client_context_takeover(true);
    let (mut srv, mut cli) = pair(both, both);
    let p = srv.negotiated().deflate().copied().unwrap();
    assert!(!p.server_no_context_takeover && !p.client_no_context_takeover);
    let msg = "the same status line, over and over, with a counter: ".repeat(8);
    let mut sizes = Vec::new();
    for i in 0..5 {
        let m = format!("{msg}{i}");
        cli.send_text(&m).unwrap();
        sizes.push(cli.output().len());
        shuttle(&mut cli, &mut srv);
        assert_eq!(
            next(&mut srv).unwrap(),
            Some((MessageKind::Text, m.clone().into_bytes()))
        );
        srv.send_text(&m).unwrap();
        shuttle(&mut srv, &mut cli);
        assert_eq!(
            next(&mut cli).unwrap(),
            Some((MessageKind::Text, m.into_bytes()))
        );
    }
    assert!(sizes[1] < sizes[0] / 2, "{sizes:?}");
}

#[test]
fn test_output_full_with_takeover_keeps_streams_in_step() {
    let both = DeflateConfig::new()
        .with_server_context_takeover(true)
        .with_client_context_takeover(true);
    let msg = "x".repeat(300) + &"yz".repeat(200);
    let (mut probe, _) = pair(both, both);
    probe.send_text(&msg).unwrap();
    let one = probe.buffered_output();
    let (srv, mut cli) = pair(both, both);
    let mut srv = srv.with_limits(Limits::new().with_max_output(one as u64));
    srv.send_text(&msg).unwrap();
    // Refused: the compressor must forget the unsent message, so the next
    // one does not refer back to it.
    assert_eq!(srv.send_text(&msg), Err(WsError::OutputFull));
    shuttle(&mut srv, &mut cli);
    srv.send_text(&msg).unwrap();
    shuttle(&mut srv, &mut cli);
    for _ in 0..2 {
        assert_eq!(
            next(&mut cli).unwrap(),
            Some((MessageKind::Text, msg.clone().into_bytes()))
        );
    }
}

#[test]
fn test_prepared_compressed_form_selection() {
    let text = "{\"tick\":1,\"symbol\":\"ABC\",\"price\":101.25} ".repeat(16);
    let config = DeflateConfig::new();
    let update = PreparedMessage::text(&text).with_deflate(&config);
    let packed = update.compressed_len().unwrap();
    assert!(packed < update.len());
    // Without context takeover: the compressed form.
    let (mut srv, mut cli) = pair(config, config);
    srv.send_prepared(&update).unwrap();
    assert_eq!(srv.output().len(), packed);
    shuttle(&mut srv, &mut cli);
    assert_eq!(
        next(&mut cli).unwrap(),
        Some((MessageKind::Text, text.clone().into_bytes()))
    );
    // With server takeover: the plain form.
    let keep = DeflateConfig::new().with_server_context_takeover(true);
    let (mut srv, _) = pair(keep, keep);
    srv.send_prepared(&update).unwrap();
    assert_eq!(srv.output(), update.as_bytes());
    // A smaller server window than the prepared one: the plain form.
    let narrow = DeflateConfig::new().with_server_max_window_bits(10);
    let (mut srv, _) = pair(narrow, narrow);
    srv.send_prepared(&update).unwrap();
    assert_eq!(srv.output(), update.as_bytes());
    // No deflate at all: the plain form.
    let mut plain = Connection::server();
    plain.send_prepared(&update).unwrap();
    assert_eq!(plain.output(), update.as_bytes());
}

#[test]
fn test_memory_released_and_wiped() {
    let (mut srv, mut cli) = pair(DeflateConfig::new(), DeflateConfig::new());
    let text = "memory ".repeat(100);
    cli.send_text(&text).unwrap();
    shuttle(&mut cli, &mut srv);
    assert!(next(&mut srv).unwrap().is_some());
    srv.send_text(&text).unwrap();
    let busy = srv.memory_in_use();
    assert!(busy > 100_000, "{busy}");
    drain(&mut srv);
    srv.release_memory();
    // Only the codec's own state stays: no engines without takeover.
    assert!(srv.memory_in_use() < 2048, "{}", srv.memory_in_use());
    // They come back on use.
    cli.send_text(&text).unwrap();
    shuttle(&mut cli, &mut srv);
    assert!(next(&mut srv).unwrap().is_some());
    srv.wipe();
    assert!(matches!(srv.poll(), Ok(Event::Closed)));
}

#[test]
fn test_detach_and_poll_split_on_inflated_messages() {
    let (mut srv, mut cli) = pair(DeflateConfig::new(), DeflateConfig::new());
    let text = "detach me ".repeat(40);
    cli.send_text(&text).unwrap();
    shuttle(&mut cli, &mut srv);
    assert!(matches!(srv.poll().unwrap(), Event::Text(_)));
    let mut owned = Vec::new();
    assert_eq!(srv.detach_message(&mut owned), Some(MessageKind::Text));
    assert_eq!(owned, text.as_bytes());
    cli.send_text(&text).unwrap();
    shuttle(&mut cli, &mut srv);
    let (event, mut sender) = srv.poll_split().unwrap();
    if let Event::Text(t) = event {
        sender.send_text(t).unwrap();
    }
    assert_eq!(srv.output()[0], 0xC1, "the echo is compressed too");
    shuttle(&mut srv, &mut cli);
    assert_eq!(
        next(&mut cli).unwrap(),
        Some((MessageKind::Text, text.into_bytes()))
    );
}

#[test]
fn test_window_bits_8_round_trip() {
    let eight = DeflateConfig::new()
        .with_server_max_window_bits(8)
        .with_client_max_window_bits(8);
    let (mut srv, mut cli) = pair(eight, eight);
    let p = srv.negotiated().deflate().copied().unwrap();
    assert_eq!((p.server_max_window_bits, p.client_max_window_bits), (8, 8));
    let text: String = (0..5000)
        .map(|i| char::from(b'a' + (i % 23) as u8))
        .collect();
    srv.send_text(&text).unwrap();
    shuttle(&mut srv, &mut cli);
    assert_eq!(
        next(&mut cli).unwrap(),
        Some((MessageKind::Text, text.clone().into_bytes()))
    );
    cli.send_text(&text).unwrap();
    shuttle(&mut cli, &mut srv);
    assert_eq!(
        next(&mut srv).unwrap(),
        Some((MessageKind::Text, text.into_bytes()))
    );
}

mod props {
    use proptest::prelude::*;

    use super::*;

    fn config() -> impl Strategy<Value = DeflateConfig> {
        (any::<bool>(), any::<bool>(), 8u8..=15, 8u8..=15, 0u8..=9).prop_map(
            |(st, ct, sb, cb, level)| {
                DeflateConfig::new()
                    .with_server_context_takeover(st)
                    .with_client_context_takeover(ct)
                    .with_server_max_window_bits(sb)
                    .with_client_max_window_bits(cb)
                    .with_level(level)
                    .with_min_size(0)
            },
        )
    }

    /// Messages that compress (few distinct bytes) and ones that do not.
    fn message() -> impl Strategy<Value = (bool, Vec<u8>)> {
        let squashy =
            proptest::collection::vec(prop_oneof![Just(b'a'), Just(b'b'), Just(b' ')], 0..3000);
        let noisy = proptest::collection::vec(any::<u8>(), 0..600);
        (any::<bool>(), prop_oneof![squashy, noisy])
    }

    /// Feeds `wire` in pieces cut at `cuts`, collecting every message.
    fn receive(conn: &mut Connection, wire: &[u8], cuts: &[usize]) -> Vec<(MessageKind, Vec<u8>)> {
        let mut got = Vec::new();
        let mut at = 0;
        let mut ends: Vec<usize> = cuts.iter().map(|c| c % (wire.len() + 1)).collect();
        ends.push(wire.len());
        ends.sort_unstable();
        for end in ends {
            let mut piece = &wire[at.min(end)..end];
            at = end.max(at);
            while !piece.is_empty() {
                let n = conn.feed(piece);
                piece = &piece[n..];
                while let Some(m) = next(conn).unwrap() {
                    got.push(m);
                }
            }
        }
        got
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]

        /// Every agreement, every split: what one end sends compressed is
        /// what the other receives, in both directions.
        #[test]
        fn prop_deflate_round_trip(
            server_cfg in config(),
            client_cfg in config(),
            messages in proptest::collection::vec(message(), 1..6),
            cuts in proptest::collection::vec(any::<usize>(), 0..8),
        ) {
            let (mut srv, mut cli) = pair(server_cfg, client_cfg);
            let mut want = Vec::new();
            for (text, bytes) in &messages {
                let text = *text && std::str::from_utf8(bytes).is_ok();
                if text {
                    cli.send_text(std::str::from_utf8(bytes).unwrap()).unwrap();
                    srv.send_text(std::str::from_utf8(bytes).unwrap()).unwrap();
                    want.push((MessageKind::Text, bytes.clone()));
                } else {
                    cli.send_binary(bytes).unwrap();
                    srv.send_binary(bytes).unwrap();
                    want.push((MessageKind::Binary, bytes.clone()));
                }
            }
            let up = cli.output().to_vec();
            let down = srv.output().to_vec();
            prop_assert_eq!(receive(&mut srv, &up, &cuts), want.clone());
            prop_assert_eq!(receive(&mut cli, &down, &cuts), want);
        }

        /// The inflated size never passes the budget: a message is
        /// delivered exactly when it fits, refused with 1009 otherwise.
        #[test]
        fn prop_inflate_within_budget(
            len in 0usize..20_000,
            budget in 1u64..20_000,
        ) {
            let (mut srv, mut cli) = pair(DeflateConfig::new(), DeflateConfig::new());
            srv = srv.with_limits(Limits::new().with_max_message(budget));
            cli.send_binary_with(&vec![7; len], SendOptions::compressed()).unwrap();
            let wire = cli.output().to_vec();
            let mut rest = &wire[..];
            let result = loop {
                let n = srv.feed(rest);
                rest = &rest[n..];
                match next(&mut srv) {
                    Ok(Some((_, m))) => break Ok(m.len()),
                    Ok(None) if rest.is_empty() => break Ok(usize::MAX),
                    Ok(None) => {}
                    Err(e) => break Err(e),
                }
            };
            if len as u64 <= budget {
                prop_assert_eq!(result, Ok(len));
            } else {
                prop_assert_eq!(result, Err(WsError::MessageTooLarge));
            }
        }
    }
}

/// Fuzz inputs (deflate_message): a compressed text message that is bad
/// UTF-8 and bad DEFLATE, or bad UTF-8 and over budget, fails the same way
/// whole and split: inflation decides, then the text is checked whole.
/// This replays the target's check (`fuzz/fuzz_targets/deflate_message.rs`).
#[test]
fn test_fuzz_inputs_same_whole_and_split() {
    let inputs: [&[u8]; 3] = [
        &[
            10, 65, 194, 194, 1, 32, 0, 249, 255, 255, 255, 236, 0, 11, 65, 130, 0, 65, 0,
        ],
        &[
            73, 193, 197, 164, 85, 0, 193, 255, 0, 0, 0, 55, 55, 210, 2, 17, 3, 0, 0, 205, 205,
        ],
        &[
            39, 65, 206, 194, 40, 1, 32, 32, 32, 32, 32, 32, 194, 6, 1, 194, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 193, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255,
            236, 66, 160, 38, 39, 1, 2, 66, 64, 130, 10, 212, 1, 0, 25, 0, 1, 13, 42, 234, 21,
        ],
    ];
    for data in inputs {
        let (&select, rest) = data.split_first().unwrap();
        let make = || {
            let limits = match select % 3 {
                0 => Limits::new()
                    .with_max_frame(200)
                    .with_max_message(500)
                    .with_max_output(300)
                    .with_input_buffer(256)
                    .with_retain(0),
                1 => Limits::new(),
                _ => Limits::new()
                    .with_max_frame(u64::MAX)
                    .with_max_message(u64::MAX)
                    .with_max_output(u64::MAX),
            };
            let config = DeflateConfig::new()
                .with_client_context_takeover(select & 0x08 != 0)
                .with_client_max_window_bits(8 + (select >> 4) % 8);
            let client = DeflateConfig::new().with_client_context_takeover(select & 0x08 != 0);
            pair(config, client).0.with_limits(limits)
        };
        let run = |pieces: &[&[u8]]| {
            let mut conn = make();
            let mut seen = Vec::new();
            for piece in pieces {
                let mut rest = *piece;
                loop {
                    let n = conn.feed(rest);
                    rest = &rest[n..];
                    loop {
                        match conn.poll() {
                            Ok(Event::Text(t)) => seen.push(Ok(t.as_bytes().to_vec())),
                            Ok(Event::Binary(b)) => seen.push(Ok(b.to_vec())),
                            Ok(Event::NeedInput | Event::Closed) => break,
                            Ok(_) => {}
                            Err(e) => seen.push(Err(e)),
                        }
                    }
                    if rest.is_empty() || n == 0 {
                        break;
                    }
                }
            }
            (seen, conn.output().to_vec())
        };
        let mut pieces = Vec::new();
        let mut left = rest;
        let mut i = 0;
        while !left.is_empty() {
            let size = (usize::from(rest[i % rest.len()]) % 64 + 1).min(left.len());
            pieces.push(&left[..size]);
            left = &left[size..];
            i += 1;
        }
        assert_eq!(run(&[rest]), run(&pieces), "input {data:?}");
    }
}

/// Inflated text was checked only once the whole
/// message was inflated, so a compressed text message whose first byte is
/// bad UTF-8 kept inflating (and holding memory) until its last fragment.
/// It now fails within the first fragment, at the first check point.
#[test]
fn test_compressed_text_bad_byte_fails_in_first_fragment() {
    let (mut srv, cli) = pair(DeflateConfig::new(), DeflateConfig::new());
    // A binary message from the client, sent in 1 KiB frames, becomes a
    // text message once its first opcode says so: text that starts with
    // 0xFF, which no UTF-8 sequence does.
    let mut cli = cli.with_limits(Limits::new().with_send_frame(1024));
    let mut data = vec![0xFF];
    let mut x = 1u32;
    data.extend((0..8 << 20).map(|_| {
        // Letters from a small generator: compressible, but not a run.
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        b'a' + (x >> 16) as u8 % 4
    }));
    cli.send_binary(&data).unwrap();
    let mut wire = cli.output().to_vec();
    assert_eq!(wire[0], 0x42, "a compressed binary first frame, not final");
    wire[0] = 0x41; // text
    let (h, n) = ws_net::frame::FrameHeader::decode(&wire).unwrap().unwrap();
    let first = &wire[..n + h.payload_len as usize];
    assert!(first.len() < wire.len(), "more fragments follow");
    assert_eq!(srv.feed(first), first.len());
    assert_eq!(srv.poll().unwrap_err(), WsError::InvalidUtf8);
    // Fails at the first check point (1 KiB of compressed input), holding
    // far less than the 8 MiB message.
    assert!(srv.memory_in_use() < 1 << 20, "{}", srv.memory_in_use());
}
