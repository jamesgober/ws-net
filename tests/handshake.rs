//! The opening handshake end to end: request and response heads as raw
//! bytes (the standalone path), the `(name, value)` path that composes with
//! an HTTP layer, the facts a server needs for its policy (Origin, Host,
//! target), refusals, and RFC 6455's own example.

use proptest::prelude::*;
use ws_net::{ClientHandshake, HandshakeError, ServerHandshake, accept_key};

/// RFC 6455 section 1.2's request.
const RFC_REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\n\
Host: server.example.com\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
Origin: http://example.com\r\n\
Sec-WebSocket-Protocol: chat, superchat\r\n\
Sec-WebSocket-Version: 13\r\n\
\r\n";

fn request_with(extra: &str, drop: &str) -> Vec<u8> {
    let mut out = String::new();
    for line in std::str::from_utf8(RFC_REQUEST)
        .unwrap()
        .split("\r\n")
        .filter(|l| !l.is_empty())
    {
        if drop.is_empty() || !line.to_ascii_lowercase().starts_with(drop) {
            out.push_str(line);
            out.push_str("\r\n");
        }
    }
    out.push_str(extra);
    out.push_str("\r\n");
    out.into_bytes()
}

#[test]
fn test_rfc_6455_request_from_head() {
    let mut wire = RFC_REQUEST.to_vec();
    wire.extend_from_slice(&[0x81, 0x80, 1, 2, 3, 4]); // a frame right behind
    let (hs, len) = ServerHandshake::from_head(&wire).unwrap().unwrap();
    assert_eq!(len, RFC_REQUEST.len());
    assert_eq!(hs.target(), "/chat");
    assert_eq!(hs.host(), "server.example.com");
    assert_eq!(hs.origin(), Some("http://example.com"));
    assert_eq!(hs.protocols().collect::<Vec<_>>(), ["chat", "superchat"]);
    assert_eq!(hs.accept_key().as_str(), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");

    // RFC 6455 section 1.3's response, with the protocol chosen.
    let mut response = Vec::new();
    hs.write_response(Some("chat"), &mut response).unwrap();
    assert_eq!(
        response,
        b"HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: upgrade\r\n\
sec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nsec-websocket-protocol: chat\r\n\r\n"
    );
}

#[test]
fn test_from_head_waits_for_the_blank_line() {
    for cut in 0..RFC_REQUEST.len() {
        assert_eq!(
            ServerHandshake::from_head(&RFC_REQUEST[..cut]),
            Ok(None),
            "cut at {cut}"
        );
    }
}

#[test]
fn test_from_head_and_from_request_agree() {
    let (from_head, _) = ServerHandshake::from_head(RFC_REQUEST).unwrap().unwrap();
    let headers = [
        ("Host", &b"server.example.com"[..]),
        ("Upgrade", b"websocket"),
        ("Connection", b"Upgrade"),
        ("Sec-WebSocket-Key", b"dGhlIHNhbXBsZSBub25jZQ=="),
        ("Origin", b"http://example.com"),
        ("Sec-WebSocket-Protocol", b"chat, superchat"),
        ("Sec-WebSocket-Version", b"13"),
    ];
    let from_pairs = ServerHandshake::from_request("GET", "/chat", headers).unwrap();
    assert_eq!(from_head, from_pairs);
}

#[test]
fn test_origin_is_optional_but_never_ambiguous() {
    let (hs, _) = ServerHandshake::from_head(&request_with("", "origin"))
        .unwrap()
        .unwrap();
    assert_eq!(hs.origin(), None);
    for bad in [
        "Origin: http://evil.example\r\n", // a second Origin
        "",
    ] {
        let wire = if bad.is_empty() {
            request_with("Origin: http://a b\r\n", "origin")
        } else {
            request_with(bad, "")
        };
        assert_eq!(
            ServerHandshake::from_head(&wire),
            Err(HandshakeError::InvalidOrigin),
            "{bad:?}"
        );
    }
}

#[test]
fn test_host_is_required_once() {
    assert_eq!(
        ServerHandshake::from_head(&request_with("", "host")),
        Err(HandshakeError::InvalidHost)
    );
    assert_eq!(
        ServerHandshake::from_head(&request_with("Host: other\r\n", "")),
        Err(HandshakeError::InvalidHost)
    );
}

#[test]
fn test_upgrade_and_connection_are_case_insensitive_lists() {
    let wire = b"GET / HTTP/1.1\r\nhost: a\r\nUPGRADE: h2c, WebSocket\r\n\
connection: keep-alive\r\nConnection: x, UpGrAdE\r\n\
sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\nsec-websocket-version:   13  \r\n\r\n";
    assert!(ServerHandshake::from_head(wire).unwrap().is_some());
}

#[test]
fn test_malformed_heads_are_refused() {
    for bad in [
        &b"GET /chat HTTP/1.0\r\nHost: a\r\n\r\n"[..],
        b"GET  /chat HTTP/1.1\r\nHost: a\r\n\r\n",
        b"GET /chat HTTP/1.1 \r\nHost: a\r\n\r\n",
        b"GET /chat\r\nHost: a\r\n\r\n",
        b"GET /chat HTTP/1.1\nHost: a\r\n\r\n",
        b"GET /chat HTTP/1.1\r\nHost: a\n\r\n",
        b"GET /chat HTTP/1.1\r\nHost: a\rb\r\n\r\n",
        b"GET /chat HTTP/1.1\r\nHost : a\r\n\r\n",
        b"GET /chat HTTP/1.1\r\n Host: a\r\n\r\n",
        b"GET /chat HTTP/1.1\r\nHost a\r\n\r\n",
        b"GET /chat HTTP/1.1\r\n: a\r\n\r\n",
        b"GET /chat HTTP/1.1\r\nHost: a\x01b\r\n\r\n",
        b"G(T /chat HTTP/1.1\r\nHost: a\r\n\r\n",
        b"\r\nGET /chat HTTP/1.1\r\nHost: a\r\n\r\n",
    ] {
        assert_eq!(
            ServerHandshake::from_head(bad),
            Err(HandshakeError::MalformedHead),
            "{:?}",
            String::from_utf8_lossy(bad)
        );
    }
    // A bare LF is refused as soon as it arrives, not after 16 KiB.
    assert_eq!(
        ServerHandshake::from_head(b"GET / HTTP/1.1\n"),
        Err(HandshakeError::MalformedHead)
    );
}

#[test]
fn test_head_budget() {
    let mut big = b"GET / HTTP/1.1\r\nHost: a\r\nX-Pad: ".to_vec();
    big.resize(ServerHandshake::MAX_HEAD, b'p');
    assert_eq!(
        ServerHandshake::from_head(&big),
        Err(HandshakeError::HeadTooLarge)
    );
    assert_eq!(HandshakeError::HeadTooLarge.status(), 431);
    big.truncate(ServerHandshake::MAX_HEAD - 1);
    assert_eq!(ServerHandshake::from_head(&big), Ok(None));
}

#[test]
fn test_refusal_responses() {
    let mut out = Vec::new();
    HandshakeError::UnsupportedVersion.write_response(&mut out);
    assert_eq!(
        out,
        b"HTTP/1.1 426 Upgrade Required\r\nsec-websocket-version: 13\r\n\
content-length: 0\r\nconnection: close\r\n\r\n"
    );
    out.clear();
    HandshakeError::InvalidKey.write_response(&mut out);
    assert_eq!(
        out,
        b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
    );
    out.clear();
    HandshakeError::HeadTooLarge.write_response(&mut out);
    assert!(out.starts_with(b"HTTP/1.1 431 Request Header Fields Too Large\r\n"));
}

#[test]
fn test_client_round_trip_over_raw_heads() {
    let client = ClientHandshake::with_nonce(*b"the sample nonce")
        .with_protocols(&["chat", "superchat"])
        .with_origin("http://example.com");
    let mut request = Vec::new();
    client
        .write_request("server.example.com", "/chat", &mut request)
        .unwrap();
    let (server, len) = ServerHandshake::from_head(&request).unwrap().unwrap();
    assert_eq!(len, request.len());
    assert_eq!(server.origin(), Some("http://example.com"));
    assert_eq!(server.host(), "server.example.com");

    let mut response = Vec::new();
    server
        .write_response(Some("superchat"), &mut response)
        .unwrap();
    response.extend_from_slice(&[0x81, 0x00]); // first frame right behind
    let (selected, head_len) = client.verify_head(&response).unwrap().unwrap();
    assert_eq!(selected, Some("superchat"));
    assert_eq!(&response[head_len..], [0x81, 0x00]);
    for cut in 0..head_len {
        assert_eq!(client.verify_head(&response[..cut]), Ok(None));
    }
}

#[test]
fn test_client_verify_head_refusals() {
    let client = ClientHandshake::with_nonce([1; 16]);
    assert_eq!(
        client.verify_head(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n"),
        Err(HandshakeError::NotSwitching(403))
    );
    assert_eq!(
        client.verify_head(b"HTTP/1.1 101\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n"),
        Err(HandshakeError::AcceptMismatch)
    );
    assert_eq!(
        client.verify_head(b"HTTP/1.0 101 OK\r\n\r\n"),
        Err(HandshakeError::MalformedHead)
    );
    assert_eq!(
        client.verify_head(b"HTTP/1.1 1O1 OK\r\n\r\n"),
        Err(HandshakeError::MalformedHead)
    );
    let mut out = Vec::new();
    assert_eq!(
        ClientHandshake::with_nonce([0; 16])
            .with_origin("http://a b")
            .write_request("a", "/", &mut out),
        Err(HandshakeError::InvalidRequest)
    );
    assert!(out.is_empty());
}

#[test]
fn test_rfc_6455_accept_key_example() {
    // RFC 6455 section 1.3.
    assert_eq!(
        accept_key(b"dGhlIHNhbXBsZSBub25jZQ==").as_str(),
        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn prop_from_head_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
        let _ = ServerHandshake::from_head(&bytes);
        let _ = ClientHandshake::with_nonce([0; 16]).verify_head(&bytes);
    }

    #[test]
    fn prop_from_head_never_panics_near_valid(
        index in any::<usize>(),
        byte in any::<u8>(),
        cut in any::<usize>(),
    ) {
        let mut wire = RFC_REQUEST.to_vec();
        let i = index % wire.len();
        wire[i] = byte;
        wire.truncate(cut % (wire.len() + 1));
        if let Ok(Some((hs, len))) = ServerHandshake::from_head(&wire) {
            prop_assert!(len <= wire.len());
            prop_assert_eq!(hs.accept_key().as_str().len(), 28);
        }
    }

    #[test]
    fn prop_any_16_byte_nonce_is_accepted(nonce in any::<[u8; 16]>()) {
        let client = ClientHandshake::with_nonce(nonce);
        let mut request = Vec::new();
        client.write_request("h", "/", &mut request).unwrap();
        let (server, _) = ServerHandshake::from_head(&request).unwrap().unwrap();
        let mut response = Vec::new();
        server.write_response(None, &mut response).unwrap();
        prop_assert_eq!(client.verify_head(&response), Ok(Some((None, response.len()))));
    }
}
