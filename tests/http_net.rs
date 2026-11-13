//! ws-net behind http-net (a dev-dependency only): the sans-IO upgrade
//! through `ServerConn`, and the blocking `Server::on_upgrade` hand-off.
//! ws-net validates the handshake even behind an HTTP layer; http-net only
//! knows an upgrade was asked for.

#![cfg(feature = "std")]

use std::{net::TcpStream, thread};

use http_net::{Response, ServerConn, ServerEvent, blocking::Server};
use ws_net::{
    AcceptPolicy, ClientHandshake, Connection, Event, HandshakeError, Message, OriginPolicy,
    ServerHandshake, blocking, extension::Negotiated,
};

const REQUEST: &[u8] = b"GET /rpc HTTP/1.1\r\nHost: api.example\r\nUpgrade: websocket\r\n\
    Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
    Sec-WebSocket-Version: 13\r\nOrigin: https://api.example\r\n\
    Sec-WebSocket-Protocol: rpc.v1\r\n\r\n";

/// The 101 as http-net builds it from ws-net's response fields
/// (`switching_protocols` writes `upgrade` and `connection` itself).
fn switching(handshake: &ServerHandshake, protocol: Option<&str>) -> Response {
    let mut response = Response::switching_protocols("websocket");
    for (name, value) in handshake
        .response_fields(protocol, &Negotiated::none())
        .unwrap()
    {
        if name.starts_with("sec-websocket-") {
            response = response.header(name, value);
        }
    }
    response
}

#[test]
fn test_http_net_sans_io_upgrade_hands_remaining_input_to_connection() {
    let mut http = ServerConn::new();
    let mut wire = REQUEST.to_vec();
    // A masked "Hello" right behind the head.
    wire.extend_from_slice(&[
        0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
    ]);
    let taken = http.feed(&wire);
    let policy = AcceptPolicy::new().with_protocols(&["rpc.v1"]).unwrap();
    let (handshake, protocol) = match http.poll().unwrap() {
        ServerEvent::Request(req) => {
            assert!(req.is_upgrade());
            let hs = ServerHandshake::from_request(req.method_str(), req.target(), req.headers())
                .unwrap();
            let protocol = policy.check(&hs).unwrap().protocol.map(String::from);
            (hs, protocol)
        }
        other => panic!("{other:?}"),
    };
    let mut out = Vec::new();
    http.respond(&switching(&handshake, protocol.as_deref()), &mut out)
        .unwrap();
    let text = String::from_utf8_lossy(&out);
    assert!(text.starts_with("HTTP/1.1 101 "), "{text}");
    assert!(text.contains("sec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"));
    assert!(text.contains("sec-websocket-protocol: rpc.v1\r\n"));
    // The response verifies on a ws-net client with the same nonce.
    let client = ClientHandshake::with_nonce(*b"the sample nonce").with_protocols(&["rpc.v1"]);
    assert_eq!(
        client.verify_head(&out).unwrap().map(|(v, _)| v.protocol),
        Some(Some("rpc.v1"))
    );

    loop {
        match http.poll().unwrap() {
            ServerEvent::Upgraded => break,
            ServerEvent::RequestEnd | ServerEvent::AwaitingResponse => {}
            other => panic!("{other:?}"),
        }
    }
    let mut conn = Connection::server().with_limits(*policy.limits());
    let mut rest = http.remaining_input().to_vec();
    rest.extend_from_slice(&wire[taken..]);
    let fed = conn.feed(&rest);
    assert_eq!(fed, rest.len());
    match conn.poll().unwrap() {
        Event::Text(text) => assert_eq!(text, "Hello"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn test_http_net_sans_io_policy_refusal_is_an_ordinary_response() {
    let mut http = ServerConn::new();
    let wire = REQUEST.replace_origin("https://evil.example");
    let _ = http.feed(&wire);
    let refusal = match http.poll().unwrap() {
        ServerEvent::Request(req) => {
            let hs = ServerHandshake::from_request(req.method_str(), req.target(), req.headers())
                .unwrap();
            AcceptPolicy::new().check(&hs).unwrap_err()
        }
        other => panic!("{other:?}"),
    };
    assert_eq!(refusal, HandshakeError::OriginRefused);
    let mut out = Vec::new();
    http.respond(&Response::new(refusal.status()), &mut out)
        .unwrap();
    assert!(out.starts_with(b"HTTP/1.1 403 "));
}

trait ReplaceOrigin {
    fn replace_origin(&self, origin: &str) -> Vec<u8>;
}

impl ReplaceOrigin for [u8] {
    fn replace_origin(&self, origin: &str) -> Vec<u8> {
        String::from_utf8_lossy(self)
            .replace("Origin: https://api.example", &format!("Origin: {origin}"))
            .into_bytes()
    }
}

#[test]
fn test_http_net_blocking_on_upgrade_continues_with_from_upgraded() {
    let server = Server::bind("127.0.0.1:0").unwrap().on_upgrade(|up| {
        let mut ws =
            blocking::WebSocket::from_upgraded(up.stream, &up.leftover, Connection::server());
        while let Ok(message) = ws.read() {
            if message.is_data() {
                let _ = ws.send(&message);
            }
        }
    });
    let addr = server.local_addr();
    let stop = server.shutdown_handle();
    let handle = thread::spawn(move || {
        server.serve(|req, _body| {
            let policy = AcceptPolicy::new().with_origins(OriginPolicy::any_origin());
            let decided =
                ServerHandshake::from_request(req.method_str(), req.target(), req.headers())
                    .and_then(|hs| {
                        let protocol = policy.check(&hs)?.protocol.map(String::from);
                        Ok((protocol, hs))
                    });
            match decided {
                Ok((protocol, hs)) => switching(&hs, protocol.as_deref()),
                Err(e) => Response::new(e.status()),
            }
        })
    });
    let stream = TcpStream::connect(addr).unwrap();
    let mut ws = blocking::connect(stream, &addr.to_string(), "/ws").unwrap();
    ws.send_text("through http-net").unwrap();
    assert_eq!(ws.read().unwrap(), Message::from("through http-net"));
    ws.close(ws_net::CloseCode::NORMAL, "").unwrap();
    let _ = ws.read();
    stop.shutdown();
    let _ = handle.join();
}
