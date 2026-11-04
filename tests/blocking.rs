//! The blocking adapter over real localhost sockets: accept and connect,
//! echo, Ping and Pong, the closing handshake, a policy refusal, and a
//! keepalive idle timeout driven by the socket's read timeout.

#![cfg(feature = "std")]

use std::{
    net::{TcpListener, TcpStream},
    thread,
    time::Duration,
};

use ws_net::{
    AcceptPolicy, ClientHandshake, CloseCode, Connection, HandshakeError, Keepalive, Message,
    OriginPolicy, WsError, blocking,
};

fn listener() -> (TcpListener, String) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    (l, addr)
}

#[test]
fn test_blocking_echo_round_trip_and_close() {
    let (l, addr) = listener();
    let server = thread::spawn(move || {
        let (stream, _) = l.accept().unwrap();
        let mut ws = blocking::accept(stream).unwrap();
        let mut seen = Vec::new();
        loop {
            match ws.read() {
                Ok(m) if m.is_data() => ws.send(&m).unwrap(),
                Ok(m) => seen.push(m),
                Err(blocking::Error::Closed) => break,
                Err(e) => panic!("{e}"),
            }
        }
        seen
    });
    let stream = TcpStream::connect(&addr).unwrap();
    let hs = ClientHandshake::try_new().unwrap().with_origin(&format!("http://{addr}"));
    let (mut ws, protocol) = blocking::connect_with(stream, &addr, "/echo", &hs).unwrap();
    assert_eq!(protocol, None);
    ws.send_text("hello").unwrap();
    assert_eq!(ws.read().unwrap(), Message::from("hello"));
    ws.send_binary(&[1, 2, 3]).unwrap();
    assert_eq!(ws.read().unwrap(), Message::from(vec![1, 2, 3]));
    ws.ping(b"p").unwrap();
    assert_eq!(ws.read().unwrap(), Message::Pong(b"p".to_vec()));
    let big = "x".repeat(300_000);
    ws.send_text(&big).unwrap();
    assert_eq!(ws.read().unwrap(), Message::Text(big));
    ws.close(CloseCode::NORMAL, "done").unwrap();
    assert_eq!(
        ws.read().unwrap(),
        Message::Close(Some((CloseCode::NORMAL, String::new())))
    );
    assert!(matches!(ws.read(), Err(blocking::Error::Closed)));
    let seen = server.join().unwrap();
    assert!(seen.contains(&Message::Ping(b"p".to_vec())));
    assert!(seen.contains(&Message::Close(Some((CloseCode::NORMAL, "done".into())))));
}

#[test]
fn test_blocking_foreign_origin_refused_403() {
    let (l, addr) = listener();
    let server = thread::spawn(move || {
        let (stream, _) = l.accept().unwrap();
        blocking::accept(stream).map(|_| ())
    });
    let stream = TcpStream::connect(&addr).unwrap();
    let hs = ClientHandshake::try_new().unwrap().with_origin("https://evil.example");
    let e = blocking::connect_with(stream, &addr, "/", &hs).unwrap_err();
    assert!(
        matches!(e, blocking::Error::Handshake(HandshakeError::NotSwitching(403))),
        "{e}"
    );
    assert!(matches!(
        server.join().unwrap(),
        Err(blocking::Error::Handshake(HandshakeError::OriginRefused))
    ));
}

#[test]
fn test_blocking_policy_selects_protocol() {
    let (l, addr) = listener();
    let server = thread::spawn(move || {
        let (stream, _) = l.accept().unwrap();
        let policy = AcceptPolicy::new()
            .with_origins(OriginPolicy::any_origin())
            .with_protocols(&["rpc.v2", "rpc.v1"])
            .unwrap();
        let (_ws, request) = blocking::accept_with(stream, &policy).unwrap();
        request.target().to_string()
    });
    let stream = TcpStream::connect(&addr).unwrap();
    let hs = ClientHandshake::try_new()
        .unwrap()
        .with_protocols(&["rpc.v1", "rpc.v2"])
        .with_header("authorization", b"Bearer t");
    let (_ws, protocol) = blocking::connect_with(stream, &addr, "/rpc?x=1", &hs).unwrap();
    assert_eq!(protocol.as_deref(), Some("rpc.v2"));
    assert_eq!(server.join().unwrap(), "/rpc?x=1");
}

#[test]
fn test_blocking_idle_timeout_through_read_timeout() {
    let (l, addr) = listener();
    let server = thread::spawn(move || {
        let (stream, _) = l.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
        let policy = AcceptPolicy::new()
            .with_keepalive(Keepalive::new().with_idle_timeout(Duration::from_millis(150)));
        let (mut ws, _) = blocking::accept_with(stream, &policy).unwrap();
        ws.read()
    });
    let stream = TcpStream::connect(&addr).unwrap();
    let mut ws = blocking::connect(stream, &addr, "/").unwrap();
    // Say nothing; the server gives up and sends 1001.
    let got = server.join().unwrap();
    assert!(matches!(got, Err(blocking::Error::Protocol(WsError::IdleTimeout))), "{got:?}");
    assert_eq!(
        ws.read().unwrap(),
        Message::Close(Some((CloseCode::GOING_AWAY, String::new())))
    );
}

#[test]
fn test_blocking_from_upgraded_large_leftover_taken_in_pieces() {
    // More leftover than one input buffer holds.
    let mut client = Connection::client_with_seed([5; 32]);
    for i in 0..200u32 {
        client.send_binary(&vec![(i % 251) as u8; 1000]).unwrap();
    }
    let leftover = client.output().to_vec();
    assert!(leftover.len() > 64 * 1024);
    let mut ws = blocking::WebSocket::from_upgraded(
        std::io::Cursor::new(Vec::new()),
        &leftover,
        Connection::server(),
    );
    for i in 0..200u32 {
        assert_eq!(ws.read().unwrap(), Message::Binary(vec![(i % 251) as u8; 1000]));
    }
}
