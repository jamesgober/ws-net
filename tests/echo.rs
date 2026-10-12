//! A WebSocket echo over a real localhost socket: the opening handshake
//! from raw head bytes, text, binary, fragmented and large messages,
//! ping/pong, the closing handshake, protocol failures, and refusals, with
//! both ends driven by ws-net.

#![cfg(feature = "std")]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    thread,
    time::Duration,
};

use ws_net::{
    ClientHandshake, CloseCode, Connection, Event, HandshakeError, ServerHandshake, WsError,
};

/// Reads until `parse` reports a complete head (`Ok(Some)`) or refuses it;
/// returns its result and the bytes that arrived after the head.
fn read_head<T>(
    stream: &mut TcpStream,
    parse: impl Fn(&[u8]) -> Result<Option<(T, usize)>, HandshakeError>,
) -> Result<(T, Vec<u8>), HandshakeError> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).unwrap_or(0);
        assert!(n > 0, "connection closed during the head");
        buf.extend_from_slice(&chunk[..n]);
        if let Some((value, len)) = parse(&buf)? {
            return Ok((value, buf.split_off(len)));
        }
    }
}

#[derive(Debug, PartialEq)]
enum Got {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close(Option<u16>),
    Closed,
    Failed(WsError),
}

/// Polls until an event other than `NeedInput` arrives, reading as needed
/// and flushing the output after every poll, including after an error,
/// whose Close frame is in the output. Returns an owned copy.
fn next(conn: &mut Connection, stream: &mut TcpStream) -> Got {
    loop {
        let got = match conn.poll() {
            Ok(Event::Text(t)) => Some(Got::Text(t.to_string())),
            Ok(Event::Binary(b)) => Some(Got::Binary(b.to_vec())),
            Ok(Event::Ping(p)) => Some(Got::Ping(p.to_vec())),
            Ok(Event::Pong(p)) => Some(Got::Pong(p.to_vec())),
            Ok(Event::Close(f)) => Some(Got::Close(f.map(|f| f.code.as_u16()))),
            Ok(Event::Closed) => Some(Got::Closed),
            Ok(Event::NeedInput) => None,
            Ok(other) => panic!("unexpected {other:?}"),
            Err(e) => Some(Got::Failed(e)),
        };
        flush(conn, stream);
        match got {
            Some(g) => return g,
            None => {
                let n = stream.read(conn.read_buf()).unwrap_or(0);
                if n == 0 {
                    conn.feed_eof();
                } else {
                    conn.commit(n);
                }
            }
        }
    }
}

fn flush(conn: &mut Connection, stream: &mut TcpStream) {
    let out = conn.output();
    if !out.is_empty() && stream.write_all(out).is_ok() {
        let n = out.len();
        conn.advance_output(n);
    }
}

/// Serves one echo connection; returns how it ended (`None`: refused at
/// the handshake).
fn echo_server(mut stream: TcpStream) -> Option<Got> {
    let (handshake, rest) = match read_head(&mut stream, ServerHandshake::from_head) {
        Ok(found) => found,
        Err(e) => {
            let mut reply = Vec::new();
            e.write_response(&mut reply);
            let _ = stream.write_all(&reply);
            return None;
        }
    };
    // The policy decision is the server's: here, one allowed origin.
    if handshake
        .origin()
        .is_some_and(|o| o != "http://allowed.example")
    {
        let _ = stream
            .write_all(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
        return None;
    }
    let protocol = handshake.protocols().find(|p| *p == "echo");
    let mut response = Vec::new();
    handshake.write_response(protocol, &mut response).ok()?;
    stream.write_all(&response).ok()?;

    let mut conn = Connection::server();
    assert_eq!(conn.feed(&rest), rest.len());
    loop {
        match next(&mut conn, &mut stream) {
            Got::Text(t) => conn.send_text(&t).ok()?,
            Got::Binary(b) => conn.send_binary(&b).ok()?,
            Got::Ping(_) | Got::Pong(_) => {}
            // The server closes the TCP connection first (RFC 6455
            // section 7.1.1): `stream` drops on return.
            ended => return Some(ended),
        }
        flush(&mut conn, &mut stream);
    }
}

fn spawn_server() -> (SocketAddr, thread::JoinHandle<Option<Got>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        echo_server(stream)
    });
    (addr, server)
}

/// Connects and completes the handshake; returns the stream, the client
/// connection, and the subprotocol the server chose.
fn connect(
    addr: SocketAddr,
    handshake: &ClientHandshake,
) -> (TcpStream, Connection, Option<String>) {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut request = Vec::new();
    handshake
        .write_request(&addr.to_string(), "/echo", &mut request)
        .unwrap();
    stream.write_all(&request).unwrap();
    let (selected, rest) = read_head(&mut stream, |buf| {
        Ok(handshake
            .verify_head(buf)?
            .map(|(p, n)| (p.map(str::to_string), n)))
    })
    .unwrap();
    let mut conn = Connection::client();
    assert_eq!(conn.feed(&rest), rest.len());
    (stream, conn, selected)
}

#[test]
fn test_echo_over_localhost() {
    let (addr, server) = spawn_server();
    let handshake = ClientHandshake::new()
        .with_protocols(&["chat", "echo"])
        .with_origin("http://allowed.example");
    let (mut stream, mut conn, selected) = connect(addr, &handshake);
    assert_eq!(selected.as_deref(), Some("echo"));

    conn.send_text("hello").unwrap();
    flush(&mut conn, &mut stream);
    assert_eq!(next(&mut conn, &mut stream), Got::Text("hello".into()));

    let big: Vec<u8> = (0..3_000_000u32).map(|i| (i % 253) as u8).collect();
    conn.send_binary(&big).unwrap(); // three 1 MiB frames
    flush(&mut conn, &mut stream);
    assert_eq!(next(&mut conn, &mut stream), Got::Binary(big));

    conn.send_text_fragment("frag", false).unwrap();
    conn.send_ping(b"between").unwrap();
    conn.send_text_fragment("mented ✓", true).unwrap();
    flush(&mut conn, &mut stream);
    assert_eq!(next(&mut conn, &mut stream), Got::Pong(b"between".to_vec()));
    assert_eq!(
        next(&mut conn, &mut stream),
        Got::Text("fragmented ✓".into())
    );

    conn.close(CloseCode::NORMAL, "bye").unwrap();
    flush(&mut conn, &mut stream);
    assert_eq!(next(&mut conn, &mut stream), Got::Close(Some(1000)));
    assert_eq!(next(&mut conn, &mut stream), Got::Closed);
    // After the closing handshake the server closes the transport.
    let mut tail = [0u8; 8];
    assert_eq!(stream.read(&mut tail).unwrap(), 0);
    assert_eq!(server.join().unwrap(), Some(Got::Close(Some(1000))));
}

#[test]
fn test_protocol_error_reaches_the_peer() {
    // A text frame that is not UTF-8: the server must fail the connection
    // with a Close frame carrying 1007, and the peer must receive it.
    let (addr, server) = spawn_server();
    let (mut stream, mut conn, _) = connect(addr, &ClientHandshake::new());
    // A masked text frame with payload 0xFF (key 0), written past the
    // client connection, which would never send it.
    stream.write_all(&[0x81, 0x81, 0, 0, 0, 0, 0xFF]).unwrap();
    assert_eq!(next(&mut conn, &mut stream), Got::Close(Some(1007)));
    assert_eq!(
        server.join().unwrap(),
        Some(Got::Failed(WsError::InvalidUtf8))
    );
}

#[test]
fn test_handshake_refusal_over_localhost() {
    let (addr, server) = spawn_server();
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .write_all(
            b"GET /echo HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 8\r\n\r\n",
        )
        .unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).unwrap();
    assert!(reply.starts_with("HTTP/1.1 426 Upgrade Required\r\n"));
    assert!(reply.contains("sec-websocket-version: 13"));
    assert_eq!(server.join().unwrap(), None);
}

#[test]
fn test_foreign_origin_is_refused_by_policy() {
    let (addr, server) = spawn_server();
    let mut stream = TcpStream::connect(addr).unwrap();
    let mut request = Vec::new();
    ClientHandshake::new()
        .with_origin("http://evil.example")
        .write_request(&addr.to_string(), "/echo", &mut request)
        .unwrap();
    stream.write_all(&request).unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).unwrap();
    assert!(reply.starts_with("HTTP/1.1 403 Forbidden\r\n"));
    assert_eq!(server.join().unwrap(), None);
}
