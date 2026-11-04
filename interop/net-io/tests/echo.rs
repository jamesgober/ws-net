//! ws-net on net-io over loopback sockets, on both drivers: messages of
//! every length class, many clients at once, Pings, the close order (the
//! server closes TCP first), refusals, a peer that vanishes, and net-io's
//! idle timeout turned into Close 1001.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    thread,
    time::{Duration, Instant},
};

use net_io::{DriverKind, Limits, Server};
use ws_net::{ClientHandshake, CloseCode, Message, blocking};
use ws_net_interop_net_io::{start, start_with};

const DRIVERS: [DriverKind; 2] = [DriverKind::Blocking, DriverKind::Reactor];

type Client = blocking::WebSocket<TcpStream>;

fn connect(addr: SocketAddr) -> Client {
    let stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let host = addr.to_string();
    let (ws, _) = blocking::connect_with(stream, &host, "/", &ClientHandshake::new()).unwrap();
    ws
}

/// Closes from the client side and reads until the closing handshake ends.
fn close(mut ws: Client) -> Option<(CloseCode, String)> {
    ws.close(CloseCode::NORMAL, "bye").unwrap();
    let mut frame = None;
    loop {
        match ws.read() {
            Ok(Message::Close(f)) => frame = f,
            Ok(_) => {}
            Err(blocking::Error::Closed) => break,
            Err(e) => panic!("{e}"),
        }
    }
    // The server closes TCP first: the next read is the FIN.
    let mut rest = Vec::new();
    let n = ws.get_mut().read_to_end(&mut rest).unwrap();
    assert_eq!(n, 0, "no bytes after the Close");
    frame
}

/// Waits until net-io has closed every connection, then stops the server.
fn finish(server: Server) {
    let start = Instant::now();
    while server.stats().open > 0 {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "connections left open"
        );
        thread::sleep(Duration::from_millis(10));
    }
    let _ = server.shutdown(Instant::now() + Duration::from_secs(5));
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 + len) as u8).collect()
}

#[test]
fn test_echo_every_length_class_both_drivers() {
    for driver in DRIVERS {
        let (server, addr) = start(driver, 2).unwrap();
        let mut ws = connect(addr);
        for len in [0, 1, 125, 126, 65_535, 65_536, 1 << 20] {
            let data = pattern(len);
            ws.send_binary(&data).unwrap();
            assert_eq!(
                ws.read().unwrap(),
                Message::Binary(data),
                "{driver:?} {len}"
            );
            let text = "é".repeat(len / 2);
            ws.send_text(&text).unwrap();
            assert_eq!(ws.read().unwrap(), Message::Text(text), "{driver:?} {len}");
        }
        // ws-net echoes the status code (RFC 6455 section 5.5.1).
        assert_eq!(close(ws).map(|(code, _)| code), Some(CloseCode::NORMAL));
        finish(server);
    }
}

#[test]
fn test_many_clients_at_once() {
    for driver in DRIVERS {
        // The blocking pool holds one connection per worker.
        let (server, addr) = start(driver, 64).unwrap();
        let clients: Vec<_> = (0..48)
            .map(|c| {
                thread::spawn(move || {
                    let mut ws = connect(addr);
                    for i in 0..200usize {
                        let msg = format!("client {c} message {i} {}", "x".repeat(i * 7));
                        ws.send_text(&msg).unwrap();
                        assert_eq!(ws.read().unwrap(), Message::Text(msg));
                    }
                    close(ws);
                })
            })
            .collect();
        for c in clients {
            c.join().unwrap();
        }
        let stats = server.stats();
        assert_eq!(stats.accepted, 48, "{driver:?}");
        finish(server);
    }
}

#[test]
fn test_ping_answered_between_messages() {
    for driver in DRIVERS {
        let (server, addr) = start(driver, 1).unwrap();
        let mut ws = connect(addr);
        ws.ping(b"are you there").unwrap();
        ws.send_text("after the ping").unwrap();
        assert_eq!(ws.read().unwrap(), Message::Pong(b"are you there".to_vec()));
        assert_eq!(ws.read().unwrap(), Message::Text("after the ping".into()));
        close(ws);
        finish(server);
    }
}

#[test]
fn test_cross_origin_refused_with_403() {
    for driver in DRIVERS {
        let (server, addr) = start(driver, 1).unwrap();
        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\
             Origin: https://elsewhere.example\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "{driver:?}: {response}"
        );
        finish(server);
    }
}

#[test]
fn test_client_vanishes_mid_message() {
    for driver in DRIVERS {
        let (server, addr) = start(driver, 1).unwrap();
        let mut ws = connect(addr);
        ws.send_text("whole").unwrap();
        assert_eq!(ws.read().unwrap(), Message::Text("whole".into()));
        // Half a frame header, then the socket goes away.
        ws.get_mut().write_all(&[0x82, 0xfe]).unwrap();
        drop(ws);
        finish(server);
    }
}

#[test]
fn test_idle_timeout_closes_with_1001() {
    for driver in DRIVERS {
        let limits = Limits::builder()
            .idle_timeout(Duration::from_millis(300))
            .build()
            .unwrap();
        let (server, addr) = start_with(driver, 1, limits).unwrap();
        let mut ws = connect(addr);
        ws.send_text("then silence").unwrap();
        assert_eq!(ws.read().unwrap(), Message::Text("then silence".into()));
        match ws.read() {
            Ok(Message::Close(Some((code, _)))) => assert_eq!(code, CloseCode::GOING_AWAY),
            other => panic!("{driver:?}: {other:?}"),
        }
        // The client's answer completes the handshake; the server closes TCP.
        assert!(matches!(ws.read(), Err(blocking::Error::Closed)));
        let mut rest = Vec::new();
        assert_eq!(ws.get_mut().read_to_end(&mut rest).unwrap(), 0);
        finish(server);
    }
}
