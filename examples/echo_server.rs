//! A WebSocket echo server on localhost, one thread per connection, with
//! no HTTP library: the opening handshake is read from the socket's raw
//! bytes by `ServerHandshake::from_head`.
//!
//! ```sh
//! cargo run --example echo_server -- 127.0.0.1:9001
//! ```
//!
//! Behind an HTTP server (http-net's upgrade hand-off), the handshake is
//! `ServerHandshake::from_request(req.method_str(), req.target(), req.headers())`
//! instead, and everything from `Connection::server()` on is unchanged.

use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    time::Duration,
};

use ws_net::{Connection, Event, ServerHandshake};

/// Reads the request head and answers it: the 101 on success, the refusal
/// otherwise. Returns the bytes that arrived after the head.
fn handshake(stream: &mut TcpStream) -> io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
        match ServerHandshake::from_head(&buf) {
            Ok(None) => continue,
            Ok(Some((request, len))) => {
                // A real server checks `request.host()` and
                // `request.origin()` against its own policy here, and
                // answers 403 to a stranger.
                let mut response = Vec::new();
                request
                    .write_response(None, &mut response)
                    .map_err(io::Error::other)?;
                stream.write_all(&response)?;
                return Ok(Some(buf.split_off(len)));
            }
            Err(refused) => {
                let mut response = Vec::new();
                refused.write_response(&mut response);
                stream.write_all(&response)?;
                return Ok(None);
            }
        }
    }
}

/// Writes everything queued, including a Close frame queued by a failure.
fn flush(conn: &mut Connection, stream: &mut TcpStream) -> io::Result<()> {
    let out = conn.output();
    stream.write_all(out)?;
    let n = out.len();
    conn.advance_output(n);
    Ok(())
}

fn serve(mut stream: TcpStream) -> io::Result<()> {
    let Some(early) = handshake(&mut stream)? else {
        return Ok(());
    };
    // A peer that stops talking does not hold a thread forever.
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;

    let mut conn = Connection::server();
    let mut pending = &early[..];
    loop {
        // The event borrows the connection; copy out what the echo needs.
        let reply = match conn.poll() {
            Ok(Event::Text(t)) => Some((true, t.as_bytes().to_vec())),
            Ok(Event::Binary(b)) => Some((false, b.to_vec())),
            Ok(Event::NeedInput) if !pending.is_empty() => {
                let n = conn.feed(pending);
                pending = &pending[n..];
                None
            }
            Ok(Event::NeedInput) => {
                match stream.read(conn.read_buf()) {
                    Ok(0) | Err(_) => conn.feed_eof(),
                    Ok(n) => conn.commit(n),
                }
                None
            }
            // Pings were answered and Close frames echoed automatically.
            Ok(Event::Closed) => break,
            Ok(_) => None,
            Err(e) => {
                // The connection failed: its Close frame (1002, 1007,
                // 1009, ...) is in the output. Send it, then hang up.
                eprintln!("protocol error: {e}");
                break;
            }
        };
        match reply {
            Some((true, text)) => {
                let text = String::from_utf8(text).map_err(io::Error::other)?;
                conn.send_text(&text).map_err(io::Error::other)?;
            }
            Some((false, data)) => conn.send_binary(&data).map_err(io::Error::other)?,
            None => {}
        }
        flush(&mut conn, &mut stream)?;
    }
    // The server closes the TCP connection first (RFC 6455 section 7.1.1).
    flush(&mut conn, &mut stream)
}

fn main() -> io::Result<()> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:9001".into());
    let listener = TcpListener::bind(&addr)?;
    println!(
        "echo server on ws://{}/ (Ctrl+C to stop)",
        listener.local_addr()?
    );
    for stream in listener.incoming() {
        let stream = stream?;
        std::thread::spawn(move || {
            if let Err(e) = serve(stream) {
                eprintln!("connection ended: {e}");
            }
        });
    }
    Ok(())
}
