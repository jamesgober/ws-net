//! A client with the blocking adapter: connects, sends a few messages,
//! reads the echoes, and closes.
//!
//! ```sh
//! cargo run --example blocking_echo -- 127.0.0.1:9001   # in one terminal
//! cargo run --example blocking_client -- 127.0.0.1:9001 # in another
//! ```

use std::net::TcpStream;

use ws_net::{ClientHandshake, CloseCode, Message, blocking};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:9001".into());
    let stream = TcpStream::connect(&addr)?;
    // A browser would send the page's Origin; the echo server's same-origin
    // policy accepts this one.
    let handshake = ClientHandshake::try_new()?.with_origin(&format!("http://{addr}"));
    let (mut ws, _protocol) = blocking::connect_with(stream, &addr, "/", &handshake)?;
    for text in ["hello", "from", "ws-net"] {
        ws.send_text(text)?;
        match ws.read()? {
            Message::Text(echo) => println!("echo: {echo}"),
            other => println!("other: {other:?}"),
        }
    }
    ws.close(CloseCode::NORMAL, "done")?;
    // Read until the server's Close completes the handshake.
    loop {
        match ws.read() {
            Ok(Message::Close(frame)) => println!("closed: {frame:?}"),
            Ok(_) => {}
            Err(blocking::Error::Closed) => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
