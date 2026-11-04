//! An echo server with the blocking adapter: one thread per connection,
//! the same-origin policy, keepalive pings, and idle connections closed.
//!
//! ```sh
//! cargo run --example blocking_echo -- 127.0.0.1:9001
//! ```
//!
//! Pair it with `cargo run --example blocking_client -- 127.0.0.1:9001`.

use std::{io, net::TcpListener, thread, time::Duration};

use ws_net::{AcceptPolicy, Keepalive, blocking};

fn main() -> io::Result<()> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:9001".into());
    let listener = TcpListener::bind(&addr)?;
    println!(
        "echo server on ws://{}/ (Ctrl+C to stop)",
        listener.local_addr()?
    );
    let policy = AcceptPolicy::new().with_keepalive(
        Keepalive::new()
            .with_ping_interval(Duration::from_secs(30))
            .with_idle_timeout(Duration::from_secs(75)),
    );
    for stream in listener.incoming() {
        let stream = stream?;
        // Reads time out so the keepalive ticks while the peer is silent.
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let policy = policy.clone();
        let _ = thread::spawn(move || match blocking::accept_with(stream, &policy) {
            Ok((mut ws, request)) => {
                println!("connected: {}", request.target());
                loop {
                    match ws.read() {
                        Ok(message) if message.is_data() => {
                            if let Err(e) = ws.send(&message) {
                                eprintln!("send failed: {e}");
                                break;
                            }
                        }
                        Ok(_) => {}
                        Err(blocking::Error::Closed) => break,
                        Err(e) => {
                            eprintln!("connection ended: {e}");
                            break;
                        }
                    }
                }
            }
            Err(e) => eprintln!("handshake refused: {e}"),
        });
    }
    Ok(())
}
