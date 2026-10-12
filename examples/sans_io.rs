//! A client and a server talking through memory: the opening handshake as
//! raw bytes, messages, a ping, a refused call, and the closing handshake,
//! with no socket. This is the loop every transport adapter wraps.
//!
//! ```sh
//! cargo run --example sans_io
//! ```

use ws_net::{ClientHandshake, CloseCode, Connection, Event, ServerHandshake, WsError};

/// Moves everything `from` has queued into `to`. A feed takes at most the
/// input buffer's free space (polling makes room); these messages are
/// small, so the buffer never fills.
fn pump(from: &mut Connection, to: &mut Connection) {
    let bytes = from.output().to_vec();
    from.advance_output(bytes.len());
    let mut rest = &bytes[..];
    while !rest.is_empty() {
        let n = to.feed(rest);
        if n == 0 {
            break;
        }
        rest = &rest[n..];
    }
}

fn drain(name: &str, conn: &mut Connection) -> Result<(), WsError> {
    loop {
        match conn.poll()? {
            Event::NeedInput | Event::Closed => return Ok(()),
            Event::Text(t) => println!("{name} got text: {t}"),
            Event::Binary(b) => println!("{name} got {} binary bytes", b.len()),
            Event::Ping(p) => println!(
                "{name} got ping {:?} (pong queued)",
                String::from_utf8_lossy(p)
            ),
            Event::Pong(p) => println!("{name} got pong {:?}", String::from_utf8_lossy(p)),
            Event::Close(frame) => println!("{name} got close {frame:?}"),
            other => println!("{name} got {other:?}"),
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Opening handshake: request bytes -> validation -> 101 bytes ->
    // verification. Bytes after each head would be the first frames.
    let client_hs = ClientHandshake::new()
        .with_protocols(&["jsonrpc"])
        .with_origin("http://127.0.0.1:9001");
    let mut request = Vec::new();
    client_hs.write_request("127.0.0.1:9001", "/rpc", &mut request)?;
    print!("{}", String::from_utf8_lossy(&request));

    let (server_hs, _) = ServerHandshake::from_head(&request)?.ok_or("incomplete request")?;
    println!(
        "server sees target {} on host {} from origin {:?}\n",
        server_hs.target(),
        server_hs.host(),
        server_hs.origin()
    );
    let mut response = Vec::new();
    server_hs.write_response(Some("jsonrpc"), &mut response)?;
    print!("{}", String::from_utf8_lossy(&response));
    let (protocol, _) = client_hs
        .verify_head(&response)?
        .ok_or("incomplete response")?;
    println!("handshake ok, subprotocol {protocol:?}\n");

    let mut client = Connection::client();
    let mut server = Connection::server();

    client.send_text("{\"jsonrpc\":\"2.0\",\"method\":\"open\"}")?;
    client.send_binary(&[1, 0, 0, 0, 7, 0, 0, 0])?;
    client.send_ping(b"are you there")?;
    pump(&mut client, &mut server);
    drain("server", &mut server)?;

    server.send_text("{\"jsonrpc\":\"2.0\",\"result\":true}")?;
    pump(&mut server, &mut client); // includes the automatic pong
    drain("client", &mut client)?;

    // A refused call changes nothing: no close code, connection still open.
    if let Err(refused) = client.send_ping(&[0; 200]) {
        println!(
            "refused: {refused} (close code {:?}, state {:?})",
            refused.close_code(),
            client.state()
        );
    }

    client.close(CloseCode::NORMAL, "done")?;
    pump(&mut client, &mut server);
    drain("server", &mut server)?;
    pump(&mut server, &mut client); // the echoed close
    drain("client", &mut client)?;
    println!(
        "client state {:?}, server state {:?}",
        client.state(),
        server.state()
    );
    Ok(())
}
