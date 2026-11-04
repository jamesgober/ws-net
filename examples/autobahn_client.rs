//! The client the Autobahn TestSuite's `fuzzingserver` mode tests (client
//! role): asks the suite for its case count, runs every case as an echo
//! client, then asks it to write the report.
//!
//! ```sh
//! docker run --rm --net=host -v "$PWD/autobahn:/config" -v "$PWD/autobahn/reports:/reports" \
//!     crossbario/autobahn-testsuite:25.10.1 wstest -m fuzzingserver -s /config/fuzzingserver.json &
//! cargo run --release --example autobahn_client -- 127.0.0.1:9002
//! python3 autobahn/check.py autobahn/reports/clients/index.json
//! ```

use std::{io, net::TcpStream};

use ws_net::{ClientHandshake, Connection, HeadReader, Limits, Message, blocking};

const AGENT: &str = "ws-net";

/// Connects to `path` with large budgets and returns the adapter.
fn open(
    addr: &str,
    path: &str,
) -> Result<blocking::WebSocket<TcpStream>, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(addr)?;
    let _ = stream.set_nodelay(true);
    let handshake = ClientHandshake::try_new()?;
    let mut request = Vec::new();
    handshake.write_request(addr, path, &mut request)?;
    io::Write::write_all(&mut stream, &request)?;
    let mut reader = HeadReader::new();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = io::Read::read(&mut stream, &mut chunk)?;
        if n == 0 {
            return Err("connection closed during the handshake".into());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some((_, len)) = reader.client(&handshake, &buf)? {
            let limits = Limits::new()
                .with_max_frame(64 << 20)
                .with_max_message(64 << 20)
                .with_max_output(u64::MAX);
            let conn = Connection::try_client()?.with_limits(limits);
            return Ok(blocking::WebSocket::from_upgraded(
                stream,
                &buf[len..],
                conn,
            ));
        }
    }
}

/// Echoes every data message until the connection ends.
fn echo(mut ws: blocking::WebSocket<TcpStream>) {
    while let Ok(message) = ws.read() {
        if message.is_data() && ws.send(&message).is_err() {
            break;
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:9002".into());
    let mut ws = open(&addr, "/getCaseCount")?;
    let count: u32 = match ws.read()? {
        Message::Text(text) => text.trim().parse()?,
        other => return Err(format!("unexpected {other:?}").into()),
    };
    drop(ws);
    println!("running {count} cases");
    for case in 1..=count {
        match open(&addr, &format!("/runCase?case={case}&agent={AGENT}")) {
            Ok(ws) => echo(ws),
            Err(e) => eprintln!("case {case}: {e}"),
        }
    }
    let ws = open(&addr, &format!("/updateReports?agent={AGENT}"))?;
    echo(ws);
    println!("report updated");
    Ok(())
}
