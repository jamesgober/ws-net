//! A WebSocket behind an HTTP server: http-net's blocking `Server` routes
//! requests, ws-net validates the upgrade and its policy, http-net writes
//! the `101` with ws-net's response fields, and `on_upgrade` hands the
//! socket to the blocking WebSocket adapter. (http-net is a dev-dependency
//! of this example only; ws-net never depends on it.)
//!
//! ```sh
//! cargo run --example http_net_upgrade -- 127.0.0.1:9002
//! ```

use std::io;

use http_net::{Response, blocking::Server};
use ws_net::{AcceptPolicy, Connection, ServerHandshake, blocking, extension::Negotiated};

fn main() -> io::Result<()> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:9002".into());
    let server = Server::bind(&addr)?.on_upgrade(|up| {
        let mut ws =
            blocking::WebSocket::from_upgraded(up.stream, &up.leftover, Connection::server());
        while let Ok(message) = ws.read() {
            if message.is_data() && ws.send(&message).is_err() {
                break;
            }
        }
    });
    println!(
        "http on http://{}/, websocket on ws://{}/ws",
        server.local_addr(),
        server.local_addr()
    );
    server.serve(|req, _body| {
        if req.target() != "/ws" {
            return Response::new(200).body(&b"hello over http\n"[..]);
        }
        // ws-net checks the upgrade even behind an HTTP layer.
        let handshake =
            match ServerHandshake::from_request(req.method_str(), req.target(), req.headers()) {
                Ok(h) => h,
                Err(e) => return Response::new(e.status()),
            };
        let decision = match AcceptPolicy::new().check(&handshake) {
            Ok(d) => d,
            Err(e) => return Response::new(e.status()),
        };
        let mut response = Response::switching_protocols("websocket");
        let fields = handshake.response_fields(decision.protocol, &Negotiated::none());
        for (name, value) in fields.into_iter().flatten() {
            // switching_protocols writes upgrade and connection itself.
            if name.starts_with("sec-websocket-") {
                response = response.header(name, value);
            }
        }
        response
    })
}
