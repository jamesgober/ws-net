//! The echo server the Autobahn TestSuite's `fuzzingclient` mode tests
//! (server role): one thread per connection through the blocking adapter,
//! every Origin accepted (the suite is not a browser), and budgets raised
//! to 64 MiB so the 9.x cases measure speed, not budgets.
//!
//! ```sh
//! cargo run --release --example autobahn_server -- 127.0.0.1:9001
//! docker run --rm --net=host -v "$PWD/autobahn:/config" -v "$PWD/autobahn/reports:/reports" \
//!     crossbario/autobahn-testsuite:25.10.1 wstest -m fuzzingclient -s /config/fuzzingclient.json
//! python3 autobahn/check.py autobahn/reports/servers/index.json
//! ```

use std::{io, net::TcpListener, thread};

use ws_net::{AcceptPolicy, Limits, OriginPolicy, blocking};

fn main() -> io::Result<()> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:9001".into());
    let listener = TcpListener::bind(&addr)?;
    println!("autobahn echo server on ws://{}/", listener.local_addr()?);
    let limits = Limits::new()
        .with_max_frame(64 << 20)
        .with_max_message(64 << 20)
        .with_max_output(u64::MAX);
    let policy = AcceptPolicy::new()
        .with_origins(OriginPolicy::any_origin())
        .with_limits(limits);
    for stream in listener.incoming() {
        let stream = stream?;
        let _ = stream.set_nodelay(true);
        let policy = policy.clone();
        let _ = thread::spawn(move || {
            let Ok((mut ws, _)) = blocking::accept_with(stream, &policy) else {
                return;
            };
            while let Ok(message) = ws.read() {
                if message.is_data() && ws.send(&message).is_err() {
                    break;
                }
            }
        });
    }
    Ok(())
}
