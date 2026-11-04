//! Broadcast in memory: one message encoded once with `PreparedMessage` and
//! appended to 10,000 server connections, with a slow subscriber refused by
//! its output budget instead of growing without bound.
//!
//! ```sh
//! cargo run --release --example broadcast
//! ```

use std::time::Instant;

use ws_net::{Connection, Limits, PreparedMessage, WsError};

fn main() {
    let limits = Limits::new().with_max_output(4096);
    let mut subscribers: Vec<Connection> = (0..10_000)
        .map(|_| Connection::server().with_limits(limits))
        .collect();
    let update = PreparedMessage::text(r#"{"jsonrpc":"2.0","method":"price","params":[101.25]}"#);

    let start = Instant::now();
    let mut full = 0;
    for round in 0..200 {
        for (i, conn) in subscribers.iter_mut().enumerate() {
            match conn.send_prepared(&update) {
                Ok(()) => {}
                Err(WsError::OutputFull) => full += 1,
                Err(e) => eprintln!("subscriber {i}: {e}"),
            }
            // Every subscriber but the first reads its output.
            if i != 0 {
                let n = conn.output().len();
                conn.advance_output(n);
            }
        }
        if round == 0 {
            println!(
                "one round: {:?} for {} subscribers",
                start.elapsed(),
                subscribers.len()
            );
        }
    }
    println!(
        "200 rounds: {:?}; the slow subscriber holds {} bytes and was refused {full} times",
        start.elapsed(),
        subscribers[0].buffered_output()
    );
}
