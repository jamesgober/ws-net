//! Keepalive without a clock of its own, in memory: the caller passes its
//! monotonic milliseconds to `on_time` and sleeps until `next_deadline`.
//!
//! ```sh
//! cargo run --example keepalive
//! ```
//!
//! A server pings a silent client every 30 s and gives up after 75 s; a
//! message that never finishes is cut off after 10 s. Simulated time, so it
//! runs instantly.

use core::time::Duration;

use ws_net::{Connection, Event, Keepalive, Millis, Tick, WsError};

fn main() -> Result<(), WsError> {
    let keepalive = Keepalive::new()
        .with_ping_interval(Duration::from_secs(30))
        .with_idle_timeout(Duration::from_secs(75))
        .with_message_timeout(Duration::from_secs(10));
    let mut server = Connection::server().with_keepalive(keepalive);
    let mut client = Connection::client_with_seed([11; 32]);

    let mut now = Millis(0);
    let _ = server.on_time(now)?;
    // The driver's loop: sleep until the next deadline, tick, write output.
    for _ in 0..2 {
        let Some(deadline) = server.next_deadline() else {
            break;
        };
        now = deadline;
        if server.on_time(now)? == Tick::PingQueued {
            let ping = server.output().to_vec();
            server.advance_output(ping.len());
            println!("{:>6} ms: server pinged", now.as_u64());
            // The client answers (its Pong is automatic) and the server
            // sees the bytes: activity, so the idle timer restarts.
            let _ = client.feed(&ping);
            let _ = client.poll()?;
            let pong = client.output().to_vec();
            client.advance_output(pong.len());
            let _ = server.feed(&pong);
            // A driver ticks after every read: the input is activity.
            let _ = server.on_time(now)?;
            if let Event::Pong(payload) = server.poll()? {
                let sent = u64::from_be_bytes(payload.try_into().unwrap_or([0; 8]));
                println!(
                    "{:>6} ms: pong for the ping sent at {sent} ms",
                    now.as_u64()
                );
            }
        }
    }

    // A slow message: the first fragment, then nothing.
    client.send_text_fragment("the beginning of", false)?;
    let wire = client.output().to_vec();
    client.advance_output(wire.len());
    let _ = server.feed(&wire);
    let _ = server.poll()?;
    let _ = server.on_time(now)?;
    while let Some(deadline) = server.next_deadline() {
        now = deadline;
        match server.on_time(now) {
            Ok(_) => continue,
            Err(e) => {
                println!(
                    "{:>6} ms: {e} (close code {:?})",
                    now.as_u64(),
                    e.close_code()
                );
                break;
            }
        }
    }
    Ok(())
}
