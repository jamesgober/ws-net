//! A sequence of API calls interleaved with input and clock ticks: no
//! panic; a refused call changes neither the state nor the output; the
//! state only moves forward (Open, Closing, Closed); the output stays
//! within its budget plus the control headroom.
#![no_main]

use core::time::Duration;

use libfuzzer_sys::fuzz_target;
use ws_net::{CloseCode, Connection, Keepalive, Limits, Millis, PreparedMessage, State, WsError};

fn rank(s: State) -> u8 {
    match s {
        State::Open => 0,
        State::Closing => 1,
        _ => 2,
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&first, mut rest)) = data.split_first() else { return };
    let limits = Limits::new()
        .with_max_output(u64::from(first) * 16)
        .with_send_frame(130);
    let keepalive = Keepalive::new()
        .with_ping_interval(Duration::from_millis(50))
        .with_idle_timeout(Duration::from_millis(400))
        .with_message_timeout(Duration::from_millis(200));
    let mut conn = if first & 1 == 0 {
        Connection::server()
    } else {
        Connection::client_with_seed([first; 32])
    }
    .with_limits(limits)
    .with_keepalive(keepalive);
    let prepared = PreparedMessage::text("prepared");
    let mut now = 0u64;
    let mut last = conn.state();
    while let Some((&op, tail)) = rest.split_first() {
        rest = tail;
        let n = usize::from(rest.first().copied().unwrap_or(0)) % 41;
        let arg = &rest[..n.min(rest.len())];
        let before_out = conn.output().to_vec();
        let before_state = conn.state();
        let result: Result<(), WsError> = match op % 14 {
            0 => conn.send_text(&String::from_utf8_lossy(arg)),
            1 => conn.send_binary(arg),
            2 => conn.send_text_fragment("frag", op & 0x80 != 0),
            3 => conn.send_binary_fragment(arg, op & 0x80 != 0),
            4 => conn.send_ping(arg),
            5 => conn.send_pong(arg),
            6 => conn.close(CloseCode::new(u16::from(op) * 37 + 990), "bye"),
            7 => conn.send_prepared(&prepared),
            8 => {
                let _ = conn.feed(arg);
                conn.poll().map(|_| ())
            }
            9 => {
                now += u64::from(op);
                conn.on_time(Millis(now)).map(|_| ())
            }
            10 => {
                conn.advance_output(n);
                Ok(())
            }
            11 => {
                conn.release_memory();
                Ok(())
            }
            12 => {
                let mut v = Vec::new();
                let _ = conn.detach_message(&mut v);
                Ok(())
            }
            _ => {
                if op & 0x40 != 0 {
                    conn.wipe();
                }
                Ok(())
            }
        };
        if let Err(e) = result {
            if e.close_code().is_none() {
                assert_eq!(conn.output(), &before_out[..], "a refused call changes no output");
                assert_eq!(conn.state(), before_state, "a refused call changes no state");
            }
        }
        let state = conn.state();
        assert!(rank(state) >= rank(last), "{last:?} -> {state:?}");
        last = state;
        assert!(conn.buffered_output() as u64 <= limits.max_output() + 256);
        rest = &rest[n.min(rest.len())..];
    }
});
