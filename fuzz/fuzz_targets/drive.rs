//! The driver shared by the connection targets (included with `#[path]`).

use ws_net::{Connection, Event, Limits, WsError, frame::FrameHeader};

/// Small, default, or lifted budgets, chosen by the input's first byte.
pub fn limits(select: u8) -> Limits {
    match select % 3 {
        0 => Limits::new()
            .with_max_frame(200)
            .with_max_message(500)
            .with_max_output(300)
            .with_input_buffer(256)
            .with_retain(0),
        1 => Limits::new(),
        _ => Limits::new()
            .with_max_frame(u64::MAX)
            .with_max_message(u64::MAX)
            .with_max_output(u64::MAX),
    }
}

#[derive(Debug, PartialEq)]
pub enum Seen {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close(Option<(u16, String)>),
    Error(WsError),
}

/// Feeds `pieces`, polling between, collecting events and every output
/// byte (drained after each poll, as a socket loop does).
pub fn run(conn: &mut Connection, pieces: &[&[u8]]) -> (Vec<Seen>, Vec<u8>) {
    let mut seen = Vec::new();
    let mut out = Vec::new();
    for piece in pieces {
        let mut rest = *piece;
        loop {
            let n = conn.feed(rest);
            rest = &rest[n..];
            loop {
                let event = match conn.poll() {
                    Ok(Event::Text(t)) => Seen::Text(t.to_string()),
                    Ok(Event::Binary(b)) => Seen::Binary(b.to_vec()),
                    Ok(Event::Ping(p)) => Seen::Ping(p.to_vec()),
                    Ok(Event::Pong(p)) => Seen::Pong(p.to_vec()),
                    Ok(Event::Close(c)) => {
                        Seen::Close(c.map(|f| (f.code.as_u16(), f.reason.to_string())))
                    }
                    Ok(_) => break,
                    Err(e) => Seen::Error(e),
                };
                seen.push(event);
                let pending = conn.output().to_vec();
                conn.advance_output(pending.len());
                out.extend_from_slice(&pending);
            }
            if rest.is_empty() || n == 0 {
                break;
            }
        }
    }
    let pending = conn.output().to_vec();
    conn.advance_output(pending.len());
    out.extend_from_slice(&pending);
    (seen, out)
}

/// The checks shared by both roles.
pub fn check(make: impl Fn() -> Connection, data: &[u8], select: u8) {
    let limits = limits(select);
    let mut whole_conn = make();
    let whole = run(&mut whole_conn, &[data]);
    // In pieces sized by the input itself (1 to 64 bytes).
    let mut pieces = Vec::new();
    let mut rest = data;
    let mut i = 0usize;
    while !rest.is_empty() {
        let size = (usize::from(data[i % data.len()]) % 64 + 1).min(rest.len());
        pieces.push(&rest[..size]);
        rest = &rest[size..];
        i += 1;
    }
    let mut split_conn = make();
    let split = run(&mut split_conn, &pieces);
    assert_eq!(whole, split, "split invariance");
    // The output is whole, valid frames.
    let mut out = &whole.1[..];
    while !out.is_empty() {
        let (h, n) = FrameHeader::decode(out)
            .expect("output decodes")
            .expect("output is whole frames");
        let total = n + usize::try_from(h.payload_len).expect("small");
        assert!(total <= out.len(), "frame within the output");
        out = &out[total..];
    }
    // Memory within the configured bounds (small budgets only).
    if select % 3 == 0 {
        let bound = limits.input_buffer() + 500 + 1024 * 1024 + 2 * (300 + 256) + 64 * 1024;
        assert!(whole_conn.memory_in_use() <= bound, "memory {}", whole_conn.memory_in_use());
    }
}
