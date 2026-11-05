//! Differential: the same client bytes into a ws-net server and a
//! tungstenite server with the same budgets. The messages and control
//! frames each delivers before stopping must agree: one sequence is a
//! prefix of the other (they may stop at different points, since ws-net
//! fails UTF-8 at the first bad byte and refuses non-minimal length
//! encodings, which tungstenite accepts, by policy, dev/PLAN.md D-012).
#![no_main]

use std::io::{self, Read, Write};

use libfuzzer_sys::fuzz_target;
use tungstenite::{
    Message,
    protocol::{Role, WebSocket, WebSocketConfig},
};
use ws_net::{Connection, Event, Limits};

#[derive(Debug, PartialEq)]
enum Seen {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
}

struct Memory<'a> {
    input: &'a [u8],
}

impl Read for Memory<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.input.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let n = buf.len().min(self.input.len());
        buf[..n].copy_from_slice(&self.input[..n]);
        self.input = &self.input[n..];
        Ok(n)
    }
}

impl Write for Memory<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn ws_net(data: &[u8]) -> Vec<Seen> {
    let limits = Limits::new()
        .with_max_frame(16 << 20)
        .with_max_message(64 << 20)
        .with_max_output(u64::MAX);
    let mut conn = Connection::server().with_limits(limits);
    let mut seen = Vec::new();
    let mut rest = data;
    loop {
        let n = conn.feed(rest);
        rest = &rest[n..];
        loop {
            match conn.poll() {
                Ok(Event::Text(t)) => seen.push(Seen::Text(t.to_string())),
                Ok(Event::Binary(b)) => seen.push(Seen::Binary(b.to_vec())),
                Ok(Event::Ping(p)) => seen.push(Seen::Ping(p.to_vec())),
                Ok(Event::Pong(p)) => seen.push(Seen::Pong(p.to_vec())),
                Ok(Event::NeedInput) => break,
                _ => return seen,
            }
        }
        if rest.is_empty() || n == 0 {
            return seen;
        }
    }
}

fn tungstenite(data: &[u8]) -> Vec<Seen> {
    let config = WebSocketConfig::default()
        .max_frame_size(Some(16 << 20))
        .max_message_size(Some(64 << 20));
    let mut ws = WebSocket::from_raw_socket(Memory { input: data }, Role::Server, Some(config));
    let mut seen = Vec::new();
    loop {
        match ws.read() {
            Ok(Message::Text(t)) => seen.push(Seen::Text(t.as_str().to_string())),
            Ok(Message::Binary(b)) => seen.push(Seen::Binary(b.to_vec())),
            Ok(Message::Ping(p)) => seen.push(Seen::Ping(p.to_vec())),
            Ok(Message::Pong(p)) => seen.push(Seen::Pong(p.to_vec())),
            Ok(_) => {}
            Err(_) => return seen,
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let a = ws_net(data);
    let b = tungstenite(data);
    let common = a.len().min(b.len());
    assert_eq!(a[..common], b[..common], "ws-net {a:?} tungstenite {b:?}");
});
