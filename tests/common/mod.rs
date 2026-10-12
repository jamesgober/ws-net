//! Shared helpers: frame builders and a driver that runs a connection over
//! input split into pieces, draining its output after every poll the way a
//! real I/O loop does.

#![allow(dead_code)]

use ws_net::{
    Connection, Event, WsError,
    frame::{FrameHeader, Opcode, apply_mask},
};

pub const KEY: [u8; 4] = [0x11, 0x22, 0x33, 0x44];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ev {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close(Option<(u16, String)>),
    Err(WsError),
}

/// A frame from raw parts: `b0` is the first header byte (FIN, RSV,
/// opcode), the payload is masked with `KEY` when `mask` is set, and the
/// length is minimally encoded.
pub fn raw(b0: u8, mask: bool, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![b0];
    let m = if mask { 0x80 } else { 0 };
    let len = payload.len();
    if len < 126 {
        out.push(m | len as u8);
    } else if len <= 0xffff {
        out.push(m | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(m | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    if mask {
        out.extend_from_slice(&KEY);
    }
    let start = out.len();
    out.extend_from_slice(payload);
    if mask {
        apply_mask(&mut out[start..], KEY, 0);
    }
    out
}

/// A masked frame as a client sends it.
pub fn client_frame(opcode: u8, fin: bool, payload: &[u8]) -> Vec<u8> {
    raw(opcode | if fin { 0x80 } else { 0 }, true, payload)
}

/// An unmasked frame as a server sends it.
pub fn server_frame(opcode: u8, fin: bool, payload: &[u8]) -> Vec<u8> {
    raw(opcode | if fin { 0x80 } else { 0 }, false, payload)
}

pub fn close_payload(code: u16, reason: &str) -> Vec<u8> {
    let mut p = code.to_be_bytes().to_vec();
    p.extend_from_slice(reason.as_bytes());
    p
}

/// Decodes a byte stream of frames (unmasking as needed).
pub fn decode_frames(mut bytes: &[u8]) -> Vec<(Opcode, bool, Vec<u8>)> {
    let mut frames = Vec::new();
    while !bytes.is_empty() {
        let (h, n) = FrameHeader::decode(bytes)
            .expect("valid output")
            .expect("complete output");
        let len = h.payload_len as usize;
        let mut payload = bytes[n..n + len].to_vec();
        if let Some(k) = h.mask {
            apply_mask(&mut payload, k, 0);
        }
        frames.push((h.opcode, h.fin, payload));
        bytes = &bytes[n + len..];
    }
    frames
}

/// Feeds `pieces` (then EOF if `eof`), polling and draining output after
/// every poll. Returns the events and the raw output.
pub fn drive(conn: &mut Connection, pieces: &[&[u8]], eof: bool) -> (Vec<Ev>, Vec<u8>) {
    let mut events = Vec::new();
    let mut out = Vec::new();
    let mut next = 0;
    let mut pending: &[u8] = &[];
    let mut eof_fed = false;
    for _ in 0..10_000_000 {
        let result = conn.poll();
        let stop = match result {
            Ok(Event::Text(t)) => {
                events.push(Ev::Text(t.to_string()));
                false
            }
            Ok(Event::Binary(b)) => {
                events.push(Ev::Binary(b.to_vec()));
                false
            }
            Ok(Event::Ping(p)) => {
                events.push(Ev::Ping(p.to_vec()));
                false
            }
            Ok(Event::Pong(p)) => {
                events.push(Ev::Pong(p.to_vec()));
                false
            }
            Ok(Event::Close(frame)) => {
                events.push(Ev::Close(
                    frame.map(|f| (f.code.as_u16(), f.reason.to_string())),
                ));
                false
            }
            Ok(Event::NeedInput) => {
                assert!(!eof_fed, "NeedInput after EOF");
                while pending.is_empty() && next < pieces.len() {
                    pending = pieces[next];
                    next += 1;
                }
                if pending.is_empty() {
                    if eof {
                        conn.feed_eof();
                        eof_fed = true;
                        false
                    } else {
                        true
                    }
                } else {
                    let n = conn.feed(pending);
                    assert!(n > 0, "input buffer full while the parser waits for input");
                    pending = &pending[n..];
                    false
                }
            }
            Ok(Event::Closed) => true,
            Ok(other) => panic!("unknown event {other:?}"),
            Err(e) => {
                events.push(Ev::Err(e));
                false
            }
        };
        let o = conn.output().to_vec();
        conn.advance_output(o.len());
        out.extend_from_slice(&o);
        if stop {
            return (events, out);
        }
    }
    panic!("driver did not terminate");
}

/// Splits `input` at the given cut points (taken modulo the length).
pub fn split<'a>(input: &'a [u8], cuts: &[usize]) -> Vec<&'a [u8]> {
    if input.is_empty() {
        return vec![input];
    }
    let mut points: Vec<usize> = cuts.iter().map(|c| c % input.len()).collect();
    points.sort_unstable();
    points.dedup();
    let mut pieces = Vec::new();
    let mut last = 0;
    for p in points {
        pieces.push(&input[last..p]);
        last = p;
    }
    pieces.push(&input[last..]);
    pieces
}
