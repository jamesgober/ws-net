//! Shared inputs for the comparison: wire bytes built once by ws-net's
//! client (masked, as a browser sends them) and an in-memory stream for
//! tungstenite.

use std::io::{self, Read, Write};

use ws_net::Connection;

/// 100,000 masked client messages: half 35-byte JSON text, half 10-byte
/// binary.
pub fn small_messages() -> Vec<u8> {
    let mut client = Connection::client_with_seed([7; 32])
        .with_limits(ws_net::Limits::new().with_max_output(u64::MAX));
    for i in 0..100_000 {
        if i % 2 == 0 {
            client
                .send_text(r#"{"jsonrpc":"2.0","method":"ping"}"#)
                .unwrap_or_default();
        } else {
            client
                .send_binary(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
                .unwrap_or_default();
        }
    }
    client.output().to_vec()
}

/// One masked 1 MiB binary message.
pub fn large_binary() -> Vec<u8> {
    let mut client = Connection::client_with_seed([7; 32]);
    client.send_binary(&vec![0x5a; 1 << 20]).unwrap_or_default();
    client.output().to_vec()
}

/// One masked 1 MiB text message, mostly ASCII with some two-byte
/// characters.
pub fn large_text() -> Vec<u8> {
    let mut client = Connection::client_with_seed([7; 32]);
    client
        .send_text(&"é-ascii-mix ".repeat((1 << 20) / 13))
        .unwrap_or_default();
    client.output().to_vec()
}

/// A browser-sized upgrade request (Chrome's, with a fixed key).
pub const BROWSER_REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\n\
Host: 127.0.0.1:53817\r\n\
Connection: Upgrade\r\n\
Pragma: no-cache\r\n\
Cache-Control: no-cache\r\n\
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36\r\n\
Upgrade: websocket\r\n\
Origin: http://127.0.0.1:53817\r\n\
Sec-WebSocket-Version: 13\r\n\
Accept-Encoding: gzip, deflate, br, zstd\r\n\
Accept-Language: en-US,en;q=0.9\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";

/// Reads from a byte slice, writes into a vector: a socket in memory.
pub struct Memory<'a> {
    pub input: &'a [u8],
    pub output: Vec<u8>,
}

impl Read for Memory<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.input.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let n = buf.len().min(self.input.len()).min(64 * 1024);
        buf[..n].copy_from_slice(&self.input[..n]);
        self.input = &self.input[n..];
        Ok(n)
    }
}

impl Write for Memory<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.output.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
