//! # ws_net
//!
//! A WebSocket (RFC 6455) protocol engine that does no I/O itself: the
//! opening handshake, frame parsing and serialization, masking,
//! fragmentation and reassembly, ping/pong, and the closing handshake, with
//! every size bounded and every protocol rule enforced. The caller owns the
//! socket; the engine turns bytes into messages and messages into bytes.
//!
//! The opening handshake works standalone over the raw request bytes, or
//! behind an HTTP layer from the request's method, target, and header
//! fields (the shape `http-net` yields). After the `101` response, the
//! connection's remaining bytes go to a [`Connection`].
//!
//! ## Tier 1: accept and echo
//!
//! ```
//! use ws_net::Event;
//!
//! // The upgrade request as it came off the socket, with the first frame
//! // right behind it: a masked "Hello" (RFC 6455 sections 1.2 and 5.7).
//! let mut wire = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\n\
//!     Upgrade: websocket\r\nConnection: Upgrade\r\nOrigin: https://server.example.com\r\n\
//!     Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n".to_vec();
//! wire.extend_from_slice(&[0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58]);
//!
//! // 1. The handshake: validate, apply the same-origin policy, answer 101.
//! let mut accepted = ws_net::accept(&wire)?.expect("complete head");
//! assert!(accepted.response.ends_with(b"sec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"));
//!
//! // 2. Messages: the bytes after the head were fed already; poll, reply.
//! let conn = &mut accepted.connection;
//! let text = match conn.poll()? {
//!     Event::Text(text) => text.to_string(),
//!     other => panic!("{other:?}"),
//! };
//! assert_eq!(text, "Hello");
//! conn.send_text(&text)?;
//! assert_eq!(conn.output(), [0x81, 0x05, b'H', b'e', b'l', b'l', b'o']);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## The handshake
//!
//! [`accept`] is the one-call server path; an [`Acceptor`] is its
//! resumable form for a head read in pieces (each byte scanned once), and
//! takes an [`AcceptPolicy`]: which pages may connect ([`OriginPolicy`],
//! the defense against cross-site WebSocket hijacking), which subprotocol
//! is spoken, and the connection's [`Limits`]. Underneath,
//! [`ServerHandshake::from_head`] (raw bytes) or
//! [`ServerHandshake::from_request`] (behind an HTTP layer) validates an
//! upgrade request and exposes its target, `Host`, and `Origin` for the
//! server's policy; [`ServerHandshake::write_response`] writes the `101`,
//! and [`HandshakeError::write_response`] the refusal.
//! [`ClientHandshake`] writes the request and verifies the response
//! ([`verify_head`](ClientHandshake::verify_head) or
//! [`verify`](ClientHandshake::verify)).
//!
//! ## The connection
//!
//! [`Connection`] enforces the masking direction, reserved bits and
//! opcodes, control-frame rules, minimal length encoding, fragmentation
//! order, incremental UTF-8 validation of text, close codes, and the
//! [`Limits`] on frames and messages. A violation fails the connection with
//! the right close code ([`WsError::close_code`]). Pings are answered and
//! Close frames echoed automatically. Calls the protocol does not allow
//! (sending after a Close, an oversized Ping) are refused without touching
//! the connection.
//!
//! What the peer sends cannot grow the connection's memory past its
//! budgets: the input buffer holds at most 64 KiB, a reassembled message at
//! most [`Limits::max_message`], and reassembly reserves at most 1 MiB
//! ahead of the bytes that have arrived. An automatic Pong still waiting at
//! the end of the output is replaced by the next one, so a peer that pings
//! without reading cannot grow the output either. What the caller sends is
//! the caller's to pace.
//!
//! ## Frames
//!
//! The [`frame`] module exposes the frame header codec and
//! [`frame::apply_mask`] for callers that build or inspect raw frames.
//!
//! ## Feature flags
//!
//! | Feature | Default | Description |
//! |---|---|---|
//! | `std` | yes | Masking-key seeds and handshake nonces from the OS cryptographic random source through `mod-rand` ([`Connection::client`], `try_client`, `ClientHandshake::new`, `try_new`). Without it the crate is `no_std` + `alloc`, and clients take a seed ([`Connection::client_with_seed`], [`ClientHandshake::with_nonce`]) that must come from a cryptographic source. |

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![deny(
    warnings,
    missing_docs,
    unsafe_op_in_unsafe_fn,
    unused_must_use,
    unused_results,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unreachable,
    clippy::dbg_macro,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::undocumented_unsafe_blocks
)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

extern crate alloc;

mod base64;
mod close;
mod conn;
mod error;
pub mod frame;
mod handshake;
mod head;
mod keys;
mod policy;
mod sha1;

pub use close::{CloseCode, CloseFrame};
pub use conn::{Connection, Event, Limits, Role, State};
pub use error::{HandshakeError, WsError};
pub use handshake::{
    AcceptKey, ClientHandshake, HeadReader, ServerHandshake, Verified, accept_key,
};
pub use policy::{AcceptPolicy, Accepted, Acceptor, Decision, OriginPolicy, accept};

/// The crate version, as in `Cargo.toml`.
///
/// # Examples
///
/// ```
/// assert!(ws_net::VERSION.starts_with("0."));
/// ```
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// The README's and the API reference's examples run as doctests, so their
// claims stay true.
#[cfg(all(doctest, feature = "std"))]
#[doc = include_str!("../README.md")]
#[doc = include_str!("../docs/API.md")]
struct DocsDoctests;

#[cfg(test)]
mod tests {
    #[test]
    fn test_public_types_send_and_sync_compile() {
        fn assert<T: Send + Sync>() {}
        assert::<crate::Connection>();
        assert::<crate::ServerHandshake>();
        assert::<crate::ClientHandshake>();
        assert::<crate::WsError>();
        assert::<crate::HandshakeError>();
        assert::<crate::Limits>();
        assert::<crate::HeadReader>();
        assert::<crate::AcceptPolicy>();
        assert::<crate::OriginPolicy>();
        assert::<crate::Acceptor>();
        assert::<crate::Accepted>();
    }

    #[test]
    fn test_connection_inline_size_at_most_512_bytes() {
        // Many idle connections: the inline part is what an idle one costs
        // once its buffers are released.
        let size = core::mem::size_of::<crate::Connection>();
        assert!(size <= 512, "size_of::<Connection>() = {size}");
    }
}
