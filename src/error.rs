//! Error types: protocol and usage errors on an open connection
//! ([`WsError`]) and opening-handshake refusals ([`HandshakeError`]).

use core::fmt;

use crate::close::CloseCode;

/// Why a connection failed, or why a call was refused.
///
/// Two kinds, told apart by [`close_code`](WsError::close_code):
///
/// - **Connection failures** (`Some(code)`): the peer broke the protocol, a
///   budget was exceeded, or the transport ended early. The connection fails
///   as RFC 6455 section 7.1.7 requires: it queues a Close frame with that
///   code (except for 1006, which is never sent), stops reading, and reports
///   the error once. Flush the output, then close the socket.
/// - **Refused calls** (`None`): [`InvalidArgument`](WsError::InvalidArgument)
///   and [`InvalidState`](WsError::InvalidState). The call did nothing and
///   the connection is unchanged.
///
/// # Examples
///
/// ```
/// use ws_net::{CloseCode, Connection, WsError};
///
/// let mut conn = Connection::server();
/// // An unmasked frame from a client.
/// let _ = conn.feed(&[0x81, 0x02, b'h', b'i']);
/// let err = conn.poll().unwrap_err();
/// assert_eq!(err, WsError::UnmaskedFrame);
/// assert_eq!(err.close_code(), Some(CloseCode::PROTOCOL_ERROR));
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WsError {
    /// RSV1, RSV2, or RSV3 is set, and no extension that defines them was
    /// negotiated. Close code 1002.
    ReservedBits,
    /// Opcode 0x3 to 0x7 or 0xB to 0xF. Close code 1002.
    ReservedOpcode,
    /// A control frame (close, ping, pong) without FIN. Close code 1002.
    FragmentedControl,
    /// A received control frame with a payload over 125 bytes. Close code
    /// 1002. (The frame codec, [`FrameHeader::encode`](crate::frame::FrameHeader::encode),
    /// also reports it for a header it refuses to write.)
    ControlTooLong,
    /// A payload length not in its shortest encoding, or a 64-bit length
    /// with the most significant bit set. Close code 1002.
    InvalidLength,
    /// A server received an unmasked frame. Close code 1002.
    UnmaskedFrame,
    /// A client received a masked frame. Close code 1002.
    MaskedFrame,
    /// A continuation frame with no fragmented message in progress. Close
    /// code 1002.
    UnexpectedContinuation,
    /// A new text or binary frame while a fragmented message is in progress.
    /// Close code 1002.
    ExpectedContinuation,
    /// A text message (or close reason) that is not valid UTF-8, detected as
    /// soon as the offending byte arrives. Close code 1007.
    InvalidUtf8,
    /// A frame larger than [`Limits::max_frame`](crate::Limits::max_frame),
    /// refused from its header. Close code 1009.
    FrameTooLarge,
    /// A message larger than
    /// [`Limits::max_message`](crate::Limits::max_message), refused before
    /// the frame that would exceed it is read. Close code 1009.
    MessageTooLarge,
    /// A Close frame with a one-byte payload. Close code 1002.
    InvalidClosePayload,
    /// A received Close frame whose status code may not appear on the wire
    /// (1005, 1006, 1015, or an unassigned code). Close code 1002.
    InvalidCloseCode,
    /// The peer closed the transport without a closing handshake. No Close
    /// frame can be sent; the status is 1006 (abnormal closure).
    UnexpectedEof,
    /// A refused call: an argument the protocol does not allow, such as a
    /// Ping payload over 125 bytes, a close code that may not be sent, or a
    /// close reason over 123 bytes. The text names the rule. Nothing was
    /// sent and the connection is unchanged.
    InvalidArgument(&'static str),
    /// A refused call: made in the wrong state, for example sending after a
    /// Close frame was sent. The text names the rule. Nothing was sent and
    /// the connection is unchanged.
    InvalidState(&'static str),
}

impl WsError {
    /// For a connection failure, its status code: the code of the Close
    /// frame queued in the output, or 1006 for
    /// [`UnexpectedEof`](WsError::UnexpectedEof) (nothing can be sent then).
    /// `None` for a refused call, which leaves the connection unchanged.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{CloseCode, WsError};
    ///
    /// assert_eq!(WsError::InvalidUtf8.close_code(), Some(CloseCode::INVALID_PAYLOAD));
    /// assert_eq!(WsError::FrameTooLarge.close_code(), Some(CloseCode::MESSAGE_TOO_BIG));
    /// assert_eq!(WsError::UnexpectedEof.close_code(), Some(CloseCode::ABNORMAL));
    /// assert_eq!(WsError::InvalidArgument("x").close_code(), None);
    /// assert_eq!(WsError::InvalidState("x").close_code(), None);
    /// ```
    #[must_use]
    pub const fn close_code(&self) -> Option<CloseCode> {
        match self {
            Self::ReservedBits
            | Self::ReservedOpcode
            | Self::FragmentedControl
            | Self::ControlTooLong
            | Self::InvalidLength
            | Self::UnmaskedFrame
            | Self::MaskedFrame
            | Self::UnexpectedContinuation
            | Self::ExpectedContinuation
            | Self::InvalidClosePayload
            | Self::InvalidCloseCode => Some(CloseCode::PROTOCOL_ERROR),
            Self::InvalidUtf8 => Some(CloseCode::INVALID_PAYLOAD),
            Self::FrameTooLarge | Self::MessageTooLarge => Some(CloseCode::MESSAGE_TOO_BIG),
            Self::UnexpectedEof => Some(CloseCode::ABNORMAL),
            Self::InvalidArgument(_) | Self::InvalidState(_) => None,
        }
    }
}

impl fmt::Display for WsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::ReservedBits => "reserved bits set without a negotiated extension",
            Self::ReservedOpcode => "reserved opcode",
            Self::FragmentedControl => "fragmented control frame",
            Self::ControlTooLong => "control frame payload over 125 bytes",
            Self::InvalidLength => "payload length not minimally encoded or over 2^63",
            Self::UnmaskedFrame => "unmasked frame from a client",
            Self::MaskedFrame => "masked frame from a server",
            Self::UnexpectedContinuation => "continuation frame without a message in progress",
            Self::ExpectedContinuation => "new data frame inside a fragmented message",
            Self::InvalidUtf8 => "text is not valid UTF-8",
            Self::FrameTooLarge => "frame exceeds the configured limit",
            Self::MessageTooLarge => "message exceeds the configured limit",
            Self::InvalidClosePayload => "close frame payload of one byte",
            Self::InvalidCloseCode => "close status code not allowed on the wire",
            Self::UnexpectedEof => "transport closed without a closing handshake",
            Self::InvalidArgument(rule) => return write!(f, "invalid argument: {rule}"),
            Self::InvalidState(rule) => return write!(f, "invalid call order: {rule}"),
        };
        f.write_str(msg)
    }
}

impl core::error::Error for WsError {}

/// Why an opening handshake was refused.
///
/// On the server, answer with [`write_response`](HandshakeError::write_response)
/// (or, behind an HTTP layer, with [`status`](HandshakeError::status) and,
/// for [`UnsupportedVersion`](HandshakeError::UnsupportedVersion), the
/// `sec-websocket-version: 13` header RFC 6455 section 4.4 requires), then
/// close the connection. On the client, the connection cannot be used.
///
/// # Examples
///
/// ```
/// use ws_net::{HandshakeError, ServerHandshake};
///
/// let headers = [("Host", &b"a"[..]), ("Upgrade", b"websocket"), ("Connection", b"Upgrade"),
///                ("Sec-WebSocket-Version", b"8"), ("Sec-WebSocket-Key", b"dGhlIHNhbXBsZSBub25jZQ==")];
/// let err = ServerHandshake::from_request("GET", "/", headers).unwrap_err();
/// assert_eq!(err, HandshakeError::UnsupportedVersion);
/// assert_eq!(err.status(), 426);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HandshakeError {
    /// The request method is not `GET`.
    NotGet,
    /// The head is not strict HTTP/1.1: a bad request or status line (only
    /// `HTTP/1.1` is accepted), a bare CR or LF, a malformed field line,
    /// or (from [`from_request`](crate::ServerHandshake::from_request)) a
    /// target that is empty or not visible ASCII.
    MalformedHead,
    /// The head did not end within
    /// [`ServerHandshake::MAX_HEAD`](crate::ServerHandshake::MAX_HEAD)
    /// bytes. Answered with 431.
    HeadTooLarge,
    /// No `Host` field, more than one, or one that is not visible ASCII.
    InvalidHost,
    /// More than one `Origin` field, or one that is not visible ASCII.
    InvalidOrigin,
    /// No `Upgrade` field listing `websocket`.
    MissingUpgrade,
    /// No `Connection` field listing `upgrade`.
    MissingConnectionUpgrade,
    /// No `Sec-WebSocket-Key` field, or more than one.
    MissingKey,
    /// `Sec-WebSocket-Key` is not the base64 encoding of 16 bytes.
    InvalidKey,
    /// `Sec-WebSocket-Version` is missing, repeated, or not `13`.
    UnsupportedVersion,
    /// A `Sec-WebSocket-Protocol` entry is not a token, or the protocol the
    /// server chose was not offered.
    InvalidProtocol,
    /// The client side: the response status is not 101.
    NotSwitching(u16),
    /// The client side: `Sec-WebSocket-Accept` is missing or does not match
    /// the key that was sent.
    AcceptMismatch,
    /// The client side: the server accepted an extension that was not
    /// offered (this crate offers none).
    UnexpectedExtension,
    /// A host, path, or origin passed to
    /// [`ClientHandshake`](crate::ClientHandshake) is empty or contains
    /// whitespace or control characters, or the path does not start with
    /// `/`.
    InvalidRequest,
}

impl HandshakeError {
    /// The HTTP status a server should answer a refused request with: 426
    /// for an unsupported version, 431 for an oversized head, 400 otherwise
    /// (client-side errors also report 400; they are not answered).
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(ws_net::HandshakeError::InvalidKey.status(), 400);
    /// assert_eq!(ws_net::HandshakeError::UnsupportedVersion.status(), 426);
    /// ```
    #[must_use]
    pub const fn status(&self) -> u16 {
        match self {
            Self::UnsupportedVersion => 426,
            Self::HeadTooLarge => 431,
            _ => 400,
        }
    }

    /// Appends the complete HTTP response refusing the request: the
    /// [`status`](Self::status) line, `sec-websocket-version: 13` for an
    /// unsupported version, an empty body, and `connection: close`. Close
    /// the connection after writing it.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut out = Vec::new();
    /// ws_net::HandshakeError::MissingUpgrade.write_response(&mut out);
    /// assert_eq!(out, b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
    /// ```
    pub fn write_response(&self, out: &mut alloc::vec::Vec<u8>) {
        out.extend_from_slice(match self.status() {
            426 => &b"HTTP/1.1 426 Upgrade Required\r\nsec-websocket-version: 13\r\n"[..],
            431 => b"HTTP/1.1 431 Request Header Fields Too Large\r\n",
            _ => b"HTTP/1.1 400 Bad Request\r\n",
        });
        out.extend_from_slice(b"content-length: 0\r\nconnection: close\r\n\r\n");
    }
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotGet => f.write_str("the opening handshake must be a GET request"),
            Self::MalformedHead => f.write_str("the HTTP head is not well-formed HTTP/1.1"),
            Self::HeadTooLarge => f.write_str("the HTTP head exceeds 16 KiB"),
            Self::InvalidHost => f.write_str("missing, repeated, or invalid Host"),
            Self::InvalidOrigin => f.write_str("repeated or invalid Origin"),
            Self::MissingUpgrade => f.write_str("missing `Upgrade: websocket`"),
            Self::MissingConnectionUpgrade => f.write_str("missing `Connection: upgrade`"),
            Self::MissingKey => f.write_str("missing or repeated Sec-WebSocket-Key"),
            Self::InvalidKey => f.write_str("Sec-WebSocket-Key is not 16 base64-encoded bytes"),
            Self::UnsupportedVersion => f.write_str("Sec-WebSocket-Version must be 13"),
            Self::InvalidProtocol => f.write_str("invalid or unoffered subprotocol"),
            Self::NotSwitching(status) => {
                write!(
                    f,
                    "server answered {status} instead of 101 Switching Protocols"
                )
            }
            Self::AcceptMismatch => f.write_str("Sec-WebSocket-Accept does not match the key"),
            Self::UnexpectedExtension => {
                f.write_str("server accepted an extension that was not offered")
            }
            Self::InvalidRequest => f.write_str(
                "host, path, or origin is empty or contains whitespace or control characters",
            ),
        }
    }
}

impl core::error::Error for HandshakeError {}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn test_close_codes_for_every_protocol_error() {
        assert_eq!(
            WsError::ReservedOpcode.close_code(),
            Some(CloseCode::PROTOCOL_ERROR)
        );
        assert_eq!(
            WsError::MessageTooLarge.close_code(),
            Some(CloseCode::MESSAGE_TOO_BIG)
        );
        assert_eq!(
            WsError::UnexpectedEof.close_code(),
            Some(CloseCode::ABNORMAL)
        );
        assert_eq!(WsError::InvalidArgument("x").close_code(), None);
    }

    #[test]
    fn test_display() {
        assert_eq!(
            WsError::InvalidState("closed").to_string(),
            "invalid call order: closed"
        );
        assert_eq!(
            WsError::InvalidArgument("too long").to_string(),
            "invalid argument: too long"
        );
        assert!(
            HandshakeError::NotSwitching(404)
                .to_string()
                .contains("404")
        );
        assert_eq!(HandshakeError::UnsupportedVersion.status(), 426);
    }
}
