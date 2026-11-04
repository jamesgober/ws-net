//! [`PreparedMessage`]: a server message encoded once and sent to many
//! connections, one copy each.

use alloc::vec::Vec;

use crate::{
    frame::{FrameHeader, Opcode},
    limits::Limits,
};

/// Per-message send options: whether a message may be compressed. The
/// default follows the connection (compress when permessage-deflate was
/// negotiated and the message is large enough). Compression is not
/// available in this version, so every option sends the message
/// uncompressed; `uncompressed()` keeps that guarantee once it is, for
/// messages that mix attacker-influenced data with secrets (CRIME and
/// BREACH style attacks, RFC 7692 section 8).
///
/// # Examples
///
/// ```
/// use ws_net::SendOptions;
///
/// assert_eq!(SendOptions::new(), SendOptions::default());
/// assert!(SendOptions::uncompressed().is_uncompressed());
/// assert!(!SendOptions::compressed().is_uncompressed());
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SendOptions {
    compress: Option<bool>,
}

impl SendOptions {
    /// Follow the connection.
    ///
    /// # Examples
    ///
    /// See [`SendOptions`].
    #[must_use]
    pub const fn new() -> Self {
        Self { compress: None }
    }

    /// Never compress this message.
    ///
    /// # Examples
    ///
    /// See [`SendOptions`].
    #[must_use]
    pub const fn uncompressed() -> Self {
        Self {
            compress: Some(false),
        }
    }

    /// Compress this message when compression was negotiated, whatever its
    /// size.
    ///
    /// # Examples
    ///
    /// See [`SendOptions`].
    #[must_use]
    pub const fn compressed() -> Self {
        Self {
            compress: Some(true),
        }
    }

    /// Whether these options forbid compression.
    ///
    /// # Examples
    ///
    /// See [`SendOptions`].
    #[must_use]
    pub const fn is_uncompressed(&self) -> bool {
        matches!(self.compress, Some(false))
    }
}

/// A server message encoded once, as complete unmasked frames, for sending
/// to many connections with
/// [`Connection::send_prepared`](crate::Connection::send_prepared): one
/// copy per recipient and no re-encoding. A client cannot use it, because a
/// client masks each frame with a fresh key.
///
/// # Examples
///
/// ```
/// use ws_net::{Connection, PreparedMessage};
///
/// let update = PreparedMessage::text(r#"{"jsonrpc":"2.0","method":"tick"}"#);
/// let mut subscribers = vec![Connection::server(), Connection::server()];
/// for conn in &mut subscribers {
///     conn.send_prepared(&update)?;
///     assert_eq!(conn.output(), update.as_bytes());
/// }
/// # Ok::<(), ws_net::WsError>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PreparedMessage {
    frames: Vec<u8>,
    payload_len: usize,
}

impl PreparedMessage {
    /// A text message, split into frames at the default send-frame size.
    ///
    /// # Examples
    ///
    /// See [`PreparedMessage`].
    #[must_use]
    pub fn text(text: &str) -> Self {
        Self::encode(Opcode::Text, text.as_bytes(), &Limits::new())
    }

    /// A binary message, split into frames at the default send-frame size.
    ///
    /// # Examples
    ///
    /// ```
    /// let m = ws_net::PreparedMessage::binary(&[1, 2, 3]);
    /// assert_eq!(m.as_bytes(), [0x82, 3, 1, 2, 3]);
    /// assert_eq!((m.len(), m.payload_len()), (5, 3));
    /// ```
    #[must_use]
    pub fn binary(data: &[u8]) -> Self {
        Self::encode(Opcode::Binary, data, &Limits::new())
    }

    /// A text message split into frames of at most `limits.send_frame()`
    /// bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{Limits, PreparedMessage};
    ///
    /// let m = PreparedMessage::text_with(&"x".repeat(300), &Limits::new().with_send_frame(200));
    /// assert_eq!(m.as_bytes()[0], 0x01); // text, not final
    /// ```
    #[must_use]
    pub fn text_with(text: &str, limits: &Limits) -> Self {
        Self::encode(Opcode::Text, text.as_bytes(), limits)
    }

    /// A binary message split into frames of at most `limits.send_frame()`
    /// bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{Limits, PreparedMessage};
    ///
    /// let m = PreparedMessage::binary_with(&[0; 250], &Limits::new().with_send_frame(125));
    /// assert_eq!(m.len(), 2 * (2 + 125));
    /// ```
    #[must_use]
    pub fn binary_with(data: &[u8], limits: &Limits) -> Self {
        Self::encode(Opcode::Binary, data, limits)
    }

    fn encode(opcode: Opcode, data: &[u8], limits: &Limits) -> Self {
        let max = usize::try_from(limits.send_frame())
            .unwrap_or(usize::MAX)
            .max(1);
        let count = data.len().div_ceil(max).max(1);
        let mut frames = Vec::with_capacity(data.len() + count * 10);
        let mut pieces = data.chunks(max);
        for i in 0..count {
            let piece = pieces.next().unwrap_or(&[]);
            let op = if i == 0 { opcode } else { Opcode::Continuation };
            // Data frames of any length up to 2^63 - 1 encode; a slice is
            // never longer.
            let _ = FrameHeader::new(op, i + 1 == count, piece.len() as u64).encode(&mut frames);
            frames.extend_from_slice(piece);
        }
        Self {
            frames,
            payload_len: data.len(),
        }
    }

    /// The encoded frames.
    ///
    /// # Examples
    ///
    /// See [`PreparedMessage`].
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.frames
    }

    /// The encoded length in bytes, headers included.
    ///
    /// # Examples
    ///
    /// See [`binary`](Self::binary).
    #[must_use]
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    /// Whether the encoding is empty (never: an empty message is one
    /// two-byte frame).
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(!ws_net::PreparedMessage::text("").is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// The message payload length.
    ///
    /// # Examples
    ///
    /// See [`binary`](Self::binary).
    #[must_use]
    pub fn payload_len(&self) -> usize {
        self.payload_len
    }
}
