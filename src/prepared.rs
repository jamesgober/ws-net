//! [`PreparedMessage`]: a server message encoded once and sent to many
//! connections, one copy each.

use alloc::vec::Vec;

use crate::{
    frame::{FrameHeader, Opcode},
    limits::Limits,
};

/// Per-message send options: whether a message may be compressed. The
/// default follows the connection: compress when permessage-deflate was
/// negotiated (feature `deflate`), the message is at least the configured
/// minimum size, and compressing makes it smaller. `uncompressed()` never
/// compresses, for messages that mix attacker-influenced data with secrets
/// (CRIME and BREACH style attacks, RFC 7692 section 8). Without a
/// negotiated compression every option sends the message as it is.
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
    /// size, and send it compressed even when that is not smaller.
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

    /// Whether these options ask for compression whatever the size.
    #[cfg_attr(not(feature = "deflate"), allow(dead_code))]
    pub(crate) const fn forces_compression(&self) -> bool {
        matches!(self.compress, Some(true))
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
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PreparedMessage {
    frames: Vec<u8>,
    payload_len: usize,
    /// The frames compressed without context, and the window bits used.
    #[cfg(feature = "deflate")]
    deflated: Option<(Vec<u8>, u8)>,
}

/// Lengths only: a broadcast may carry what its recipients must not see in
/// a log.
impl core::fmt::Debug for PreparedMessage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut d = f.debug_struct("PreparedMessage");
        let _ = d
            .field("len", &self.frames.len())
            .field("payload_len", &self.payload_len);
        #[cfg(feature = "deflate")]
        let _ = d.field(
            "deflated_len",
            &self.deflated.as_ref().map(|(f, _)| f.len()),
        );
        d.finish()
    }
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
        // budget: caller: the caller's message
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
            #[cfg(feature = "deflate")]
            deflated: None,
        }
    }

    /// Adds a form compressed without context (permessage-deflate, feature
    /// `deflate`), at `config`'s server window bits and level, split into
    /// frames as the plain form is. [`Connection::send_prepared`](crate::Connection::send_prepared)
    /// sends it to a connection that negotiated permessage-deflate with
    /// `server_no_context_takeover` and a server window at least as large;
    /// every other connection gets the plain form. Kept only when it is
    /// smaller. The compression runs once, for all recipients.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{DeflateConfig, PreparedMessage};
    ///
    /// let update = PreparedMessage::text(&"tick ".repeat(100)).with_deflate(&DeflateConfig::new());
    /// assert!(update.compressed_len().is_some_and(|n| n < update.len()));
    /// ```
    #[cfg(feature = "deflate")]
    #[cfg_attr(docsrs, doc(cfg(feature = "deflate")))]
    #[must_use]
    pub fn with_deflate(mut self, config: &crate::DeflateConfig) -> Self {
        use compress_lib::{
            Level,
            message::{Compressor, MessageConfig},
        };
        let bits = config.server_max_window_bits();
        let level = Level::new(config.level()).unwrap_or(Level::FAST);
        let message = MessageConfig::new()
            .with_window_bits(bits)
            .with_level(level);
        let Ok(mut tx) = Compressor::new(message) else {
            return self;
        };
        let (opcode, payload, max) = self.payload();
        let mut packed = Vec::new();
        if tx.compress_message(&payload, &mut packed).is_err() {
            return self;
        }
        let count = packed.len().div_ceil(max).max(1);
        // budget: caller: the caller's message, compressed
        let mut frames = Vec::with_capacity(packed.len() + count * 10);
        let mut pieces = packed.chunks(max);
        for i in 0..count {
            let piece = pieces.next().unwrap_or(&[]);
            let (op, rsv) = if i == 0 {
                (opcode, 0b100)
            } else {
                (Opcode::Continuation, 0)
            };
            let header = FrameHeader::new(op, i + 1 == count, piece.len() as u64).with_rsv(rsv);
            let _ = header.encode(&mut frames);
            frames.extend_from_slice(piece);
        }
        if frames.len() < self.frames.len() {
            self.deflated = Some((frames, bits));
        }
        self
    }

    /// The length of the compressed form, when there is one.
    ///
    /// # Examples
    ///
    /// See [`with_deflate`](Self::with_deflate).
    #[cfg(feature = "deflate")]
    #[cfg_attr(docsrs, doc(cfg(feature = "deflate")))]
    #[must_use]
    pub fn compressed_len(&self) -> Option<usize> {
        self.deflated.as_ref().map(|(f, _)| f.len())
    }

    /// The opcode, the payload, and the frame size of the plain form.
    #[cfg(feature = "deflate")]
    fn payload(&self) -> (Opcode, Vec<u8>, usize) {
        // budget: caller: a copy of the caller's message
        let mut payload = Vec::with_capacity(self.payload_len);
        let mut opcode = Opcode::Binary;
        let mut max = usize::MAX;
        let mut rest = self.frames.as_slice();
        let mut first = true;
        while let Ok(Some((h, n))) = FrameHeader::decode(rest) {
            let len = usize::try_from(h.payload_len).unwrap_or(usize::MAX);
            let body = rest.get(n..n.saturating_add(len)).unwrap_or(&[]);
            if first {
                opcode = h.opcode;
                if !h.fin {
                    max = len.max(1);
                }
                first = false;
            }
            payload.extend_from_slice(body);
            rest = rest.get(n.saturating_add(len)..).unwrap_or(&[]);
            if h.fin {
                break;
            }
        }
        (opcode, payload, max)
    }

    /// The frames to send to a connection that accepts a compressed form
    /// made with up to `bits` window bits (`None`: plain only).
    #[cfg_attr(not(feature = "deflate"), allow(clippy::unused_self))]
    pub(crate) fn frames_for(&self, bits: Option<u8>) -> &[u8] {
        #[cfg(feature = "deflate")]
        if let (Some(max), Some((frames, used))) = (bits, &self.deflated) {
            if *used <= max {
                return frames;
            }
        }
        #[cfg(not(feature = "deflate"))]
        let _ = bits;
        &self.frames
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
