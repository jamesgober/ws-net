//! The frame layer (RFC 6455 section 5.2): header decoding and encoding and
//! payload masking. [`Connection`](crate::Connection) is built on it; use it
//! directly only to build or inspect raw frames.

use alloc::vec::Vec;

use crate::error::WsError;

/// A frame opcode.
///
/// # Examples
///
/// ```
/// use ws_net::frame::Opcode;
///
/// assert_eq!(Opcode::from_u8(0x1), Some(Opcode::Text));
/// assert_eq!(Opcode::from_u8(0x3), None); // reserved
/// assert!(Opcode::Ping.is_control());
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Opcode {
    /// 0x0: a later fragment of a fragmented message.
    Continuation,
    /// 0x1: the first (or only) frame of a UTF-8 text message.
    Text,
    /// 0x2: the first (or only) frame of a binary message.
    Binary,
    /// 0x8: begins or answers the closing handshake.
    Close,
    /// 0x9: asks the peer for a Pong.
    Ping,
    /// 0xA: answers a Ping (or is sent unsolicited as a heartbeat).
    Pong,
}

impl Opcode {
    /// The opcode for a 4-bit value, or `None` for reserved values.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(ws_net::frame::Opcode::from_u8(0xA), Some(ws_net::frame::Opcode::Pong));
    /// ```
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0x0 => Self::Continuation,
            0x1 => Self::Text,
            0x2 => Self::Binary,
            0x8 => Self::Close,
            0x9 => Self::Ping,
            0xA => Self::Pong,
            _ => return None,
        })
    }

    /// The 4-bit wire value.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(ws_net::frame::Opcode::Close.as_u8(), 0x8);
    /// ```
    #[must_use]
    pub const fn as_u8(&self) -> u8 {
        match self {
            Self::Continuation => 0x0,
            Self::Text => 0x1,
            Self::Binary => 0x2,
            Self::Close => 0x8,
            Self::Ping => 0x9,
            Self::Pong => 0xA,
        }
    }

    /// Whether this is a control opcode (close, ping, pong).
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(!ws_net::frame::Opcode::Binary.is_control());
    /// ```
    #[must_use]
    pub const fn is_control(&self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }
}

/// A frame header.
///
/// [`decode`](FrameHeader::decode) enforces every rule that holds whatever
/// the endpoint's role: reserved opcodes, control frames that are
/// fragmented or longer than 125 bytes, and payload lengths that are not
/// minimally encoded or exceed 2^63 - 1. Rules that depend on the role or
/// the negotiation (masking direction, RSV bits) are enforced by
/// [`Connection`](crate::Connection).
///
/// # Examples
///
/// ```
/// use ws_net::frame::{FrameHeader, Opcode};
///
/// let header = FrameHeader::new(Opcode::Text, true, 5).with_mask([1, 2, 3, 4]);
/// let mut wire = Vec::new();
/// header.encode(&mut wire).unwrap();
/// assert_eq!(wire, [0x81, 0x85, 1, 2, 3, 4]);
///
/// let (decoded, len) = FrameHeader::decode(&wire).unwrap().unwrap();
/// assert_eq!(decoded, header);
/// assert_eq!(len, 6);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FrameHeader {
    /// Whether this is the final frame of its message.
    pub fin: bool,
    /// The RSV1, RSV2, RSV3 bits (in the low three bits).
    pub rsv: u8,
    /// The opcode.
    pub opcode: Opcode,
    /// The masking key, present on every frame a client sends.
    pub mask: Option<[u8; 4]>,
    /// The payload length.
    pub payload_len: u64,
}

/// The largest payload length the protocol can express (the 64-bit length
/// field's most significant bit must be zero).
const MAX_PAYLOAD: u64 = i64::MAX as u64;

impl FrameHeader {
    /// A header with no RSV bits and no mask.
    ///
    /// # Examples
    ///
    /// ```
    /// let h = ws_net::frame::FrameHeader::new(ws_net::frame::Opcode::Ping, true, 0);
    /// assert_eq!(h.encoded_len(), 2);
    /// ```
    #[must_use]
    pub const fn new(opcode: Opcode, fin: bool, payload_len: u64) -> Self {
        Self {
            fin,
            rsv: 0,
            opcode,
            mask: None,
            payload_len,
        }
    }

    /// Sets the masking key.
    ///
    /// # Examples
    ///
    /// ```
    /// let h = ws_net::frame::FrameHeader::new(ws_net::frame::Opcode::Text, true, 0).with_mask([9; 4]);
    /// assert_eq!(h.mask, Some([9; 4]));
    /// ```
    #[must_use]
    pub const fn with_mask(mut self, key: [u8; 4]) -> Self {
        self.mask = Some(key);
        self
    }

    /// Decodes a header from the start of `bytes`: `Ok(None)` if more bytes
    /// are needed, otherwise the header and its length in bytes (2 to 14).
    ///
    /// # Errors
    ///
    /// [`WsError::ReservedOpcode`], [`WsError::FragmentedControl`],
    /// [`WsError::ControlTooLong`], [`WsError::InvalidLength`].
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{frame::FrameHeader, WsError};
    ///
    /// assert_eq!(FrameHeader::decode(&[0x81]), Ok(None));
    /// // A 2-byte length used for a 5-byte payload.
    /// assert_eq!(FrameHeader::decode(&[0x82, 126, 0, 5]), Err(WsError::InvalidLength));
    /// ```
    pub fn decode(bytes: &[u8]) -> Result<Option<(Self, usize)>, WsError> {
        let [b0, b1, ..] = *bytes else {
            return Ok(None);
        };
        let opcode = Opcode::from_u8(b0 & 0x0f).ok_or(WsError::ReservedOpcode)?;
        let fin = b0 & 0x80 != 0;
        let masked = b1 & 0x80 != 0;
        let len7 = b1 & 0x7f;
        if opcode.is_control() {
            if !fin {
                return Err(WsError::FragmentedControl);
            }
            if len7 > 125 {
                return Err(WsError::ControlTooLong);
            }
        }
        let ext = match len7 {
            126 => 2,
            127 => 8,
            _ => 0,
        };
        let total = 2 + ext + if masked { 4 } else { 0 };
        let Some(header) = bytes.get(..total) else {
            return Ok(None);
        };
        let payload_len = match len7 {
            126 => {
                let n = u64::from(u16::from_be_bytes([header[2], header[3]]));
                if n < 126 {
                    return Err(WsError::InvalidLength);
                }
                n
            }
            127 => {
                let mut be = [0u8; 8];
                be.copy_from_slice(&header[2..10]);
                let n = u64::from_be_bytes(be);
                if n <= u64::from(u16::MAX) || n > MAX_PAYLOAD {
                    return Err(WsError::InvalidLength);
                }
                n
            }
            n => u64::from(n),
        };
        let mask = masked.then(|| {
            let k = &header[2 + ext..total];
            [k[0], k[1], k[2], k[3]]
        });
        Ok(Some((
            Self {
                fin,
                rsv: (b0 >> 4) & 0x07,
                opcode,
                mask,
                payload_len,
            },
            total,
        )))
    }

    /// The encoded header length in bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::frame::{FrameHeader, Opcode};
    /// assert_eq!(FrameHeader::new(Opcode::Binary, true, 126).encoded_len(), 4);
    /// assert_eq!(FrameHeader::new(Opcode::Binary, true, 65_536).encoded_len(), 10);
    /// ```
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        let ext = if self.payload_len < 126 {
            0
        } else if self.payload_len <= u16::MAX as u64 {
            2
        } else {
            8
        };
        2 + ext + if self.mask.is_some() { 4 } else { 0 }
    }

    /// Appends the header to `out`, with the payload length in its shortest
    /// encoding.
    ///
    /// # Errors
    ///
    /// The same rules [`decode`](Self::decode) enforces, so every encoded
    /// header decodes: [`WsError::FragmentedControl`] and
    /// [`WsError::ControlTooLong`] for control frames,
    /// [`WsError::InvalidLength`] above 2^63 - 1, and
    /// [`WsError::ReservedBits`] when `rsv` uses more than three bits.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{frame::{FrameHeader, Opcode}, WsError};
    ///
    /// let mut out = Vec::new();
    /// FrameHeader::new(Opcode::Binary, false, 300).encode(&mut out).unwrap();
    /// assert_eq!(out, [0x02, 126, 0x01, 0x2c]);
    /// assert_eq!(FrameHeader::new(Opcode::Ping, true, 126).encode(&mut out), Err(WsError::ControlTooLong));
    /// ```
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), WsError> {
        if self.rsv > 0x07 {
            return Err(WsError::ReservedBits);
        }
        if self.opcode.is_control() {
            if !self.fin {
                return Err(WsError::FragmentedControl);
            }
            if self.payload_len > 125 {
                return Err(WsError::ControlTooLong);
            }
        }
        if self.payload_len > MAX_PAYLOAD {
            return Err(WsError::InvalidLength);
        }
        let b0 = (u8::from(self.fin) << 7) | (self.rsv << 4) | self.opcode.as_u8();
        let mask_bit = if self.mask.is_some() { 0x80 } else { 0 };
        if self.payload_len < 126 {
            out.extend_from_slice(&[b0, mask_bit | self.payload_len as u8]);
        } else if let Ok(n) = u16::try_from(self.payload_len) {
            out.extend_from_slice(&[b0, mask_bit | 126]);
            out.extend_from_slice(&n.to_be_bytes());
        } else {
            out.extend_from_slice(&[b0, mask_bit | 127]);
            out.extend_from_slice(&self.payload_len.to_be_bytes());
        }
        if let Some(key) = self.mask {
            out.extend_from_slice(&key);
        }
        Ok(())
    }
}

/// XORs `data` with the masking `key` (RFC 6455 section 5.3), as if `data`
/// began `offset` bytes into the payload. Masking and unmasking are the same
/// operation, and a payload may be processed in pieces by passing each
/// piece's offset. Any `offset` is accepted; only its value modulo 4
/// matters.
///
/// # Examples
///
/// ```
/// use ws_net::frame::apply_mask;
///
/// let key = [0x37, 0xfa, 0x21, 0x3d];
/// let mut data = *b"Hello";
/// apply_mask(&mut data, key, 0);
/// assert_eq!(data, [0x7f, 0x9f, 0x4d, 0x51, 0x58]); // RFC 6455 section 5.7
/// apply_mask(&mut data[..2], key, 0);
/// apply_mask(&mut data[2..], key, 2);
/// assert_eq!(&data, b"Hello");
/// ```
#[inline]
pub fn apply_mask(data: &mut [u8], key: [u8; 4], offset: usize) {
    // Only the offset's position within the 4-byte key matters; reducing it
    // first keeps any offset (a 64-bit stream position) overflow-free.
    let phase = offset % 4;
    let mut rotated = [0u8; 8];
    for (i, b) in rotated.iter_mut().enumerate() {
        *b = key[(phase + i) % 4];
    }
    // Eight bytes at a time; the rotated key repeats every four bytes, so
    // after whole words the remainder starts at key position 0 again.
    let word = u64::from_ne_bytes(rotated);
    let mut chunks = data.chunks_exact_mut(8);
    for chunk in &mut chunks {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(chunk);
        chunk.copy_from_slice(&(u64::from_ne_bytes(bytes) ^ word).to_ne_bytes());
    }
    for (i, b) in chunks.into_remainder().iter_mut().enumerate() {
        *b ^= rotated[i % 4];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc6455_section_5_7_examples() {
        // Unmasked "Hello".
        let (h, n) = FrameHeader::decode(&[0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f])
            .unwrap()
            .unwrap();
        assert_eq!(
            (h.fin, h.opcode, h.payload_len, h.mask, n),
            (true, Opcode::Text, 5, None, 2)
        );
        // Fragmented unmasked "Hel" + "lo".
        let (h, _) = FrameHeader::decode(&[0x01, 0x03]).unwrap().unwrap();
        assert_eq!((h.fin, h.opcode), (false, Opcode::Text));
        let (h, _) = FrameHeader::decode(&[0x80, 0x02]).unwrap().unwrap();
        assert_eq!((h.fin, h.opcode), (true, Opcode::Continuation));
        // 256-byte and 64 KiB binary messages.
        let (h, n) = FrameHeader::decode(&[0x82, 0x7E, 0x01, 0x00])
            .unwrap()
            .unwrap();
        assert_eq!((h.payload_len, n), (256, 4));
        let (h, n) = FrameHeader::decode(&[0x82, 0x7F, 0, 0, 0, 0, 0, 1, 0, 0])
            .unwrap()
            .unwrap();
        assert_eq!((h.payload_len, n), (65_536, 10));
    }

    #[test]
    fn test_decode_rejections() {
        assert_eq!(
            FrameHeader::decode(&[0x83, 0x00]),
            Err(WsError::ReservedOpcode)
        );
        assert_eq!(
            FrameHeader::decode(&[0x8B, 0x00]),
            Err(WsError::ReservedOpcode)
        );
        assert_eq!(
            FrameHeader::decode(&[0x09, 0x00]),
            Err(WsError::FragmentedControl)
        );
        assert_eq!(
            FrameHeader::decode(&[0x89, 0x7E]),
            Err(WsError::ControlTooLong)
        );
        assert_eq!(
            FrameHeader::decode(&[0x82, 0x7F, 0, 0, 0, 0, 0, 0, 0xff, 0xff]),
            Err(WsError::InvalidLength)
        );
        assert_eq!(
            FrameHeader::decode(&[0x82, 0x7F, 0x80, 0, 0, 0, 0, 0, 0, 0]),
            Err(WsError::InvalidLength)
        );
        assert_eq!(FrameHeader::decode(&[0x82, 0x7E, 0x00]), Ok(None));
        assert_eq!(FrameHeader::decode(&[0x82, 0x80, 1, 2, 3]), Ok(None));
        let (h, _) = FrameHeader::decode(&[0xF1, 0x00]).unwrap().unwrap();
        assert_eq!(h.rsv, 0x7);
    }

    #[test]
    fn test_encode_rejections() {
        let mut out = Vec::new();
        let mut h = FrameHeader::new(Opcode::Close, false, 0);
        assert_eq!(h.encode(&mut out), Err(WsError::FragmentedControl));
        h = FrameHeader::new(Opcode::Binary, true, MAX_PAYLOAD + 1);
        assert_eq!(h.encode(&mut out), Err(WsError::InvalidLength));
        h = FrameHeader::new(Opcode::Binary, true, 0);
        h.rsv = 8;
        assert_eq!(h.encode(&mut out), Err(WsError::ReservedBits));
        assert!(out.is_empty());
    }

    #[test]
    fn test_mask_matches_bytewise_reference() {
        let key = [0xde, 0xad, 0xbe, 0xef];
        for len in 0..40 {
            for offset in 0..9 {
                let mut fast: Vec<u8> = (0..len as u8).collect();
                let mut slow = fast.clone();
                apply_mask(&mut fast, key, offset);
                for (i, b) in slow.iter_mut().enumerate() {
                    *b ^= key[(offset + i) % 4];
                }
                assert_eq!(fast, slow, "len {len} offset {offset}");
            }
        }
    }
}
