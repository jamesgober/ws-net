//! The connection: frame parsing, reassembly, control frames, the closing
//! handshake, and the output queue.

use alloc::vec::Vec;
use core::fmt;

use crate::{
    close::{CloseCode, CloseFrame},
    error::WsError,
    frame::{FrameHeader, Opcode, apply_mask},
    keys::MaskGen,
};

/// Capacity of the input buffer. The parser never waits for more than one
/// control frame (139 bytes) to be buffered, so this only bounds how much
/// input is taken per read.
const INPUT_CAP: usize = 64 * 1024;
/// Smallest input allocation.
const INPUT_MIN: usize = 4096;
/// A reassembly buffer above this capacity is released after delivery, so
/// an idle connection does not hold a large message's memory.
const MSG_RETAIN: usize = 1024 * 1024;
/// Output already written beyond this is compacted away eagerly.
const OUT_COMPACT: usize = 64 * 1024;
/// The most reassembly space reserved ahead of the bytes that have arrived.
/// A header announces a length but proves nothing; with the budgets lifted,
/// reserving what it announces would let 14 bytes request terabytes.
const RESERVE_CAP: u64 = 1024 * 1024;

/// Budgets on incoming frames and messages.
///
/// | Budget | Default |
/// |---|---|
/// | frame payload | 1 MiB |
/// | message (all fragments) | 16 MiB |
///
/// Both are checked from frame headers, before the payload is read: a frame
/// over the frame budget, or one that would take its message over the
/// message budget, fails the connection with close code 1009. The defaults
/// are the budgets of LexerSketch Studio. Outgoing messages larger than the
/// frame budget are split into frames of at most that size, so a peer with
/// the same limits accepts them.
///
/// # Examples
///
/// ```
/// let limits = ws_net::Limits::new().with_max_frame(64 * 1024).with_max_message(1 << 20);
/// assert_eq!(limits.max_frame(), 64 * 1024);
/// assert_eq!(limits.max_message(), 1 << 20);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Limits {
    frame: u64,
    message: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self::new()
    }
}

impl Limits {
    /// The defaults: 1 MiB frames, 16 MiB messages.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(ws_net::Limits::new(), ws_net::Limits::default());
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            frame: 1024 * 1024,
            message: 16 * 1024 * 1024,
        }
    }

    /// Sets the largest accepted frame payload, at least 125 bytes (the
    /// largest control frame).
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(ws_net::Limits::new().with_max_frame(1).max_frame(), 125);
    /// ```
    #[must_use]
    pub const fn with_max_frame(mut self, bytes: u64) -> Self {
        self.frame = if bytes < 125 { 125 } else { bytes };
        self
    }

    /// Sets the largest accepted message, summed over its fragments.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(ws_net::Limits::new().with_max_message(0).max_message(), 0);
    /// ```
    #[must_use]
    pub const fn with_max_message(mut self, bytes: u64) -> Self {
        self.message = bytes;
        self
    }

    /// The frame payload budget.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(ws_net::Limits::new().max_frame(), 1 << 20);
    /// ```
    #[must_use]
    pub const fn max_frame(&self) -> u64 {
        self.frame
    }

    /// The message budget.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(ws_net::Limits::new().max_message(), 16 << 20);
    /// ```
    #[must_use]
    pub const fn max_message(&self) -> u64 {
        self.message
    }
}

/// Which end of the connection this is. Clients mask every frame they send
/// and refuse masked frames; servers do the opposite.
///
/// # Examples
///
/// ```
/// assert_eq!(ws_net::Connection::server().role(), ws_net::Role::Server);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    /// The accepting end.
    Server,
    /// The connecting end.
    Client,
}

/// The closing-handshake state.
///
/// # Examples
///
/// ```
/// use ws_net::{CloseCode, Connection, State};
///
/// let mut conn = Connection::server();
/// assert_eq!(conn.state(), State::Open);
/// conn.close(CloseCode::GOING_AWAY, "restart").unwrap();
/// assert_eq!(conn.state(), State::Closing);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum State {
    /// Messages flow both ways.
    Open,
    /// This end sent a Close frame and waits for the peer's.
    Closing,
    /// Both Close frames are exchanged, or the connection failed. Flush the
    /// output, then close the transport (a server closes first; RFC 6455
    /// section 7.1.1).
    Closed,
}

/// What a [`Connection`] has for the caller after [`poll`](Connection::poll).
///
/// # Examples
///
/// ```
/// use ws_net::{Connection, Event};
///
/// let mut conn = Connection::server();
/// // A masked "hi" text frame from a client.
/// let _ = conn.feed(&[0x81, 0x82, 0, 0, 0, 0, b'h', b'i']);
/// assert!(matches!(conn.poll().unwrap(), Event::Text("hi")));
/// assert!(matches!(conn.poll().unwrap(), Event::NeedInput));
/// ```
#[non_exhaustive]
#[derive(Debug)]
pub enum Event<'a> {
    /// A complete text message, validated as UTF-8.
    Text(&'a str),
    /// A complete binary message.
    Binary(&'a [u8]),
    /// A Ping. The Pong reply is already queued in the output.
    Ping(&'a [u8]),
    /// A Pong.
    Pong(&'a [u8]),
    /// The peer's Close frame (`None` when it carried no status code). If
    /// this end had not sent one, the reply is queued in the output. The
    /// connection is now [`State::Closed`].
    Close(Option<CloseFrame<'a>>),
    /// More input is needed.
    NeedInput,
    /// The connection is finished; nothing more will be read.
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Text,
    Binary,
}

impl Kind {
    const fn opcode(self) -> Opcode {
        match self {
            Self::Text => Opcode::Text,
            Self::Binary => Opcode::Binary,
        }
    }
}

/// A data frame whose payload is being read.
#[derive(Clone, Copy, Debug)]
struct Streaming {
    kind: Kind,
    fin: bool,
    remaining: u64,
    mask: Option<[u8; 4]>,
    /// Position of the next payload byte within the masking key (0 to 3).
    phase: usize,
}

/// Input side: buffer, frame in progress, message reassembly.
struct Reader {
    input: Vec<u8>,
    pos: usize,
    filled: usize,
    eof: bool,
    frame: Option<Streaming>,
    message: Option<Kind>,
    msg: Vec<u8>,
    /// Bytes of `msg` known to be complete, valid UTF-8.
    checked: usize,
    delivered: bool,
    received_close: bool,
}

impl Reader {
    fn spare(&mut self) -> &mut [u8] {
        if self.filled == self.input.len() {
            let len = self.input.len();
            if self.pos > 0 && (self.pos >= len / 2 || len == INPUT_CAP) {
                self.input.copy_within(self.pos..self.filled, 0);
                self.filled -= self.pos;
                self.pos = 0;
            } else if len < INPUT_CAP {
                let grown = len.saturating_mul(2).clamp(INPUT_MIN, INPUT_CAP);
                self.input.resize(grown, 0);
            }
        }
        let filled = self.filled;
        self.input.get_mut(filled..).unwrap_or(&mut [])
    }

    /// Validates the unchecked tail of a text message. With `complete`, a
    /// trailing partial sequence is an error too.
    fn check_utf8(&mut self, complete: bool) -> Result<(), WsError> {
        let tail = self.msg.get(self.checked..).unwrap_or(&[]);
        match core::str::from_utf8(tail) {
            Ok(_) => {
                self.checked = self.msg.len();
                Ok(())
            }
            Err(e) if e.error_len().is_none() && !complete => {
                // A sequence cut at the end of what has arrived so far; it
                // is re-examined when the next bytes arrive.
                self.checked += e.valid_up_to();
                Ok(())
            }
            Err(_) => Err(WsError::InvalidUtf8),
        }
    }
}

/// Output side: the queue, masking, and the close flags.
struct Writer {
    role: Role,
    masks: Option<MaskGen>,
    out: Vec<u8>,
    out_pos: usize,
    pong: Option<([u8; 125], u8)>,
    /// Where the last automatic Pong starts in `out`, while it is the last
    /// frame queued and none of it has been written.
    pong_at: Option<usize>,
    sending: Option<Kind>,
    sent_close: bool,
    failed: bool,
}

impl Writer {
    fn frame(&mut self, opcode: Opcode, fin: bool, payload: &[u8]) -> Result<(), WsError> {
        self.flush_pong();
        // Anything queued behind the Pong pins it in place.
        self.pong_at = None;
        self.raw_frame(opcode, fin, payload)
    }

    fn raw_frame(&mut self, opcode: Opcode, fin: bool, payload: &[u8]) -> Result<(), WsError> {
        let mut header = FrameHeader::new(opcode, fin, payload.len() as u64);
        let key = self.masks.as_mut().map(MaskGen::next_key);
        if let Some(k) = key {
            header = header.with_mask(k);
        }
        header.encode(&mut self.out)?;
        let start = self.out.len();
        self.out.extend_from_slice(payload);
        if let Some(k) = key {
            if let Some(body) = self.out.get_mut(start..) {
                apply_mask(body, k, 0);
            }
        }
        Ok(())
    }

    fn flush_pong(&mut self) {
        if let Some((payload, len)) = self.pong.take() {
            // An earlier automatic Pong that is still last in the queue and
            // unwritten is replaced, not followed. RFC 6455 section 5.5.3
            // allows answering only the latest Ping, and it keeps a peer that
            // pings but never reads from growing the queue without bound.
            if let Some(start) = self.pong_at.take() {
                if start >= self.out_pos {
                    self.out.truncate(start);
                }
            }
            let start = self.out.len();
            let body = payload.get(..usize::from(len)).unwrap_or(&[]);
            // A Pong of at most 125 bytes always encodes; the result can
            // only be `Ok`.
            if self.raw_frame(Opcode::Pong, true, body).is_err() {
                self.failed = true;
            } else {
                self.pong_at = Some(start);
            }
        }
    }

    fn queue_close(&mut self, code: Option<CloseCode>, reason: &str) -> Result<(), WsError> {
        let mut payload = [0u8; 125];
        let len = match code {
            Some(c) => {
                payload[..2].copy_from_slice(&c.as_u16().to_be_bytes());
                let n = reason.len().min(123);
                payload[2..2 + n].copy_from_slice(&reason.as_bytes()[..n]);
                2 + n
            }
            None => 0,
        };
        self.sent_close = true;
        self.frame(Opcode::Close, true, &payload[..len])
    }

    /// Fails the connection (RFC 6455 section 7.1.7): queue a Close with the
    /// error's code unless one was sent or the transport is already gone.
    fn fail(&mut self, e: WsError) -> WsError {
        if let Some(code) = e.close_code() {
            if code != CloseCode::ABNORMAL && !self.sent_close {
                // Writing a two-byte Close cannot fail; any error would only
                // repeat the failure being reported.
                if self.queue_close(Some(code), "").is_err() {
                    self.out.clear();
                    self.out_pos = 0;
                    self.pong_at = None;
                }
            }
        }
        self.pong = None;
        self.failed = true;
        e
    }

    fn check_can_send(&self) -> Result<(), WsError> {
        if self.sent_close || self.failed {
            return Err(WsError::InvalidState("a Close frame was already sent"));
        }
        Ok(())
    }
}

/// One WebSocket connection: a sans-IO state machine (RFC 6455).
///
/// Input goes in through [`feed`](Self::feed) (or
/// [`read_buf`](Self::read_buf) + [`commit`](Self::commit)); messages and
/// control frames come out of [`poll`](Self::poll) as [`Event`]s. Everything
/// to send (your messages, automatic Pong and Close replies) accumulates in
/// an output queue: write [`output`](Self::output) to the transport and
/// report how much was written with [`advance_output`](Self::advance_output).
///
/// Every RFC 6455 rule is enforced: masking direction, reserved bits and
/// opcodes, control-frame size and fragmentation, minimal length encoding,
/// fragmentation order, UTF-8 validity of text (checked incrementally, so a
/// bad byte fails the connection as soon as it arrives), and close codes.
/// A violation fails the connection with the matching close code (see
/// [`WsError::close_code`]).
///
/// The output queue holds whatever you send; pacing it is the caller's job.
/// Automatic replies do not accumulate on their own: a Pong waits until the
/// next [`output`](Self::output) or send, and one still unwritten at the end
/// of the queue is replaced by the next (answering only the most recent
/// Ping, as RFC 6455 section 5.5.3 allows); at most one Close is ever
/// queued.
///
/// # Examples
///
/// ```
/// use ws_net::{Connection, Event};
///
/// let mut server = Connection::server();
/// let mut client = Connection::client_with_seed([42; 32]);
///
/// client.send_text("hello").unwrap();
/// let wire = client.output().to_vec();
/// client.advance_output(wire.len());
///
/// let _ = server.feed(&wire);
/// match server.poll().unwrap() {
///     Event::Text(text) => assert_eq!(text, "hello"),
///     other => panic!("{other:?}"),
/// }
/// ```
pub struct Connection {
    limits: Limits,
    reader: Reader,
    writer: Writer,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("role", &self.writer.role)
            .field("state", &self.state())
            .field("buffered_input", &(self.reader.filled - self.reader.pos))
            .field(
                "pending_output",
                &(self.writer.out.len() - self.writer.out_pos),
            )
            .field("limits", &self.limits)
            .finish()
    }
}

impl Connection {
    fn with_role(role: Role, masks: Option<MaskGen>) -> Self {
        Self {
            limits: Limits::new(),
            reader: Reader {
                input: Vec::new(),
                pos: 0,
                filled: 0,
                eof: false,
                frame: None,
                message: None,
                msg: Vec::new(),
                checked: 0,
                delivered: false,
                received_close: false,
            },
            writer: Writer {
                role,
                masks,
                out: Vec::new(),
                out_pos: 0,
                pong: None,
                pong_at: None,
                sending: None,
                sent_close: false,
                failed: false,
            },
        }
    }

    /// The server end of a connection whose opening handshake succeeded.
    ///
    /// # Examples
    ///
    /// ```
    /// let conn = ws_net::Connection::server();
    /// assert_eq!(conn.state(), ws_net::State::Open);
    /// ```
    #[must_use]
    pub fn server() -> Self {
        Self::with_role(Role::Server, None)
    }

    /// The client end, with masking keys from the operating system's random
    /// source (feature `std`).
    ///
    /// # Examples
    ///
    /// ```
    /// let mut conn = ws_net::Connection::client();
    /// conn.send_binary(b"x").unwrap();
    /// assert_eq!(conn.output()[1] & 0x80, 0x80); // masked
    /// ```
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    #[must_use]
    pub fn client() -> Self {
        Self::client_with_seed(crate::keys::os_seed())
    }

    /// The client end, with masking keys derived from a 32-byte secret
    /// `seed` (for `no_std`, or for reproducible tests). The seed must be
    /// unpredictable to the peer: RFC 6455 section 5.3 requires that a
    /// peer cannot predict masking keys.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut a = ws_net::Connection::client_with_seed([7; 32]);
    /// let mut b = ws_net::Connection::client_with_seed([7; 32]);
    /// a.send_text("same").unwrap();
    /// b.send_text("same").unwrap();
    /// assert_eq!(a.output(), b.output());
    /// ```
    #[must_use]
    pub fn client_with_seed(seed: [u8; 32]) -> Self {
        Self::with_role(Role::Client, Some(MaskGen::new(seed)))
    }

    /// Replaces the limits.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{Connection, Limits, WsError};
    ///
    /// let mut conn = Connection::server().with_limits(Limits::new().with_max_frame(128));
    /// // A masked binary frame announcing 200 bytes.
    /// let _ = conn.feed(&[0x82, 0xFE, 0x00, 0xC8, 1, 2, 3, 4]);
    /// assert_eq!(conn.poll().unwrap_err(), WsError::FrameTooLarge);
    /// ```
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// The limits.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(ws_net::Connection::server().limits(), &ws_net::Limits::new());
    /// ```
    #[must_use]
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// This end's role.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(ws_net::Connection::client_with_seed([0; 32]).role(), ws_net::Role::Client);
    /// ```
    #[must_use]
    pub fn role(&self) -> Role {
        self.writer.role
    }

    /// The closing-handshake state.
    ///
    /// # Examples
    ///
    /// See [`State`].
    #[must_use]
    pub fn state(&self) -> State {
        if self.writer.failed || self.reader.received_close {
            State::Closed
        } else if self.writer.sent_close {
            State::Closing
        } else {
            State::Open
        }
    }

    /// Copies as much of `bytes` into the input buffer as fits (64 KiB at
    /// most at a time) and returns how many were taken. Poll, then feed the
    /// rest.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut conn = ws_net::Connection::server();
    /// assert_eq!(conn.feed(&[0x81]), 1);
    /// ```
    #[must_use = "bytes beyond the returned count were not taken"]
    pub fn feed(&mut self, mut bytes: &[u8]) -> usize {
        let mut taken = 0;
        while !bytes.is_empty() {
            let spare = self.reader.spare();
            if spare.is_empty() {
                break;
            }
            let n = spare.len().min(bytes.len());
            spare[..n].copy_from_slice(&bytes[..n]);
            self.reader.filled += n;
            taken += n;
            bytes = &bytes[n..];
        }
        taken
    }

    /// Spare space at the end of the input buffer, for reading from a
    /// socket without an intermediate copy; follow with
    /// [`commit`](Self::commit). Never empty while the connection is waiting
    /// for input.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut conn = ws_net::Connection::server();
    /// let frame = [0x89, 0x80, 0, 0, 0, 0]; // masked empty Ping
    /// conn.read_buf()[..6].copy_from_slice(&frame);
    /// conn.commit(6);
    /// assert!(matches!(conn.poll().unwrap(), ws_net::Event::Ping(b"")));
    /// ```
    pub fn read_buf(&mut self) -> &mut [u8] {
        self.reader.spare()
    }

    /// Records that `n` bytes were written into [`read_buf`](Self::read_buf).
    ///
    /// # Examples
    ///
    /// See [`read_buf`](Self::read_buf).
    pub fn commit(&mut self, n: usize) {
        self.reader.filled = self
            .reader
            .filled
            .saturating_add(n)
            .min(self.reader.input.len());
    }

    /// Records that the transport closed. Before the closing handshake
    /// completed this is [`WsError::UnexpectedEof`] (close code 1006).
    ///
    /// # Examples
    ///
    /// ```
    /// let mut conn = ws_net::Connection::server();
    /// conn.feed_eof();
    /// assert_eq!(conn.poll().unwrap_err(), ws_net::WsError::UnexpectedEof);
    /// ```
    pub fn feed_eof(&mut self) {
        self.reader.eof = true;
    }

    /// Advances the parser and reports the next message, control frame, or
    /// what it needs.
    ///
    /// # Errors
    ///
    /// A protocol violation fails the connection: a Close frame with the
    /// error's [`close_code`](WsError::close_code) is queued in the output,
    /// the error is returned once, and later polls report
    /// [`Event::Closed`].
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{CloseCode, Connection, WsError};
    ///
    /// let mut conn = Connection::server();
    /// // Masked text frame whose payload is the invalid byte 0xFF.
    /// let _ = conn.feed(&[0x81, 0x81, 0, 0, 0, 0, 0xFF]);
    /// assert_eq!(conn.poll().unwrap_err(), WsError::InvalidUtf8);
    /// // The Close frame with code 1007 is ready to send.
    /// assert_eq!(conn.output(), [0x88, 0x02, 0x03, 0xEF]);
    /// ```
    pub fn poll(&mut self) -> Result<Event<'_>, WsError> {
        let reader = &mut self.reader;
        let writer = &mut self.writer;
        if reader.delivered {
            reader.delivered = false;
            if reader.msg.capacity() > MSG_RETAIN {
                reader.msg = Vec::new();
            } else {
                reader.msg.clear();
            }
            reader.checked = 0;
        }
        if writer.failed || reader.received_close {
            return Ok(Event::Closed);
        }
        loop {
            if let Some(mut f) = reader.frame.take() {
                let avail = reader.filled - reader.pos;
                if f.remaining > 0 && avail == 0 {
                    reader.frame = Some(f);
                    if reader.eof {
                        return Err(writer.fail(WsError::UnexpectedEof));
                    }
                    return Ok(Event::NeedInput);
                }
                let n = usize::try_from(f.remaining)
                    .unwrap_or(usize::MAX)
                    .min(avail);
                let start = reader.pos;
                if let Some(chunk) = reader.input.get_mut(start..start + n) {
                    if let Some(key) = f.mask {
                        apply_mask(chunk, key, f.phase);
                    }
                    reader.msg.extend_from_slice(chunk);
                }
                reader.pos += n;
                f.phase = (f.phase + n) % 4;
                f.remaining -= n as u64;
                if f.kind == Kind::Text {
                    let complete = f.remaining == 0 && f.fin;
                    if let Err(e) = reader.check_utf8(complete) {
                        return Err(writer.fail(e));
                    }
                }
                if f.remaining > 0 {
                    reader.frame = Some(f);
                    continue;
                }
                if !f.fin {
                    continue;
                }
                reader.message = None;
                reader.delivered = true;
                return Ok(match f.kind {
                    Kind::Text => match core::str::from_utf8(&reader.msg) {
                        Ok(text) => Event::Text(text),
                        Err(_) => return Err(writer.fail(WsError::InvalidUtf8)),
                    },
                    Kind::Binary => Event::Binary(&reader.msg),
                });
            }

            let unread = reader.input.get(reader.pos..reader.filled).unwrap_or(&[]);
            let (header, header_len) = match FrameHeader::decode(unread) {
                Ok(Some(h)) => h,
                Ok(None) if reader.eof => return Err(writer.fail(WsError::UnexpectedEof)),
                Ok(None) => return Ok(Event::NeedInput),
                Err(e) => return Err(writer.fail(e)),
            };
            if header.rsv != 0 {
                return Err(writer.fail(WsError::ReservedBits));
            }
            match (writer.role, header.mask) {
                (Role::Server, None) => return Err(writer.fail(WsError::UnmaskedFrame)),
                (Role::Client, Some(_)) => return Err(writer.fail(WsError::MaskedFrame)),
                _ => {}
            }
            if header.payload_len > self.limits.frame {
                return Err(writer.fail(WsError::FrameTooLarge));
            }
            let available = unread.len() - header_len;

            if header.opcode.is_control() {
                // At most 125 bytes: wait until the whole frame is here.
                let len = header.payload_len as usize;
                if available < len {
                    if reader.eof {
                        return Err(writer.fail(WsError::UnexpectedEof));
                    }
                    return Ok(Event::NeedInput);
                }
                let start = reader.pos + header_len;
                reader.pos = start + len;
                let payload = reader.input.get_mut(start..start + len).unwrap_or(&mut []);
                if let Some(key) = header.mask {
                    apply_mask(payload, key, 0);
                }
                let payload = reader.input.get(start..start + len).unwrap_or(&[]);
                match header.opcode {
                    Opcode::Ping => {
                        if !writer.sent_close {
                            let mut copy = [0u8; 125];
                            copy[..len].copy_from_slice(payload);
                            writer.pong = Some((copy, len as u8));
                        }
                        return Ok(Event::Ping(payload));
                    }
                    Opcode::Pong => return Ok(Event::Pong(payload)),
                    _ => {
                        let frame = match parse_close(payload) {
                            Ok(frame) => frame,
                            Err(e) => return Err(writer.fail(e)),
                        };
                        reader.received_close = true;
                        if !writer.sent_close {
                            let echo = writer.queue_close(frame.map(|f| f.code), "");
                            if let Err(e) = echo {
                                return Err(writer.fail(e));
                            }
                        }
                        return Ok(Event::Close(frame));
                    }
                }
            }

            let kind = match (header.opcode, reader.message) {
                (Opcode::Continuation, Some(kind)) => kind,
                (Opcode::Continuation, None) => {
                    return Err(writer.fail(WsError::UnexpectedContinuation));
                }
                (_, Some(_)) => return Err(writer.fail(WsError::ExpectedContinuation)),
                (Opcode::Text, None) => Kind::Text,
                (_, None) => Kind::Binary,
            };
            let total = (reader.msg.len() as u64).saturating_add(header.payload_len);
            if total > self.limits.message {
                return Err(writer.fail(WsError::MessageTooLarge));
            }

            if header.opcode != Opcode::Continuation
                && header.fin
                && available as u64 >= header.payload_len
            {
                // The whole single-frame message is buffered: unmask it in
                // place and hand out a slice of the input, no copy.
                let start = reader.pos + header_len;
                let end = start + header.payload_len as usize;
                reader.pos = end;
                let payload = reader.input.get_mut(start..end).unwrap_or(&mut []);
                if let Some(key) = header.mask {
                    apply_mask(payload, key, 0);
                }
                let payload = reader.input.get(start..end).unwrap_or(&[]);
                return Ok(match kind {
                    Kind::Text => match core::str::from_utf8(payload) {
                        Ok(text) => Event::Text(text),
                        Err(_) => return Err(writer.fail(WsError::InvalidUtf8)),
                    },
                    Kind::Binary => Event::Binary(payload),
                });
            }

            reader.pos += header_len;
            reader.message = Some(kind);
            // Reserving the frame up front saves growing the buffer piece by
            // piece, but only up to RESERVE_CAP: the length is the peer's
            // claim, and the budgets may have been lifted.
            let ahead = header.payload_len.min(RESERVE_CAP);
            reader.msg.reserve(usize::try_from(ahead).unwrap_or(0));
            let streaming = Streaming {
                kind,
                fin: header.fin,
                remaining: header.payload_len,
                mask: header.mask,
                phase: 0,
            };
            // The streaming step at the top of the loop reads the payload
            // (an empty fragment completes at once there, and may end the
            // message).
            reader.frame = Some(streaming);
        }
    }

    /// Sends a text message (split into frames of at most
    /// [`Limits::max_frame`] bytes when larger).
    ///
    /// # Errors
    ///
    /// [`WsError::InvalidState`] after a Close frame was sent, or while a
    /// fragmented message is being sent.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut conn = ws_net::Connection::server();
    /// conn.send_text("hi").unwrap();
    /// assert_eq!(conn.output(), [0x81, 0x02, b'h', b'i']);
    /// ```
    pub fn send_text(&mut self, text: &str) -> Result<(), WsError> {
        self.send_message(Kind::Text, text.as_bytes())
    }

    /// Sends a binary message (split like [`send_text`](Self::send_text)).
    ///
    /// # Errors
    ///
    /// As [`send_text`](Self::send_text).
    ///
    /// # Examples
    ///
    /// ```
    /// let mut conn = ws_net::Connection::server();
    /// conn.send_binary(&[1, 2, 3]).unwrap();
    /// assert_eq!(conn.output(), [0x82, 0x03, 1, 2, 3]);
    /// ```
    pub fn send_binary(&mut self, data: &[u8]) -> Result<(), WsError> {
        self.send_message(Kind::Binary, data)
    }

    fn send_message(&mut self, kind: Kind, data: &[u8]) -> Result<(), WsError> {
        self.writer.check_can_send()?;
        if self.writer.sending.is_some() {
            return Err(WsError::InvalidState("a fragmented message is being sent"));
        }
        self.write_fragments(kind.opcode(), data, true)
    }

    /// Writes `data` as one or more frames of at most `max_frame` bytes;
    /// the first uses `first`, the rest are continuations; `fin` marks the
    /// last.
    fn write_fragments(&mut self, first: Opcode, data: &[u8], fin: bool) -> Result<(), WsError> {
        let max = usize::try_from(self.limits.frame)
            .unwrap_or(usize::MAX)
            .max(1);
        if data.len() <= max {
            return self.writer.frame(first, fin, data);
        }
        let count = data.len().div_ceil(max);
        for (i, piece) in data.chunks(max).enumerate() {
            let opcode = if i == 0 { first } else { Opcode::Continuation };
            self.writer.frame(opcode, fin && i + 1 == count, piece)?;
        }
        Ok(())
    }

    /// Sends one fragment of a text message; `fin` ends the message. Each
    /// fragment is a `&str`, so the message is valid UTF-8 whole. Control
    /// frames may be sent between fragments; other messages may not.
    ///
    /// # Errors
    ///
    /// [`WsError::InvalidState`] after a Close frame was sent, or while a
    /// fragmented binary message is being sent.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut conn = ws_net::Connection::server();
    /// conn.send_text_fragment("Hel", false).unwrap();
    /// conn.send_text_fragment("lo", true).unwrap();
    /// // RFC 6455 section 5.7: a fragmented unmasked "Hello".
    /// assert_eq!(conn.output(), [0x01, 0x03, b'H', b'e', b'l', 0x80, 0x02, b'l', b'o']);
    /// ```
    pub fn send_text_fragment(&mut self, text: &str, fin: bool) -> Result<(), WsError> {
        self.send_fragment(Kind::Text, text.as_bytes(), fin)
    }

    /// Sends one fragment of a binary message; `fin` ends the message.
    ///
    /// # Errors
    ///
    /// As [`send_text_fragment`](Self::send_text_fragment).
    ///
    /// # Examples
    ///
    /// ```
    /// let mut conn = ws_net::Connection::server();
    /// conn.send_binary_fragment(&[1], false).unwrap();
    /// conn.send_ping(b"").unwrap();
    /// conn.send_binary_fragment(&[2], true).unwrap();
    /// assert_eq!(conn.output(), [0x02, 0x01, 1, 0x89, 0x00, 0x80, 0x01, 2]);
    /// ```
    pub fn send_binary_fragment(&mut self, data: &[u8], fin: bool) -> Result<(), WsError> {
        self.send_fragment(Kind::Binary, data, fin)
    }

    fn send_fragment(&mut self, kind: Kind, data: &[u8], fin: bool) -> Result<(), WsError> {
        self.writer.check_can_send()?;
        let opcode = match self.writer.sending {
            None => kind.opcode(),
            Some(k) if k == kind => Opcode::Continuation,
            Some(_) => {
                return Err(WsError::InvalidState(
                    "a fragmented message of the other type is being sent",
                ));
            }
        };
        self.write_fragments(opcode, data, fin)?;
        self.writer.sending = if fin { None } else { Some(kind) };
        Ok(())
    }

    /// Sends a Ping (payload at most 125 bytes).
    ///
    /// # Errors
    ///
    /// [`WsError::InvalidArgument`] for a payload over 125 bytes;
    /// [`WsError::InvalidState`] after a Close frame was sent.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut conn = ws_net::Connection::server();
    /// conn.send_ping(b"t=1").unwrap();
    /// assert_eq!(conn.output(), [0x89, 0x03, b't', b'=', b'1']);
    /// assert!(conn.send_ping(&[0; 126]).is_err());
    /// ```
    pub fn send_ping(&mut self, payload: &[u8]) -> Result<(), WsError> {
        self.send_control(Opcode::Ping, payload)
    }

    /// Sends an unsolicited Pong (a one-way heartbeat). Replies to Pings
    /// are automatic.
    ///
    /// # Errors
    ///
    /// As [`send_ping`](Self::send_ping).
    ///
    /// # Examples
    ///
    /// ```
    /// let mut conn = ws_net::Connection::server();
    /// conn.send_pong(b"").unwrap();
    /// assert_eq!(conn.output(), [0x8A, 0x00]);
    /// ```
    pub fn send_pong(&mut self, payload: &[u8]) -> Result<(), WsError> {
        self.send_control(Opcode::Pong, payload)
    }

    fn send_control(&mut self, opcode: Opcode, payload: &[u8]) -> Result<(), WsError> {
        self.writer.check_can_send()?;
        if payload.len() > 125 {
            return Err(WsError::InvalidArgument(
                "control frame payload over 125 bytes",
            ));
        }
        self.writer.frame(opcode, true, payload)
    }

    /// Starts the closing handshake with `code` and `reason` (at most 123
    /// bytes of UTF-8). Keep polling: the peer's Close completes the
    /// handshake ([`Event::Close`], then [`State::Closed`]).
    ///
    /// # Errors
    ///
    /// [`WsError::InvalidArgument`] for a code that may not be sent (1005,
    /// 1006, 1015, unassigned codes; see [`CloseCode::is_sendable`]) or a
    /// reason over 123 bytes; [`WsError::InvalidState`] if a Close frame was
    /// already sent. A refused call sends nothing.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{CloseCode, Connection};
    ///
    /// let mut conn = Connection::server();
    /// conn.close(CloseCode::NORMAL, "done").unwrap();
    /// assert_eq!(conn.output(), [0x88, 0x06, 0x03, 0xE8, b'd', b'o', b'n', b'e']);
    /// assert!(conn.send_text("late").is_err());
    /// ```
    pub fn close(&mut self, code: CloseCode, reason: &str) -> Result<(), WsError> {
        self.writer.check_can_send()?;
        if !code.is_sendable() {
            return Err(WsError::InvalidArgument(
                "close code may not be sent (1005, 1006, 1015, or unassigned)",
            ));
        }
        if reason.len() > 123 {
            return Err(WsError::InvalidArgument("close reason over 123 bytes"));
        }
        self.writer.queue_close(Some(code), reason)
    }

    /// The bytes waiting to be written to the transport (including queued
    /// Pong and Close replies).
    ///
    /// # Examples
    ///
    /// ```
    /// let mut conn = ws_net::Connection::server();
    /// assert!(conn.output().is_empty());
    /// conn.send_text("x").unwrap();
    /// assert_eq!(conn.output().len(), 3);
    /// ```
    pub fn output(&mut self) -> &[u8] {
        self.writer.flush_pong();
        self.writer.out.get(self.writer.out_pos..).unwrap_or(&[])
    }

    /// Marks `n` bytes of [`output`](Self::output) as written.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut conn = ws_net::Connection::server();
    /// conn.send_text("abc").unwrap(); // 2 header bytes + "abc"
    /// conn.advance_output(3);
    /// assert_eq!(conn.output(), b"bc");
    /// ```
    pub fn advance_output(&mut self, n: usize) {
        let w = &mut self.writer;
        w.out_pos = w.out_pos.saturating_add(n).min(w.out.len());
        if w.pong_at.is_some_and(|start| start < w.out_pos) {
            // Part of the Pong is on the wire: it can no longer be replaced.
            w.pong_at = None;
        }
        if w.out_pos == w.out.len() {
            w.out.clear();
            w.out_pos = 0;
            w.pong_at = None;
        } else if w.out_pos > OUT_COMPACT && w.out_pos > w.out.len() / 2 {
            let _drained = w.out.drain(..w.out_pos);
            w.pong_at = w.pong_at.map(|start| start - w.out_pos);
            w.out_pos = 0;
        }
    }
}

/// Parses and validates a Close payload (RFC 6455 section 5.5.1).
fn parse_close(payload: &[u8]) -> Result<Option<CloseFrame<'_>>, WsError> {
    match payload {
        [] => Ok(None),
        [_] => Err(WsError::InvalidClosePayload),
        [hi, lo, reason @ ..] => {
            let code = CloseCode::new(u16::from_be_bytes([*hi, *lo]));
            if !code.is_sendable() {
                return Err(WsError::InvalidCloseCode);
            }
            let reason = core::str::from_utf8(reason).map_err(|_| WsError::InvalidUtf8)?;
            Ok(Some(CloseFrame { code, reason }))
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn masked(opcode: u8, fin: bool, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let opcode = Opcode::from_u8(opcode).unwrap();
        FrameHeader::new(opcode, fin, payload.len() as u64)
            .with_mask([1, 2, 3, 4])
            .encode(&mut out)
            .unwrap();
        let start = out.len();
        out.extend_from_slice(payload);
        apply_mask(&mut out[start..], [1, 2, 3, 4], 0);
        out
    }

    #[test]
    fn test_streamed_message_and_fast_path_agree() {
        let frame = masked(0x1, true, "κόσμε".as_bytes());
        let mut whole = Connection::server();
        let _ = whole.feed(&frame);
        assert!(matches!(whole.poll().unwrap(), Event::Text("κόσμε")));
        let mut bytewise = Connection::server();
        let mut got = None;
        for b in &frame {
            let _ = bytewise.feed(core::slice::from_ref(b));
            if let Event::Text(t) = bytewise.poll().unwrap() {
                got = Some(alloc::string::String::from(t));
            }
        }
        assert_eq!(got.as_deref(), Some("κόσμε"));
    }

    #[test]
    fn test_empty_fragments_and_messages() {
        let mut conn = Connection::server();
        let mut wire = masked(0x1, false, b"");
        wire.extend(masked(0x0, false, b""));
        wire.extend(masked(0x0, true, b""));
        wire.extend(masked(0x2, true, b""));
        let _ = conn.feed(&wire);
        assert!(matches!(conn.poll().unwrap(), Event::Text("")));
        assert!(matches!(conn.poll().unwrap(), Event::Binary(b"")));
        assert!(matches!(conn.poll().unwrap(), Event::NeedInput));
    }

    #[test]
    fn test_send_side_state_errors() {
        let mut conn = Connection::server();
        conn.send_text_fragment("a", false).unwrap();
        assert!(matches!(conn.send_text("b"), Err(WsError::InvalidState(_))));
        assert!(matches!(
            conn.send_binary_fragment(b"b", true),
            Err(WsError::InvalidState(_))
        ));
        conn.send_text_fragment("c", true).unwrap();
        assert!(matches!(
            conn.close(CloseCode::NO_STATUS, ""),
            Err(WsError::InvalidArgument(_))
        ));
        let long = "x".repeat(124);
        assert!(matches!(
            conn.close(CloseCode::NORMAL, &long),
            Err(WsError::InvalidArgument(_))
        ));
        conn.close(CloseCode::NORMAL, "").unwrap();
        assert!(matches!(
            conn.close(CloseCode::NORMAL, ""),
            Err(WsError::InvalidState(_))
        ));
        assert!(matches!(conn.send_ping(b""), Err(WsError::InvalidState(_))));
    }

    #[test]
    fn test_outgoing_messages_split_at_frame_limit() {
        let mut conn = Connection::server().with_limits(Limits::new().with_max_frame(200));
        conn.send_binary(&vec![7u8; 450]).unwrap();
        let out = conn.output().to_vec();
        let (h1, n1) = FrameHeader::decode(&out).unwrap().unwrap();
        assert_eq!(
            (h1.opcode, h1.fin, h1.payload_len),
            (Opcode::Binary, false, 200)
        );
        let rest = &out[n1 + 200..];
        let (h2, n2) = FrameHeader::decode(rest).unwrap().unwrap();
        assert_eq!(
            (h2.opcode, h2.fin, h2.payload_len),
            (Opcode::Continuation, false, 200)
        );
        let (h3, _) = FrameHeader::decode(&rest[n2 + 200..]).unwrap().unwrap();
        assert_eq!(
            (h3.opcode, h3.fin, h3.payload_len),
            (Opcode::Continuation, true, 50)
        );
    }

    #[test]
    fn test_output_advance_and_compaction() {
        let mut conn = Connection::server();
        for _ in 0..100 {
            conn.send_binary(&[0u8; 1000]).unwrap();
        }
        let total = conn.output().len();
        conn.advance_output(70_000);
        assert_eq!(conn.output().len(), total - 70_000);
        conn.advance_output(usize::MAX);
        assert!(conn.output().is_empty());
    }

    #[test]
    fn test_only_latest_ping_is_answered() {
        let mut conn = Connection::server();
        let mut wire = masked(0x9, true, b"one");
        wire.extend(masked(0x9, true, b"two"));
        let _ = conn.feed(&wire);
        assert!(matches!(conn.poll().unwrap(), Event::Ping(b"one")));
        assert!(matches!(conn.poll().unwrap(), Event::Ping(b"two")));
        assert_eq!(conn.output(), [0x8A, 0x03, b't', b'w', b'o']);
    }

    #[test]
    fn test_large_message_buffer_is_released() {
        let mut conn = Connection::server();
        // Two 1 MiB fragments plus one byte: the reassembly buffer grows
        // past MSG_RETAIN and must be released after delivery.
        let payload = vec![b'a'; MSG_RETAIN];
        let mut wire = masked(0x2, false, &payload);
        wire.extend(masked(0x0, false, &payload));
        wire.extend(masked(0x0, true, b"z"));
        let mut fed = 0;
        let mut seen = false;
        while !seen {
            fed += conn.feed(&wire[fed..]);
            match conn.poll().unwrap() {
                Event::Binary(b) => {
                    assert_eq!(b.len(), 2 * payload.len() + 1);
                    seen = true;
                }
                Event::NeedInput => {}
                other => panic!("{other:?}"),
            }
        }
        assert!(matches!(conn.poll().unwrap(), Event::NeedInput));
        assert_eq!(conn.reader.msg.capacity(), 0);
    }
}
