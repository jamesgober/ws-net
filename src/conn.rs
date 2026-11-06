//! The connection: frame parsing, reassembly, control frames, the closing
//! handshake, and the output queue.

use alloc::{string::String, vec::Vec};
use core::{fmt, hint::black_box};

use crate::{
    close::{CloseCode, CloseFrame},
    error::WsError,
    extension::Negotiated,
    frame::{FrameHeader, Opcode, apply_mask},
    keepalive::{Clock, Keepalive, Millis, Tick, UNSET, due},
    keys::MaskGen,
    limits::Limits,
    message::{Message, MessageKind, Stats},
    prepared::{PreparedMessage, SendOptions},
};

/// Smallest input allocation.
const INPUT_MIN: usize = 4096;
/// Output already written beyond this is compacted away eagerly.
const OUT_COMPACT: usize = 64 * 1024;
/// The most reassembly space reserved ahead of the bytes that have arrived.
/// A header announces a length but proves nothing; with the budgets lifted,
/// reserving what it announces would let 14 bytes request terabytes.
const RESERVE_CAP: u64 = 1024 * 1024;
/// Output allowed above `max_output` for an automatic Pong and a Close, at
/// most 131 bytes each (2 header bytes, a 4-byte mask for a client, 125
/// bytes of payload), so a flooded queue can still answer and close.
const CONTROL_HEADROOM: u64 = 262;

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

impl Event<'_> {
    /// An owned copy of a message, control frame, or Close; `None` for
    /// [`NeedInput`](Event::NeedInput) and [`Closed`](Event::Closed).
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{Connection, Message};
    ///
    /// let mut conn = Connection::server();
    /// let _ = conn.feed(&[0x81, 0x82, 0, 0, 0, 0, b'h', b'i']);
    /// assert_eq!(conn.poll()?.to_message(), Some(Message::from("hi")));
    /// assert_eq!(conn.poll()?.to_message(), None); // NeedInput
    /// # Ok::<(), ws_net::WsError>(())
    /// ```
    #[must_use]
    pub fn to_message(&self) -> Option<Message> {
        Some(match self {
            Event::Text(text) => Message::Text((*text).into()),
            Event::Binary(data) => Message::Binary(data.to_vec()),
            Event::Ping(data) => Message::Ping(data.to_vec()),
            Event::Pong(data) => Message::Pong(data.to_vec()),
            Event::Close(frame) => Message::Close(frame.map(|f| (f.code, f.reason.into()))),
            Event::NeedInput | Event::Closed => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Text,
    Binary,
}

impl From<Kind> for MessageKind {
    fn from(kind: Kind) -> Self {
        match kind {
            Kind::Text => Self::Text,
            Kind::Binary => Self::Binary,
        }
    }
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

/// Where the last data event's bytes are, for `detach_message`.
#[derive(Clone, Copy, Debug)]
enum Lent {
    /// In the reassembly buffer.
    Reassembled(MessageKind),
    /// In the input buffer, at this range (single-frame fast path).
    Input(MessageKind, usize, usize),
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
    /// A text message being reassembled: every byte in it was validated
    /// once, as it arrived, so delivering it needs no second pass.
    text: String,
    /// The start of a UTF-8 sequence cut at the end of the last chunk
    /// (at most 3 bytes), completed by the next one.
    carry: [u8; 4],
    carry_len: u8,
    delivered: bool,
    received_close: bool,
    /// Input arrived since the last `on_time`.
    arrived: bool,
    lent: Option<Lent>,
    bytes_in: u64,
    frames_in: u64,
    messages_in: u64,
    pings_in: u64,
    pongs_in: u64,
    closes_in: u64,
}

impl Reader {
    fn spare(&mut self, cap: usize) -> &mut [u8] {
        if self.filled == self.input.len() {
            let len = self.input.len();
            if self.pos > 0 && (self.pos >= len / 2 || len >= cap) {
                self.input.copy_within(self.pos..self.filled, 0);
                self.filled -= self.pos;
                self.pos = 0;
                // Bytes lent by the last event have moved.
                self.lent = None;
            } else if len < cap {
                let grown = len.saturating_mul(2).clamp(INPUT_MIN.min(cap), cap);
                self.input.resize(grown, 0);
            }
        }
        let filled = self.filled;
        self.input.get_mut(filled..).unwrap_or(&mut [])
    }

    /// Appends the unmasked bytes of a text message, validating each byte
    /// once. A sequence cut at the end of `chunk` waits in `carry` for the
    /// next chunk; it is checked as a prefix right away, so an invalid byte
    /// fails the moment it arrives. With `complete`, nothing follows, so a
    /// cut sequence is an error too.
    fn push_text(
        text: &mut String,
        carry: &mut [u8; 4],
        carry_len: &mut u8,
        chunk: &[u8],
        complete: bool,
    ) -> Result<(), WsError> {
        let mut rest = chunk;
        if *carry_len > 0 {
            let have = usize::from(*carry_len);
            let width = utf8_width(carry[0]);
            let take = width.saturating_sub(have).min(rest.len());
            let (head, tail) = rest.split_at(take);
            if let Some(dst) = carry.get_mut(have..have + take) {
                dst.copy_from_slice(head);
            }
            rest = tail;
            let have = have + take;
            let seq = carry.get(..have).unwrap_or(&[]);
            if have < width {
                *carry_len = have as u8;
                return match core::str::from_utf8(seq) {
                    Err(e) if e.error_len().is_none() && !complete => Ok(()),
                    _ => Err(WsError::InvalidUtf8),
                };
            }
            let c = core::str::from_utf8(seq).map_err(|_| WsError::InvalidUtf8)?;
            text.push_str(c);
            *carry_len = 0;
        }
        let cut = incomplete_tail(rest);
        let (body, tail) = rest.split_at(rest.len() - cut);
        let valid = core::str::from_utf8(body).map_err(|_| WsError::InvalidUtf8)?;
        text.push_str(valid);
        if cut > 0 {
            match core::str::from_utf8(tail) {
                Err(e) if e.error_len().is_none() && !complete => {}
                _ => return Err(WsError::InvalidUtf8),
            }
            if let Some(dst) = carry.get_mut(..cut) {
                dst.copy_from_slice(tail);
            }
            *carry_len = cut as u8;
        } else if complete && *carry_len > 0 {
            return Err(WsError::InvalidUtf8);
        }
        Ok(())
    }

    /// Bytes of the message in progress.
    fn message_len(&self) -> usize {
        self.msg.len() + self.text.len() + usize::from(self.carry_len)
    }

    /// Ends a text message's reassembly: its allocation goes back to `msg`
    /// for reuse.
    fn reclaim_text(&mut self) {
        if self.text.capacity() > 0 {
            let mut bytes = core::mem::take(&mut self.text).into_bytes();
            bytes.clear();
            if bytes.capacity() > self.msg.capacity() {
                self.msg = bytes;
            }
        }
        self.carry_len = 0;
    }

    /// Whether a data message is partly received.
    fn in_message(&self) -> bool {
        self.message.is_some() || self.frame.is_some()
    }
}

/// Zeroes all of `v`'s allocation, spare capacity included (bytes a
/// compaction or a `clear` left behind), then empties it.
fn wipe_vec(v: &mut Vec<u8>) {
    v.iter_mut().for_each(|b| *b = 0);
    let spare = v.capacity() - v.len();
    v.extend(core::iter::repeat_n(0, spare));
    let _ = black_box(&mut *v);
    v.clear();
}

/// The length of the UTF-8 sequence that `lead` starts, or 0 when `lead`
/// cannot start one.
const fn utf8_width(lead: u8) -> usize {
    match lead {
        0x00..=0x7F => 1,
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => 0,
    }
}

/// How many bytes at the end of `bytes` begin a sequence that needs more
/// bytes than are there (0 to 3). Only the last three bytes are looked at,
/// so the cost is constant; whether they are valid is checked separately.
fn incomplete_tail(bytes: &[u8]) -> usize {
    let len = bytes.len();
    for back in 1..=len.min(3) {
        let b = bytes.get(len - back).copied().unwrap_or(0);
        if b & 0xC0 != 0x80 {
            return if utf8_width(b) > back { back } else { 0 };
        }
    }
    0
}

/// Output side: the queue, masking, and the close flags.
struct Writer {
    role: Role,
    masks: Option<MaskGen>,
    out: Vec<u8>,
    out_pos: usize,
    /// Where the last automatic Pong starts in `out`, while it is the last
    /// frame queued and none of it has been written.
    pong_at: Option<usize>,
    sending: Option<Kind>,
    sent_close: bool,
    failed: bool,
    /// The pending-output budget, copied from the limits.
    max_output: u64,
    /// The close timeout fired: the transport may close now.
    timed_out: bool,
    bytes_out: u64,
    messages_out: u64,
}

impl Writer {
    /// Bytes waiting for the transport, a pending automatic Pong included.
    fn pending(&self) -> usize {
        self.out.len() - self.out_pos
    }

    /// Whether `extra` more bytes fit in the output budget (plus `headroom`).
    fn fits(&self, extra: usize, headroom: u64) -> bool {
        let total = (self.pending() as u64).saturating_add(extra as u64);
        total <= self.max_output.saturating_add(headroom)
    }

    /// The encoded size of `len` payload bytes in one frame from this end.
    fn frame_size(&self, len: usize) -> usize {
        let mask = if self.masks.is_some() { 4 } else { 0 };
        let ext = if len < 126 {
            0
        } else if len <= 0xFFFF {
            2
        } else {
            8
        };
        2 + ext + mask + len
    }

    /// The encoded size of `len` bytes split into frames of at most `max`.
    fn message_size(&self, len: usize, max: usize) -> usize {
        if len <= max {
            return self.frame_size(len);
        }
        let full = len / max;
        let rest = len % max;
        let mut size = self.frame_size(max).saturating_mul(full);
        if rest > 0 {
            size = size.saturating_add(self.frame_size(rest));
        }
        size
    }

    fn check_data_room(&self, extra: usize) -> Result<(), WsError> {
        if self.fits(extra, 0) {
            Ok(())
        } else {
            Err(WsError::OutputFull)
        }
    }

    fn send_message(&mut self, limits: &Limits, kind: Kind, data: &[u8]) -> Result<(), WsError> {
        self.check_can_send()?;
        if self.sending.is_some() {
            return Err(WsError::InvalidState("a fragmented message is being sent"));
        }
        self.write_fragments(limits, kind.opcode(), data, true)?;
        self.messages_out = self.messages_out.saturating_add(1);
        Ok(())
    }

    /// Writes `data` as one or more frames of at most `send_frame` bytes;
    /// the first uses `first`, the rest are continuations; `fin` marks the
    /// last. Refused whole, with nothing written, if it does not fit.
    fn write_fragments(
        &mut self,
        limits: &Limits,
        first: Opcode,
        data: &[u8],
        fin: bool,
    ) -> Result<(), WsError> {
        let max = usize::try_from(limits.send_frame())
            .unwrap_or(usize::MAX)
            .max(1);
        if data.len() <= max {
            // The common case, one frame: its size is the budget check.
            self.check_data_room(self.frame_size(data.len()))?;
            self.pong_at = None;
            return self.raw_frame(first, fin, data);
        }
        self.check_data_room(self.message_size(data.len(), max))?;
        let count = data.len().div_ceil(max);
        let before = self.out.len();
        for (i, piece) in data.chunks(max).enumerate() {
            let opcode = if i == 0 { first } else { Opcode::Continuation };
            if let Err(e) = self.frame(opcode, fin && i + 1 == count, piece) {
                // Only a failed key refill gets here: take back the frames
                // already written, so the refused send changes nothing.
                self.out.truncate(before);
                return Err(e);
            }
        }
        Ok(())
    }

    fn send_fragment(
        &mut self,
        limits: &Limits,
        kind: Kind,
        data: &[u8],
        fin: bool,
    ) -> Result<(), WsError> {
        self.check_can_send()?;
        let opcode = match self.sending {
            None => kind.opcode(),
            Some(k) if k == kind => Opcode::Continuation,
            Some(_) => {
                return Err(WsError::InvalidState(
                    "a fragmented message of the other type is being sent",
                ));
            }
        };
        self.write_fragments(limits, opcode, data, fin)?;
        self.sending = if fin { None } else { Some(kind) };
        if fin {
            self.messages_out = self.messages_out.saturating_add(1);
        }
        Ok(())
    }

    fn send_control(&mut self, opcode: Opcode, payload: &[u8]) -> Result<(), WsError> {
        self.check_can_send()?;
        if payload.len() > 125 {
            return Err(WsError::InvalidArgument(
                "control frame payload over 125 bytes",
            ));
        }
        self.check_data_room(self.frame_size(payload.len()))?;
        self.frame(opcode, true, payload)
    }

    fn close(&mut self, code: Option<CloseCode>, reason: &str) -> Result<(), WsError> {
        self.check_can_send()?;
        if let Some(code) = code {
            if !code.is_sendable() {
                return Err(WsError::InvalidArgument(
                    "close code may not be sent (1005, 1006, 1015, or unassigned)",
                ));
            }
        } else if !reason.is_empty() {
            return Err(WsError::InvalidArgument(
                "a close reason needs a status code",
            ));
        }
        if reason.len() > 123 {
            return Err(WsError::InvalidArgument("close reason over 123 bytes"));
        }
        self.queue_close(code, reason)
    }

    fn send_prepared(&mut self, message: &PreparedMessage) -> Result<(), WsError> {
        if self.role == Role::Client {
            return Err(WsError::InvalidState(
                "a client masks every frame; prepared messages are for servers",
            ));
        }
        self.check_can_send()?;
        if self.sending.is_some() {
            return Err(WsError::InvalidState("a fragmented message is being sent"));
        }
        self.check_data_room(message.len())?;
        self.pong_at = None;
        self.out.extend_from_slice(message.as_bytes());
        self.messages_out = self.messages_out.saturating_add(1);
        Ok(())
    }

    /// Zeroes everything this writer holds that the peer did not see.
    fn wipe(&mut self) {
        wipe_vec(&mut self.out);
        self.out_pos = 0;
        self.pong_at = None;
        if let Some(masks) = self.masks.as_mut() {
            masks.wipe();
        }
        self.failed = true;
    }

    fn frame(&mut self, opcode: Opcode, fin: bool, payload: &[u8]) -> Result<(), WsError> {
        // Anything queued behind the Pong pins it in place.
        self.pong_at = None;
        self.raw_frame(opcode, fin, payload)
    }

    /// Appends one frame. Every caller passes a valid opcode, and a
    /// control payload already checked to be at most 125 bytes, so the
    /// header is written directly: this is the send hot path.
    fn raw_frame(&mut self, opcode: Opcode, fin: bool, payload: &[u8]) -> Result<(), WsError> {
        // A client without a key source never sends: an unmasked client
        // frame is a protocol error, and a predictable key defeats masking.
        let key = match (&mut self.masks, self.role) {
            (Some(m), _) => Some(m.next_key().ok_or(WsError::RandomUnavailable)?),
            (None, Role::Client) => return Err(WsError::RandomUnavailable),
            (None, Role::Server) => None,
        };
        let len = payload.len();
        let mut header = [0u8; crate::frame::MAX_HEADER_LEN];
        header[0] = (u8::from(fin) << 7) | opcode.as_u8();
        let mask_bit = if key.is_some() { 0x80 } else { 0 };
        let mut n = 2;
        if len < 126 {
            header[1] = mask_bit | len as u8;
        } else if let Ok(short) = u16::try_from(len) {
            header[1] = mask_bit | 126;
            header[2..4].copy_from_slice(&short.to_be_bytes());
            n = 4;
        } else {
            header[1] = mask_bit | 127;
            header[2..10].copy_from_slice(&(len as u64).to_be_bytes());
            n = 10;
        }
        if let Some(k) = key {
            header[n..n + 4].copy_from_slice(&k);
            n += 4;
        }
        self.out.extend_from_slice(header.get(..n).unwrap_or(&[]));
        let start = self.out.len();
        self.out.extend_from_slice(payload);
        if let Some(k) = key {
            if let Some(body) = self.out.get_mut(start..) {
                apply_mask(body, k, 0);
            }
        }
        Ok(())
    }

    /// Queues the automatic Pong for a received Ping.
    fn queue_pong(&mut self, payload: &[u8]) {
        // An earlier automatic Pong that is still last in the queue and
        // unwritten is replaced, not followed. RFC 6455 section 5.5.3
        // allows answering only the latest Ping, and it keeps a peer that
        // pings but never reads from growing the queue without bound.
        if let Some(start) = self.pong_at.take() {
            if start >= self.out_pos {
                self.out.truncate(start);
            }
        }
        // A queue full to its headroom means the peer is not reading: the
        // Pong is dropped (a later Ping is answered).
        if !self.fits(self.frame_size(payload.len()), CONTROL_HEADROOM / 2) {
            return;
        }
        let start = self.out.len();
        // A Pong of at most 125 bytes always encodes; the result can only
        // be `Ok`, or `RandomUnavailable` for a client that cannot send.
        if self.raw_frame(Opcode::Pong, true, payload).is_ok() {
            self.pong_at = Some(start);
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
        self.frame(Opcode::Close, true, &payload[..len])?;
        self.sent_close = true;
        Ok(())
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
        self.failed = true;
        e
    }

    fn check_can_send(&self) -> Result<(), WsError> {
        if self.role == Role::Client && self.masks.is_none() {
            return Err(WsError::RandomUnavailable);
        }
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
    clock: Clock,
    negotiated: Negotiated,
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
                text: String::new(),
                carry: [0; 4],
                carry_len: 0,
                delivered: false,
                received_close: false,
                arrived: false,
                lent: None,
                bytes_in: 0,
                frames_in: 0,
                messages_in: 0,
                pings_in: 0,
                pongs_in: 0,
                closes_in: 0,
            },
            writer: Writer {
                role,
                masks,
                out: Vec::new(),
                out_pos: 0,
                pong_at: None,
                sending: None,
                sent_close: false,
                failed: false,
                max_output: Limits::DEFAULT_MAX_OUTPUT,
                timed_out: false,
                bytes_out: 0,
                messages_out: 0,
            },
            clock: Clock::default(),
            negotiated: Negotiated::none(),
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

    /// The client end, with masking keys derived from a seed drawn from the
    /// operating system's cryptographic random source (feature `std`).
    ///
    /// The OS source can fail (a sandbox that filters the system call). This
    /// constructor then fails closed: the connection is [`State::Closed`]
    /// and every send returns [`WsError::RandomUnavailable`]; it never
    /// falls back to a weaker source and never panics. Use
    /// [`try_client`](Self::try_client) to see the failure up front.
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
        Self::try_client().unwrap_or_else(|_| {
            let mut conn = Self::with_role(Role::Client, None);
            conn.writer.failed = true;
            conn
        })
    }

    /// The client end, with masking keys from the operating system's
    /// cryptographic random source, or an error when that source fails
    /// (feature `std`).
    ///
    /// # Errors
    ///
    /// [`WsError::RandomUnavailable`] when the OS random source cannot
    /// supply the 32-byte seed.
    ///
    /// # Examples
    ///
    /// ```
    /// let conn = ws_net::Connection::try_client()?;
    /// assert_eq!(conn.role(), ws_net::Role::Client);
    /// # Ok::<(), ws_net::WsError>(())
    /// ```
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn try_client() -> Result<Self, WsError> {
        let masks = MaskGen::from_os().ok_or(WsError::RandomUnavailable)?;
        Ok(Self::with_role(Role::Client, Some(masks)))
    }

    /// The client end, with masking keys derived from a 32-byte secret
    /// `seed` (for `no_std`, or for reproducible tests). The seed must be
    /// unpredictable to the peer: RFC 6455 section 5.3 requires that a
    /// peer cannot predict masking keys, so take it from a cryptographic
    /// random source, never from a clock, a counter, or a fixed value.
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
        self.writer.max_output = limits.max_output();
        self
    }

    /// Applies what the opening handshake negotiated. A connection built
    /// by [`accept`](crate::accept), [`ServerHandshake::accept`](crate::ServerHandshake::accept),
    /// or [`ClientHandshake::connection`](crate::ClientHandshake::connection)
    /// already has it. No extension is negotiated in this version, so the
    /// value is always [`Negotiated::none`].
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{Connection, extension::Negotiated};
    ///
    /// let conn = Connection::server().with_extensions(Negotiated::none());
    /// assert!(conn.negotiated().is_empty());
    /// ```
    #[must_use]
    pub fn with_extensions(mut self, negotiated: Negotiated) -> Self {
        self.negotiated = negotiated;
        self
    }

    /// The extensions in force.
    ///
    /// # Examples
    ///
    /// See [`with_extensions`](Self::with_extensions).
    #[must_use]
    pub fn negotiated(&self) -> &Negotiated {
        &self.negotiated
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

    /// Whether the connection is [`State::Open`]: neither end has sent a
    /// Close and it has not failed.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut conn = ws_net::Connection::server();
    /// assert!(conn.is_open());
    /// conn.close(ws_net::CloseCode::NORMAL, "").unwrap();
    /// assert!(!conn.is_open());
    /// ```
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.state() == State::Open
    }

    /// Whether a new data message would be accepted now: no Close was sent,
    /// the connection has not failed, and no fragmented message is being
    /// sent. After the peer's Close this end may still send until it echoes
    /// (the echo is automatic, so in practice the answer is then `false`).
    ///
    /// # Examples
    ///
    /// ```
    /// let mut conn = ws_net::Connection::server();
    /// assert!(conn.can_send());
    /// conn.send_text_fragment("part", false).unwrap();
    /// assert!(!conn.can_send()); // finish the fragmented message first
    /// conn.send_text_fragment("", true).unwrap();
    /// assert!(conn.can_send());
    /// ```
    #[must_use]
    pub fn can_send(&self) -> bool {
        !self.writer.sent_close && !self.writer.failed && self.writer.sending.is_none()
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
    ///
    /// At most [`Limits::input_buffer`] bytes are buffered; a leftover
    /// larger than that is fed in a loop with polls between.
    #[must_use = "bytes beyond the returned count were not taken"]
    pub fn feed(&mut self, mut bytes: &[u8]) -> usize {
        let mut taken = 0;
        let cap = self.limits.input_buffer();
        while !bytes.is_empty() {
            let spare = self.reader.spare(cap);
            if spare.is_empty() {
                break;
            }
            let n = spare.len().min(bytes.len());
            spare[..n].copy_from_slice(&bytes[..n]);
            self.reader.filled += n;
            taken += n;
            bytes = &bytes[n..];
        }
        if taken > 0 {
            self.reader.arrived = true;
            self.reader.bytes_in = self.reader.bytes_in.saturating_add(taken as u64);
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
        self.reader.spare(self.limits.input_buffer())
    }

    /// Records that `n` bytes were written into [`read_buf`](Self::read_buf).
    ///
    /// # Examples
    ///
    /// See [`read_buf`](Self::read_buf).
    pub fn commit(&mut self, n: usize) {
        let before = self.reader.filled;
        self.reader.filled = before.saturating_add(n).min(self.reader.input.len());
        let added = self.reader.filled - before;
        if added > 0 {
            self.reader.arrived = true;
            self.reader.bytes_in = self.reader.bytes_in.saturating_add(added as u64);
        }
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
        poll_inner(&mut self.reader, &mut self.writer, &self.limits)
    }

    /// As [`poll`](Self::poll), also returning a [`Sender`] that borrows
    /// only the output side, so a handler can reply while it still holds
    /// the message.
    ///
    /// # Errors
    ///
    /// As [`poll`](Self::poll).
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{Connection, Event};
    ///
    /// let mut conn = Connection::server();
    /// let _ = conn.feed(&[0x81, 0x82, 0, 0, 0, 0, b'h', b'i']); // masked "hi"
    /// let (event, mut sender) = conn.poll_split()?;
    /// if let Event::Text(text) = event {
    ///     sender.send_text(text)?; // no copy of the message needed
    /// }
    /// assert_eq!(conn.output(), [0x81, 0x02, b'h', b'i']);
    /// # Ok::<(), ws_net::WsError>(())
    /// ```
    pub fn poll_split(&mut self) -> Result<(Event<'_>, Sender<'_>), WsError> {
        let Self {
            reader,
            writer,
            limits,
            ..
        } = self;
        let event = poll_inner(reader, writer, limits)?;
        Ok((event, Sender { writer, limits }))
    }
}

/// Makes room for `need` more bytes in a reassembly buffer, doubling as
/// usual but never past the message budget (the budget was checked against
/// the header, so `len + need` fits it), so a message's buffer holds at
/// most `max_message` bytes.
fn grow(msg: &mut Vec<u8>, need: usize, max_message: u64) -> Result<(), WsError> {
    let len = msg.len();
    if msg.capacity() - len >= need {
        return Ok(());
    }
    let budget = usize::try_from(max_message).unwrap_or(usize::MAX);
    let wanted = len.saturating_add(need);
    let target = msg
        .capacity()
        .saturating_mul(2)
        .max(wanted)
        .min(budget.max(wanted));
    // Allocation failure fails the connection (1011) instead of aborting
    // the process; a smaller exact request is tried first.
    if msg.try_reserve_exact(target - len).is_err() {
        msg.try_reserve_exact(need)
            .map_err(|_| WsError::AllocationFailed)?;
    }
    Ok(())
}

/// [`grow`] for a text message's `String`.
fn grow_text(text: &mut String, need: usize, max_message: u64) -> Result<(), WsError> {
    let len = text.len();
    if text.capacity() - len >= need {
        return Ok(());
    }
    let budget = usize::try_from(max_message).unwrap_or(usize::MAX);
    let wanted = len.saturating_add(need);
    let target = text
        .capacity()
        .saturating_mul(2)
        .max(wanted)
        .min(budget.max(wanted));
    // Allocation failure fails the connection (1011) instead of aborting
    // the process; a smaller exact request is tried first.
    if text.try_reserve_exact(target - len).is_err() {
        text.try_reserve_exact(need)
            .map_err(|_| WsError::AllocationFailed)?;
    }
    Ok(())
}

/// The receive state machine, over the two halves so that a [`Sender`] can
/// borrow the writer while the event borrows the reader.
fn poll_inner<'r>(
    reader: &'r mut Reader,
    writer: &mut Writer,
    limits: &Limits,
) -> Result<Event<'r>, WsError> {
    reader.lent = None;
    if reader.delivered {
        reader.delivered = false;
        reader.reclaim_text();
        if reader.msg.capacity() > limits.retain() {
            reader.msg = Vec::new();
        } else {
            reader.msg.clear();
        }
    }
    if reader.pos == reader.filled {
        // Nothing buffered: start the next read at the front, so the buffer
        // never needs compacting. (The input buffer is bounded by its own
        // limit and kept for the next read; `release_memory` frees it.)
        reader.pos = 0;
        reader.filled = 0;
    }
    if writer.failed || reader.received_close {
        return Ok(Event::Closed);
    }
    {
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
                f.remaining -= n as u64;
                let complete = f.remaining == 0 && f.fin;
                if let Some(chunk) = reader.input.get_mut(start..start + n) {
                    if let Some(key) = f.mask {
                        apply_mask(chunk, key, f.phase);
                    }
                    match f.kind {
                        Kind::Binary => {
                            if let Err(e) = grow(&mut reader.msg, chunk.len(), limits.max_message())
                            {
                                return Err(writer.fail(e));
                            }
                            reader.msg.extend_from_slice(chunk);
                        }
                        Kind::Text => {
                            let need = chunk.len() + usize::from(reader.carry_len);
                            let grown = grow_text(&mut reader.text, need, limits.max_message());
                            if let Err(e) = grown {
                                return Err(writer.fail(e));
                            }
                            let chunk = reader.input.get(start..start + n).unwrap_or(&[]);
                            let pushed = Reader::push_text(
                                &mut reader.text,
                                &mut reader.carry,
                                &mut reader.carry_len,
                                chunk,
                                complete,
                            );
                            if let Err(e) = pushed {
                                return Err(writer.fail(e));
                            }
                        }
                    }
                }
                reader.pos += n;
                f.phase = (f.phase + n) % 4;
                if f.remaining > 0 {
                    reader.frame = Some(f);
                    continue;
                }
                if !f.fin {
                    continue;
                }
                reader.message = None;
                reader.delivered = true;
                reader.messages_in = reader.messages_in.saturating_add(1);
                reader.lent = Some(Lent::Reassembled(f.kind.into()));
                return Ok(match f.kind {
                    Kind::Text => Event::Text(&reader.text),
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
            if header.payload_len > limits.max_frame() {
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
                // Counted once whole: the header is decoded again on every
                // poll until the payload is here.
                reader.frames_in = reader.frames_in.saturating_add(1);
                let start = reader.pos + header_len;
                reader.pos = start + len;
                let payload = reader.input.get_mut(start..start + len).unwrap_or(&mut []);
                if let Some(key) = header.mask {
                    apply_mask(payload, key, 0);
                }
                let payload = reader.input.get(start..start + len).unwrap_or(&[]);
                match header.opcode {
                    Opcode::Ping => {
                        reader.pings_in = reader.pings_in.saturating_add(1);
                        if !writer.sent_close {
                            writer.queue_pong(payload);
                        }
                        return Ok(Event::Ping(payload));
                    }
                    Opcode::Pong => {
                        reader.pongs_in = reader.pongs_in.saturating_add(1);
                        return Ok(Event::Pong(payload));
                    }
                    _ => {
                        reader.closes_in = reader.closes_in.saturating_add(1);
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

            reader.frames_in = reader.frames_in.saturating_add(1);
            let kind = match (header.opcode, reader.message) {
                (Opcode::Continuation, Some(kind)) => kind,
                (Opcode::Continuation, None) => {
                    return Err(writer.fail(WsError::UnexpectedContinuation));
                }
                (_, Some(_)) => return Err(writer.fail(WsError::ExpectedContinuation)),
                (Opcode::Text, None) => Kind::Text,
                (_, None) => Kind::Binary,
            };
            let total = (reader.message_len() as u64).saturating_add(header.payload_len);
            if total > limits.max_message() {
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
                if kind == Kind::Text && core::str::from_utf8(payload).is_err() {
                    return Err(writer.fail(WsError::InvalidUtf8));
                }
                // Lent (for `detach_message`) only once it is valid.
                reader.messages_in = reader.messages_in.saturating_add(1);
                reader.lent = Some(Lent::Input(kind.into(), start, end));
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
            if reader.message.is_none() && kind == Kind::Text {
                // Reuse the binary buffer's allocation; it is empty here, so
                // the conversion checks nothing.
                let bytes = core::mem::take(&mut reader.msg);
                reader.text = String::from_utf8(bytes).unwrap_or_default();
                reader.text.clear();
            }
            reader.message = Some(kind);
            // Reserving the frame up front saves growing the buffer piece by
            // piece, but only up to RESERVE_CAP: the length is the peer's
            // claim, and the budgets may have been lifted.
            let ahead = header.payload_len.min(RESERVE_CAP);
            let ahead = usize::try_from(ahead).unwrap_or(0);
            let grown = match kind {
                Kind::Binary => grow(&mut reader.msg, ahead, limits.max_message()),
                Kind::Text => grow_text(&mut reader.text, ahead, limits.max_message()),
            };
            if let Err(e) = grown {
                return Err(writer.fail(e));
            }
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
}

impl Connection {
    /// Sends a text message (split into frames of at most
    /// [`Limits::send_frame`] bytes when larger).
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
        self.writer
            .send_message(&self.limits, Kind::Text, text.as_bytes())
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
        self.writer.send_message(&self.limits, Kind::Binary, data)
    }

    /// As [`send_text`](Self::send_text), with per-message
    /// [`SendOptions`]. With no compression negotiated (always, in this
    /// version), the options change nothing on the wire; code written
    /// against them keeps its meaning when permessage-deflate lands, so a
    /// message carrying a secret can say `SendOptions::uncompressed()` now.
    ///
    /// # Errors
    ///
    /// As [`send_text`](Self::send_text).
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{Connection, SendOptions};
    ///
    /// let mut conn = Connection::server();
    /// conn.send_text_with("token=s3cr3t", SendOptions::uncompressed())?;
    /// assert_eq!(conn.output()[0], 0x81); // RSV1 clear: not compressed
    /// # Ok::<(), ws_net::WsError>(())
    /// ```
    pub fn send_text_with(&mut self, text: &str, options: SendOptions) -> Result<(), WsError> {
        let _ = options;
        self.send_text(text)
    }

    /// As [`send_binary`](Self::send_binary), with per-message
    /// [`SendOptions`].
    ///
    /// # Errors
    ///
    /// As [`send_binary`](Self::send_binary).
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{Connection, SendOptions};
    ///
    /// let mut conn = Connection::server();
    /// conn.send_binary_with(&[1], SendOptions::new())?;
    /// assert_eq!(conn.output(), [0x82, 0x01, 1]);
    /// # Ok::<(), ws_net::WsError>(())
    /// ```
    pub fn send_binary_with(&mut self, data: &[u8], options: SendOptions) -> Result<(), WsError> {
        let _ = options;
        self.send_binary(data)
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
        self.writer
            .send_fragment(&self.limits, Kind::Text, text.as_bytes(), fin)
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
        self.writer
            .send_fragment(&self.limits, Kind::Binary, data, fin)
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
        self.writer.send_control(Opcode::Ping, payload)
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
        self.writer.send_control(Opcode::Pong, payload)
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
        self.writer.close(Some(code), reason)
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
        let before = w.out_pos;
        w.out_pos = w.out_pos.saturating_add(n).min(w.out.len());
        w.bytes_out = w.bytes_out.saturating_add((w.out_pos - before) as u64);
        if w.pong_at.is_some_and(|start| start < w.out_pos) {
            // Part of the Pong is on the wire: it can no longer be replaced.
            w.pong_at = None;
        }
        if w.out_pos == w.out.len() {
            if w.out.capacity() > self.limits.retain() {
                w.out = Vec::new();
            } else {
                w.out.clear();
            }
            w.out_pos = 0;
            w.pong_at = None;
        } else if w.out_pos > OUT_COMPACT && w.out_pos > w.out.len() / 2 {
            let _drained = w.out.drain(..w.out_pos);
            w.pong_at = w.pong_at.map(|start| start - w.out_pos);
            w.out_pos = 0;
        }
    }
}

impl Connection {
    /// Sets the keepalive and timeout rules (see [`Keepalive`]); they take
    /// effect at the next [`on_time`](Self::on_time).
    ///
    /// # Examples
    ///
    /// See [`on_time`](Self::on_time).
    #[must_use]
    pub fn with_keepalive(mut self, keepalive: Keepalive) -> Self {
        self.clock.set(keepalive);
        self
    }

    /// Applies the keepalive rules at `now`, the caller's monotonic time.
    /// Call it after each read and at [`next_deadline`](Self::next_deadline);
    /// with nothing due it does almost nothing. Any input byte since the
    /// last call counts as activity.
    ///
    /// Order within one tick: a close timeout, then the idle timeout, then
    /// the message timeout, then a keepalive Ping. Poll the input you have
    /// before ticking: a message that completes in the buffered bytes is
    /// not timed out.
    ///
    /// # Errors
    ///
    /// [`WsError::IdleTimeout`] (Close 1001 queued),
    /// [`WsError::CloseTimeout`] (nothing more sent; close the transport),
    /// [`WsError::MessageTimeout`] (Close 1008 queued). Each is returned
    /// once; the connection is then [`State::Closed`] and later ticks
    /// return `Ok(Tick::Nothing)`.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::time::Duration;
    /// use ws_net::{Connection, Keepalive, Millis, Tick, WsError};
    ///
    /// let keepalive = Keepalive::new()
    ///     .with_ping_interval(Duration::from_secs(30))
    ///     .with_idle_timeout(Duration::from_secs(75));
    /// let mut conn = Connection::server().with_keepalive(keepalive);
    /// assert_eq!(conn.on_time(Millis(0))?, Tick::Nothing);
    /// assert_eq!(conn.next_deadline(), Some(Millis(30_000)));
    ///
    /// // Silence: a Ping carrying the time goes out at 30 s...
    /// assert_eq!(conn.on_time(Millis(30_000))?, Tick::PingQueued);
    /// assert_eq!(conn.output()[..2], [0x89, 0x08]);
    /// // ...and at 75 s the connection gives up, queuing Close 1001.
    /// assert_eq!(conn.on_time(Millis(75_000)), Err(WsError::IdleTimeout));
    /// # Ok::<(), WsError>(())
    /// ```
    pub fn on_time(&mut self, now: Millis) -> Result<Tick, WsError> {
        let clock = &mut self.clock;
        let reader = &mut self.reader;
        let writer = &mut self.writer;
        if !clock.armed {
            return Ok(Tick::Nothing);
        }
        let now = now.as_u64().max(clock.now);
        clock.now = now;
        if writer.failed || reader.received_close {
            // Closed, but the transport may still wait on a peer that is
            // not reading our output, or (a client) on the server's EOF:
            // the close timeout bounds that wait. A timer failure started
            // it already; any other starts it now.
            let waiting = writer.pending() > 0 || (writer.role == Role::Client && !reader.eof);
            if waiting && !writer.timed_out {
                if clock.close_sent == UNSET {
                    clock.close_sent = now;
                }
                if due(clock.close_sent, clock.close).is_some_and(|d| d <= now) {
                    writer.timed_out = true;
                }
            }
            return Ok(Tick::Nothing);
        }
        if reader.arrived || clock.last_rx == UNSET {
            reader.arrived = false;
            clock.last_rx = now;
            clock.ping_sent = UNSET;
        }
        let is_due = |at: u64, after: u64| due(at, after).is_some_and(|d| d <= now);
        if writer.sent_close {
            if clock.close_sent == UNSET {
                clock.close_sent = now;
            }
            if is_due(clock.close_sent, clock.close) {
                writer.timed_out = true;
                return Err(writer.fail(WsError::CloseTimeout));
            }
        }
        if is_due(clock.last_rx, clock.idle) {
            if clock.close_sent == UNSET {
                clock.close_sent = now; // the queued 1001
            }
            return Err(writer.fail(WsError::IdleTimeout));
        }
        if reader.in_message() {
            if clock.message_started == UNSET || clock.message_seq != reader.messages_in {
                clock.message_started = now;
                clock.message_seq = reader.messages_in;
            }
            if is_due(clock.message_started, clock.message) {
                if clock.close_sent == UNSET {
                    clock.close_sent = now; // the queued 1008
                }
                return Err(writer.fail(WsError::MessageTimeout));
            }
        } else {
            clock.message_started = UNSET;
        }
        if clock.ping_sent == UNSET && !writer.sent_close && is_due(clock.last_rx, clock.ping) {
            // Marked as sent even when the output is full, so the deadline
            // moves on instead of firing on every tick.
            clock.ping_sent = now;
            if writer
                .send_control(Opcode::Ping, &now.to_be_bytes())
                .is_ok()
            {
                return Ok(Tick::PingQueued);
            }
        }
        Ok(Tick::Nothing)
    }

    /// The earliest time at which [`on_time`](Self::on_time) has work, or
    /// `None` when no timer is armed: sleep until then, and an idle
    /// connection costs no CPU. Before the first `on_time` the timers have
    /// no start, so this is `None`.
    ///
    /// # Examples
    ///
    /// See [`on_time`](Self::on_time).
    #[must_use]
    pub fn next_deadline(&self) -> Option<Millis> {
        let c = &self.clock;
        if !c.armed {
            return None;
        }
        if self.writer.failed || self.reader.received_close {
            let w = &self.writer;
            let waiting = w.pending() > 0 || (w.role == Role::Client && !self.reader.eof);
            if !waiting || w.timed_out {
                return None;
            }
            let since = if c.close_sent == UNSET {
                c.now
            } else {
                c.close_sent
            };
            return due(since, c.close).map(Millis);
        }
        let ping = if c.ping_sent == UNSET && !self.writer.sent_close {
            due(c.last_rx, c.ping)
        } else {
            None
        };
        let idle = due(c.last_rx, c.idle);
        let close = if self.writer.sent_close {
            let since = if c.close_sent == UNSET {
                c.now
            } else {
                c.close_sent
            };
            due(since, c.close)
        } else {
            None
        };
        let message = if self.reader.in_message() {
            let fresh = c.message_started == UNSET || c.message_seq != self.reader.messages_in;
            due(if fresh { c.now } else { c.message_started }, c.message)
        } else {
            None
        };
        [ping, idle, close, message]
            .into_iter()
            .flatten()
            .min()
            .map(Millis)
    }

    /// Whether the transport should be closed now: the connection is
    /// [`State::Closed`] and its output is written. A server closes first
    /// (RFC 6455 section 7.1.1), so for a server that is the whole rule; a
    /// client waits for the server to close, so for a client it also needs
    /// the server's EOF fed or a failure. After the close timeout it is
    /// true at once, even with output unwritten: the peer stopped reading.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{CloseCode, Connection};
    ///
    /// let mut server = Connection::server();
    /// server.close(CloseCode::NORMAL, "")?;
    /// let _ = server.feed(&[0x88, 0x82, 0, 0, 0, 0, 0x03, 0xE8]); // the client's echo
    /// let _ = server.poll()?;
    /// assert!(!server.should_close_transport()); // our Close is not written yet
    /// let n = server.output().len();
    /// server.advance_output(n);
    /// assert!(server.should_close_transport());
    /// # Ok::<(), ws_net::WsError>(())
    /// ```
    #[must_use]
    pub fn should_close_transport(&self) -> bool {
        // The peer stopped answering our Close: what is still queued will
        // not be read.
        if self.writer.timed_out {
            return true;
        }
        if self.state() != State::Closed || self.writer.pending() > 0 {
            return false;
        }
        match self.writer.role {
            Role::Server => true,
            Role::Client => self.reader.eof || self.writer.timed_out || self.writer.failed,
        }
    }

    /// Bytes waiting for the transport, an automatic Pong not yet encoded
    /// included.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut conn = ws_net::Connection::server();
    /// conn.send_text("abc")?;
    /// assert_eq!(conn.buffered_output(), 5);
    /// # Ok::<(), ws_net::WsError>(())
    /// ```
    #[must_use]
    pub fn buffered_output(&self) -> usize {
        self.writer.pending()
    }

    /// Frees every buffer that holds no pending bytes: the input buffer when
    /// all input was read, the reassembly buffer when no message is in
    /// progress, the output when it was all written. An idle connection then
    /// holds no heap memory ([`memory_in_use`](Self::memory_in_use) is 0).
    ///
    /// # Examples
    ///
    /// ```
    /// let mut conn = ws_net::Connection::server();
    /// conn.send_binary(&[0; 100_000])?;
    /// conn.release_memory();
    /// assert!(conn.memory_in_use() >= 100_000); // still pending: kept
    /// let n = conn.output().len();
    /// conn.advance_output(n);
    /// conn.release_memory();
    /// assert_eq!(conn.memory_in_use(), 0);
    /// # Ok::<(), ws_net::WsError>(())
    /// ```
    pub fn release_memory(&mut self) {
        let r = &mut self.reader;
        if r.pos == r.filled {
            r.input = Vec::new();
            r.pos = 0;
            r.filled = 0;
            r.lent = None;
        }
        if !r.in_message() {
            r.msg = Vec::new();
            r.text = String::new();
            r.carry_len = 0;
            r.delivered = false;
            r.lent = None;
        }
        let w = &mut self.writer;
        if w.out_pos == w.out.len() {
            w.out = Vec::new();
            w.out_pos = 0;
            w.pong_at = None;
        }
        if let Some(masks) = w.masks.as_mut() {
            masks.release();
        }
    }

    /// Heap bytes held by this connection's buffers (capacities, not
    /// lengths).
    ///
    /// # Examples
    ///
    /// ```
    /// let mut conn = ws_net::Connection::server();
    /// assert_eq!(conn.memory_in_use(), 0); // nothing allocated until used
    /// let _ = conn.feed(&[0x89, 0x80, 0, 0, 0, 0]);
    /// assert!(conn.memory_in_use() > 0);
    /// ```
    #[must_use]
    pub fn memory_in_use(&self) -> usize {
        self.reader.input.capacity()
            + self.reader.msg.capacity()
            + self.reader.text.capacity()
            + self.writer.out.capacity()
            + self.writer.masks.as_ref().map_or(0, MaskGen::heap)
    }

    /// Overwrites with zeros every buffered byte (input, reassembly,
    /// output, a pending Pong) and the masking-key seed, then fails the
    /// connection ([`State::Closed`], nothing more sent): for ejecting a
    /// connection whose messages may carry secrets.
    ///
    /// The writes go through [`core::hint::black_box`] so they are not
    /// removed as dead stores. Rust documents `black_box` as best effort,
    /// so this is a strong hint, not a guarantee; a guaranteed wipe needs
    /// volatile writes, which need `unsafe`, which this crate forbids.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{Connection, Event, State};
    ///
    /// let mut conn = Connection::server();
    /// let _ = conn.feed(&[0x82, 0x83, 0, 0, 0, 0, 7, 7, 7]); // masked binary
    /// assert!(matches!(conn.poll(), Ok(Event::Binary(_))));
    /// conn.wipe();
    /// assert_eq!(conn.state(), State::Closed);
    /// assert!(conn.output().is_empty());
    /// assert!(matches!(conn.poll(), Ok(Event::Closed)));
    /// ```
    pub fn wipe(&mut self) {
        let r = &mut self.reader;
        wipe_vec(&mut r.input);
        wipe_vec(&mut r.msg);
        let mut text = core::mem::take(&mut r.text).into_bytes();
        wipe_vec(&mut text);
        r.carry = [0; 4];
        r.carry_len = 0;
        r.pos = 0;
        r.filled = 0;
        r.lent = None;
        r.frame = None;
        r.message = None;
        self.writer.wipe();
    }

    /// The connection's counters.
    ///
    /// # Examples
    ///
    /// See [`Stats`].
    #[must_use]
    pub fn stats(&self) -> Stats {
        let r = &self.reader;
        let w = &self.writer;
        Stats {
            bytes_in: r.bytes_in,
            bytes_out: w.bytes_out,
            frames_in: r.frames_in,
            messages_in: r.messages_in,
            messages_out: w.messages_out,
            pings_in: r.pings_in,
            pongs_in: r.pongs_in,
            closes_in: r.closes_in,
        }
    }

    /// Moves the message the last [`poll`](Self::poll) returned
    /// ([`Event::Text`] or [`Event::Binary`]) into `into`, clearing `into`
    /// first, and returns its kind. A reassembled message is moved by
    /// swapping buffers, with no copy (the connection keeps `into`'s old
    /// allocation for the next message); a single-frame message lent from
    /// the input buffer is copied (at most the input buffer size).
    ///
    /// Returns `None`, changing nothing, when the last poll returned no data
    /// message, or when input was fed since.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{Connection, Event, MessageKind};
    ///
    /// let mut conn = Connection::server();
    /// let _ = conn.feed(&[0x81, 0x82, 0, 0, 0, 0, b'h', b'i']); // masked "hi"
    /// assert!(matches!(conn.poll()?, Event::Text(_)));
    /// let mut owned = Vec::new();
    /// assert_eq!(conn.detach_message(&mut owned), Some(MessageKind::Text));
    /// assert_eq!(owned, b"hi");
    /// assert_eq!(conn.detach_message(&mut owned), None); // already taken
    /// # Ok::<(), ws_net::WsError>(())
    /// ```
    pub fn detach_message(&mut self, into: &mut Vec<u8>) -> Option<MessageKind> {
        let r = &mut self.reader;
        let lent = r.lent.take()?;
        into.clear();
        match lent {
            Lent::Reassembled(MessageKind::Text) => {
                let text = core::mem::take(&mut r.text).into_bytes();
                r.msg = core::mem::replace(into, text);
                Some(MessageKind::Text)
            }
            Lent::Reassembled(kind) => {
                core::mem::swap(into, &mut r.msg);
                Some(kind)
            }
            Lent::Input(kind, start, end) => {
                into.extend_from_slice(r.input.get(start..end).unwrap_or(&[]));
                Some(kind)
            }
        }
    }

    /// Sends an owned [`Message`]: text, binary, Ping, Pong, or Close (a
    /// `Close(None)` sends a Close with no status code).
    ///
    /// # Errors
    ///
    /// As the matching call ([`send_text`](Self::send_text),
    /// [`send_ping`](Self::send_ping), [`close`](Self::close), ...).
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{Connection, Message};
    ///
    /// let mut conn = Connection::server();
    /// conn.send(&Message::from("hi"))?;
    /// conn.send(&Message::Close(None))?;
    /// assert_eq!(conn.output(), [0x81, 0x02, b'h', b'i', 0x88, 0x00]);
    /// # Ok::<(), ws_net::WsError>(())
    /// ```
    pub fn send(&mut self, message: &Message) -> Result<(), WsError> {
        match message {
            Message::Text(text) => self.send_text(text),
            Message::Binary(data) => self.send_binary(data),
            Message::Ping(payload) => self.send_ping(payload),
            Message::Pong(payload) => self.send_pong(payload),
            Message::Close(Some((code, reason))) => self.close(*code, reason),
            Message::Close(None) => self.writer.close(None, ""),
        }
    }

    /// Appends a [`PreparedMessage`]: one copy of frames encoded once, for
    /// broadcast.
    ///
    /// # Errors
    ///
    /// [`WsError::InvalidState`] for the client role (a client masks each
    /// frame with a fresh key), after a Close was sent, or while a
    /// fragmented message is being sent; [`WsError::OutputFull`].
    ///
    /// # Examples
    ///
    /// See [`PreparedMessage`].
    pub fn send_prepared(&mut self, message: &PreparedMessage) -> Result<(), WsError> {
        self.writer.send_prepared(message)
    }
}

/// The output side of a [`Connection`], from
/// [`poll_split`](Connection::poll_split): the same send rules and the same
/// output budget, while the event still borrows the input side.
///
/// # Examples
///
/// See [`Connection::poll_split`].
pub struct Sender<'a> {
    writer: &'a mut Writer,
    limits: &'a Limits,
}

impl fmt::Debug for Sender<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sender")
            .field("pending_output", &self.writer.pending())
            .finish()
    }
}

impl Sender<'_> {
    /// As [`Connection::send_text`].
    ///
    /// # Errors
    ///
    /// As [`Connection::send_text`].
    ///
    /// # Examples
    ///
    /// See [`Connection::poll_split`].
    pub fn send_text(&mut self, text: &str) -> Result<(), WsError> {
        self.writer
            .send_message(self.limits, Kind::Text, text.as_bytes())
    }

    /// As [`Connection::send_binary`].
    ///
    /// # Errors
    ///
    /// As [`Connection::send_binary`].
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{Connection, Event};
    ///
    /// let mut conn = Connection::server();
    /// let _ = conn.feed(&[0x82, 0x81, 0, 0, 0, 0, 9]); // masked binary [9]
    /// let (event, mut sender) = conn.poll_split()?;
    /// if let Event::Binary(data) = event {
    ///     sender.send_binary(data)?;
    /// }
    /// assert_eq!(conn.output(), [0x82, 0x01, 9]);
    /// # Ok::<(), ws_net::WsError>(())
    /// ```
    pub fn send_binary(&mut self, data: &[u8]) -> Result<(), WsError> {
        self.writer.send_message(self.limits, Kind::Binary, data)
    }

    /// As [`Connection::send_ping`].
    ///
    /// # Errors
    ///
    /// As [`Connection::send_ping`].
    ///
    /// # Examples
    ///
    /// ```
    /// let mut conn = ws_net::Connection::server();
    /// let (_, mut sender) = conn.poll_split()?;
    /// sender.send_ping(b"t")?;
    /// assert_eq!(conn.output(), [0x89, 0x01, b't']);
    /// # Ok::<(), ws_net::WsError>(())
    /// ```
    pub fn send_ping(&mut self, payload: &[u8]) -> Result<(), WsError> {
        self.writer.send_control(Opcode::Ping, payload)
    }

    /// As [`Connection::send_pong`].
    ///
    /// # Errors
    ///
    /// As [`Connection::send_pong`].
    ///
    /// # Examples
    ///
    /// ```
    /// let mut conn = ws_net::Connection::server();
    /// let (_, mut sender) = conn.poll_split()?;
    /// sender.send_pong(b"")?;
    /// assert_eq!(conn.output(), [0x8A, 0x00]);
    /// # Ok::<(), ws_net::WsError>(())
    /// ```
    pub fn send_pong(&mut self, payload: &[u8]) -> Result<(), WsError> {
        self.writer.send_control(Opcode::Pong, payload)
    }

    /// As [`Connection::close`].
    ///
    /// # Errors
    ///
    /// As [`Connection::close`].
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::CloseCode;
    ///
    /// let mut conn = ws_net::Connection::server();
    /// let (_, mut sender) = conn.poll_split()?;
    /// sender.close(CloseCode::POLICY_VIOLATION, "session ended")?;
    /// assert_eq!(conn.state(), ws_net::State::Closing);
    /// # Ok::<(), ws_net::WsError>(())
    /// ```
    pub fn close(&mut self, code: CloseCode, reason: &str) -> Result<(), WsError> {
        self.writer.close(Some(code), reason)
    }

    /// As [`Connection::send_prepared`].
    ///
    /// # Errors
    ///
    /// As [`Connection::send_prepared`].
    ///
    /// # Examples
    ///
    /// ```
    /// let update = ws_net::PreparedMessage::text("tick");
    /// let mut conn = ws_net::Connection::server();
    /// let (_, mut sender) = conn.poll_split()?;
    /// sender.send_prepared(&update)?;
    /// assert_eq!(conn.output(), update.as_bytes());
    /// # Ok::<(), ws_net::WsError>(())
    /// ```
    pub fn send_prepared(&mut self, message: &PreparedMessage) -> Result<(), WsError> {
        self.writer.send_prepared(message)
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
    fn test_receive_streamed_and_fast_path_same_events() {
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
    fn test_fragments_empty_pieces_delivered() {
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
    fn test_send_wrong_state_refused() {
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
    fn test_send_over_send_frame_split_into_frames() {
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
    fn test_output_advance_compacts_written_prefix() {
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
    fn test_pong_unwritten_replaced_by_latest() {
        let mut conn = Connection::server();
        let mut wire = masked(0x9, true, b"one");
        wire.extend(masked(0x9, true, b"two"));
        let _ = conn.feed(&wire);
        assert!(matches!(conn.poll().unwrap(), Event::Ping(b"one")));
        assert!(matches!(conn.poll().unwrap(), Event::Ping(b"two")));
        assert_eq!(conn.output(), [0x8A, 0x03, b't', b'w', b'o']);
    }

    #[test]
    fn test_reassembly_large_buffer_released_after_delivery() {
        let mut conn = Connection::server();
        // Two 1 MiB fragments plus one byte: the reassembly buffer grows
        // past Limits::DEFAULT_RETAIN and must be released after delivery.
        let payload = vec![b'a'; Limits::DEFAULT_RETAIN];
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
