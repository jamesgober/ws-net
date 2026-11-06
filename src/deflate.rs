//! permessage-deflate (RFC 7692) on compress-lib: the configuration, the
//! negotiation in both roles, and the per-connection codec state.
//!
//! Without the `deflate` feature only an empty codec type remains, so the
//! connection code reads the same either way.

#[cfg(feature = "deflate")]
pub(crate) use on::{Agreed, Codec, accept, offer, verify};

#[cfg(not(feature = "deflate"))]
pub(crate) use off::Codec;

#[cfg(not(feature = "deflate"))]
mod off {
    use alloc::vec::Vec;

    use alloc::boxed::Box;

    use crate::{conn::Role, error::WsError, extension::Negotiated, prepared::SendOptions};

    /// No codec exists without the feature: a connection's `Option` of it
    /// is always `None`.
    pub(crate) enum Codec {}

    impl Codec {
        pub(crate) fn new(_negotiated: Negotiated, _role: Role) -> Option<Box<Self>> {
            None
        }
        pub(crate) fn negotiated(&self) -> &Negotiated {
            match *self {}
        }
        pub(crate) fn begin(&mut self, _compressed: bool) {
            match *self {}
        }
        pub(crate) fn inflating(&self) -> bool {
            match *self {}
        }
        pub(crate) fn admit(&mut self, _len: u64, _max_message: u64) -> Result<(), WsError> {
            match *self {}
        }
        #[allow(clippy::ptr_arg)]
        pub(crate) fn inflate(
            &mut self,
            _chunk: &[u8],
            _last: bool,
            _msg: &mut Vec<u8>,
            _max_message: u64,
        ) -> Result<(), WsError> {
            match *self {}
        }
        pub(crate) fn end_message(&mut self) {
            match *self {}
        }
        pub(crate) fn compress(&mut self, _data: &[u8], _options: SendOptions) -> Option<&[u8]> {
            match *self {}
        }
        pub(crate) fn unsent(&mut self) {
            match *self {}
        }
        pub(crate) fn trim(&mut self, _retain: usize) {
            match *self {}
        }
        pub(crate) fn prepared_bits(&self) -> Option<u8> {
            match *self {}
        }
        pub(crate) fn release(&mut self) {
            match *self {}
        }
        pub(crate) fn memory(&self) -> usize {
            match *self {}
        }
        pub(crate) fn wipe(&mut self) {
            match *self {}
        }
    }
}

#[cfg(feature = "deflate")]
pub(crate) mod on {
    use alloc::{boxed::Box, vec::Vec};
    use core::fmt;

    use compress_lib::{
        ErrorKind, Level,
        message::{Compressor, Decompressor, MessageConfig},
    };

    use crate::{
        conn::Role,
        error::{HandshakeError, WsError},
        extension::{Negotiated, Offer, Param},
        prepared::SendOptions,
    };

    /// The extension's registered name.
    const NAME: &str = "permessage-deflate";

    /// The longest header value this crate writes: the name and all four
    /// parameters with two-digit window bits.
    const VALUE_MAX: usize = 128;

    /// What a server accepts and a client offers (RFC 7692 section 7).
    ///
    /// The defaults are memory-lean and keep secrets from leaking across
    /// messages: no context takeover in either direction (each message
    /// compressed on its own, so attacker-chosen data in one message cannot
    /// probe a secret in an earlier one through compressed sizes, RFC 7692
    /// section 8), window bits 15 accepted and offered, level 1, and
    /// messages under 256 bytes sent uncompressed.
    ///
    /// | Setting | Default | Server | Client |
    /// |---|---|---|---|
    /// | server context takeover | off | may keep its compression window between messages | lets the server keep it (otherwise asks for `server_no_context_takeover`) |
    /// | client context takeover | off | lets the client keep it (otherwise answers `client_no_context_takeover`) | keeps its window between messages |
    /// | server window bits | 15 | the largest window it compresses with | the largest it lets the server use |
    /// | client window bits | 15 | the largest it lets the client use; below 15 it declines a client that cannot be limited | the largest it compresses with |
    /// | level | 1 | compression level (0 to 9) | the same |
    /// | min size | 256 | smaller messages go uncompressed | the same |
    ///
    /// Memory per connection (compress-lib's figures): a decompressor
    /// without takeover holds its decode tables, about 12 KiB, and with
    /// takeover adds the window (`2^bits` bytes); a compressor at level 1
    /// holds about 330 KiB at 15 bits and about 30 KiB at 9. Both are built
    /// on first use. [`Connection::release_memory`](crate::Connection::release_memory)
    /// drops one that holds no context.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::DeflateConfig;
    ///
    /// let config = DeflateConfig::new().with_client_max_window_bits(10).with_min_size(64);
    /// assert_eq!(config.client_max_window_bits(), 10);
    /// assert!(!config.server_context_takeover());
    /// assert_eq!(DeflateConfig::new().with_server_max_window_bits(20).server_max_window_bits(), 15);
    /// ```
    #[non_exhaustive]
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct DeflateConfig {
        server_takeover: bool,
        client_takeover: bool,
        server_bits: u8,
        client_bits: u8,
        level: u8,
        min_size: usize,
    }

    impl Default for DeflateConfig {
        fn default() -> Self {
            Self::new()
        }
    }

    impl DeflateConfig {
        /// The defaults in the table above.
        ///
        /// # Examples
        ///
        /// See [`DeflateConfig`].
        #[must_use]
        pub const fn new() -> Self {
            Self {
                server_takeover: false,
                client_takeover: false,
                server_bits: 15,
                client_bits: 15,
                level: 1,
                min_size: 256,
            }
        }

        /// Whether the server may keep its compression window between
        /// messages (better ratio for similar messages; costs the window per
        /// connection, and lets one message's data probe another's).
        ///
        /// # Examples
        ///
        /// ```
        /// assert!(ws_net::DeflateConfig::new().with_server_context_takeover(true).server_context_takeover());
        /// ```
        #[must_use]
        pub const fn with_server_context_takeover(mut self, on: bool) -> Self {
            self.server_takeover = on;
            self
        }

        /// Whether the client may keep its compression window between
        /// messages.
        ///
        /// # Examples
        ///
        /// ```
        /// assert!(ws_net::DeflateConfig::new().with_client_context_takeover(true).client_context_takeover());
        /// ```
        #[must_use]
        pub const fn with_client_context_takeover(mut self, on: bool) -> Self {
            self.client_takeover = on;
            self
        }

        /// The largest window the server compresses with, clamped to 8 to
        /// 15 bits.
        ///
        /// # Examples
        ///
        /// ```
        /// assert_eq!(ws_net::DeflateConfig::new().with_server_max_window_bits(3).server_max_window_bits(), 8);
        /// ```
        #[must_use]
        pub const fn with_server_max_window_bits(mut self, bits: u8) -> Self {
            self.server_bits = clamp_bits(bits);
            self
        }

        /// The largest window the client compresses with, clamped to 8 to
        /// 15 bits.
        ///
        /// # Examples
        ///
        /// ```
        /// assert_eq!(ws_net::DeflateConfig::new().with_client_max_window_bits(9).client_max_window_bits(), 9);
        /// ```
        #[must_use]
        pub const fn with_client_max_window_bits(mut self, bits: u8) -> Self {
            self.client_bits = clamp_bits(bits);
            self
        }

        /// The compression level, 0 (stored, no compression) to 9, clamped.
        /// Level 1 is the fastest that compresses.
        ///
        /// # Examples
        ///
        /// ```
        /// assert_eq!(ws_net::DeflateConfig::new().with_level(12).level(), 9);
        /// ```
        #[must_use]
        pub const fn with_level(mut self, level: u8) -> Self {
            self.level = if level > 9 { 9 } else { level };
            self
        }

        /// Messages shorter than this are sent uncompressed, unless sent
        /// with [`SendOptions::compressed`].
        ///
        /// # Examples
        ///
        /// ```
        /// assert_eq!(ws_net::DeflateConfig::new().with_min_size(0).min_size(), 0);
        /// ```
        #[must_use]
        pub const fn with_min_size(mut self, bytes: usize) -> Self {
            self.min_size = bytes;
            self
        }

        /// See [`with_server_context_takeover`](Self::with_server_context_takeover).
        ///
        /// # Examples
        ///
        /// See [`DeflateConfig`].
        #[must_use]
        pub const fn server_context_takeover(&self) -> bool {
            self.server_takeover
        }

        /// See [`with_client_context_takeover`](Self::with_client_context_takeover).
        ///
        /// # Examples
        ///
        /// See [`DeflateConfig`].
        #[must_use]
        pub const fn client_context_takeover(&self) -> bool {
            self.client_takeover
        }

        /// See [`with_server_max_window_bits`](Self::with_server_max_window_bits).
        ///
        /// # Examples
        ///
        /// See [`DeflateConfig`].
        #[must_use]
        pub const fn server_max_window_bits(&self) -> u8 {
            self.server_bits
        }

        /// See [`with_client_max_window_bits`](Self::with_client_max_window_bits).
        ///
        /// # Examples
        ///
        /// See [`DeflateConfig`].
        #[must_use]
        pub const fn client_max_window_bits(&self) -> u8 {
            self.client_bits
        }

        /// See [`with_level`](Self::with_level).
        ///
        /// # Examples
        ///
        /// See [`DeflateConfig`].
        #[must_use]
        pub const fn level(&self) -> u8 {
            self.level
        }

        /// See [`with_min_size`](Self::with_min_size).
        ///
        /// # Examples
        ///
        /// See [`DeflateConfig`].
        #[must_use]
        pub const fn min_size(&self) -> usize {
            self.min_size
        }
    }

    const fn clamp_bits(bits: u8) -> u8 {
        if bits < 8 {
            8
        } else if bits > 15 {
            15
        } else {
            bits
        }
    }

    /// The parameters a handshake agreed on, from
    /// [`Negotiated::deflate`](crate::extension::Negotiated::deflate).
    /// Each direction is described once: the `server_` fields govern what
    /// the server sends, the `client_` fields what the client sends.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{AcceptPolicy, DeflateConfig, ServerHandshake};
    ///
    /// let h = ServerHandshake::from_request("GET", "/", [
    ///     ("Host", &b"a.example"[..]), ("Upgrade", b"websocket"), ("Connection", b"Upgrade"),
    ///     ("Sec-WebSocket-Version", b"13"), ("Sec-WebSocket-Key", b"dGhlIHNhbXBsZSBub25jZQ=="),
    ///     ("Sec-WebSocket-Extensions", b"permessage-deflate; client_max_window_bits"),
    /// ])?;
    /// let policy = AcceptPolicy::new().with_deflate(DeflateConfig::new());
    /// let params = *policy.check(&h)?.extensions.deflate().expect("accepted");
    /// assert!(params.server_no_context_takeover && params.client_no_context_takeover);
    /// assert_eq!((params.server_max_window_bits, params.client_max_window_bits), (15, 15));
    /// # Ok::<(), ws_net::HandshakeError>(())
    /// ```
    #[non_exhaustive]
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct DeflateParams {
        /// The server compresses each message on its own.
        pub server_no_context_takeover: bool,
        /// The client compresses each message on its own.
        pub client_no_context_takeover: bool,
        /// The largest window the server compresses with (8 to 15).
        pub server_max_window_bits: u8,
        /// The largest window the client compresses with (8 to 15).
        pub client_max_window_bits: u8,
    }

    /// An agreement: the parameters, this end's own settings, and the
    /// header value that states it.
    #[derive(Clone, Copy, PartialEq, Eq, Hash)]
    pub(crate) struct Agreed {
        pub(crate) params: DeflateParams,
        level: u8,
        min_size: usize,
        value: [u8; VALUE_MAX],
        value_len: u8,
    }

    impl fmt::Debug for Agreed {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Agreed")
                .field("params", &self.params)
                .field("level", &self.level)
                .field("min_size", &self.min_size)
                .finish()
        }
    }

    impl Agreed {
        /// The `Sec-WebSocket-Extensions` element for this agreement.
        pub(crate) fn value(&self) -> &[u8] {
            self.value.get(..usize::from(self.value_len)).unwrap_or(&[])
        }
    }

    /// A header value in a fixed buffer (at most [`VALUE_MAX`] bytes).
    struct Value {
        bytes: [u8; VALUE_MAX],
        len: usize,
    }

    impl Value {
        fn new() -> Self {
            let mut v = Self {
                bytes: [0; VALUE_MAX],
                len: 0,
            };
            // budget: fixed: a 128-byte array, no heap
            v.push(NAME.as_bytes());
            v
        }

        fn push(&mut self, piece: &[u8]) {
            let end = self.len + piece.len();
            if let Some(dst) = self.bytes.get_mut(self.len..end) {
                dst.copy_from_slice(piece);
                self.len = end;
            }
        }

        fn param(&mut self, name: &str, bits: Option<u8>) {
            // budget: fixed: a 128-byte array, no heap
            self.push(b"; ");
            self.push(name.as_bytes());
            if let Some(b) = bits {
                self.push(b"=");
                if b >= 10 {
                    self.push(&[b'1', b'0' + (b - 10)]);
                } else {
                    self.push(&[b'0' + b]);
                }
            }
        }
    }

    /// The parameters of one offer or response element, each at most once.
    #[derive(Clone, Copy, Default)]
    struct Elem {
        snct: bool,
        cnct: bool,
        smwb: Option<u8>,
        /// Present, with a value or none.
        cmwb: Option<Option<u8>>,
    }

    /// A window size: a decimal 8 to 15 without leading zeros.
    fn bits(value: &str) -> Option<u8> {
        match value {
            "8" => Some(8),
            "9" => Some(9),
            "10" => Some(10),
            "11" => Some(11),
            "12" => Some(12),
            "13" => Some(13),
            "14" => Some(14),
            "15" => Some(15),
            _ => None,
        }
    }

    /// Reads an element's parameters. `None` for an unknown name, a
    /// repeated one, or a bad value: an offer is then declined, a response
    /// fails the handshake. In a response `client_max_window_bits` needs a
    /// value.
    fn read<'a>(params: impl Iterator<Item = Param<'a>>, response: bool) -> Option<Elem> {
        let mut e = Elem::default();
        let mut seen = [false; 4];
        for p in params {
            let slot = [
                "server_no_context_takeover",
                "client_no_context_takeover",
                "server_max_window_bits",
                "client_max_window_bits",
            ]
            .iter()
            .position(|n| n.eq_ignore_ascii_case(p.name))?;
            let first = seen.get_mut(slot)?;
            if *first {
                return None;
            }
            *first = true;
            match (slot, p.value) {
                (0, None) => e.snct = true,
                (1, None) => e.cnct = true,
                (2, Some(v)) => e.smwb = Some(bits(v)?),
                (3, None) if !response => e.cmwb = Some(None),
                (3, Some(v)) => e.cmwb = Some(Some(bits(v)?)),
                _ => return None,
            }
        }
        Some(e)
    }

    fn agreed(params: DeflateParams, config: &DeflateConfig, value: &Value) -> Agreed {
        Agreed {
            params,
            level: config.level,
            min_size: config.min_size,
            value: value.bytes,
            value_len: value.len as u8,
        }
    }

    /// The server's choice: the first offer it can accept, in the client's
    /// order (RFC 7692 section 5). Offers with an unknown, repeated, or
    /// invalid parameter are declined, as is one whose client window
    /// cannot be limited to the configured size.
    pub(crate) fn accept<'a>(
        config: &DeflateConfig,
        offers: impl Iterator<Item = Offer<'a>>,
    ) -> Option<Agreed> {
        offers
            .filter(|o| o.name().eq_ignore_ascii_case(NAME))
            .find_map(|o| accept_one(config, &read(o.params(), false)?))
    }

    fn accept_one(config: &DeflateConfig, offer: &Elem) -> Option<Agreed> {
        let server_no = !config.server_takeover || offer.snct;
        let client_no = !config.client_takeover || offer.cnct;
        let server_bits = config.server_bits.min(offer.smwb.unwrap_or(15));
        let client_bits = match offer.cmwb {
            Some(hint) => config.client_bits.min(hint.unwrap_or(15)),
            // A client that did not offer the parameter may use 15 bits,
            // and the response may not mention it (section 7.1.2.2).
            None if config.client_bits < 15 => return None,
            None => 15,
        };
        let mut value = Value::new();
        if server_no {
            value.param("server_no_context_takeover", None);
        }
        if client_no {
            value.param("client_no_context_takeover", None);
        }
        if offer.smwb.is_some() || server_bits < 15 {
            value.param("server_max_window_bits", Some(server_bits));
        }
        if offer.cmwb.is_some() && client_bits < 15 {
            value.param("client_max_window_bits", Some(client_bits));
        }
        let params = DeflateParams {
            server_no_context_takeover: server_no,
            client_no_context_takeover: client_no,
            server_max_window_bits: server_bits,
            client_max_window_bits: client_bits,
        };
        Some(agreed(params, config, &value))
    }

    /// The client's offer: one element, asking for what the configuration
    /// does not allow the server and stating what the client will do.
    pub(crate) fn offer(config: &DeflateConfig) -> ([u8; VALUE_MAX], usize) {
        let mut value = Value::new();
        if !config.server_takeover {
            value.param("server_no_context_takeover", None);
        }
        if !config.client_takeover {
            value.param("client_no_context_takeover", None);
        }
        if config.server_bits < 15 {
            value.param("server_max_window_bits", Some(config.server_bits));
        }
        let hint = (config.client_bits < 15).then_some(config.client_bits);
        value.param("client_max_window_bits", hint);
        (value.bytes, value.len)
    }

    /// Checks the server's acceptance against the offer (RFC 7692 section
    /// 7): every parameter known, once, valid, and within what was asked.
    pub(crate) fn verify(
        config: &DeflateConfig,
        element: &Offer<'_>,
    ) -> Result<Agreed, HandshakeError> {
        let e = read(element.params(), true).ok_or(HandshakeError::InvalidExtensions)?;
        // The offer asked for no server takeover unless allowed, and for a
        // server window no larger than configured.
        if !config.server_takeover && !e.snct {
            return Err(HandshakeError::InvalidExtensions);
        }
        let server_bits = e.smwb.unwrap_or(15);
        if server_bits > config.server_bits {
            return Err(HandshakeError::InvalidExtensions);
        }
        let client_bits = e.cmwb.flatten().unwrap_or(15).min(config.client_bits);
        let client_no = e.cnct || !config.client_takeover;
        let params = DeflateParams {
            server_no_context_takeover: e.snct,
            client_no_context_takeover: client_no,
            server_max_window_bits: server_bits,
            client_max_window_bits: client_bits,
        };
        let mut value = Value::new();
        if e.snct {
            value.param("server_no_context_takeover", None);
        }
        if client_no {
            value.param("client_no_context_takeover", None);
        }
        if server_bits < 15 {
            value.param("server_max_window_bits", Some(server_bits));
        }
        if client_bits < 15 {
            value.param("client_max_window_bits", Some(client_bits));
        }
        Ok(agreed(params, config, &value))
    }

    /// One connection's compression state: the agreement, an engine per
    /// direction (built on first use), and the message being inflated.
    pub(crate) struct Codec {
        negotiated: Negotiated,
        tx_config: MessageConfig,
        tx_keep: bool,
        rx_config: MessageConfig,
        rx_keep: bool,
        min_size: usize,
        tx: Option<Compressor>,
        rx: Option<Decompressor>,
        /// A compressed message waiting to be framed.
        scratch: Vec<u8>,
        /// The message being received is compressed.
        inflating: bool,
        /// Compressed bytes of the message being received.
        wire: u64,
    }

    impl Codec {
        /// The codec for what `negotiated` holds, or `None` when nothing
        /// that compresses was negotiated.
        pub(crate) fn new(negotiated: Negotiated, role: Role) -> Option<Box<Self>> {
            let a = negotiated.agreed()?;
            let p = a.params;
            let (tx_bits, tx_keep, rx_bits, rx_keep) = match role {
                Role::Server => (
                    p.server_max_window_bits,
                    !p.server_no_context_takeover,
                    p.client_max_window_bits,
                    !p.client_no_context_takeover,
                ),
                Role::Client => (
                    p.client_max_window_bits,
                    !p.client_no_context_takeover,
                    p.server_max_window_bits,
                    !p.server_no_context_takeover,
                ),
            };
            let level = Level::new(a.level).unwrap_or(Level::FAST);
            // budget: fixed: one allocation per compressing connection
            Some(Box::new(Self {
                negotiated,
                tx_config: MessageConfig::new()
                    .with_window_bits(tx_bits)
                    .with_context_takeover(tx_keep)
                    .with_level(level),
                tx_keep,
                rx_config: MessageConfig::new()
                    .with_window_bits(rx_bits)
                    .with_context_takeover(rx_keep),
                rx_keep,
                min_size: a.min_size,
                tx: None,
                rx: None,
                scratch: Vec::new(),
                inflating: false,
                wire: 0,
            }))
        }

        pub(crate) fn negotiated(&self) -> &Negotiated {
            &self.negotiated
        }

        /// A data message starts; `compressed` is its RSV1 bit.
        pub(crate) fn begin(&mut self, compressed: bool) {
            self.inflating = compressed;
            self.wire = 0;
        }

        pub(crate) fn inflating(&self) -> bool {
            self.inflating
        }

        /// Admits a frame of `len` compressed bytes into the message. The
        /// compressed size is bounded too, by the message budget plus a
        /// sixty-fourth: DEFLATE grows data by far less, and without the
        /// bound a stream of empty blocks would be read without end.
        pub(crate) fn admit(&mut self, len: u64, max_message: u64) -> Result<(), WsError> {
            let cap = max_message
                .saturating_add(max_message / 64)
                .saturating_add(1024);
            self.wire = self.wire.saturating_add(len);
            if self.wire > cap {
                return Err(WsError::MessageTooLarge);
            }
            Ok(())
        }

        /// Inflates one piece of the message's compressed payload onto
        /// `msg`, which holds the message so far; `last` ends the message.
        /// The output is capped at `max_message` while it is produced, so a
        /// compressed bomb stops at the budget (1009).
        ///
        /// Inflated text is validated whole once the message is complete,
        /// not piece by piece: compress-lib drops the output of a step that
        /// fails, so a check in pieces would report a bad byte or a failure
        /// after it depending on how the input was split. The budget bounds
        /// the work before the check.
        pub(crate) fn inflate(
            &mut self,
            chunk: &[u8],
            last: bool,
            msg: &mut Vec<u8>,
            max_message: u64,
        ) -> Result<(), WsError> {
            if self.rx.is_none() {
                let rx =
                    Decompressor::new(self.rx_config).map_err(|_| WsError::AllocationFailed)?;
                self.rx = Some(rx);
            }
            let Some(rx) = self.rx.as_mut() else {
                return Err(WsError::AllocationFailed);
            };
            let max = usize::try_from(max_message).unwrap_or(usize::MAX);
            // budget: max_message: compress-lib caps the output at `max`
            // while inflating, growing `msg` with `try_reserve_exact`.
            match rx.decompress_fragment(chunk, last, msg, max) {
                Ok(_) => Ok(()),
                Err(e) => Err(match e.kind() {
                    ErrorKind::OutputLimit => WsError::MessageTooLarge,
                    ErrorKind::AllocationFailed => WsError::AllocationFailed,
                    _ => WsError::InvalidCompressedData,
                }),
            }
        }

        pub(crate) fn end_message(&mut self) {
            self.inflating = false;
            self.wire = 0;
        }

        /// Compresses `data` for sending, or `None` to send it as it is:
        /// the options forbid compression, it is under the minimum size, or
        /// compressing did not make it smaller (unless the options ask for
        /// compression). After `None` from a compressed attempt, or after
        /// the caller does not send the result, [`unsent`](Self::unsent)
        /// must run.
        pub(crate) fn compress(&mut self, data: &[u8], options: SendOptions) -> Option<&[u8]> {
            if options.is_uncompressed() {
                return None;
            }
            let forced = options.forces_compression();
            if !forced && data.len() < self.min_size {
                return None;
            }
            if self.tx.is_none() {
                self.tx = Some(Compressor::new(self.tx_config).ok()?);
            }
            let tx = self.tx.as_mut()?;
            self.scratch.clear();
            // budget: caller: the compressed form of a message the caller
            // sends, checked against `max_output` before it is queued.
            if tx.compress_message(data, &mut self.scratch).is_err()
                || (!forced && self.scratch.len() >= data.len())
            {
                self.unsent();
                return None;
            }
            Some(&self.scratch)
        }

        /// The last compressed message was not sent: with context takeover
        /// the compressor's window now holds a message the peer never
        /// received, so it starts over (correct for the peer, whose window
        /// only gains back-references we no longer make).
        pub(crate) fn unsent(&mut self) {
            if self.tx_keep {
                if let Some(tx) = self.tx.as_mut() {
                    tx.reset();
                }
            }
        }

        /// Frees the compression scratch buffer when it outgrew `retain`.
        pub(crate) fn trim(&mut self, retain: usize) {
            if self.scratch.capacity() > retain {
                self.scratch = Vec::new();
            } else {
                self.scratch.clear();
            }
        }

        /// The largest window of a prepared message this connection may
        /// send as it is: one compressed without context is valid when this
        /// end also compresses without context.
        pub(crate) fn prepared_bits(&self) -> Option<u8> {
            (!self.tx_keep).then_some(self.tx_config.window_bits())
        }

        /// Drops the engines that hold no context between messages, and
        /// the scratch buffer.
        pub(crate) fn release(&mut self) {
            if !self.tx_keep {
                self.tx = None;
            }
            if !self.rx_keep && !self.inflating {
                self.rx = None;
            }
            self.scratch = Vec::new();
        }

        /// Heap bytes held: this state and both engines.
        pub(crate) fn memory(&self) -> usize {
            core::mem::size_of::<Self>()
                + self.tx.as_ref().map_or(0, Compressor::memory_in_use)
                + self.rx.as_ref().map_or(0, Decompressor::memory_in_use)
                + self.scratch.capacity()
        }

        /// Forgets every compressed byte this connection saw or sent.
        pub(crate) fn wipe(&mut self) {
            crate::conn::wipe_vec(&mut self.scratch);
            // The engines' windows hold plaintext of earlier messages.
            self.tx = None;
            self.rx = None;
            self.end_message();
        }
    }
}
