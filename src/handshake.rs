//! The opening handshake (RFC 6455 section 4): validating a client's
//! upgrade request, computing `Sec-WebSocket-Accept`, writing the `101`
//! response, and the client's side of the same exchange.
//!
//! Two ways in, with the same rules behind both:
//!
//! - **Behind an HTTP layer** ([`ServerHandshake::from_request`],
//!   [`ClientHandshake::verify`]): the method, target, and header fields as
//!   `(name, value)` pairs, the shape `http-net`'s `RequestHead` and
//!   `ResponseHead` yield.
//! - **Standalone over raw bytes** ([`ServerHandshake::from_head`],
//!   [`ClientHandshake::verify_head`]): the head as it came off the socket,
//!   read by the strict, bounded reader in `head.rs`.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;

use parse_net::{list::contains_token, text::is_token};

use crate::{
    base64,
    error::HandshakeError,
    extension::{self, Negotiated, Offers},
    head::{self, is_visible},
    sha1::Sha1,
};

/// The GUID RFC 6455 section 1.3 appends to the client's key.
const GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// A `Sec-WebSocket-Accept` value: base64 of
/// `SHA-1(key || "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")`, always 28 ASCII
/// characters.
///
/// # Examples
///
/// ```
/// let accept = ws_net::accept_key(b"dGhlIHNhbXBsZSBub25jZQ==");
/// assert_eq!(accept.as_str(), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="); // RFC 6455 section 1.3
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AcceptKey([u8; 28]);

impl AcceptKey {
    /// The value as text.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(ws_net::accept_key(b"x").as_str().len(), 28);
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.0).unwrap_or("")
    }

    /// The value as bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(ws_net::accept_key(b"x").as_bytes().len(), 28);
    /// ```
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for AcceptKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AcceptKey").field(&self.as_str()).finish()
    }
}

impl fmt::Display for AcceptKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Computes the `Sec-WebSocket-Accept` value for a client's
/// `Sec-WebSocket-Key`. Validation of the key is
/// [`ServerHandshake`]'s job; this is the bare computation.
///
/// # Examples
///
/// ```
/// assert_eq!(
///     ws_net::accept_key(b"dGhlIHNhbXBsZSBub25jZQ==").as_str(),
///     "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
/// );
/// ```
#[must_use]
pub fn accept_key(key: &[u8]) -> AcceptKey {
    let mut h = Sha1::new();
    h.update(key);
    h.update(GUID);
    let digest = h.finish();
    let mut out = [0u8; 28];
    base64::encode_into(&digest, &mut out);
    AcceptKey(out)
}

/// Whether the comma list `value` holds `token` (ASCII case-insensitive).
/// A value that is not a valid RFC 9110 list holds nothing (fail closed).
fn list_has(value: &[u8], token: &[u8]) -> bool {
    contains_token([value], token)
}

/// A validated opening request, ready to be accepted.
///
/// It carries what a server decides policy on: the [`target`](Self::target)
/// to route, the [`host`](Self::host) to check against its own authority
/// (DNS-rebinding defense), and the [`origin`](Self::origin) to check
/// against the pages allowed to connect (cross-site WebSocket hijacking
/// defense). Refuse with `403` when a check fails; this crate makes no
/// policy decision itself.
///
/// # Examples
///
/// ```
/// use ws_net::ServerHandshake;
///
/// // The request from RFC 6455 section 1.2, as raw bytes.
/// let request = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\n\
///     Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
///     Origin: http://example.com\r\nSec-WebSocket-Protocol: chat, superchat\r\n\
///     Sec-WebSocket-Version: 13\r\n\r\n";
/// let (handshake, head_len) = ServerHandshake::from_head(request)?.expect("complete head");
/// assert_eq!(head_len, request.len());
/// assert_eq!(handshake.origin(), Some("http://example.com"));
/// assert_eq!(handshake.accept_key().as_str(), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
/// assert_eq!(handshake.protocols().collect::<Vec<_>>(), ["chat", "superchat"]);
///
/// let mut response = Vec::new();
/// handshake.write_response(Some("chat"), &mut response)?;
/// assert!(response.starts_with(b"HTTP/1.1 101 Switching Protocols\r\n"));
/// # Ok::<(), ws_net::HandshakeError>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct ServerHandshake {
    accept: AcceptKey,
    /// One allocation for everything kept: the target, `Host`, `Origin`,
    /// the offered protocols joined by `,`, and the offered extensions
    /// joined by `, `, in that order.
    buf: String,
    /// Where each part of `buf` ends: target, host, origin, protocols,
    /// extensions.
    ends: [usize; 5],
    has_origin: bool,
}

impl fmt::Debug for ServerHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // budget: max_head: the request's protocols, at most `MAX_PROTOCOLS`.
        f.debug_struct("ServerHandshake")
            // The path only: a query string can carry a token.
            .field("path", &self.target().split('?').next().unwrap_or(""))
            .field("host", &self.host())
            .field("origin", &self.origin())
            .field("protocols", &self.protocols().collect::<Vec<_>>())
            .field("extensions", &self.part(4))
            .finish_non_exhaustive()
    }
}

/// Whether `name` is a field the handshake writes itself, so a caller may
/// not add it: `host`, `upgrade`, `connection`, any `sec-websocket-*`, and
/// the body framing fields.
fn reserved(name: &str) -> bool {
    [
        "host",
        "upgrade",
        "connection",
        "content-length",
        "transfer-encoding",
        "origin",
    ]
    .iter()
    .any(|r| name.eq_ignore_ascii_case(r))
        || name
            .get(..14)
            .is_some_and(|p| p.eq_ignore_ascii_case("sec-websocket-"))
}

/// Checks an extra header: a token name that is not reserved, and a field
/// value with no control bytes.
fn check_extra(name: &str, value: &[u8]) -> Result<(), HandshakeError> {
    if !is_token(name.as_bytes())
        || reserved(name)
        || parse_net::scan::check_field_value(value).is_err()
        || value.first().is_some_and(|b| *b == b' ' || *b == b'\t')
        || value.last().is_some_and(|b| *b == b' ' || *b == b'\t')
    {
        return Err(HandshakeError::InvalidRequest);
    }
    Ok(())
}

impl ServerHandshake {
    /// The largest request head [`from_head`](Self::from_head) accepts, and
    /// the largest response head
    /// [`ClientHandshake::verify_head`] accepts: 16 KiB.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(ws_net::ServerHandshake::MAX_HEAD, 16 * 1024);
    /// ```
    pub const MAX_HEAD: usize = head::MAX_HEAD;

    /// The most subprotocols accepted from one request, over all its
    /// `Sec-WebSocket-Protocol` fields; one more is
    /// [`HandshakeError::InvalidProtocol`].
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(ws_net::ServerHandshake::MAX_PROTOCOLS, 64);
    /// ```
    pub const MAX_PROTOCOLS: usize = 64;

    /// The most extension offers accepted from one request, over all its
    /// `Sec-WebSocket-Extensions` fields; one more is
    /// [`HandshakeError::InvalidExtensions`].
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(ws_net::ServerHandshake::MAX_EXTENSION_OFFERS, 16);
    /// ```
    pub const MAX_EXTENSION_OFFERS: usize = extension::MAX_OFFERS;

    /// Validates a client's opening request (RFC 6455 section 4.2.1) from
    /// its method, request target, and header fields, as an HTTP layer
    /// parsed them. With `http-net`:
    /// `ServerHandshake::from_request(req.method_str(), req.target(), req.headers())`.
    ///
    /// Checked: the method is `GET`; the target is visible ASCII; exactly
    /// one `Host`; `Upgrade` lists `websocket` and `Connection` lists
    /// `upgrade` (case-insensitive, in any field of that name);
    /// exactly one `Sec-WebSocket-Version`, equal to `13`; exactly one
    /// `Sec-WebSocket-Key`, the canonical base64 of 16 bytes; at most one
    /// `Origin`; every offered subprotocol a token, at most 64; no body (no
    /// `Transfer-Encoding`, no `Content-Length` other than `0`), because the
    /// bytes after the head are the first frames. The HTTP
    /// layer is trusted for the rest (an HTTP/1.1 request, well-formed
    /// fields); [`from_head`](Self::from_head) checks those too.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::NotGet`], [`MalformedHead`](HandshakeError::MalformedHead)
    /// (bad target), [`InvalidHost`](HandshakeError::InvalidHost),
    /// [`MissingUpgrade`](HandshakeError::MissingUpgrade),
    /// [`MissingConnectionUpgrade`](HandshakeError::MissingConnectionUpgrade),
    /// [`UnsupportedVersion`](HandshakeError::UnsupportedVersion),
    /// [`MissingKey`](HandshakeError::MissingKey),
    /// [`InvalidKey`](HandshakeError::InvalidKey),
    /// [`InvalidOrigin`](HandshakeError::InvalidOrigin),
    /// [`InvalidProtocol`](HandshakeError::InvalidProtocol),
    /// [`UnexpectedBody`](HandshakeError::UnexpectedBody). Answer with
    /// [`HandshakeError::write_response`].
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::ServerHandshake;
    ///
    /// let headers = [
    ///     ("Host", &b"127.0.0.1:8080"[..]),
    ///     ("Upgrade", b"websocket"),
    ///     ("Connection", b"keep-alive, Upgrade"),
    ///     ("Sec-WebSocket-Version", b"13"),
    ///     ("Sec-WebSocket-Key", b"dGhlIHNhbXBsZSBub25jZQ=="),
    ///     ("Origin", b"http://127.0.0.1:8080"),
    /// ];
    /// let handshake = ServerHandshake::from_request("GET", "/rpc", headers)?;
    /// assert_eq!(handshake.target(), "/rpc");
    /// assert_eq!(handshake.host(), "127.0.0.1:8080");
    /// # Ok::<(), ws_net::HandshakeError>(())
    /// ```
    pub fn from_request<'h, I>(
        method: &str,
        target: &str,
        headers: I,
    ) -> Result<Self, HandshakeError>
    where
        I: IntoIterator<Item = (&'h str, &'h [u8])>,
    {
        if method != "GET" {
            return Err(HandshakeError::NotGet);
        }
        // Origin-form only: a resource name starting with `/` (RFC 6455
        // section 4.1). An absolute-form target would carry an authority
        // that HTTP says to use instead of `Host`, so the Host policy would
        // check a value the target overrides; `*` and authority-form are
        // not WebSocket requests.
        if !target.starts_with('/') || target.starts_with("//") || !is_visible(target.as_bytes()) {
            return Err(HandshakeError::MalformedHead);
        }
        let mut upgrade = false;
        let mut connection = false;
        let (mut hosts, mut host): (usize, &[u8]) = (0, &[]);
        let (mut origins, mut origin): (usize, &[u8]) = (0, &[]);
        let (mut keys, mut key): (usize, &[u8]) = (0, &[]);
        let (mut versions, mut version_ok) = (0usize, false);
        let mut body = false;
        // Borrowed until the record is built, so it takes one allocation.
        let mut protocols: [&[u8]; Self::MAX_PROTOCOLS] = [&[]; Self::MAX_PROTOCOLS];
        let mut protocol_count = 0usize;
        let mut extensions: [&[u8]; extension::MAX_OFFERS] = [&[]; extension::MAX_OFFERS];
        let mut extension_count = 0usize;
        let mut offers = 0usize;
        for (name, value) in headers {
            if name.eq_ignore_ascii_case("host") {
                hosts += 1;
                host = value;
            } else if name.eq_ignore_ascii_case("upgrade") {
                upgrade |= list_has(value, b"websocket");
            } else if name.eq_ignore_ascii_case("connection") {
                connection |= list_has(value, b"upgrade");
            } else if name.eq_ignore_ascii_case("sec-websocket-key") {
                keys += 1;
                key = value;
            } else if name.eq_ignore_ascii_case("sec-websocket-version") {
                versions += 1;
                version_ok = value == b"13";
            } else if name.eq_ignore_ascii_case("origin") {
                origins += 1;
                origin = value;
            } else if name.eq_ignore_ascii_case("sec-websocket-extensions") {
                // Each field with an offer holds at least one, so at most
                // MAX_OFFERS fields are kept.
                offers += extension::validate(value, extension::MAX_OFFERS - offers)?;
                // Each element is one offer (validated just now), so at
                // most MAX_OFFERS are kept; empty elements are dropped so
                // the stored list re-parses whatever the input's spacing.
                if let Ok(list) = parse_net::list(value) {
                    for element in list.iter() {
                        if let Some(slot) = extensions.get_mut(extension_count) {
                            *slot = element;
                            extension_count += 1;
                        }
                    }
                }
            } else if name.eq_ignore_ascii_case("transfer-encoding") {
                body = true;
            } else if name.eq_ignore_ascii_case("content-length") {
                // Only a lone `0` declares no body; anything else (another
                // number, a list, garbage) is refused, never interpreted.
                body |= value != b"0";
            } else if name.eq_ignore_ascii_case("sec-websocket-protocol") {
                let offered =
                    parse_net::list(value).map_err(|_| HandshakeError::InvalidProtocol)?;
                for p in offered.iter() {
                    let Some(slot) = protocols.get_mut(protocol_count) else {
                        return Err(HandshakeError::InvalidProtocol);
                    };
                    if !is_token(p) {
                        return Err(HandshakeError::InvalidProtocol);
                    }
                    *slot = p;
                    protocol_count += 1;
                }
            }
        }
        if body {
            return Err(HandshakeError::UnexpectedBody);
        }
        if hosts != 1 || !is_visible(host) {
            return Err(HandshakeError::InvalidHost);
        }
        if !upgrade {
            return Err(HandshakeError::MissingUpgrade);
        }
        if !connection {
            return Err(HandshakeError::MissingConnectionUpgrade);
        }
        if versions != 1 || !version_ok {
            return Err(HandshakeError::UnsupportedVersion);
        }
        if keys != 1 {
            return Err(HandshakeError::MissingKey);
        }
        let mut nonce = [0u8; 24];
        if key.len() != 24 || base64::decode_into(key, &mut nonce) != Some(16) {
            return Err(HandshakeError::InvalidKey);
        }
        // Two Origins would let a policy check read one and a later layer
        // trust the other; refuse rather than pick.
        if origins > 1 || (origins == 1 && !is_visible(origin)) {
            return Err(HandshakeError::InvalidOrigin);
        }
        let protocols = protocols.get(..protocol_count).unwrap_or(&[]);
        let extensions = extensions.get(..extension_count).unwrap_or(&[]);
        let origin = if origins == 1 { origin } else { &[] };
        let joined = |parts: &[&[u8]], sep: usize| {
            parts.iter().map(|p| p.len()).sum::<usize>() + sep * parts.len().saturating_sub(1)
        };
        let len =
            target.len() + host.len() + origin.len() + joined(protocols, 1) + joined(extensions, 2);
        // budget: max_head: the record holds parts of a head of at most
        // `MAX_HEAD` bytes, in one allocation.
        let mut buf = String::with_capacity(len);
        let mut ends = [0usize; 5];
        let push = |bytes: &[u8], buf: &mut String| -> Result<(), HandshakeError> {
            // Every part was checked to be ASCII (visible, tokens, or the
            // extension grammar), so this never fails.
            let text = core::str::from_utf8(bytes).map_err(|_| HandshakeError::MalformedHead)?;
            buf.push_str(text);
            Ok(())
        };
        push(target.as_bytes(), &mut buf)?;
        ends[0] = buf.len();
        push(host, &mut buf)?;
        ends[1] = buf.len();
        push(origin, &mut buf)?;
        ends[2] = buf.len();
        for (i, p) in protocols.iter().enumerate() {
            if i > 0 {
                buf.push(',');
            }
            push(p, &mut buf)?;
        }
        ends[3] = buf.len();
        for (i, e) in extensions.iter().enumerate() {
            if i > 0 {
                buf.push_str(", ");
            }
            push(e, &mut buf)?;
        }
        ends[4] = buf.len();
        Ok(Self {
            accept: accept_key(key),
            buf,
            ends,
            has_origin: origins == 1,
        })
    }

    /// Validates a request from its raw head bytes, for use without an HTTP
    /// layer: `Ok(None)` until the blank line ending the head has arrived,
    /// then the handshake and the head's length in bytes. Bytes after the
    /// head are the connection's first frames: feed them to the
    /// [`Connection`](crate::Connection).
    ///
    /// The head must be strict HTTP/1.1 and at most
    /// [`MAX_HEAD`](Self::MAX_HEAD) bytes: CRLF line endings (a bare CR or
    /// LF is refused as soon as it arrives), `METHOD SP target SP HTTP/1.1`,
    /// token field names with no space before the colon, no line folding,
    /// no control bytes in values. Each call scans at most `MAX_HEAD`
    /// bytes, so calling it again after every read costs bounded work per
    /// read.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::MalformedHead`], [`HeadTooLarge`](HandshakeError::HeadTooLarge),
    /// and everything [`from_request`](Self::from_request) reports.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::ServerHandshake;
    ///
    /// let request = b"GET /rpc HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUpgrade: websocket\r\n\
    ///     Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
    ///     Sec-WebSocket-Version: 13\r\n\r\n";
    /// // Not all of it has arrived yet.
    /// assert_eq!(ServerHandshake::from_head(&request[..40])?, None);
    /// let (handshake, len) = ServerHandshake::from_head(request)?.expect("complete");
    /// assert_eq!((handshake.target(), len), ("/rpc", request.len()));
    /// # Ok::<(), ws_net::HandshakeError>(())
    /// ```
    pub fn from_head(bytes: &[u8]) -> Result<Option<(Self, usize)>, HandshakeError> {
        let Some(head) = head::split(bytes)? else {
            return Ok(None);
        };
        let (method, target) =
            head::request_line(head.first).ok_or(HandshakeError::MalformedHead)?;
        let handshake = Self::from_request(method, target, head.fields())?;
        Ok(Some((handshake, head.len)))
    }

    /// Part `i` of the record (see `ends`).
    fn part(&self, i: usize) -> &str {
        let start = match i {
            0 => 0,
            _ => self.ends.get(i - 1).copied().unwrap_or(0),
        };
        let end = self.ends.get(i).copied().unwrap_or(start);
        self.buf.get(start..end).unwrap_or("")
    }

    fn offered(&self, protocol: &str) -> bool {
        self.protocols().any(|offered| offered == protocol)
    }

    /// The `Sec-WebSocket-Accept` value for this request.
    ///
    /// # Examples
    ///
    /// See [`ServerHandshake`].
    #[must_use]
    pub fn accept_key(&self) -> &AcceptKey {
        &self.accept
    }

    /// The request target (the path and query), for routing.
    ///
    /// # Examples
    ///
    /// See [`from_request`](Self::from_request).
    #[must_use]
    pub fn target(&self) -> &str {
        self.part(0)
    }

    /// The `Host` field: compare it with this server's own authority before
    /// accepting.
    ///
    /// # Examples
    ///
    /// See [`from_request`](Self::from_request).
    #[must_use]
    pub fn host(&self) -> &str {
        self.part(1)
    }

    /// The `Origin` field, if the client sent one (browsers always do).
    /// RFC 6455 section 10.2: a server that only serves its own pages should
    /// refuse other origins, with `403`.
    ///
    /// # Examples
    ///
    /// See [`ServerHandshake`].
    #[must_use]
    pub fn origin(&self) -> Option<&str> {
        self.has_origin.then(|| self.part(2))
    }

    /// The subprotocols the client offered, in its order of preference.
    ///
    /// # Examples
    ///
    /// See [`ServerHandshake`].
    pub fn protocols(&self) -> impl Iterator<Item = &str> {
        self.part(3).split(',').filter(|p| !p.is_empty())
    }

    /// The first protocol of the server's `preference` list that the client
    /// offered, or `None`. Protocols are tokens and compared exactly (case
    /// matters), so the server's order wins over the client's.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::ServerHandshake;
    ///
    /// let h = ServerHandshake::from_request("GET", "/", [
    ///     ("Host", &b"a"[..]), ("Upgrade", b"websocket"), ("Connection", b"Upgrade"),
    ///     ("Sec-WebSocket-Version", b"13"), ("Sec-WebSocket-Key", b"dGhlIHNhbXBsZSBub25jZQ=="),
    ///     ("Sec-WebSocket-Protocol", b"v1.rpc, v2.rpc"),
    /// ])?;
    /// assert_eq!(h.select_protocol(&["v2.rpc", "v1.rpc"]), Some("v2.rpc"));
    /// assert_eq!(h.select_protocol(&["V2.RPC"]), None);
    /// # Ok::<(), ws_net::HandshakeError>(())
    /// ```
    #[must_use]
    pub fn select_protocol<'p>(&self, preference: &[&'p str]) -> Option<&'p str> {
        preference.iter().copied().find(|p| self.offered(p))
    }

    /// The extensions the client offered, in its order, parsed. They were
    /// validated when the handshake was built, so every item is `Ok`.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::ServerHandshake;
    ///
    /// let h = ServerHandshake::from_request("GET", "/", [
    ///     ("Host", &b"a"[..]), ("Upgrade", b"websocket"), ("Connection", b"Upgrade"),
    ///     ("Sec-WebSocket-Version", b"13"), ("Sec-WebSocket-Key", b"dGhlIHNhbXBsZSBub25jZQ=="),
    ///     ("Sec-WebSocket-Extensions", b"permessage-deflate; client_max_window_bits"),
    /// ])?;
    /// let names: Vec<_> = h.extensions().filter_map(Result::ok).map(|o| o.name()).collect();
    /// assert_eq!(names, ["permessage-deflate"]);
    /// # Ok::<(), ws_net::HandshakeError>(())
    /// ```
    pub fn extensions(&self) -> Offers<'_> {
        extension::parse(self.part(4).as_bytes())
    }

    /// Writes the `101` with the selected `protocol`, the negotiated
    /// `extensions`, and `extra` response headers (a `Set-Cookie`, a
    /// server name). Extra headers are validated: a token name that is not
    /// one the handshake writes itself (`upgrade`, `connection`,
    /// `sec-websocket-*`, ...), and a value with no control bytes and no
    /// surrounding whitespace.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::InvalidProtocol`] for a protocol that was not
    /// offered; [`HandshakeError::InvalidRequest`] for a bad extra header.
    /// Nothing is written then.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{HandshakeError, ServerHandshake, extension::Negotiated};
    ///
    /// let h = ServerHandshake::from_request("GET", "/", [
    ///     ("Host", &b"a"[..]), ("Upgrade", b"websocket"), ("Connection", b"Upgrade"),
    ///     ("Sec-WebSocket-Version", b"13"), ("Sec-WebSocket-Key", b"dGhlIHNhbXBsZSBub25jZQ=="),
    /// ])?;
    /// let mut out = Vec::new();
    /// h.write_response_with(None, &Negotiated::none(), &[("x-served-by", b"edge-1")], &mut out)?;
    /// assert!(out.ends_with(b"x-served-by: edge-1\r\n\r\n"));
    /// let bad = h.write_response_with(None, &Negotiated::none(), &[("Upgrade", b"h2c")], &mut out);
    /// assert_eq!(bad, Err(HandshakeError::InvalidRequest));
    /// # Ok::<(), HandshakeError>(())
    /// ```
    pub fn write_response_with(
        &self,
        protocol: Option<&str>,
        extensions: &Negotiated,
        extra: &[(&str, &[u8])],
        out: &mut Vec<u8>,
    ) -> Result<(), HandshakeError> {
        for (name, value) in extra {
            check_extra(name, value)?;
        }
        self.write_response(protocol, out)?;
        // Insert the extra fields before the blank line that ends the head.
        let end = out.len() - 2;
        let mut tail = Vec::new();
        if let Some(value) = extensions.header_value() {
            // budget: max_head: one element of at most 128 bytes
            tail.extend_from_slice(b"sec-websocket-extensions: ");
            tail.extend_from_slice(value);
            tail.extend_from_slice(b"\r\n");
        }
        for (name, value) in extra {
            // budget: caller: the extra headers the caller passes
            tail.extend_from_slice(name.as_bytes());
            tail.extend_from_slice(b": ");
            tail.extend_from_slice(value);
            tail.extend_from_slice(b"\r\n");
        }
        let _ = out.splice(end..end, tail);
        Ok(())
    }

    /// The `101` response's header fields as `(name, value)` pairs, for an
    /// HTTP layer that writes the status line itself (http-net's
    /// `Response::switching_protocols`): `upgrade`, `connection`,
    /// `sec-websocket-accept`, `sec-websocket-protocol` when one is
    /// selected, and `sec-websocket-extensions` when one was negotiated.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::InvalidProtocol`] for a protocol that was not
    /// offered.
    ///
    /// The fields borrow `extensions` (the extension value is written
    /// there), so pass the decision's, as below, not a temporary.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{AcceptPolicy, ServerHandshake};
    ///
    /// let h = ServerHandshake::from_request("GET", "/", [
    ///     ("Host", &b"a"[..]), ("Upgrade", b"websocket"), ("Connection", b"Upgrade"),
    ///     ("Sec-WebSocket-Version", b"13"), ("Sec-WebSocket-Key", b"dGhlIHNhbXBsZSBub25jZQ=="),
    ///     ("Sec-WebSocket-Protocol", b"chat"), ("Origin", b"http://a"),
    /// ])?;
    /// let decision = AcceptPolicy::new().with_protocols(&["chat"])?.check(&h)?;
    /// let fields: Vec<_> = h.response_fields(decision.protocol, &decision.extensions)?.collect();
    /// assert_eq!(fields, [
    ///     ("upgrade", &b"websocket"[..]),
    ///     ("connection", b"upgrade"),
    ///     ("sec-websocket-accept", b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
    ///     ("sec-websocket-protocol", b"chat"),
    /// ]);
    /// # Ok::<(), ws_net::HandshakeError>(())
    /// ```
    pub fn response_fields<'s>(
        &'s self,
        protocol: Option<&'s str>,
        extensions: &'s Negotiated,
    ) -> Result<ResponseFields<'s>, HandshakeError> {
        if let Some(p) = protocol {
            if !self.offered(p) {
                return Err(HandshakeError::InvalidProtocol);
            }
        }
        Ok(ResponseFields {
            accept: self.accept.as_bytes(),
            protocol,
            extensions: extensions.header_value(),
            next: 0,
        })
    }

    /// Writes the complete `101 Switching Protocols` response, selecting
    /// `protocol` (which must be one the client offered) or none. No
    /// extension is accepted; [`write_response_with`](Self::write_response_with)
    /// writes a negotiated one. With `http-net`, send
    /// `Response::switching_protocols("websocket")` with a
    /// `sec-websocket-accept` header of [`accept_key`](Self::accept_key)
    /// (and `sec-websocket-protocol` if one was chosen) instead.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::InvalidProtocol`] when `protocol` was not offered.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::ServerHandshake;
    ///
    /// let h = ServerHandshake::from_request("GET", "/", [
    ///     ("Host", &b"a"[..]), ("Upgrade", b"websocket"), ("Connection", b"Upgrade"),
    ///     ("Sec-WebSocket-Version", b"13"), ("Sec-WebSocket-Key", b"dGhlIHNhbXBsZSBub25jZQ=="),
    /// ])?;
    /// let mut out = Vec::new();
    /// h.write_response(None, &mut out)?;
    /// assert_eq!(out, b"HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\n\
    ///     connection: upgrade\r\nsec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n");
    /// assert!(h.write_response(Some("chat"), &mut out).is_err());
    /// # Ok::<(), ws_net::HandshakeError>(())
    /// ```
    pub fn write_response(
        &self,
        protocol: Option<&str>,
        out: &mut Vec<u8>,
    ) -> Result<(), HandshakeError> {
        if let Some(p) = protocol {
            if !self.offered(p) {
                return Err(HandshakeError::InvalidProtocol);
            }
        }
        // budget: max_head: fixed lines, the accept value, and one protocol from the request
        out.extend_from_slice(
            b"HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: upgrade\r\nsec-websocket-accept: ",
        );
        out.extend_from_slice(self.accept.as_bytes());
        out.extend_from_slice(b"\r\n");
        if let Some(p) = protocol {
            out.extend_from_slice(b"sec-websocket-protocol: ");
            out.extend_from_slice(p.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        Ok(())
    }
}

/// The header fields of a `101` response, from
/// [`ServerHandshake::response_fields`].
///
/// # Examples
///
/// See [`ServerHandshake::response_fields`].
#[derive(Clone, Debug)]
pub struct ResponseFields<'s> {
    accept: &'s [u8],
    protocol: Option<&'s str>,
    extensions: Option<&'s [u8]>,
    next: u8,
}

impl<'s> Iterator for ResponseFields<'s> {
    type Item = (&'static str, &'s [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let item = match self.next {
                0 => Some(("upgrade", &b"websocket"[..])),
                1 => Some(("connection", &b"upgrade"[..])),
                2 => Some(("sec-websocket-accept", self.accept)),
                3 => self
                    .protocol
                    .map(|p| ("sec-websocket-protocol", p.as_bytes())),
                4 => self.extensions.map(|e| ("sec-websocket-extensions", e)),
                _ => return None,
            };
            self.next += 1;
            if item.is_some() {
                return item;
            }
        }
    }
}

/// The client side of the opening handshake: the request to send and the
/// check of the server's response.
///
/// # Examples
///
/// ```
/// use ws_net::{ClientHandshake, ServerHandshake};
///
/// let client = ClientHandshake::with_nonce(*b"the sample nonce");
/// assert_eq!(client.key(), "dGhlIHNhbXBsZSBub25jZQ==");
/// let mut request = Vec::new();
/// client.write_request("server.example.com", "/chat", &mut request)?;
/// assert!(request.starts_with(b"GET /chat HTTP/1.1\r\nhost: server.example.com\r\n"));
///
/// // The server's side, then its response checked from raw bytes.
/// let (server, _) = ServerHandshake::from_head(&request)?.expect("complete");
/// let mut response = Vec::new();
/// server.write_response(None, &mut response)?;
/// assert_eq!(client.verify_head(&response)?, Some((None, response.len())));
/// # Ok::<(), ws_net::HandshakeError>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct ClientHandshake {
    key: [u8; 24],
    expected: AcceptKey,
    protocols: Vec<String>,
    origin: Option<String>,
    /// Extra request headers, validated at write.
    headers: Vec<(String, Vec<u8>)>,
    /// Set when the OS random source failed: the nonce is not random, so
    /// the request is never written.
    unusable: bool,
    /// The permessage-deflate offer, when made.
    #[cfg(feature = "deflate")]
    deflate: Option<crate::DeflateConfig>,
}

impl ClientHandshake {
    /// A handshake with a fresh 16-byte nonce from the operating system's
    /// cryptographic random source (feature `std`).
    ///
    /// The OS source can fail (a sandbox that filters the system call). This
    /// constructor then fails closed: [`write_request`](Self::write_request)
    /// returns [`HandshakeError::RandomUnavailable`] and writes nothing; it
    /// never falls back to a predictable nonce and never panics. Use
    /// [`try_new`](Self::try_new) to see the failure up front.
    ///
    /// # Examples
    ///
    /// ```
    /// let a = ws_net::ClientHandshake::new();
    /// let b = ws_net::ClientHandshake::new();
    /// assert_ne!(a.key(), b.key());
    /// ```
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    #[must_use]
    pub fn new() -> Self {
        Self::try_new().unwrap_or_else(|_| {
            let mut handshake = Self::with_nonce([0; 16]);
            handshake.unusable = true;
            handshake
        })
    }

    /// A handshake with a fresh nonce from the operating system's
    /// cryptographic random source, or an error when that source fails
    /// (feature `std`).
    ///
    /// # Errors
    ///
    /// [`HandshakeError::RandomUnavailable`].
    ///
    /// # Examples
    ///
    /// ```
    /// let client = ws_net::ClientHandshake::try_new()?;
    /// assert_eq!(client.key().len(), 24);
    /// # Ok::<(), ws_net::HandshakeError>(())
    /// ```
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn try_new() -> Result<Self, HandshakeError> {
        let mut nonce = [0u8; 16];
        mod_rand::tier3::fill_bytes(&mut nonce).map_err(|_| HandshakeError::RandomUnavailable)?;
        Ok(Self::with_nonce(nonce))
    }

    /// A handshake with a caller-chosen 16-byte nonce. RFC 6455 requires
    /// the nonce to be randomly selected for each connection.
    ///
    /// # Examples
    ///
    /// See [`ClientHandshake`].
    #[must_use]
    pub fn with_nonce(nonce: [u8; 16]) -> Self {
        let mut key = [0u8; 24];
        base64::encode_into(&nonce, &mut key);
        Self {
            expected: accept_key(&key),
            key,
            protocols: Vec::new(),
            origin: None,
            headers: Vec::new(),
            unusable: false,
            #[cfg(feature = "deflate")]
            deflate: None,
        }
    }

    /// Offers permessage-deflate with `config`'s parameters (feature
    /// `deflate`). Read the response with [`verify_full`](Self::verify_full),
    /// [`HeadReader::client`], or the `blocking` module, which return what
    /// was agreed for [`connection`](Self::connection): `verify` and
    /// `verify_head` check the agreement but return only the subprotocol.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{ClientHandshake, DeflateConfig};
    ///
    /// let h = ClientHandshake::with_nonce([0; 16]).with_deflate(DeflateConfig::new());
    /// let mut out = Vec::new();
    /// h.write_request("a", "/", &mut out)?;
    /// assert!(out.windows(46).any(|w| w == b"permessage-deflate; server_no_context_takeover"));
    /// # Ok::<(), ws_net::HandshakeError>(())
    /// ```
    #[cfg(feature = "deflate")]
    #[cfg_attr(docsrs, doc(cfg(feature = "deflate")))]
    #[must_use]
    pub fn with_deflate(mut self, config: crate::DeflateConfig) -> Self {
        self.deflate = Some(config);
        self
    }

    /// Offers subprotocols, in order of preference. Each must be a token;
    /// this is checked by [`write_request`](Self::write_request).
    ///
    /// # Examples
    ///
    /// ```
    /// let h = ws_net::ClientHandshake::with_nonce([0; 16]).with_protocols(&["jsonrpc", "v2.rpc"]);
    /// let mut out = Vec::new();
    /// h.write_request("a", "/", &mut out)?;
    /// assert!(out.windows(39).any(|w| w == b"sec-websocket-protocol: jsonrpc, v2.rpc"));
    /// # Ok::<(), ws_net::HandshakeError>(())
    /// ```
    #[must_use]
    pub fn with_protocols(mut self, protocols: &[&str]) -> Self {
        // budget: caller
        self.protocols = protocols.iter().map(ToString::to_string).collect();
        self
    }

    /// Sends an `Origin` field, as a browser does. It must be visible
    /// ASCII; this is checked by [`write_request`](Self::write_request).
    ///
    /// # Examples
    ///
    /// ```
    /// let h = ws_net::ClientHandshake::with_nonce([0; 16]).with_origin("http://127.0.0.1:8080");
    /// let mut out = Vec::new();
    /// h.write_request("127.0.0.1:8080", "/rpc", &mut out)?;
    /// assert!(out.windows(30).any(|w| w == b"origin: http://127.0.0.1:8080\r"));
    /// # Ok::<(), ws_net::HandshakeError>(())
    /// ```
    #[must_use]
    pub fn with_origin(mut self, origin: &str) -> Self {
        // budget: caller
        self.origin = Some(origin.to_string());
        self
    }

    /// Adds a request header: `Authorization`, `Cookie`, a back-channel
    /// credential. Validated by [`write_request`](Self::write_request): a
    /// token name that is not one the handshake writes itself (`host`,
    /// `upgrade`, `connection`, `origin`, `sec-websocket-*`, body framing),
    /// and a value with no control bytes and no surrounding whitespace.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{ClientHandshake, HandshakeError};
    ///
    /// let h = ClientHandshake::with_nonce([0; 16]).with_header("authorization", b"Bearer t0k3n");
    /// let mut out = Vec::new();
    /// h.write_request("a", "/", &mut out)?;
    /// assert!(out.ends_with(b"authorization: Bearer t0k3n\r\n\r\n"));
    ///
    /// let bad = ClientHandshake::with_nonce([0; 16]).with_header("Sec-WebSocket-Key", b"x");
    /// assert_eq!(bad.write_request("a", "/", &mut out), Err(HandshakeError::InvalidRequest));
    /// # Ok::<(), HandshakeError>(())
    /// ```
    #[must_use]
    pub fn with_header(mut self, name: &str, value: &[u8]) -> Self {
        // budget: caller
        self.headers.push((name.to_string(), value.to_vec()));
        self
    }

    /// The `Sec-WebSocket-Key` value sent.
    ///
    /// # Examples
    ///
    /// See [`ClientHandshake`].
    #[must_use]
    pub fn key(&self) -> &str {
        core::str::from_utf8(&self.key).unwrap_or("")
    }

    /// Writes the opening request for `path` on `host` (the `Host` value,
    /// with the port if it is not the default).
    ///
    /// # Errors
    ///
    /// [`HandshakeError::InvalidRequest`] when `host`, `path`, or the origin
    /// is empty or contains whitespace or control characters, or `path`
    /// does not start with `/`; [`HandshakeError::InvalidProtocol`] for an
    /// offered protocol that is not a token. Nothing is written then.
    ///
    /// # Examples
    ///
    /// See [`ClientHandshake`].
    pub fn write_request(
        &self,
        host: &str,
        path: &str,
        out: &mut Vec<u8>,
    ) -> Result<(), HandshakeError> {
        if self.unusable {
            return Err(HandshakeError::RandomUnavailable);
        }
        let origin_ok = self
            .origin
            .as_deref()
            .is_none_or(|o| is_visible(o.as_bytes()));
        if !is_visible(host.as_bytes())
            || !is_visible(path.as_bytes())
            || !path.starts_with('/')
            || !origin_ok
        {
            return Err(HandshakeError::InvalidRequest);
        }
        if self.protocols.iter().any(|p| !is_token(p.as_bytes())) {
            return Err(HandshakeError::InvalidProtocol);
        }
        for (name, value) in &self.headers {
            check_extra(name, value)?;
        }
        // budget: caller: the caller's host, path, and configuration
        out.extend_from_slice(b"GET ");
        out.extend_from_slice(path.as_bytes());
        out.extend_from_slice(b" HTTP/1.1\r\nhost: ");
        out.extend_from_slice(host.as_bytes());
        out.extend_from_slice(
            b"\r\nupgrade: websocket\r\nconnection: upgrade\r\nsec-websocket-key: ",
        );
        out.extend_from_slice(&self.key);
        out.extend_from_slice(b"\r\nsec-websocket-version: 13\r\n");
        if let Some(origin) = &self.origin {
            out.extend_from_slice(b"origin: ");
            out.extend_from_slice(origin.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        #[cfg(feature = "deflate")]
        if let Some(config) = &self.deflate {
            let (value, len) = crate::deflate::offer(config);
            out.extend_from_slice(b"sec-websocket-extensions: ");
            out.extend_from_slice(value.get(..len).unwrap_or(&[]));
            out.extend_from_slice(b"\r\n");
        }
        if !self.protocols.is_empty() {
            out.extend_from_slice(b"sec-websocket-protocol: ");
            for (i, p) in self.protocols.iter().enumerate() {
                if i > 0 {
                    out.extend_from_slice(b", ");
                }
                out.extend_from_slice(p.as_bytes());
            }
            out.extend_from_slice(b"\r\n");
        }
        for (name, value) in &self.headers {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        Ok(())
    }

    /// The client [`Connection`](crate::Connection) for a verified
    /// response, with masking keys from the OS cryptographic random source
    /// and the negotiated extensions (feature `std`). It fails closed as
    /// [`Connection::client`](crate::Connection::client) does.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::ClientHandshake;
    ///
    /// let client = ClientHandshake::with_nonce(*b"the sample nonce");
    /// let response = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
    ///     Connection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    /// let (verified, _) = ws_net::HeadReader::new().client(&client, response)?.expect("complete");
    /// let mut conn = client.connection(&verified);
    /// conn.send_text("hi").unwrap();
    /// assert_eq!(conn.output()[1] & 0x80, 0x80); // masked
    /// # Ok::<(), ws_net::HandshakeError>(())
    /// ```
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    #[must_use]
    pub fn connection(&self, verified: &Verified<'_>) -> crate::Connection {
        crate::Connection::client().with_extensions(verified.extensions)
    }

    /// As [`connection`](Self::connection) with a caller seed (`no_std`,
    /// reproducible tests); the seed must come from a cryptographic source.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{ClientHandshake, Verified};
    ///
    /// let client = ClientHandshake::with_nonce([0; 16]);
    /// let conn = client.connection_with_seed(&Verified::none(), [3; 32]);
    /// assert_eq!(conn.role(), ws_net::Role::Client);
    /// ```
    #[must_use]
    pub fn connection_with_seed(
        &self,
        verified: &Verified<'_>,
        seed: [u8; 32],
    ) -> crate::Connection {
        crate::Connection::client_with_seed(seed).with_extensions(verified.extensions)
    }

    /// Checks the server's response as [`verify`](Self::verify) does, and
    /// returns everything verified: the selected subprotocol and the
    /// negotiated extensions (permessage-deflate when it was offered with
    /// [`with_deflate`](Self::with_deflate) and accepted).
    ///
    /// # Errors
    ///
    /// As [`verify`](Self::verify).
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::ClientHandshake;
    ///
    /// let client = ClientHandshake::with_nonce(*b"the sample nonce").with_protocols(&["chat"]);
    /// let fields = [
    ///     ("Upgrade", &b"websocket"[..]), ("Connection", b"Upgrade"),
    ///     ("Sec-WebSocket-Accept", b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="), ("Sec-WebSocket-Protocol", b"chat"),
    /// ];
    /// let verified = client.verify_full(101, fields)?;
    /// assert_eq!(verified.protocol, Some("chat"));
    /// assert!(verified.extensions.is_empty());
    /// # Ok::<(), ws_net::HandshakeError>(())
    /// ```
    pub fn verify_full<'h, I>(
        &self,
        status: u16,
        headers: I,
    ) -> Result<Verified<'_>, HandshakeError>
    where
        I: IntoIterator<Item = (&'h str, &'h [u8])>,
    {
        let (protocol, extensions) = self.verify_parts(status, headers)?;
        Ok(Verified {
            protocol,
            extensions,
        })
    }

    /// Checks the server's response (RFC 6455 section 4.1, the client's
    /// side) from its status and header fields, as an HTTP layer parsed
    /// them, and returns the subprotocol it selected, if any. With
    /// `http-net`: `client.verify(resp.status(), resp.headers())`.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::NotSwitching`] for a status other than 101,
    /// [`MissingUpgrade`](HandshakeError::MissingUpgrade),
    /// [`MissingConnectionUpgrade`](HandshakeError::MissingConnectionUpgrade),
    /// [`AcceptMismatch`](HandshakeError::AcceptMismatch),
    /// [`UnexpectedExtension`](HandshakeError::UnexpectedExtension) for an
    /// extension that was not offered,
    /// [`InvalidExtensions`](HandshakeError::InvalidExtensions) for an
    /// acceptance that breaks RFC 7692 section 7,
    /// [`InvalidProtocol`](HandshakeError::InvalidProtocol) for a protocol
    /// that was not offered, or more than one `Sec-WebSocket-Protocol`.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{ClientHandshake, HandshakeError};
    ///
    /// let client = ClientHandshake::with_nonce([1; 16]);
    /// let bad = [("Upgrade", &b"websocket"[..]), ("Connection", b"upgrade"),
    ///            ("Sec-WebSocket-Accept", b"AAAAAAAAAAAAAAAAAAAAAAAAAAA=")];
    /// assert_eq!(client.verify(101, bad), Err(HandshakeError::AcceptMismatch));
    /// assert_eq!(client.verify(403, []), Err(HandshakeError::NotSwitching(403)));
    /// ```
    pub fn verify<'h, I>(&self, status: u16, headers: I) -> Result<Option<&str>, HandshakeError>
    where
        I: IntoIterator<Item = (&'h str, &'h [u8])>,
    {
        self.verify_parts(status, headers)
            .map(|(protocol, _)| protocol)
    }

    fn verify_parts<'h, I>(
        &self,
        status: u16,
        headers: I,
    ) -> Result<(Option<&str>, Negotiated), HandshakeError>
    where
        I: IntoIterator<Item = (&'h str, &'h [u8])>,
    {
        if status != 101 {
            return Err(HandshakeError::NotSwitching(status));
        }
        let mut upgrade = false;
        let mut connection = false;
        let mut accepts = 0usize;
        let mut accept_ok = false;
        let mut selected: Option<&str> = None;
        let mut protocol_fields = 0usize;
        let mut extensions = Negotiated::none();
        let mut elements = 0usize;
        for (name, value) in headers {
            if name.eq_ignore_ascii_case("upgrade") {
                upgrade |= list_has(value, b"websocket");
            } else if name.eq_ignore_ascii_case("connection") {
                connection |= list_has(value, b"upgrade");
            } else if name.eq_ignore_ascii_case("sec-websocket-accept") {
                accepts += 1;
                accept_ok = value == self.expected.as_bytes();
            } else if name.eq_ignore_ascii_case("sec-websocket-extensions") {
                for element in extension::parse(value) {
                    // Without an offer, any element (or a value that is not
                    // a list at all) is one the client did not ask for.
                    let element = element.map_err(|e| self.unasked(e))?;
                    elements += 1;
                    extensions = self.agree(&element, elements)?;
                }
            } else if name.eq_ignore_ascii_case("sec-websocket-protocol") {
                protocol_fields += 1;
                selected = self
                    .protocols
                    .iter()
                    .find(|p| p.as_bytes() == value)
                    .map(String::as_str);
                if selected.is_none() {
                    return Err(HandshakeError::InvalidProtocol);
                }
            }
        }
        if !upgrade {
            return Err(HandshakeError::MissingUpgrade);
        }
        if !connection {
            return Err(HandshakeError::MissingConnectionUpgrade);
        }
        if accepts != 1 || !accept_ok {
            return Err(HandshakeError::AcceptMismatch);
        }
        if protocol_fields > 1 {
            return Err(HandshakeError::InvalidProtocol);
        }
        Ok((selected, extensions))
    }

    /// The error for a malformed extensions field: invalid against an
    /// offer, unasked for without one.
    #[cfg_attr(not(feature = "deflate"), allow(clippy::unused_self))]
    fn unasked(&self, malformed: HandshakeError) -> HandshakeError {
        #[cfg(feature = "deflate")]
        if self.deflate.is_some() {
            return malformed;
        }
        let _ = malformed;
        HandshakeError::UnexpectedExtension
    }

    /// The agreement in the `nth` (from 1) accepted element: only the one
    /// permessage-deflate offer can be accepted, once.
    #[cfg_attr(not(feature = "deflate"), allow(clippy::unused_self))]
    fn agree(
        &self,
        element: &extension::Offer<'_>,
        nth: usize,
    ) -> Result<Negotiated, HandshakeError> {
        #[cfg(feature = "deflate")]
        if let Some(config) = &self.deflate {
            if element.name().eq_ignore_ascii_case("permessage-deflate") {
                // Two acceptances would both claim RSV1 (RFC 7692 section 5).
                if nth > 1 {
                    return Err(HandshakeError::InvalidExtensions);
                }
                return crate::deflate::verify(config, element).map(Negotiated::with_deflate);
            }
        }
        let _ = (element, nth);
        Err(HandshakeError::UnexpectedExtension)
    }

    /// Checks the server's response from its raw head bytes, for use
    /// without an HTTP layer: `Ok(None)` until the blank line ending the
    /// head has arrived, then the selected subprotocol and the head's
    /// length in bytes. Bytes after the head are the connection's first
    /// frames. The head is read as strictly as
    /// [`ServerHandshake::from_head`] reads a request (status line
    /// `HTTP/1.1 SP 3DIGIT [SP reason]`), within
    /// [`ServerHandshake::MAX_HEAD`] bytes.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::MalformedHead`], [`HeadTooLarge`](HandshakeError::HeadTooLarge),
    /// and everything [`verify`](Self::verify) reports.
    ///
    /// # Examples
    ///
    /// See [`ClientHandshake`].
    pub fn verify_head(
        &self,
        bytes: &[u8],
    ) -> Result<Option<(Option<&str>, usize)>, HandshakeError> {
        let Some(head) = head::split(bytes)? else {
            return Ok(None);
        };
        let status = head::status_line(head.first).ok_or(HandshakeError::MalformedHead)?;
        let selected = self.verify(status, head.fields())?;
        Ok(Some((selected, head.len)))
    }
}

impl Verified<'_> {
    /// A verification with no subprotocol and no extensions, for building a
    /// client connection by hand (tests, a handshake checked elsewhere).
    ///
    /// # Examples
    ///
    /// ```
    /// let v = ws_net::Verified::none();
    /// assert_eq!(v.protocol, None);
    /// ```
    #[must_use]
    pub const fn none() -> Self {
        Self {
            protocol: None,
            extensions: Negotiated::none(),
        }
    }
}

/// Header names only: extra headers carry credentials (`Authorization`,
/// `Cookie`). The key is public on the wire.
impl fmt::Debug for ClientHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // budget: caller: the header names the caller configured
        let names: Vec<&str> = self.headers.iter().map(|(n, _)| n.as_str()).collect();
        f.debug_struct("ClientHandshake")
            .field("key", &self.key())
            .field("protocols", &self.protocols)
            .field("origin", &self.origin)
            .field("headers", &names)
            .finish_non_exhaustive()
    }
}

/// What a client learns from a verified `101` response.
///
/// # Examples
///
/// See [`HeadReader::client`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Verified<'a> {
    /// The subprotocol the server selected, one the client offered.
    pub protocol: Option<&'a str>,
    /// The extensions in force (none in this version).
    pub extensions: Negotiated,
}

/// A resumable reader for the raw handshake head, for a server or a client
/// reading from a socket in pieces.
///
/// [`ServerHandshake::from_head`] and [`ClientHandshake::verify_head`] scan
/// the whole buffer on every call, so a peer that sends its head one byte
/// per read makes them do quadratic work (up to about 134 million byte
/// visits for a 16 KiB head; the class of CVE-2023-43669). A `HeadReader`
/// remembers how far it scanned: pass it the same buffer each time, grown
/// at the end, and the total work is linear in the head however it is cut.
/// The rules are those of `from_head` and `verify_head`.
///
/// After it returns a head or an error, call [`reset`](Self::reset) before
/// reading another head.
///
/// # Examples
///
/// ```
/// use ws_net::HeadReader;
///
/// let request = b"GET /chat HTTP/1.1\r\nHost: a.example\r\nUpgrade: websocket\r\n\
///     Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
///     Sec-WebSocket-Version: 13\r\n\r\n";
/// let mut reader = HeadReader::new();
/// let mut buffer = Vec::new();
/// let mut done = None;
/// for &byte in request.iter() {
///     buffer.push(byte); // one byte per read, the worst case
///     if let Some(found) = reader.server(&buffer)? {
///         done = Some(found);
///     }
/// }
/// let (handshake, len) = done.expect("complete");
/// assert_eq!((handshake.target(), len), ("/chat", request.len()));
/// # Ok::<(), ws_net::HandshakeError>(())
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct HeadReader {
    scan: head::Scan,
    /// The error the last read ended with: repeated until `reset`.
    failed: Option<HandshakeError>,
}

impl HeadReader {
    /// A reader at the start of a head.
    ///
    /// # Examples
    ///
    /// See [`HeadReader`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reads a client's request head from `bytes` (the same buffer as on
    /// the previous call, grown at the end): `Ok(None)` until the head is
    /// complete, then the handshake and the head's length, as
    /// [`ServerHandshake::from_head`].
    ///
    /// # Errors
    ///
    /// As [`ServerHandshake::from_head`]; [`HandshakeError::InvalidRequest`]
    /// when `bytes` is shorter than what was already scanned.
    ///
    /// # Examples
    ///
    /// See [`HeadReader`].
    pub fn server(
        &mut self,
        bytes: &[u8],
    ) -> Result<Option<(ServerHandshake, usize)>, HandshakeError> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        let r = Self::read_server(&mut self.scan, bytes);
        if let Err(e) = r {
            self.failed = Some(e);
        }
        r
    }

    fn read_server(
        scan: &mut head::Scan,
        bytes: &[u8],
    ) -> Result<Option<(ServerHandshake, usize)>, HandshakeError> {
        let Some(head) = head::split_resume(scan, bytes)? else {
            return Ok(None);
        };
        let (method, target) =
            head::request_line(head.first).ok_or(HandshakeError::MalformedHead)?;
        let handshake = ServerHandshake::from_request(method, target, head.fields())?;
        Ok(Some((handshake, head.len)))
    }

    /// Reads a server's response head from `bytes` (the same buffer as on
    /// the previous call, grown at the end) and verifies it against
    /// `handshake`: `Ok(None)` until the head is complete, then what was
    /// verified and the head's length, as [`ClientHandshake::verify_head`].
    ///
    /// # Errors
    ///
    /// As [`ClientHandshake::verify_head`];
    /// [`HandshakeError::InvalidRequest`] when `bytes` is shorter than what
    /// was already scanned.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{ClientHandshake, HeadReader};
    ///
    /// let client = ClientHandshake::with_nonce(*b"the sample nonce");
    /// let response = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
    ///     Connection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    /// let mut reader = HeadReader::new();
    /// assert_eq!(reader.client(&client, &response[..20])?, None);
    /// let (verified, len) = reader.client(&client, response)?.expect("complete");
    /// assert_eq!((verified.protocol, len), (None, response.len()));
    /// # Ok::<(), ws_net::HandshakeError>(())
    /// ```
    pub fn client<'c>(
        &mut self,
        handshake: &'c ClientHandshake,
        bytes: &[u8],
    ) -> Result<Option<(Verified<'c>, usize)>, HandshakeError> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        let r = (|| {
            let Some(head) = head::split_resume(&mut self.scan, bytes)? else {
                return Ok(None);
            };
            let status = head::status_line(head.first).ok_or(HandshakeError::MalformedHead)?;
            let verified = handshake.verify_full(status, head.fields())?;
            Ok(Some((verified, head.len)))
        })();
        if let Err(e) = r {
            self.failed = Some(e);
        }
        r
    }

    /// Starts over, for the next head.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut reader = ws_net::HeadReader::new();
    /// assert_eq!(reader.server(b"GET / HTTP/1.1\r\n")?, None);
    /// reader.reset();
    /// assert_eq!(reader, ws_net::HeadReader::new());
    /// # Ok::<(), ws_net::HandshakeError>(())
    /// ```
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

#[cfg(feature = "std")]
impl Default for ClientHandshake {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rfc_headers() -> [(&'static str, &'static [u8]); 5] {
        [
            ("Host", b"server.example.com"),
            ("Upgrade", b"websocket"),
            ("Connection", b"keep-alive, Upgrade"),
            ("Sec-WebSocket-Version", b"13"),
            ("Sec-WebSocket-Key", b"dGhlIHNhbXBsZSBub25jZQ=="),
        ]
    }

    fn without(i: usize) -> Vec<(&'static str, &'static [u8])> {
        rfc_headers()
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, h)| *h)
            .collect()
    }

    #[test]
    fn test_accept_key_rfc_sample_matches() {
        assert_eq!(
            accept_key(b"dGhlIHNhbXBsZSBub25jZQ==").as_str(),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
        assert_eq!(
            alloc::format!("{}", accept_key(b"dGhlIHNhbXBsZSBub25jZQ==")),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn test_server_invalid_requests_refused() {
        let ok = rfc_headers();
        assert!(ServerHandshake::from_request("GET", "/", ok).is_ok());
        assert_eq!(
            ServerHandshake::from_request("POST", "/", ok),
            Err(HandshakeError::NotGet)
        );
        assert_eq!(
            ServerHandshake::from_request("get", "/", ok),
            Err(HandshakeError::NotGet)
        );
        assert_eq!(
            ServerHandshake::from_request("GET", "/a b", ok),
            Err(HandshakeError::MalformedHead)
        );
        let expect = [
            HandshakeError::InvalidHost,
            HandshakeError::MissingUpgrade,
            HandshakeError::MissingConnectionUpgrade,
            HandshakeError::UnsupportedVersion,
            HandshakeError::MissingKey,
        ];
        for (i, e) in expect.into_iter().enumerate() {
            assert_eq!(
                ServerHandshake::from_request("GET", "/", without(i)),
                Err(e)
            );
        }
        let mut twice: Vec<(&str, &[u8])> = ok.to_vec();
        twice.push(("sec-websocket-key", b"dGhlIHNhbXBsZSBub25jZQ=="));
        assert_eq!(
            ServerHandshake::from_request("GET", "/", twice),
            Err(HandshakeError::MissingKey)
        );
        let mut two_versions: Vec<(&str, &[u8])> = ok.to_vec();
        two_versions.push(("sec-websocket-version", b"13"));
        assert_eq!(
            ServerHandshake::from_request("GET", "/", two_versions),
            Err(HandshakeError::UnsupportedVersion)
        );
        for bad_version in [&b"8"[..], b"13, 8", b"013", b""] {
            let mut h = without(3);
            h.push(("Sec-WebSocket-Version", bad_version));
            assert_eq!(
                ServerHandshake::from_request("GET", "/", h),
                Err(HandshakeError::UnsupportedVersion),
                "{bad_version:?}"
            );
        }
        for bad_key in [
            &b"dGhlIHNhbXBsZSBub25jZQ"[..],
            b"dGhlIHNhbXBsZSBub25jZR==",
            b"AAAA",
            b"dGhlIHNhbXBsZSBub25jZSE=",
            b"dGhlIHNhbXBsZSBub25jZQ==AAAA",
            b"",
        ] {
            let mut h = without(4);
            h.push(("Sec-WebSocket-Key", bad_key));
            assert_eq!(
                ServerHandshake::from_request("GET", "/", h),
                Err(HandshakeError::InvalidKey),
                "{bad_key:?}"
            );
        }
        let mut proto: Vec<(&str, &[u8])> = ok.to_vec();
        proto.push(("Sec-WebSocket-Protocol", b"a b"));
        assert_eq!(
            ServerHandshake::from_request("GET", "/", proto),
            Err(HandshakeError::InvalidProtocol)
        );
        // More than 64 offered protocols are refused rather than stored.
        let list: Vec<u8> = b"a,".repeat(65);
        let mut proto: Vec<(&str, &[u8])> = ok.to_vec();
        proto.push(("Sec-WebSocket-Protocol", &list));
        assert_eq!(
            ServerHandshake::from_request("GET", "/", proto),
            Err(HandshakeError::InvalidProtocol)
        );
        // Offers across several fields accumulate, in order.
        let mut proto: Vec<(&str, &[u8])> = ok.to_vec();
        proto.push(("Sec-WebSocket-Protocol", b"a, , b"));
        proto.push(("sec-websocket-protocol", b"c"));
        let h = ServerHandshake::from_request("GET", "/", proto).unwrap();
        assert_eq!(h.protocols().collect::<Vec<_>>(), ["a", "b", "c"]);
        assert_eq!(h.origin(), None);
    }

    #[test]
    fn test_server_lists_rfc9110_quote_aware() {
        let with = |name: &'static str, value: &'static [u8]| {
            let mut h: Vec<(&str, &[u8])> = rfc_headers().to_vec();
            h.push((name, value));
            ServerHandshake::from_request("GET", "/", h)
        };
        // A comma inside a quoted string does not split, and a quoted
        // string is not a token.
        assert_eq!(
            with("Sec-WebSocket-Protocol", b"\"a,b\""),
            Err(HandshakeError::InvalidProtocol)
        );
        // An unterminated quote or a control byte is not a list at all.
        assert_eq!(
            with("Sec-WebSocket-Protocol", b"chat, \"x"),
            Err(HandshakeError::InvalidProtocol)
        );
        assert_eq!(
            with("Sec-WebSocket-Protocol", b"chat\x00"),
            Err(HandshakeError::InvalidProtocol)
        );
        // `upgrade` inside quotes or a comment is not the token.
        let mut h = without(2);
        h.push(("Connection", b"\"upgrade\""));
        assert_eq!(
            ServerHandshake::from_request("GET", "/", h),
            Err(HandshakeError::MissingConnectionUpgrade)
        );
        let mut h = without(1);
        h.push(("Upgrade", b"(websocket) h2c"));
        assert_eq!(
            ServerHandshake::from_request("GET", "/", h),
            Err(HandshakeError::MissingUpgrade)
        );
        // A list that does not parse holds nothing (fail closed).
        let mut h = without(1);
        h.push(("Upgrade", b"websocket, \"x"));
        assert_eq!(
            ServerHandshake::from_request("GET", "/", h),
            Err(HandshakeError::MissingUpgrade)
        );
        // Comments and empty elements around the tokens are fine.
        let mut h = without(2);
        h.push(("Connection", b"keep-alive (legacy), , Upgrade"));
        assert!(ServerHandshake::from_request("GET", "/", h).is_ok());
    }

    #[test]
    fn test_client_verify_each_rule_enforced() {
        let client = ClientHandshake::with_nonce(*b"the sample nonce").with_protocols(&["chat"]);
        let good: [(&str, &[u8]); 4] = [
            ("Upgrade", b"WebSocket"),
            ("Connection", b"Upgrade"),
            ("Sec-WebSocket-Accept", b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
            ("Sec-WebSocket-Protocol", b"chat"),
        ];
        assert_eq!(client.verify(101, good), Ok(Some("chat")));
        let mut ext = good.to_vec();
        ext.push(("Sec-WebSocket-Extensions", b"permessage-deflate"));
        assert_eq!(
            client.verify(101, ext),
            Err(HandshakeError::UnexpectedExtension)
        );
        let mut empty_ext = good.to_vec();
        empty_ext.push(("Sec-WebSocket-Extensions", b" , "));
        assert_eq!(client.verify(101, empty_ext), Ok(Some("chat")));
        // A value that is not a list is refused, not read as empty.
        let mut broken_ext = good.to_vec();
        broken_ext.push(("Sec-WebSocket-Extensions", b"\"x"));
        assert_eq!(
            client.verify(101, broken_ext),
            Err(HandshakeError::UnexpectedExtension)
        );
        let mut other = good.to_vec();
        other[3] = ("Sec-WebSocket-Protocol", b"superchat");
        assert_eq!(
            client.verify(101, other),
            Err(HandshakeError::InvalidProtocol)
        );
        let mut twice = good.to_vec();
        twice.push(("Sec-WebSocket-Protocol", b"chat"));
        assert_eq!(
            client.verify(101, twice),
            Err(HandshakeError::InvalidProtocol)
        );
        let mut two_accepts = good.to_vec();
        two_accepts.push(("Sec-WebSocket-Accept", b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
        assert_eq!(
            client.verify(101, two_accepts),
            Err(HandshakeError::AcceptMismatch)
        );
        assert_eq!(
            client.verify(101, good[1..].to_vec()),
            Err(HandshakeError::MissingUpgrade)
        );
        let mut no_conn = good.to_vec();
        let _removed = no_conn.remove(1);
        assert_eq!(
            client.verify(101, no_conn),
            Err(HandshakeError::MissingConnectionUpgrade)
        );
        let mut out = Vec::new();
        for (host, path) in [("a b", "/"), ("a", "x"), ("", "/"), ("a", "")] {
            assert_eq!(
                client.write_request(host, path, &mut out),
                Err(HandshakeError::InvalidRequest),
                "{host:?} {path:?}"
            );
        }
        assert_eq!(
            ClientHandshake::with_nonce([0; 16])
                .with_protocols(&["a b"])
                .write_request("a", "/", &mut out),
            Err(HandshakeError::InvalidProtocol)
        );
        assert!(out.is_empty());
    }
}
