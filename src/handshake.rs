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

use crate::{
    base64,
    error::HandshakeError,
    head::{self, is_token, is_visible},
    sha1::Sha1,
};

/// The GUID RFC 6455 section 1.3 appends to the client's key.
const GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The most subprotocols accepted from one request.
const MAX_PROTOCOLS: usize = 64;

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

/// The non-empty elements of a comma-separated field value.
fn list(value: &[u8]) -> impl Iterator<Item = &[u8]> {
    value
        .split(|&b| b == b',')
        .map(head::trim_ows)
        .filter(|e| !e.is_empty())
}

fn list_has(value: &[u8], token: &[u8]) -> bool {
    list(value).any(|e| e.eq_ignore_ascii_case(token))
}

/// Text from bytes already checked to be visible ASCII.
fn ascii(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerHandshake {
    accept: AcceptKey,
    target: String,
    host: String,
    origin: Option<String>,
    protocols: Vec<String>,
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
    /// `Origin`; every offered subprotocol a token, at most 64. The HTTP
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
    /// [`InvalidProtocol`](HandshakeError::InvalidProtocol). Answer with
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
        if !is_visible(target.as_bytes()) {
            return Err(HandshakeError::MalformedHead);
        }
        let mut upgrade = false;
        let mut connection = false;
        let (mut hosts, mut host): (usize, &[u8]) = (0, &[]);
        let (mut origins, mut origin): (usize, &[u8]) = (0, &[]);
        let (mut keys, mut key): (usize, &[u8]) = (0, &[]);
        let (mut versions, mut version_ok) = (0usize, false);
        let mut protocols = Vec::new();
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
            } else if name.eq_ignore_ascii_case("sec-websocket-protocol") {
                for p in list(value) {
                    if !is_token(p) || protocols.len() == MAX_PROTOCOLS {
                        return Err(HandshakeError::InvalidProtocol);
                    }
                    protocols.push(ascii(p));
                }
            }
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
        Ok(Self {
            accept: accept_key(key),
            target: target.to_string(),
            host: ascii(host),
            origin: (origins == 1).then(|| ascii(origin)),
            protocols,
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
        &self.target
    }

    /// The `Host` field: compare it with this server's own authority before
    /// accepting.
    ///
    /// # Examples
    ///
    /// See [`from_request`](Self::from_request).
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
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
        self.origin.as_deref()
    }

    /// The subprotocols the client offered, in its order of preference.
    ///
    /// # Examples
    ///
    /// See [`ServerHandshake`].
    pub fn protocols(&self) -> impl Iterator<Item = &str> {
        self.protocols.iter().map(String::as_str)
    }

    /// Writes the complete `101 Switching Protocols` response, selecting
    /// `protocol` (which must be one the client offered) or none.
    /// Extensions are never accepted. With `http-net`, send
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
            if !self.protocols.iter().any(|offered| offered == p) {
                return Err(HandshakeError::InvalidProtocol);
            }
        }
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientHandshake {
    key: [u8; 24],
    expected: AcceptKey,
    protocols: Vec<String>,
    origin: Option<String>,
}

impl ClientHandshake {
    /// A handshake with a fresh random nonce from the operating system's
    /// random source (feature `std`).
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
        let seed = crate::keys::os_seed();
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&seed[..16]);
        Self::with_nonce(nonce)
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
        }
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
        self.origin = Some(origin.to_string());
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
        out.extend_from_slice(b"\r\n");
        Ok(())
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
    /// [`UnexpectedExtension`](HandshakeError::UnexpectedExtension),
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
        if status != 101 {
            return Err(HandshakeError::NotSwitching(status));
        }
        let mut upgrade = false;
        let mut connection = false;
        let mut accepts = 0usize;
        let mut accept_ok = false;
        let mut selected: Option<&str> = None;
        let mut protocol_fields = 0usize;
        for (name, value) in headers {
            if name.eq_ignore_ascii_case("upgrade") {
                upgrade |= list_has(value, b"websocket");
            } else if name.eq_ignore_ascii_case("connection") {
                connection |= list_has(value, b"upgrade");
            } else if name.eq_ignore_ascii_case("sec-websocket-accept") {
                accepts += 1;
                accept_ok = value == self.expected.as_bytes();
            } else if name.eq_ignore_ascii_case("sec-websocket-extensions") {
                if list(value).next().is_some() {
                    return Err(HandshakeError::UnexpectedExtension);
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
        Ok(selected)
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
    fn test_accept_key_rfc_example() {
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
    fn test_server_rejections() {
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
    fn test_client_verify_rules() {
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
