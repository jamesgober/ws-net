//! Server policy for the opening handshake: which pages may connect
//! ([`OriginPolicy`]), which subprotocols are spoken ([`AcceptPolicy`]), and
//! the Tier 1 entry points that apply it ([`accept`], [`Acceptor`]).
//!
//! A browser attaches the user's cookies to a WebSocket request from any
//! page, on any site. Without an Origin check, a page on another site can
//! open a socket to this server as the user (cross-site WebSocket
//! hijacking, CWE-1385). Browsers always send `Origin` and a page cannot
//! change it, so the check is the defense. The Tier 1 path applies the
//! same-origin rule by default.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use parse_net::{Origin, OriginValue, parse_host_port, parse_origin, text::is_token};

use crate::{
    conn::Connection,
    error::HandshakeError,
    extension::Negotiated,
    handshake::{HeadReader, ServerHandshake},
    keepalive::Keepalive,
    limits::Limits,
};

/// Which `Origin` values may open a connection.
///
/// Origins are compared as RFC 6454 serialized origins: scheme and host
/// ASCII case-insensitively, IP literals by value, ports after the scheme's
/// default (80 for `http`, 443 for `https`) is filled in. Never by prefix,
/// suffix, or substring: `https://example.com.evil.net` is not
/// `https://example.com`. The opaque origin `null` never matches, and only
/// `http` and `https` origins match at all (a web page has one of those).
///
/// # Examples
///
/// ```
/// use ws_net::OriginPolicy;
///
/// let policy = OriginPolicy::allow(&["https://app.example.com"])?;
/// assert!(policy.permits(Some("HTTPS://APP.EXAMPLE.COM:443"), "ws.example.com"));
/// assert!(!policy.permits(Some("https://app.example.com.evil.net"), "ws.example.com"));
/// assert!(!policy.permits(Some("null"), "ws.example.com"));
///
/// // The default: the page's authority must be the Host it connects to.
/// let same = OriginPolicy::same_origin();
/// assert!(same.permits(Some("https://chat.example.com"), "chat.example.com"));
/// assert!(!same.permits(Some("https://evil.example"), "chat.example.com"));
/// # Ok::<(), ws_net::HandshakeError>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OriginPolicy {
    /// The Origin's host and port must be the request's `Host`. The scheme
    /// is not compared, so an `http` page passes for a `wss` endpoint on the
    /// same authority; use [`AllowList`](Self::AllowList) to pin it.
    SameOrigin {
        /// Whether a request with no `Origin` is accepted. Browsers always
        /// send one, so a missing Origin means a non-browser client, which
        /// carries no ambient browser credentials.
        allow_missing: bool,
    },
    /// The Origin must be one of these serialized origins
    /// (`scheme://host[:port]`). Build it with [`OriginPolicy::allow`],
    /// which validates each entry; an entry that does not parse never
    /// matches.
    AllowList {
        /// The allowed origins.
        origins: Vec<String>,
        /// Whether a request with no `Origin` is accepted.
        allow_missing: bool,
    },
    /// Every Origin, and none, is accepted. Only for endpoints that use no
    /// ambient credentials (no cookies, no HTTP authentication): any page
    /// on any site can connect.
    Any,
}

impl Default for OriginPolicy {
    fn default() -> Self {
        Self::same_origin()
    }
}

/// The scheme's default port, for the two schemes a page can have.
fn web_scheme_port(scheme: &[u8]) -> Option<u16> {
    if scheme.eq_ignore_ascii_case(b"http") {
        Some(80)
    } else if scheme.eq_ignore_ascii_case(b"https") {
        Some(443)
    } else {
        None
    }
}

/// A web origin (`http` or `https`) from `value`, or `None`.
fn web_origin(value: &[u8]) -> Option<Origin<'_>> {
    match parse_origin(value) {
        Ok(OriginValue::Origin(o)) if web_scheme_port(o.scheme).is_some() => Some(o),
        _ => None,
    }
}

/// Whether origin `o` names the authority in the `Host` value `host`.
fn same_authority(o: &Origin<'_>, host: &str) -> bool {
    let Ok(hp) = parse_host_port(host.as_bytes()) else {
        return false;
    };
    if hp.empty_port || hp.host.is_empty() || !o.host.eq_ignore_ascii_case(&hp.host) {
        return false;
    }
    match hp.port {
        // `Host` names the port: the Origin's port, explicit or default,
        // must be it.
        Some(port) => o.effective_port() == Some(port),
        // `Host` uses the endpoint's default port: so must the page.
        None => o.port.is_none_or(|p| Some(p) == web_scheme_port(o.scheme)),
    }
}

impl OriginPolicy {
    /// The same-origin rule, accepting a missing `Origin`: the Tier 1
    /// default.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::OriginPolicy;
    ///
    /// let p = OriginPolicy::same_origin();
    /// assert!(p.permits(Some("http://127.0.0.1:8080"), "127.0.0.1:8080"));
    /// assert!(!p.permits(Some("http://127.0.0.1:9090"), "127.0.0.1:8080"));
    /// assert!(p.permits(None, "127.0.0.1:8080"));
    /// ```
    #[must_use]
    pub const fn same_origin() -> Self {
        Self::SameOrigin {
            allow_missing: true,
        }
    }

    /// An allowlist of serialized origins, each `http` or `https`, with a
    /// host and an optional port, and no path, query, userinfo, or trailing
    /// slash. A missing `Origin` is accepted (see
    /// [`allow_missing`](Self::allow_missing)).
    ///
    /// # Errors
    ///
    /// [`HandshakeError::InvalidRequest`] for an entry that is not such an
    /// origin; nothing is built.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{HandshakeError, OriginPolicy};
    ///
    /// assert!(OriginPolicy::allow(&["https://a.example", "http://[::1]:8080"]).is_ok());
    /// for bad in ["https://a.example/", "a.example", "null", "ftp://a.example", "https://u@a.example"] {
    ///     assert_eq!(OriginPolicy::allow(&[bad]), Err(HandshakeError::InvalidRequest), "{bad}");
    /// }
    /// ```
    pub fn allow(origins: &[&str]) -> Result<Self, HandshakeError> {
        // budget: caller
        let mut list = Vec::with_capacity(origins.len());
        for entry in origins {
            if web_origin(entry.as_bytes()).is_none() || entry.trim() != *entry {
                return Err(HandshakeError::InvalidRequest);
            }
            list.push(entry.to_string());
        }
        Ok(Self::AllowList {
            origins: list,
            allow_missing: true,
        })
    }

    /// Every Origin is accepted. The name is loud on purpose: grep for it.
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(ws_net::OriginPolicy::any_origin().permits(Some("https://anyone.example"), "a"));
    /// ```
    #[must_use]
    pub const fn any_origin() -> Self {
        Self::Any
    }

    /// Sets whether a request without `Origin` is accepted (no effect on
    /// [`Any`](Self::Any)).
    ///
    /// # Examples
    ///
    /// ```
    /// let strict = ws_net::OriginPolicy::same_origin().allow_missing(false);
    /// assert!(!strict.permits(None, "a.example"));
    /// ```
    #[must_use]
    pub fn allow_missing(self, allow: bool) -> Self {
        match self {
            Self::SameOrigin { .. } => Self::SameOrigin {
                allow_missing: allow,
            },
            Self::AllowList { origins, .. } => Self::AllowList {
                origins,
                allow_missing: allow,
            },
            Self::Any => Self::Any,
        }
    }

    /// Whether a request with this `Origin` (or none) to this `Host` may
    /// connect. Fails closed: an Origin or Host that does not parse is
    /// refused.
    ///
    /// # Examples
    ///
    /// See [`OriginPolicy`].
    #[must_use]
    pub fn permits(&self, origin: Option<&str>, host: &str) -> bool {
        match (self, origin) {
            (Self::Any, _) => true,
            (Self::SameOrigin { allow_missing } | Self::AllowList { allow_missing, .. }, None) => {
                *allow_missing
            }
            (Self::SameOrigin { .. }, Some(origin)) => {
                web_origin(origin.as_bytes()).is_some_and(|o| same_authority(&o, host))
            }
            (Self::AllowList { origins, .. }, Some(origin)) => {
                let Some(o) = web_origin(origin.as_bytes()) else {
                    return false;
                };
                origins
                    .iter()
                    .filter_map(|entry| web_origin(entry.as_bytes()))
                    .any(|allowed| allowed.same_origin(&o))
            }
        }
    }
}

/// A server's handshake policy: who may connect, which subprotocol is
/// spoken, and the limits of the connection that results.
///
/// The default is the Tier 1 policy: the same-origin rule (a missing
/// `Origin` accepted), no subprotocol, default [`Limits`].
///
/// # Examples
///
/// ```
/// use ws_net::{AcceptPolicy, Limits, OriginPolicy};
///
/// let policy = AcceptPolicy::new()
///     .with_origins(OriginPolicy::allow(&["https://app.example.com"])?)
///     .with_protocols(&["v2.rpc", "v1.rpc"])?
///     .require_protocol()
///     .with_limits(Limits::new().with_max_message(1 << 20));
/// assert_eq!(policy.limits().max_message(), 1 << 20);
/// # Ok::<(), ws_net::HandshakeError>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AcceptPolicy {
    origins: OriginPolicy,
    protocols: Vec<String>,
    require_protocol: bool,
    limits: Limits,
    keepalive: Option<Keepalive>,
    /// Allowed `Host` authorities, validated; empty means any.
    hosts: Vec<String>,
    /// Whether the endpoint is reached over TLS, when known.
    secure: Option<bool>,
}

/// What a policy decided for an acceptable request.
///
/// # Examples
///
/// See [`AcceptPolicy::check`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Decision<'a> {
    /// The subprotocol to select: the first of the policy's that the client
    /// offered.
    pub protocol: Option<&'a str>,
    /// The extensions to accept (none in this version: every offer is
    /// declined, which RFC 6455 allows).
    pub extensions: Negotiated,
}

impl AcceptPolicy {
    /// The Tier 1 policy.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(ws_net::AcceptPolicy::new(), ws_net::AcceptPolicy::default());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the Origin rule.
    ///
    /// # Examples
    ///
    /// See [`AcceptPolicy`].
    #[must_use]
    pub fn with_origins(mut self, origins: OriginPolicy) -> Self {
        self.origins = origins;
        self
    }

    /// Sets the subprotocols this server speaks, in its order of
    /// preference. The first one the client offered is selected.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::InvalidProtocol`] for an entry that is not a token.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{AcceptPolicy, HandshakeError};
    ///
    /// assert!(AcceptPolicy::new().with_protocols(&["chat"]).is_ok());
    /// assert_eq!(AcceptPolicy::new().with_protocols(&["a b"]), Err(HandshakeError::InvalidProtocol));
    /// ```
    pub fn with_protocols(mut self, preference: &[&str]) -> Result<Self, HandshakeError> {
        if preference.iter().any(|p| !is_token(p.as_bytes())) {
            return Err(HandshakeError::InvalidProtocol);
        }
        // budget: caller
        self.protocols = preference.iter().map(ToString::to_string).collect();
        Ok(self)
    }

    /// Refuses a client that offers none of this server's subprotocols
    /// ([`HandshakeError::ProtocolRequired`]), instead of accepting it with
    /// no subprotocol.
    ///
    /// # Examples
    ///
    /// See [`AcceptPolicy::check`].
    #[must_use]
    pub fn require_protocol(mut self) -> Self {
        self.require_protocol = true;
        self
    }

    /// Sets the limits of accepted connections.
    ///
    /// # Examples
    ///
    /// See [`AcceptPolicy`].
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Sets the keepalive and timeouts of accepted connections.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::time::Duration;
    /// use ws_net::{AcceptPolicy, Keepalive};
    ///
    /// let k = Keepalive::new().with_ping_interval(Duration::from_secs(30));
    /// assert_eq!(AcceptPolicy::new().with_keepalive(k).keepalive(), Some(&k));
    /// ```
    #[must_use]
    pub fn with_keepalive(mut self, keepalive: Keepalive) -> Self {
        self.keepalive = Some(keepalive);
        self
    }

    /// Sets the `Host` values this server answers to (the DNS-rebinding
    /// defense: a page on the attacker's domain, resolved to this server's
    /// address, sends the attacker's name as `Host`). Each entry is an RFC
    /// 3986 authority, a host and an optional port, compared ASCII
    /// case-insensitively, IP literals by value. An entry without a port
    /// matches the endpoint's default port (443 with
    /// [`with_secure(true)`](Self::with_secure), 80 with `false`; a request
    /// without a port only, when unknown).
    ///
    /// # Errors
    ///
    /// [`HandshakeError::InvalidRequest`] for an entry that is not an
    /// authority (userinfo, an empty or invalid port, a path).
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{AcceptPolicy, HandshakeError};
    ///
    /// let p = AcceptPolicy::new().with_hosts(&["chat.example.com", "[::1]:8080"])?;
    /// assert_eq!(p.hosts().count(), 2);
    /// for bad in ["u@chat.example", "chat.example:", "chat.example:65536", "chat.example/x", ""] {
    ///     assert_eq!(AcceptPolicy::new().with_hosts(&[bad]), Err(HandshakeError::InvalidRequest));
    /// }
    /// # Ok::<(), HandshakeError>(())
    /// ```
    pub fn with_hosts(mut self, hosts: &[&str]) -> Result<Self, HandshakeError> {
        // budget: caller
        let mut list = Vec::with_capacity(hosts.len());
        for entry in hosts {
            match parse_net::host::parse_uri_host_port(entry.as_bytes()) {
                Ok(hp) if !hp.empty_port && !hp.host.is_empty() => list.push(entry.to_string()),
                _ => return Err(HandshakeError::InvalidRequest),
            }
        }
        self.hosts = list;
        Ok(self)
    }

    /// Tells the policy whether this endpoint is reached over TLS (`wss`).
    /// The same-origin rule then also requires the page's scheme to match
    /// (`https` for `true`, `http` for `false`), and a port-less `Host`
    /// entry means 443 or 80.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{AcceptPolicy, HandshakeError, ServerHandshake};
    ///
    /// let h = ServerHandshake::from_request("GET", "/", [
    ///     ("Host", &b"chat.example"[..]), ("Upgrade", b"websocket"), ("Connection", b"Upgrade"),
    ///     ("Sec-WebSocket-Version", b"13"), ("Sec-WebSocket-Key", b"dGhlIHNhbXBsZSBub25jZQ=="),
    ///     ("Origin", b"http://chat.example"),
    /// ])?;
    /// assert!(AcceptPolicy::new().check(&h).is_ok()); // scheme not compared
    /// let wss = AcceptPolicy::new().with_secure(true);
    /// assert_eq!(wss.check(&h), Err(HandshakeError::OriginRefused)); // an http page
    /// # Ok::<(), HandshakeError>(())
    /// ```
    #[must_use]
    pub fn with_secure(mut self, secure: bool) -> Self {
        self.secure = Some(secure);
        self
    }

    /// The keepalive of accepted connections, if set.
    ///
    /// # Examples
    ///
    /// See [`with_keepalive`](Self::with_keepalive).
    #[must_use]
    pub fn keepalive(&self) -> Option<&Keepalive> {
        self.keepalive.as_ref()
    }

    /// The `Host` allowlist (empty: any).
    ///
    /// # Examples
    ///
    /// See [`with_hosts`](Self::with_hosts).
    pub fn hosts(&self) -> impl Iterator<Item = &str> {
        self.hosts.iter().map(String::as_str)
    }

    /// Whether `host` is allowed by the `Host` list (always, when empty).
    fn host_allowed(&self, host: &str) -> bool {
        if self.hosts.is_empty() {
            return true;
        }
        let Ok(got) = parse_net::parse_host_port(host.as_bytes()) else {
            return false;
        };
        if got.empty_port {
            return false;
        }
        let default = self.secure.map(|tls| if tls { 443 } else { 80 });
        let effective = |port: Option<u16>| port.or(default);
        self.hosts.iter().any(|entry| {
            parse_net::host::parse_uri_host_port(entry.as_bytes()).is_ok_and(|want| {
                want.host.eq_ignore_ascii_case(&got.host)
                    && effective(want.port) == effective(got.port)
            })
        })
    }

    /// The Origin rule.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(ws_net::AcceptPolicy::new().origins(), &ws_net::OriginPolicy::same_origin());
    /// ```
    #[must_use]
    pub fn origins(&self) -> &OriginPolicy {
        &self.origins
    }

    /// The limits of accepted connections.
    ///
    /// # Examples
    ///
    /// See [`AcceptPolicy`].
    #[must_use]
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Decides on a validated request without writing anything: for an
    /// HTTP layer that writes its own `101`.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::OriginRefused`] (answer 403),
    /// [`HandshakeError::ProtocolRequired`] (answer 400).
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{AcceptPolicy, HandshakeError, ServerHandshake};
    ///
    /// let h = ServerHandshake::from_request("GET", "/", [
    ///     ("Host", &b"chat.example"[..]), ("Upgrade", b"websocket"), ("Connection", b"Upgrade"),
    ///     ("Sec-WebSocket-Version", b"13"), ("Sec-WebSocket-Key", b"dGhlIHNhbXBsZSBub25jZQ=="),
    ///     ("Origin", b"https://chat.example"), ("Sec-WebSocket-Protocol", b"v1, v2"),
    /// ])?;
    /// let policy = AcceptPolicy::new().with_protocols(&["v2", "v1"])?;
    /// assert_eq!(policy.check(&h)?.protocol, Some("v2"));
    ///
    /// let strict = AcceptPolicy::new().with_protocols(&["v3"])?.require_protocol();
    /// assert_eq!(strict.check(&h), Err(HandshakeError::ProtocolRequired));
    /// # Ok::<(), ws_net::HandshakeError>(())
    /// ```
    pub fn check<'h>(
        &self,
        handshake: &'h ServerHandshake,
    ) -> Result<Decision<'h>, HandshakeError> {
        if !self.host_allowed(handshake.host()) {
            return Err(HandshakeError::HostRefused);
        }
        if !self.origins.permits(handshake.origin(), handshake.host()) {
            return Err(HandshakeError::OriginRefused);
        }
        if let (Some(tls), OriginPolicy::SameOrigin { .. }, Some(origin)) =
            (self.secure, &self.origins, handshake.origin())
        {
            let scheme = if tls { "https://" } else { "http://" };
            let matches = origin
                .get(..scheme.len())
                .is_some_and(|s| s.eq_ignore_ascii_case(scheme));
            if !matches {
                return Err(HandshakeError::OriginRefused);
            }
        }
        let protocol = self
            .protocols
            .iter()
            .find_map(|p| handshake.protocols().find(|offered| offered == p));
        if protocol.is_none() && self.require_protocol {
            return Err(HandshakeError::ProtocolRequired);
        }
        Ok(Decision {
            protocol,
            extensions: Negotiated::none(),
        })
    }
}

impl ServerHandshake {
    /// Applies `policy`, appends the `101` response with the selected
    /// subprotocol to `out`, and returns the server [`Connection`] with the
    /// policy's limits.
    ///
    /// # Errors
    ///
    /// As [`AcceptPolicy::check`]; nothing is written. Answer with
    /// [`HandshakeError::write_response`].
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{AcceptPolicy, HandshakeError, ServerHandshake};
    ///
    /// let request = b"GET / HTTP/1.1\r\nHost: a.example\r\nUpgrade: websocket\r\n\
    ///     Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
    ///     Sec-WebSocket-Version: 13\r\nOrigin: https://evil.example\r\n\r\n";
    /// let (h, _) = ServerHandshake::from_head(request)?.expect("complete");
    /// let mut out = Vec::new();
    /// let refused = h.accept(&AcceptPolicy::new(), &mut out).unwrap_err();
    /// assert_eq!(refused, HandshakeError::OriginRefused);
    /// refused.write_response(&mut out);
    /// assert!(out.starts_with(b"HTTP/1.1 403 Forbidden\r\n"));
    /// # Ok::<(), ws_net::HandshakeError>(())
    /// ```
    pub fn accept(
        &self,
        policy: &AcceptPolicy,
        out: &mut Vec<u8>,
    ) -> Result<Connection, HandshakeError> {
        let decision = policy.check(self)?;
        self.write_response(decision.protocol, out)?;
        let conn = Connection::server()
            .with_limits(policy.limits)
            .with_extensions(decision.extensions);
        Ok(match policy.keepalive {
            Some(k) => conn.with_keepalive(k),
            None => conn,
        })
    }
}

/// Appends a complete refusal response: `HTTP/1.1 <status> <reason>`,
/// `content-length: 0`, `connection: close`, and `retry-after` when given.
/// For refusals a server decides itself: 403 by policy, 429 for a rate
/// limit, 503 when shedding load. (A [`HandshakeError`] writes its own
/// with [`HandshakeError::write_response`].)
///
/// # Errors
///
/// [`HandshakeError::InvalidRequest`] for a status outside 400 to 599;
/// nothing is written.
///
/// # Examples
///
/// ```
/// let mut out = Vec::new();
/// ws_net::write_refusal(503, Some(30), &mut out)?;
/// assert_eq!(out, b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\
///     connection: close\r\nretry-after: 30\r\n\r\n");
/// assert!(ws_net::write_refusal(200, None, &mut out).is_err());
/// # Ok::<(), ws_net::HandshakeError>(())
/// ```
pub fn write_refusal(
    status: u16,
    retry_after_seconds: Option<u32>,
    out: &mut Vec<u8>,
) -> Result<(), HandshakeError> {
    if !(400..=599).contains(&status) {
        return Err(HandshakeError::InvalidRequest);
    }
    let reason = match status {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        408 => "Request Timeout",
        426 => "Upgrade Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        s if s < 500 => "Client Error",
        _ => "Server Error",
    };
    // budget: fixed
    out.extend_from_slice(b"HTTP/1.1 ");
    out.extend_from_slice(alloc::format!("{status} {reason}").as_bytes());
    out.extend_from_slice(b"\r\ncontent-length: 0\r\nconnection: close\r\n");
    if let Some(secs) = retry_after_seconds {
        out.extend_from_slice(alloc::format!("retry-after: {secs}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    Ok(())
}

/// An accepted connection: write [`response`](Self::response) to the
/// transport, then drive [`connection`](Self::connection). The input bytes
/// up to [`consumed`](Self::consumed) were the head and frames already fed
/// to the connection; feed the rest yourself (a connection takes at most
/// its input buffer per call).
#[non_exhaustive]
#[derive(Debug)]
pub struct Accepted {
    /// The `101 Switching Protocols` response.
    pub response: Vec<u8>,
    /// The server end, holding the frames that followed the head.
    pub connection: Connection,
    /// Input bytes used: the head, plus the frames fed to `connection`.
    pub consumed: usize,
    /// The request, for routing on its target.
    pub handshake: ServerHandshake,
}

/// Accepts a WebSocket from a socket's first bytes, in one call: the Tier 1
/// server entry point.
///
/// `bytes` starts with the request head. Until the head is complete the
/// result is `Ok(None)`: read more, append, and call again. Then the request
/// is validated, the same-origin policy applied ([`AcceptPolicy::new`]),
/// the `101` written, and a server [`Connection`] built and fed the bytes
/// that followed the head.
///
/// Each call scans `bytes` from the start; when the head arrives in many
/// small reads, use an [`Acceptor`], which scans each byte once.
///
/// The Tier 1 policy accepts any `Host`. A service on a private address
/// (a development daemon on `127.0.0.1`, an agent RPC) is open to DNS
/// rebinding: a page on the attacker's domain, resolved to that address,
/// sends a matching `Host` and `Origin` of its own choosing. Such a
/// service should accept through an [`AcceptPolicy`] with
/// [`with_hosts`](AcceptPolicy::with_hosts).
///
/// # Errors
///
/// Every [`HandshakeError`] of [`ServerHandshake::from_head`], plus
/// [`HandshakeError::OriginRefused`]. Answer with
/// [`HandshakeError::write_response`] and close the transport.
///
/// # Examples
///
/// ```
/// use ws_net::Event;
///
/// let mut wire = b"GET /chat HTTP/1.1\r\nHost: chat.example\r\nUpgrade: websocket\r\n\
///     Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
///     Origin: https://chat.example\r\nSec-WebSocket-Version: 13\r\n\r\n".to_vec();
/// // A masked "Hello" right behind the head (RFC 6455 section 5.7).
/// wire.extend_from_slice(&[0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58]);
///
/// let mut accepted = ws_net::accept(&wire)?.expect("complete head");
/// assert!(accepted.response.starts_with(b"HTTP/1.1 101 "));
/// assert_eq!(accepted.consumed, wire.len());
/// assert_eq!(accepted.handshake.target(), "/chat");
/// match accepted.connection.poll()? {
///     Event::Text(text) => assert_eq!(text, "Hello"),
///     other => panic!("{other:?}"),
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn accept(bytes: &[u8]) -> Result<Option<Accepted>, HandshakeError> {
    Acceptor::new().accept(bytes)
}

/// The resumable form of [`accept`], for a head read in pieces: each byte
/// of the head is scanned once over all calls (see [`HeadReader`]).
///
/// Pass the same buffer each time, grown at the end. One `Acceptor` accepts
/// one connection.
///
/// # Examples
///
/// ```
/// use ws_net::{AcceptPolicy, Acceptor, OriginPolicy};
///
/// let request = b"GET / HTTP/1.1\r\nHost: a.example\r\nUpgrade: websocket\r\n\
///     Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
///     Sec-WebSocket-Version: 13\r\nOrigin: https://app.example\r\n\r\n";
/// let policy = AcceptPolicy::new().with_origins(OriginPolicy::allow(&["https://app.example"])?);
/// let mut acceptor = Acceptor::with_policy(policy);
/// let mut buffer = Vec::new();
/// let mut accepted = None;
/// for piece in request.chunks(7) {
///     buffer.extend_from_slice(piece);
///     if let Some(a) = acceptor.accept(&buffer)? {
///         accepted = Some(a);
///     }
/// }
/// assert_eq!(accepted.expect("complete").consumed, request.len());
/// # Ok::<(), ws_net::HandshakeError>(())
/// ```
#[derive(Clone, Debug, Default)]
pub struct Acceptor {
    reader: HeadReader,
    policy: AcceptPolicy,
}

impl Acceptor {
    /// An acceptor with the Tier 1 policy ([`AcceptPolicy::new`]).
    ///
    /// # Examples
    ///
    /// See [`Acceptor`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An acceptor with `policy`.
    ///
    /// # Examples
    ///
    /// See [`Acceptor`].
    #[must_use]
    pub fn with_policy(policy: AcceptPolicy) -> Self {
        Self {
            reader: HeadReader::new(),
            policy,
        }
    }

    /// As [`accept`], over the buffer seen so far.
    ///
    /// # Errors
    ///
    /// As [`accept`]; [`HandshakeError::InvalidRequest`] when `bytes` is
    /// shorter than on the previous call.
    ///
    /// # Examples
    ///
    /// See [`Acceptor`].
    pub fn accept(&mut self, bytes: &[u8]) -> Result<Option<Accepted>, HandshakeError> {
        let Some((handshake, head_len)) = self.reader.server(bytes)? else {
            return Ok(None);
        };
        // budget: max_head: the 101 response (`write_response`)
        let mut response = Vec::with_capacity(160);
        let mut connection = handshake.accept(&self.policy, &mut response)?;
        let rest = bytes.get(head_len..).unwrap_or(&[]);
        let fed = connection.feed(rest);
        Ok(Some(Accepted {
            response,
            connection,
            consumed: head_len + fed,
            handshake,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_origin_allowlist_bypass_attempts_refused() {
        let p = OriginPolicy::allow(&["https://example.com"]).unwrap();
        for evil in [
            "https://example.com.evil.net",
            "https://evilexample.com",
            "https://example.com@evil.net",
            "http://example.com",
            "https://example.com:8443",
            "null",
            "https://example.com/",
            "https://example.com/path",
            "",
            "https://",
        ] {
            assert!(!p.permits(Some(evil), "example.com"), "{evil}");
        }
        for same in [
            "https://example.com",
            "HTTPS://EXAMPLE.COM",
            "https://example.com:443",
            "https://EXAMPLE.com:443",
        ] {
            assert!(p.permits(Some(same), "example.com"), "{same}");
        }
    }

    #[test]
    fn test_same_origin_ports_and_literals_compared() {
        let p = OriginPolicy::same_origin();
        assert!(p.permits(Some("http://example.com"), "example.com"));
        assert!(p.permits(Some("https://example.com"), "example.com"));
        assert!(p.permits(Some("http://example.com"), "example.com:80"));
        assert!(p.permits(Some("https://example.com"), "example.com:443"));
        assert!(p.permits(Some("http://example.com:8080"), "example.com:8080"));
        assert!(!p.permits(Some("http://example.com:8080"), "example.com"));
        assert!(!p.permits(Some("http://example.com"), "example.com:8080"));
        assert!(!p.permits(Some("http://example.com"), "example.com:443"));
        assert!(p.permits(Some("http://[::1]:9000"), "[0:0::1]:9000"));
        assert!(p.permits(Some("http://127.0.0.1"), "127.0.0.1"));
        // Not a web page, or a Host that does not parse: refused.
        assert!(!p.permits(Some("chrome-extension://abc"), "abc"));
        assert!(!p.permits(Some("null"), "example.com"));
        assert!(!p.permits(Some("http://example.com"), "example.com:"));
        assert!(!p.permits(Some("http://example.com"), "u@example.com"));
        assert!(!p.permits(Some("http://example.com"), ""));
    }

    #[test]
    fn test_origin_policy_missing_origin_follows_flag() {
        assert!(OriginPolicy::same_origin().permits(None, "a"));
        assert!(
            !OriginPolicy::same_origin()
                .allow_missing(false)
                .permits(None, "a")
        );
        let list = OriginPolicy::allow(&["https://a.example"])
            .unwrap()
            .allow_missing(false);
        assert!(!list.permits(None, "a.example"));
        assert!(
            OriginPolicy::any_origin()
                .allow_missing(false)
                .permits(None, "a")
        );
        // An entry built by hand that does not parse never matches.
        let raw = OriginPolicy::AllowList {
            origins: alloc::vec!["not an origin".to_string()],
            allow_missing: false,
        };
        assert!(!raw.permits(Some("not an origin"), "a"));
    }

    fn handshake(host: &str, origin: Option<&str>) -> ServerHandshake {
        let mut fields: Vec<(&str, &[u8])> = alloc::vec![
            ("Host", host.as_bytes()),
            ("Upgrade", b"websocket"),
            ("Connection", b"Upgrade"),
            ("Sec-WebSocket-Version", b"13"),
            ("Sec-WebSocket-Key", b"dGhlIHNhbXBsZSBub25jZQ=="),
        ];
        if let Some(o) = origin {
            fields.push(("Origin", o.as_bytes()));
        }
        ServerHandshake::from_request("GET", "/", fields).unwrap()
    }

    #[test]
    fn test_host_allowlist_dns_rebinding_refused_403() {
        let p = AcceptPolicy::new()
            .with_origins(OriginPolicy::any_origin())
            .with_hosts(&["chat.example", "[::1]:8080", "10.0.0.1:9000"])
            .unwrap();
        for ok in [
            "chat.example",
            "CHAT.EXAMPLE",
            "[0::1]:8080",
            "10.0.0.1:9000",
        ] {
            assert!(p.check(&handshake(ok, None)).is_ok(), "{ok}");
        }
        for bad in [
            "attacker.example",
            "chat.example:8080",
            "[::1]",
            "10.0.0.1",
            "chat.example.evil",
        ] {
            assert_eq!(
                p.check(&handshake(bad, None)),
                Err(HandshakeError::HostRefused),
                "{bad}"
            );
        }
        assert_eq!(HandshakeError::HostRefused.status(), 403);
        // With the endpoint's scheme known, a port-less entry means its default.
        let tls = p.clone().with_secure(true);
        assert!(tls.check(&handshake("chat.example:443", None)).is_ok());
        assert!(tls.check(&handshake("chat.example:80", None)).is_err());
        let plain = p.with_secure(false);
        assert!(plain.check(&handshake("chat.example:80", None)).is_ok());
    }

    #[test]
    fn test_secure_same_origin_pins_scheme() {
        let wss = AcceptPolicy::new().with_secure(true);
        assert!(
            wss.check(&handshake("a.example", Some("https://a.example")))
                .is_ok()
        );
        assert_eq!(
            wss.check(&handshake("a.example", Some("http://a.example"))),
            Err(HandshakeError::OriginRefused)
        );
        let ws = AcceptPolicy::new().with_secure(false);
        assert!(
            ws.check(&handshake("a.example", Some("http://a.example")))
                .is_ok()
        );
        // Missing Origin is still governed by allow_missing.
        assert!(wss.check(&handshake("a.example", None)).is_ok());
    }

    #[test]
    fn test_write_refusal_statuses() {
        let mut out = Vec::new();
        write_refusal(429, None, &mut out).unwrap();
        assert!(out.starts_with(b"HTTP/1.1 429 Too Many Requests\r\n"));
        out.clear();
        write_refusal(499, None, &mut out).unwrap();
        assert!(out.starts_with(b"HTTP/1.1 499 Client Error\r\n"));
        for bad in [0, 101, 399, 600] {
            let mut out = Vec::new();
            assert_eq!(
                write_refusal(bad, None, &mut out),
                Err(HandshakeError::InvalidRequest)
            );
            assert!(out.is_empty());
        }
    }

    #[test]
    fn test_origin_allow_entry_with_whitespace_refused() {
        assert_eq!(
            OriginPolicy::allow(&[" https://a.example"]),
            Err(HandshakeError::InvalidRequest)
        );
    }
}
