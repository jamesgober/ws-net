//! Close status codes (RFC 6455 section 7.4 and the IANA registry).

use core::fmt;

/// A Close frame status code.
///
/// Any `u16` can be represented; [`is_sendable`](CloseCode::is_sendable)
/// says whether it may appear in a Close frame on the wire. Codes 1005,
/// 1006, and 1015 are reserved for reporting and never sent; codes below
/// 1000, 1004, 1016 to 2999, and 5000 and above are not assigned.
///
/// # Examples
///
/// ```
/// use ws_net::CloseCode;
///
/// assert!(CloseCode::NORMAL.is_sendable());
/// assert!(CloseCode::new(4000).is_sendable()); // private use
/// assert!(!CloseCode::NO_STATUS.is_sendable());
/// assert_eq!(CloseCode::GOING_AWAY.as_u16(), 1001);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CloseCode(u16);

impl CloseCode {
    /// 1000: the purpose of the connection has been fulfilled.
    pub const NORMAL: Self = Self(1000);
    /// 1001: the endpoint is going away (server shutdown, page navigation).
    pub const GOING_AWAY: Self = Self(1001);
    /// 1002: a protocol error.
    pub const PROTOCOL_ERROR: Self = Self(1002);
    /// 1003: a data type the endpoint cannot accept.
    pub const UNSUPPORTED_DATA: Self = Self(1003);
    /// 1005: no status code was present (reporting only, never sent).
    pub const NO_STATUS: Self = Self(1005);
    /// 1006: the connection closed without a Close frame (reporting only).
    pub const ABNORMAL: Self = Self(1006);
    /// 1007: data inconsistent with the message type (invalid UTF-8).
    pub const INVALID_PAYLOAD: Self = Self(1007);
    /// 1008: a message violates the endpoint's policy.
    pub const POLICY_VIOLATION: Self = Self(1008);
    /// 1009: a message too big to process.
    pub const MESSAGE_TOO_BIG: Self = Self(1009);
    /// 1010: the client expected an extension the server did not negotiate.
    pub const MANDATORY_EXTENSION: Self = Self(1010);
    /// 1011: the server hit an unexpected condition.
    pub const INTERNAL_ERROR: Self = Self(1011);
    /// 1012: the service is restarting.
    pub const SERVICE_RESTART: Self = Self(1012);
    /// 1013: try again later.
    pub const TRY_AGAIN_LATER: Self = Self(1013);
    /// 1014: a gateway received an invalid response.
    pub const BAD_GATEWAY: Self = Self(1014);
    /// 1015: TLS handshake failure (reporting only, never sent).
    pub const TLS_HANDSHAKE: Self = Self(1015);

    /// Wraps any code.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(ws_net::CloseCode::new(1000), ws_net::CloseCode::NORMAL);
    /// ```
    #[must_use]
    pub const fn new(code: u16) -> Self {
        Self(code)
    }

    /// The numeric code.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(ws_net::CloseCode::MESSAGE_TOO_BIG.as_u16(), 1009);
    /// ```
    #[must_use]
    pub const fn as_u16(&self) -> u16 {
        self.0
    }

    /// Whether the code may be sent in a Close frame: 1000 to 1003, 1007 to
    /// 1014, and 3000 to 4999.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::CloseCode;
    /// assert!(CloseCode::new(3000).is_sendable());
    /// assert!(!CloseCode::new(1004).is_sendable());
    /// assert!(!CloseCode::new(2999).is_sendable());
    /// ```
    #[must_use]
    pub const fn is_sendable(&self) -> bool {
        matches!(self.0, 1000..=1003 | 1007..=1014 | 3000..=4999)
    }
}

impl fmt::Display for CloseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl From<CloseCode> for u16 {
    fn from(code: CloseCode) -> Self {
        code.0
    }
}

/// The status code and reason of a received Close frame.
///
/// # Examples
///
/// ```
/// use ws_net::{CloseCode, Connection, Event};
///
/// let mut client = Connection::client_with_seed([7; 32]);
/// let _ = client.feed(&[0x88, 0x05, 0x03, 0xE8, b'b', b'y', b'e']);
/// match client.poll().unwrap() {
///     Event::Close(Some(frame)) => {
///         assert_eq!(frame.code, CloseCode::NORMAL);
///         assert_eq!(frame.reason, "bye");
///     }
///     other => panic!("{other:?}"),
/// }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CloseFrame<'a> {
    /// The status code (always sendable: invalid codes fail the connection).
    pub code: CloseCode,
    /// The reason, validated as UTF-8 (at most 123 bytes).
    pub reason: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sendable_ranges_at_boundaries() {
        for (code, ok) in [
            (0, false),
            (999, false),
            (1000, true),
            (1003, true),
            (1004, false),
            (1005, false),
            (1006, false),
            (1007, true),
            (1014, true),
            (1015, false),
            (1016, false),
            (2999, false),
            (3000, true),
            (4999, true),
            (5000, false),
            (u16::MAX, false),
        ] {
            assert_eq!(CloseCode::new(code).is_sendable(), ok, "{code}");
        }
        assert_eq!(u16::from(CloseCode::NORMAL), 1000);
        assert_eq!(alloc::format!("{}", CloseCode::NORMAL), "1000");
    }
}
