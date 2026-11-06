//! Owned messages ([`Message`]), the kind of a data message
//! ([`MessageKind`]), and the connection's counters ([`Stats`]).

use alloc::{string::String, vec::Vec};

use crate::close::CloseCode;

/// An owned message, for the convenience APIs and the blocking adapter.
/// [`Event`](crate::Event) is the borrowed, zero-copy form.
///
/// # Examples
///
/// ```
/// use ws_net::{CloseCode, Message};
///
/// assert_eq!(Message::from("hi"), Message::Text("hi".to_string()));
/// assert_eq!(Message::from(vec![1, 2]), Message::Binary(vec![1, 2]));
/// let bye = Message::Close(Some((CloseCode::NORMAL, "done".to_string())));
/// assert!(bye.is_close());
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// A text message.
    Text(String),
    /// A binary message.
    Binary(Vec<u8>),
    /// A Ping, payload at most 125 bytes.
    Ping(Vec<u8>),
    /// A Pong, payload at most 125 bytes.
    Pong(Vec<u8>),
    /// A Close, with its status code and reason (`None`: no status code).
    Close(Option<(CloseCode, String)>),
}

impl Message {
    /// Whether this is a text or binary message.
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(ws_net::Message::from("x").is_data());
    /// assert!(!ws_net::Message::Ping(vec![]).is_data());
    /// ```
    #[must_use]
    pub const fn is_data(&self) -> bool {
        matches!(self, Self::Text(_) | Self::Binary(_))
    }

    /// Whether this is a Close.
    ///
    /// # Examples
    ///
    /// See [`Message`].
    #[must_use]
    pub const fn is_close(&self) -> bool {
        matches!(self, Self::Close(_))
    }
}

impl From<&str> for Message {
    fn from(text: &str) -> Self {
        // budget: caller
        Self::Text(String::from(text))
    }
}

impl From<String> for Message {
    fn from(text: String) -> Self {
        Self::Text(text)
    }
}

impl From<&[u8]> for Message {
    fn from(data: &[u8]) -> Self {
        // budget: caller
        Self::Binary(data.to_vec())
    }
}

impl From<Vec<u8>> for Message {
    fn from(data: Vec<u8>) -> Self {
        Self::Binary(data)
    }
}

/// The kind of a data message.
///
/// # Examples
///
/// See [`Connection::detach_message`](crate::Connection::detach_message).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MessageKind {
    /// Text, valid UTF-8.
    Text,
    /// Binary.
    Binary,
}

/// A connection's counters, for metrics and rate limiting (frame floods,
/// ping floods, byte rates). Every counter saturates at `u64::MAX`.
///
/// # Examples
///
/// ```
/// let mut conn = ws_net::Connection::server();
/// let _ = conn.feed(&[0x89, 0x80, 0, 0, 0, 0]); // a masked empty Ping
/// let _ = conn.poll();
/// let stats = conn.stats();
/// assert_eq!((stats.bytes_in, stats.frames_in, stats.pings_in), (6, 1, 1));
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Stats {
    /// Bytes taken by `feed` and `commit`.
    pub bytes_in: u64,
    /// Bytes acknowledged by `advance_output`.
    pub bytes_out: u64,
    /// Frame headers parsed.
    pub frames_in: u64,
    /// Complete data messages received.
    pub messages_in: u64,
    /// Data messages queued (a fragmented one counts when it ends).
    pub messages_out: u64,
    /// Pings received.
    pub pings_in: u64,
    /// Pongs received.
    pub pongs_in: u64,
    /// Close frames received.
    pub closes_in: u64,
}

impl Stats {
    /// Data frames received (Text, Binary, and Continuation): the frames
    /// that are not Ping, Pong, or Close.
    ///
    /// With [`messages_in`](Self::messages_in) and
    /// [`pings_in`](Self::pings_in) it gives the two ratios that flag an
    /// abusive peer sooner than byte rates: fragments per message
    /// (`data_frames_in / messages_in`) and Pings per message
    /// (`pings_in / messages_in`). A browser sends one frame per message
    /// and few Pings.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut conn = ws_net::Connection::server();
    /// // A masked Ping, then "hi" in two fragments.
    /// assert_eq!(conn.feed(&[0x89, 0x80, 0, 0, 0, 0]), 6);
    /// assert_eq!(conn.feed(&[0x01, 0x81, 0, 0, 0, 0, b'h', 0x80, 0x81, 0, 0, 0, 0, b'i']), 14);
    /// while !matches!(conn.poll(), Ok(ws_net::Event::NeedInput)) {}
    /// let stats = conn.stats();
    /// assert_eq!((stats.data_frames_in(), stats.messages_in, stats.pings_in), (2, 1, 1));
    /// ```
    #[must_use]
    pub const fn data_frames_in(&self) -> u64 {
        self.frames_in
            .saturating_sub(self.pings_in)
            .saturating_sub(self.pongs_in)
            .saturating_sub(self.closes_in)
    }
}
