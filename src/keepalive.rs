//! Keepalive and timeouts without a clock: the caller passes its monotonic
//! time in milliseconds to [`Connection::on_time`](crate::Connection::on_time)
//! and asks [`Connection::next_deadline`](crate::Connection::next_deadline)
//! when to call again, so an idle connection costs no CPU.

use core::{ops::Add, time::Duration};

/// A point on the caller's monotonic clock, in milliseconds. Only
/// differences matter; the origin is the caller's. Arithmetic saturates.
///
/// # Examples
///
/// ```
/// use core::time::Duration;
/// use ws_net::Millis;
///
/// let t = Millis(1_000) + Duration::from_secs(30);
/// assert_eq!(t, Millis(31_000));
/// assert_eq!(Millis(u64::MAX) + Duration::from_secs(1), Millis(u64::MAX));
/// assert_eq!(Millis::from_duration(Duration::from_millis(1500)).as_u64(), 1500);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Millis(pub u64);

impl Millis {
    /// A time from a duration since the caller's origin (for example
    /// `Instant::now() - start`), saturating at `u64::MAX` milliseconds.
    ///
    /// # Examples
    ///
    /// See [`Millis`].
    #[must_use]
    pub fn from_duration(since_origin: Duration) -> Self {
        Self(u64::try_from(since_origin.as_millis()).unwrap_or(u64::MAX))
    }

    /// The milliseconds.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(ws_net::Millis(7).as_u64(), 7);
    /// ```
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl Add<Duration> for Millis {
    type Output = Self;

    fn add(self, d: Duration) -> Self {
        let ms = u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
        Self(self.0.saturating_add(ms))
    }
}

/// Keepalive and timeout settings of a connection.
///
/// | Setting | Default | Effect when due |
/// |---|---|---|
/// | [`ping_interval`](Self::with_ping_interval) | off | no frame arrived for this long: queue a Ping carrying the time |
/// | [`idle_timeout`](Self::with_idle_timeout) | off | no byte arrived for this long: fail with [`IdleTimeout`](crate::WsError::IdleTimeout), Close 1001 queued |
/// | [`close_timeout`](Self::with_close_timeout) | 5 s | this end sent Close and the peer did not answer: fail with [`CloseTimeout`](crate::WsError::CloseTimeout), nothing more sent |
/// | [`message_timeout`](Self::with_message_timeout) | off | a data message stayed incomplete this long: fail with [`MessageTimeout`](crate::WsError::MessageTimeout), Close 1008 queued |
///
/// Times are measured between calls to
/// [`on_time`](crate::Connection::on_time), so precision is the spacing of
/// those calls: call it after each read and at
/// [`next_deadline`](crate::Connection::next_deadline).
///
/// # Examples
///
/// ```
/// use core::time::Duration;
/// use ws_net::Keepalive;
///
/// // The editor tool: a Ping every 30 s, give up after 75 s of silence.
/// let k = Keepalive::new()
///     .with_ping_interval(Duration::from_secs(30))
///     .with_idle_timeout(Duration::from_secs(75));
/// assert_eq!(k.close_timeout(), Some(Duration::from_secs(5)));
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Keepalive {
    ping: Option<Duration>,
    idle: Option<Duration>,
    close: Option<Duration>,
    message: Option<Duration>,
}

impl Default for Keepalive {
    fn default() -> Self {
        Self::new()
    }
}

impl Keepalive {
    /// Pings and idle and message timeouts off; close timeout 5 s.
    ///
    /// # Examples
    ///
    /// ```
    /// let k = ws_net::Keepalive::new();
    /// assert_eq!((k.ping_interval(), k.idle_timeout(), k.message_timeout()), (None, None, None));
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ping: None,
            idle: None,
            close: Some(Duration::from_secs(5)),
            message: None,
        }
    }

    /// Queue a Ping when no frame has arrived for `interval`. Its 8-byte
    /// payload is the `on_time` value (big-endian milliseconds), so the
    /// Pong's round trip can be measured.
    ///
    /// # Examples
    ///
    /// See [`Keepalive`].
    #[must_use]
    pub const fn with_ping_interval(mut self, interval: Duration) -> Self {
        self.ping = Some(interval);
        self
    }

    /// Fail the connection when no byte has arrived for `timeout`. Set it
    /// above the ping interval plus a round trip.
    ///
    /// # Examples
    ///
    /// See [`Keepalive`].
    #[must_use]
    pub const fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle = Some(timeout);
        self
    }

    /// How long to wait for the peer's Close after this end sent one.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::time::Duration;
    /// let k = ws_net::Keepalive::new().with_close_timeout(Duration::from_secs(1));
    /// assert_eq!(k.close_timeout(), Some(Duration::from_secs(1)));
    /// ```
    #[must_use]
    pub const fn with_close_timeout(mut self, timeout: Duration) -> Self {
        self.close = Some(timeout);
        self
    }

    /// Fail a data message that stays incomplete longer than `timeout`
    /// (a slow-message attack holds the message budget otherwise).
    ///
    /// # Examples
    ///
    /// ```
    /// use core::time::Duration;
    /// let k = ws_net::Keepalive::new().with_message_timeout(Duration::from_secs(10));
    /// assert_eq!(k.message_timeout(), Some(Duration::from_secs(10)));
    /// ```
    #[must_use]
    pub const fn with_message_timeout(mut self, timeout: Duration) -> Self {
        self.message = Some(timeout);
        self
    }

    /// The ping interval.
    ///
    /// # Examples
    ///
    /// See [`Keepalive::new`].
    #[must_use]
    pub const fn ping_interval(&self) -> Option<Duration> {
        self.ping
    }

    /// The idle timeout.
    ///
    /// # Examples
    ///
    /// See [`Keepalive::new`].
    #[must_use]
    pub const fn idle_timeout(&self) -> Option<Duration> {
        self.idle
    }

    /// The close timeout.
    ///
    /// # Examples
    ///
    /// See [`Keepalive`].
    #[must_use]
    pub const fn close_timeout(&self) -> Option<Duration> {
        self.close
    }

    /// The message timeout.
    ///
    /// # Examples
    ///
    /// See [`Keepalive::new`].
    #[must_use]
    pub const fn message_timeout(&self) -> Option<Duration> {
        self.message
    }
}

/// What [`Connection::on_time`](crate::Connection::on_time) did.
///
/// # Examples
///
/// See [`Connection::on_time`](crate::Connection::on_time).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Tick {
    /// Nothing was due.
    Nothing,
    /// A keepalive Ping was queued: write the output.
    PingQueued,
}

/// "Not set" for the clock's millisecond fields.
pub(crate) const UNSET: u64 = u64::MAX;

/// The connection's clock state: when things last happened, in the
/// caller's milliseconds (`UNSET` when they have not). Times are taken at
/// the first `on_time` after the event, never from a clock of our own.
/// Plain `u64` fields keep the connection small.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Clock {
    /// The settings in milliseconds, `UNSET` when off.
    pub(crate) ping: u64,
    pub(crate) idle: u64,
    pub(crate) close: u64,
    pub(crate) message: u64,
    /// Whether a `Keepalive` was set at all.
    pub(crate) armed: bool,
    /// The last tick that saw new input bytes (or the first tick).
    pub(crate) last_rx: u64,
    /// When the keepalive Ping went out, until input arrives.
    pub(crate) ping_sent: u64,
    /// When this end's Close was first seen by a tick.
    pub(crate) close_sent: u64,
    /// When the message in progress was first seen, and its sequence
    /// number (messages received before it).
    pub(crate) message_started: u64,
    pub(crate) message_seq: u64,
    /// The latest time seen; a clock that goes backwards is treated as no
    /// time passing.
    pub(crate) now: u64,
}

/// A connection's timers start as [`Keepalive::new`]'s: no Ping, no idle
/// or message timeout, and the 5 s close timeout, so a connection whose
/// peer never answers its Close is released without any configuration.
impl Default for Clock {
    fn default() -> Self {
        Self {
            ping: UNSET,
            idle: UNSET,
            close: ms(Keepalive::new().close),
            message: UNSET,
            armed: true,
            last_rx: UNSET,
            ping_sent: UNSET,
            close_sent: UNSET,
            message_started: UNSET,
            message_seq: 0,
            now: 0,
        }
    }
}

fn ms(d: Option<Duration>) -> u64 {
    d.map_or(UNSET, |d| u64::try_from(d.as_millis()).unwrap_or(UNSET - 1))
}

impl Clock {
    pub(crate) fn set(&mut self, k: Keepalive) {
        self.ping = ms(k.ping);
        self.idle = ms(k.idle);
        self.close = ms(k.close);
        self.message = ms(k.message);
        self.armed = true;
    }
}

/// `at + after`, or `None` when either is unset; saturating.
pub(crate) fn due(at: u64, after: u64) -> Option<u64> {
    (at != UNSET && after != UNSET).then(|| at.saturating_add(after))
}
