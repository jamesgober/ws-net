//! [`Limits`]: every size budget of a connection.

/// The size budgets of a connection.
///
/// | Budget | Default | Bounds |
/// |---|---|---|
/// | incoming frame payload ([`max_frame`](Self::max_frame)) | 1 MiB | at least 125 |
/// | incoming message, all fragments ([`max_message`](Self::max_message)) | 16 MiB | any |
/// | outgoing frame payload ([`send_frame`](Self::send_frame)) | equal to `max_frame` | at least 125 |
/// | pending output ([`max_output`](Self::max_output)) | 32 MiB | any; 262 bytes more for automatic Pong and Close |
/// | input buffer ([`input_buffer`](Self::input_buffer)) | 64 KiB | 256 B to 1 MiB |
/// | capacity kept per buffer after use ([`retain`](Self::retain)) | 64 KiB | any |
///
/// The incoming budgets are checked from frame headers, before the payload
/// is read: a frame over the frame budget, or one that would take its
/// message over the message budget, fails the connection with close code
/// 1009. The frame and message defaults are the budgets of an editor tool,
/// the first consumer. A send that would take the pending output over its budget is
/// refused with [`WsError::OutputFull`](crate::WsError::OutputFull), and
/// changes nothing.
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
    /// Outgoing frame payload size; `None` follows `frame`.
    send_frame: Option<u64>,
    output: u64,
    input: usize,
    retain: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self::new()
    }
}

impl Limits {
    /// The default incoming frame budget: 1 MiB.
    pub const DEFAULT_MAX_FRAME: u64 = 1024 * 1024;
    /// The default incoming message budget: 16 MiB.
    pub const DEFAULT_MAX_MESSAGE: u64 = 16 * 1024 * 1024;
    /// The default pending-output budget: 32 MiB, a full default message
    /// plus framing with room to spare.
    pub const DEFAULT_MAX_OUTPUT: u64 = 32 * 1024 * 1024;
    /// The default input buffer: 64 KiB.
    pub const DEFAULT_INPUT_BUFFER: usize = 64 * 1024;
    /// The default capacity kept in each buffer after use: 64 KiB.
    pub const DEFAULT_RETAIN: usize = 64 * 1024;
    /// The smallest input buffer: room for a whole control frame (139
    /// bytes) and a whole header (14 bytes) with space to spare.
    pub const MIN_INPUT_BUFFER: usize = 256;
    /// The largest input buffer: 1 MiB.
    pub const MAX_INPUT_BUFFER: usize = 1024 * 1024;

    /// The defaults (see the table on [`Limits`]).
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::Limits;
    ///
    /// assert_eq!(Limits::new(), Limits::default());
    /// assert_eq!(Limits::new().max_output(), Limits::DEFAULT_MAX_OUTPUT);
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            frame: Self::DEFAULT_MAX_FRAME,
            message: Self::DEFAULT_MAX_MESSAGE,
            send_frame: None,
            output: Self::DEFAULT_MAX_OUTPUT,
            input: Self::DEFAULT_INPUT_BUFFER,
            retain: Self::DEFAULT_RETAIN,
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

    /// Sets the largest outgoing frame payload, at least 125 bytes. Larger
    /// messages are split into frames of this size. Until it is set, it
    /// follows [`max_frame`](Self::max_frame): what this end sends is what
    /// a peer with the same limits accepts.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::Limits;
    ///
    /// // Accept frames up to 1 MiB, send frames of at most 16 KiB.
    /// let limits = Limits::new().with_send_frame(16 * 1024);
    /// assert_eq!((limits.max_frame(), limits.send_frame()), (1 << 20, 16 * 1024));
    /// assert_eq!(Limits::new().with_send_frame(0).send_frame(), 125);
    /// ```
    #[must_use]
    pub const fn with_send_frame(mut self, bytes: u64) -> Self {
        self.send_frame = Some(if bytes < 125 { 125 } else { bytes });
        self
    }

    /// The largest outgoing frame payload.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::Limits;
    ///
    /// assert_eq!(Limits::new().with_max_frame(4096).send_frame(), 4096);
    /// ```
    #[must_use]
    pub const fn send_frame(&self) -> u64 {
        match self.send_frame {
            Some(bytes) => bytes,
            None => self.frame,
        }
    }

    /// Sets the pending-output budget: a send that would take the bytes
    /// waiting for the transport over it is refused with
    /// [`WsError::OutputFull`](crate::WsError::OutputFull). Automatic Pong
    /// replies and Close frames may use 262 bytes more, so a connection
    /// whose peer stopped reading can still answer and close. `u64::MAX`
    /// lifts the budget.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::{Connection, Limits, WsError};
    ///
    /// let mut conn = Connection::server().with_limits(Limits::new().with_max_output(1024));
    /// conn.send_binary(&[0; 1000])?;
    /// assert_eq!(conn.send_binary(&[0; 100]), Err(WsError::OutputFull));
    /// conn.close(ws_net::CloseCode::GOING_AWAY, "slow reader")?; // the headroom
    /// # Ok::<(), WsError>(())
    /// ```
    #[must_use]
    pub const fn with_max_output(mut self, bytes: u64) -> Self {
        self.output = bytes;
        self
    }

    /// The pending-output budget.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(ws_net::Limits::new().max_output(), 32 << 20);
    /// ```
    #[must_use]
    pub const fn max_output(&self) -> u64 {
        self.output
    }

    /// Sets the input buffer capacity, clamped to 256 bytes to 1 MiB: how
    /// much input one [`feed`](crate::Connection::feed) or
    /// [`read_buf`](crate::Connection::read_buf) takes at most. Smaller
    /// means less memory per connection and more calls per message.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::Limits;
    ///
    /// assert_eq!(Limits::new().with_input_buffer(16 * 1024).input_buffer(), 16 * 1024);
    /// assert_eq!(Limits::new().with_input_buffer(1).input_buffer(), Limits::MIN_INPUT_BUFFER);
    /// ```
    #[must_use]
    pub const fn with_input_buffer(mut self, bytes: usize) -> Self {
        self.input = if bytes < Self::MIN_INPUT_BUFFER {
            Self::MIN_INPUT_BUFFER
        } else if bytes > Self::MAX_INPUT_BUFFER {
            Self::MAX_INPUT_BUFFER
        } else {
            bytes
        };
        self
    }

    /// The input buffer capacity.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(ws_net::Limits::new().input_buffer(), 64 * 1024);
    /// ```
    #[must_use]
    pub const fn input_buffer(&self) -> usize {
        self.input
    }

    /// Sets the capacity each buffer keeps after use. A buffer that grew
    /// past it (a large message, a burst of output) is shrunk back once it
    /// holds nothing pending, so an idle connection does not keep its
    /// largest burst. `0` frees each buffer as soon as it empties.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(ws_net::Limits::new().with_retain(4096).retain(), 4096);
    /// ```
    #[must_use]
    pub const fn with_retain(mut self, bytes: usize) -> Self {
        self.retain = bytes;
        self
    }

    /// The capacity kept per buffer after use.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(ws_net::Limits::new().retain(), 64 * 1024);
    /// ```
    #[must_use]
    pub const fn retain(&self) -> usize {
        self.retain
    }
}
