//! A blocking adapter over any `Read + Write` stream (feature `std`): a
//! `TcpStream`, a TLS stream, an in-memory pipe. It drives the sans-IO
//! [`Connection`] for you, the way a `std::net` program expects.
//!
//! ```no_run
//! use std::net::TcpListener;
//! use ws_net::{Message, blocking};
//!
//! let listener = TcpListener::bind("127.0.0.1:9001")?;
//! for stream in listener.incoming() {
//!     let mut ws = blocking::accept(stream?)?; // same-origin policy, 101 written
//!     while let Ok(message) = ws.read() {
//!         if message.is_data() {
//!             ws.send(&message)?; // echo
//!         }
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Timeouts: the adapter calls [`Connection::on_time`] around every read,
//! with time from `std::time::Instant`. While it is blocked in `read`,
//! nothing ticks, so give the stream a read timeout
//! (`TcpStream::set_read_timeout`) of at most the keepalive's ping
//! interval: a timed-out read ticks the keepalive and reads again, and an
//! idle timeout then ends the connection.

use std::{
    fmt, io,
    io::{Read, Write},
    string::String,
    time::Instant,
    vec::Vec,
};

use crate::{
    close::CloseCode,
    conn::{Connection, Event},
    error::{HandshakeError, WsError},
    handshake::{ClientHandshake, HeadReader, ServerHandshake},
    keepalive::{Millis, Tick},
    message::Message,
    policy::{AcceptPolicy, Acceptor},
};

/// Why a blocking call failed.
///
/// # Examples
///
/// ```
/// use ws_net::{HandshakeError, WsError, blocking::Error};
///
/// let e = Error::from(WsError::InvalidUtf8);
/// assert_eq!(e.to_string(), "protocol: text is not valid UTF-8");
/// assert!(matches!(Error::from(HandshakeError::OriginRefused), Error::Handshake(_)));
/// ```
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// The stream failed.
    Io(io::Error),
    /// The connection failed (its Close frame was written first) or a call
    /// was refused.
    Protocol(WsError),
    /// The opening handshake was refused (on the server side, the refusal
    /// was written first).
    Handshake(HandshakeError),
    /// The connection is closed: the closing handshake is complete. Drop
    /// the stream (a server closes first).
    Closed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "i/o: {e}"),
            Self::Protocol(e) => write!(f, "protocol: {e}"),
            Self::Handshake(e) => write!(f, "handshake: {e}"),
            Self::Closed => f.write_str("the connection is closed"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Protocol(e) => Some(e),
            Self::Handshake(e) => Some(e),
            Self::Closed => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<WsError> for Error {
    fn from(e: WsError) -> Self {
        Self::Protocol(e)
    }
}

impl From<HandshakeError> for Error {
    fn from(e: HandshakeError) -> Self {
        Self::Handshake(e)
    }
}

/// Reads at most 4 KiB per call while the head is incomplete.
const HEAD_CHUNK: usize = 4096;

fn read_some<S: Read>(stream: &mut S, buf: &mut Vec<u8>) -> Result<(), Error> {
    let mut chunk = [0u8; HEAD_CHUNK];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => return Err(Error::Io(io::ErrorKind::UnexpectedEof.into())),
            Ok(n) => {
                buf.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
                return Ok(());
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(Error::Io(e)),
        }
    }
}

/// Accepts a WebSocket on `stream` with the Tier 1 policy
/// ([`AcceptPolicy::new`]: same-origin): reads the request head, writes the
/// `101` or the refusal, and returns the connection.
///
/// # Errors
///
/// [`Error::Io`]; [`Error::Handshake`] after the refusal was written.
///
/// # Examples
///
/// See the [module](self).
pub fn accept<S: Read + Write>(stream: S) -> Result<WebSocket<S>, Error> {
    accept_with(stream, &AcceptPolicy::new()).map(|(ws, _)| ws)
}

/// As [`accept`] with a policy; also returns the request, for routing on
/// its target.
///
/// # Errors
///
/// As [`accept`].
///
/// # Examples
///
/// ```no_run
/// use std::net::TcpListener;
/// use ws_net::{AcceptPolicy, OriginPolicy, blocking};
///
/// let policy = AcceptPolicy::new().with_origins(OriginPolicy::allow(&["https://app.example"])?);
/// let (stream, _) = TcpListener::bind("127.0.0.1:0")?.accept()?;
/// let (mut ws, request) = blocking::accept_with(stream, &policy)?;
/// println!("connected to {}", request.target());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn accept_with<S: Read + Write>(
    mut stream: S,
    policy: &AcceptPolicy,
) -> Result<(WebSocket<S>, ServerHandshake), Error> {
    let mut acceptor = Acceptor::with_policy(policy.clone());
    let mut buf = Vec::new();
    loop {
        read_some(&mut stream, &mut buf)?;
        match acceptor.accept(&buf) {
            Ok(None) => {}
            Ok(Some(accepted)) => {
                stream.write_all(&accepted.response)?;
                stream.flush()?;
                let leftover = buf.get(accepted.consumed..).unwrap_or(&[]);
                let ws = WebSocket::from_upgraded(stream, leftover, accepted.connection);
                return Ok((ws, accepted.handshake));
            }
            Err(refused) => {
                let mut response = Vec::new();
                refused.write_response(&mut response);
                // Best effort: the refusal is the error that matters.
                let _ = stream.write_all(&response).and_then(|()| stream.flush());
                return Err(Error::Handshake(refused));
            }
        }
    }
}

/// Opens a WebSocket over `stream` as a client: writes the request for
/// `path` on `host` with a fresh nonce, verifies the `101`, and returns
/// the connection.
///
/// # Errors
///
/// [`Error::Io`], [`Error::Handshake`] (a refusal, a bad response, or
/// `RandomUnavailable`).
///
/// # Examples
///
/// ```no_run
/// use std::net::TcpStream;
/// use ws_net::blocking;
///
/// let mut ws = blocking::connect(TcpStream::connect("127.0.0.1:9001")?, "127.0.0.1:9001", "/")?;
/// ws.send_text("hello")?;
/// println!("{:?}", ws.read()?);
/// ws.close(ws_net::CloseCode::NORMAL, "")?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn connect<S: Read + Write>(stream: S, host: &str, path: &str) -> Result<WebSocket<S>, Error> {
    let handshake = ClientHandshake::try_new()?;
    connect_with(stream, host, path, &handshake).map(|(ws, _)| ws)
}

/// As [`connect`] with a prepared [`ClientHandshake`] (subprotocols,
/// `Origin`, extra headers); also returns the selected subprotocol.
///
/// # Errors
///
/// As [`connect`].
///
/// # Examples
///
/// ```no_run
/// use std::net::TcpStream;
/// use ws_net::{ClientHandshake, blocking};
///
/// let hs = ClientHandshake::try_new()?.with_protocols(&["rpc.v2"]).with_header("authorization", b"Bearer t");
/// let stream = TcpStream::connect("127.0.0.1:9001")?;
/// let (ws, protocol) = blocking::connect_with(stream, "127.0.0.1:9001", "/rpc", &hs)?;
/// assert_eq!(protocol.as_deref(), Some("rpc.v2"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn connect_with<S: Read + Write>(
    mut stream: S,
    host: &str,
    path: &str,
    handshake: &ClientHandshake,
) -> Result<(WebSocket<S>, Option<String>), Error> {
    let mut request = Vec::new();
    handshake.write_request(host, path, &mut request)?;
    stream.write_all(&request)?;
    stream.flush()?;
    let mut reader = HeadReader::new();
    let mut buf = Vec::new();
    loop {
        read_some(&mut stream, &mut buf)?;
        if let Some((verified, len)) = reader.client(handshake, &buf)? {
            let protocol = verified.protocol.map(String::from);
            let connection = Connection::try_client()?;
            let leftover = buf.get(len..).unwrap_or(&[]);
            return Ok((
                WebSocket::from_upgraded(stream, leftover, connection),
                protocol,
            ));
        }
    }
}

/// A WebSocket over a blocking stream.
///
/// # Examples
///
/// See the [module](self) and [`WebSocket::from_upgraded`].
pub struct WebSocket<S> {
    stream: S,
    connection: Connection,
    /// Bytes that arrived with the handshake, not yet taken by the
    /// connection.
    pending: Vec<u8>,
    taken: usize,
    start: Instant,
}

impl<S> fmt::Debug for WebSocket<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebSocket")
            .field("connection", &self.connection)
            .field("pending", &(self.pending.len() - self.taken))
            .finish_non_exhaustive()
    }
}

impl<S: Read + Write> WebSocket<S> {
    /// Continues on a stream whose handshake was done elsewhere, such as
    /// http-net's upgrade hand-off (`Upgraded { stream, leftover, .. }`):
    /// `leftover` are the bytes that arrived after the head.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::Cursor;
    /// use ws_net::{Connection, Message, blocking::WebSocket};
    ///
    /// // A masked "Hello" that arrived with the request head.
    /// let leftover = [0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58];
    /// let mut ws = WebSocket::from_upgraded(Cursor::new(Vec::new()), &leftover, Connection::server());
    /// assert_eq!(ws.read()?, Message::from("Hello"));
    /// # Ok::<(), ws_net::blocking::Error>(())
    /// ```
    pub fn from_upgraded(stream: S, leftover: &[u8], connection: Connection) -> Self {
        Self {
            stream,
            connection,
            pending: leftover.to_vec(),
            taken: 0,
            start: Instant::now(),
        }
    }

    fn now(&self) -> Millis {
        Millis::from_duration(self.start.elapsed())
    }

    /// Ticks the keepalive; an expiry is written and returned.
    fn tick(&mut self) -> Result<(), Error> {
        match self.connection.on_time(self.now()) {
            Ok(Tick::PingQueued) => self.flush(),
            Ok(_) => Ok(()),
            Err(e) => {
                let _ = self.flush();
                Err(Error::Protocol(e))
            }
        }
    }

    /// Reads until a message, Ping, Pong, or Close arrives. Automatic
    /// replies (Pong, the Close echo) are written before this returns or
    /// blocks again.
    ///
    /// # Errors
    ///
    /// [`Error::Closed`] once the closing handshake is complete;
    /// [`Error::Protocol`] when the connection failed (its Close frame was
    /// written) or a keepalive timeout fired; [`Error::Io`].
    ///
    /// # Examples
    ///
    /// See [`from_upgraded`](Self::from_upgraded).
    pub fn read(&mut self) -> Result<Message, Error> {
        loop {
            if self.taken < self.pending.len() {
                let n = self
                    .connection
                    .feed(self.pending.get(self.taken..).unwrap_or(&[]));
                self.taken += n;
                if self.taken == self.pending.len() {
                    self.pending = Vec::new();
                    self.taken = 0;
                }
            }
            let message = match self.connection.poll() {
                Ok(Event::NeedInput) => None,
                Ok(Event::Closed) => {
                    self.flush()?;
                    return Err(Error::Closed);
                }
                Ok(event) => event.to_message(),
                Err(e) => {
                    let _ = self.flush();
                    return Err(Error::Protocol(e));
                }
            };
            if let Some(message) = message {
                self.flush()?;
                return Ok(message);
            }
            self.flush()?;
            if self.taken < self.pending.len() {
                continue;
            }
            self.tick()?;
            match self.stream.read(self.connection.read_buf()) {
                Ok(0) => self.connection.feed_eof(),
                Ok(n) => self.connection.commit(n),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(e) => return Err(Error::Io(e)),
            }
            self.tick()?;
        }
    }

    /// Sends a text message.
    ///
    /// # Errors
    ///
    /// [`Error::Protocol`] for a refused send, [`Error::Io`].
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::Cursor;
    /// use ws_net::{Connection, blocking::WebSocket};
    ///
    /// let mut ws = WebSocket::from_upgraded(Cursor::new(Vec::new()), &[], Connection::server());
    /// ws.send_text("hi")?;
    /// assert_eq!(ws.get_ref().get_ref(), &[0x81, 0x02, b'h', b'i']);
    /// # Ok::<(), ws_net::blocking::Error>(())
    /// ```
    pub fn send_text(&mut self, text: &str) -> Result<(), Error> {
        self.connection.send_text(text)?;
        self.flush()
    }

    /// Sends a binary message.
    ///
    /// # Errors
    ///
    /// As [`send_text`](Self::send_text).
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::Cursor;
    /// use ws_net::{Connection, blocking::WebSocket};
    ///
    /// let mut ws = WebSocket::from_upgraded(Cursor::new(Vec::new()), &[], Connection::server());
    /// ws.send_binary(&[1, 2])?;
    /// assert_eq!(ws.get_ref().get_ref(), &[0x82, 0x02, 1, 2]);
    /// # Ok::<(), ws_net::blocking::Error>(())
    /// ```
    pub fn send_binary(&mut self, data: &[u8]) -> Result<(), Error> {
        self.connection.send_binary(data)?;
        self.flush()
    }

    /// Sends an owned [`Message`].
    ///
    /// # Errors
    ///
    /// As [`send_text`](Self::send_text).
    ///
    /// # Examples
    ///
    /// See the [module](self).
    pub fn send(&mut self, message: &Message) -> Result<(), Error> {
        self.connection.send(message)?;
        self.flush()
    }

    /// Sends a Ping.
    ///
    /// # Errors
    ///
    /// As [`send_text`](Self::send_text).
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::Cursor;
    /// use ws_net::{Connection, blocking::WebSocket};
    ///
    /// let mut ws = WebSocket::from_upgraded(Cursor::new(Vec::new()), &[], Connection::server());
    /// ws.ping(b"t")?;
    /// assert_eq!(ws.get_ref().get_ref(), &[0x89, 0x01, b't']);
    /// # Ok::<(), ws_net::blocking::Error>(())
    /// ```
    pub fn ping(&mut self, payload: &[u8]) -> Result<(), Error> {
        self.connection.send_ping(payload)?;
        self.flush()
    }

    /// Starts the closing handshake; keep calling [`read`](Self::read)
    /// until it returns [`Error::Closed`] to complete it.
    ///
    /// # Errors
    ///
    /// As [`send_text`](Self::send_text).
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::Cursor;
    /// use ws_net::{CloseCode, Connection, blocking::WebSocket};
    ///
    /// let mut ws = WebSocket::from_upgraded(Cursor::new(Vec::new()), &[], Connection::server());
    /// ws.close(CloseCode::NORMAL, "")?;
    /// assert_eq!(ws.get_ref().get_ref(), &[0x88, 0x02, 0x03, 0xE8]);
    /// # Ok::<(), ws_net::blocking::Error>(())
    /// ```
    pub fn close(&mut self, code: CloseCode, reason: &str) -> Result<(), Error> {
        self.connection.close(code, reason)?;
        self.flush()
    }

    /// Writes everything queued and flushes the stream.
    ///
    /// # Errors
    ///
    /// [`Error::Io`]; a stream that accepts no bytes is `WriteZero`.
    ///
    /// # Examples
    ///
    /// See [`send_text`](Self::send_text).
    pub fn flush(&mut self) -> Result<(), Error> {
        loop {
            let out = self.connection.output();
            if out.is_empty() {
                break;
            }
            match self.stream.write(out) {
                Ok(0) => return Err(Error::Io(io::ErrorKind::WriteZero.into())),
                Ok(n) => self.connection.advance_output(n),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(Error::Io(e)),
            }
        }
        self.stream.flush()?;
        Ok(())
    }
}

impl<S> WebSocket<S> {
    /// The connection, for its state, counters, and limits.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::Cursor;
    /// use ws_net::{Connection, blocking::WebSocket};
    ///
    /// let ws = WebSocket::from_upgraded(Cursor::new(Vec::new()), &[], Connection::server());
    /// assert!(ws.connection().is_open());
    /// ```
    #[must_use]
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// The connection, mutably (for example to set keepalive with
    /// `Connection::with_keepalive` before creating the adapter, or to
    /// send a fragmented message).
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::Cursor;
    /// use ws_net::{Connection, blocking::WebSocket};
    ///
    /// let mut ws = WebSocket::from_upgraded(Cursor::new(Vec::new()), &[], Connection::server());
    /// ws.connection_mut().send_text_fragment("a", false)?;
    /// # Ok::<(), ws_net::WsError>(())
    /// ```
    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.connection
    }

    /// The stream.
    ///
    /// # Examples
    ///
    /// See [`send_text`](Self::send_text).
    #[must_use]
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// The stream, mutably (to set timeouts).
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::Cursor;
    /// use ws_net::{Connection, blocking::WebSocket};
    ///
    /// let mut ws = WebSocket::from_upgraded(Cursor::new(Vec::new()), &[], Connection::server());
    /// ws.get_mut().set_position(0);
    /// ```
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// The stream, giving up the connection.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::Cursor;
    /// use ws_net::{Connection, blocking::WebSocket};
    ///
    /// let ws = WebSocket::from_upgraded(Cursor::new(vec![1]), &[], Connection::server());
    /// assert_eq!(ws.into_inner().into_inner(), [1]);
    /// ```
    pub fn into_inner(self) -> S {
        self.stream
    }
}
