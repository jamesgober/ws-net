//! A WebSocket echo service as a net-io [`Session`]: net-io owns the socket,
//! the timers, and the limits; ws-net turns its bytes into messages and the
//! echoes into frames. Neither does the other's job, so the session is only
//! the glue between the two sans-IO halves.
//!
//! The glue has three rules:
//!
//! - every input byte goes to ws-net at once (its input buffer is the
//!   bound), so no message waits in net-io's input for a later read;
//! - ws-net's output moves to net-io's output as far as net-io's budget
//!   allows, and the session asks for a write while any of it is left;
//! - once ws-net says [`Connection::should_close_transport`], the session
//!   returns [`Step::Close`] and net-io flushes and closes the socket. The
//!   server closes TCP first (RFC 6455 section 7.1.1).

use std::net::SocketAddr;

use net_io::{
    AllowAll, CloseReason, ConnectionInfo, DriverKind, Endpoint, Input, Limits, NetError, Phase,
    PrefixPolicy, Server, ServerBuilder, Session, SessionContext, Step, TimeoutKind,
};
use ws_net::{Acceptor, CloseCode, Connection, Event, State, WsError};

/// Where a connection is.
// Stored once per connection, so boxing the large variant would only add an
// allocation per connection.
#[allow(clippy::large_enum_variant)]
enum Stage {
    /// Reading the upgrade request.
    Handshake(Acceptor),
    /// Exchanging frames.
    Open(Connection),
    /// The handshake was refused and the refusal queued.
    Refused,
}

/// One connection's echo service.
pub struct WsEcho {
    stage: Stage,
}

impl Default for WsEcho {
    fn default() -> Self {
        Self::new()
    }
}

impl WsEcho {
    /// A session waiting for the upgrade request.
    #[must_use]
    pub fn new() -> Self {
        Self {
            stage: Stage::Handshake(Acceptor::new()),
        }
    }

    /// As [`new`](Self::new), with the connection's budgets.
    #[must_use]
    pub fn with_limits(limits: ws_net::Limits) -> Self {
        let policy = ws_net::AcceptPolicy::new().with_limits(limits);
        Self {
            stage: Stage::Handshake(Acceptor::with_policy(policy)),
        }
    }
}

/// Feeds every input byte to `conn` and echoes each message it completes.
fn pump(conn: &mut Connection, input: &mut Input) {
    loop {
        let refused = match conn.poll_split() {
            Ok((Event::Text(text), mut sender)) => sender.send_text(text).err(),
            Ok((Event::Binary(data), mut sender)) => sender.send_binary(data).err(),
            Ok((Event::NeedInput, _)) => {
                let n = conn.feed(input.bytes());
                input.consume(n);
                if n == 0 {
                    return;
                }
                None
            }
            // Pings are answered and the peer's Close echoed by ws-net.
            Ok((Event::Closed, _)) | Err(_) => return,
            Ok(_) => None,
        };
        if refused == Some(WsError::OutputFull) {
            // The peer sends but does not read its echoes: past ws-net's
            // output budget, close instead of buffering more.
            let _ = conn.close(CloseCode::POLICY_VIOLATION, "not reading");
        }
    }
}

/// Moves what net-io's output takes and says what to do next.
fn next(conn: &mut Connection, cx: &mut SessionContext<'_>) -> Step {
    let taken = cx.output().push_partial(conn.output());
    conn.advance_output(taken);
    if conn.should_close_transport() {
        return Step::Close;
    }
    if !cx.output().is_empty() || conn.buffered_output() > 0 {
        return Step::Write;
    }
    cx.set_phase(Phase::Idle);
    Step::Read
}

impl Session for WsEcho {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        if let Stage::Handshake(acceptor) = &mut self.stage {
            match acceptor.accept(input.bytes()) {
                Ok(None) => {
                    // Part of the head: read on under the read timeout.
                    cx.set_phase(Phase::Receiving);
                    return Step::Read;
                }
                Ok(Some(accepted)) => {
                    input.consume(accepted.consumed);
                    if cx.output().push(&accepted.response).is_err() {
                        return Step::Abort;
                    }
                    self.stage = Stage::Open(accepted.connection);
                }
                Err(refused) => {
                    let mut response = Vec::new();
                    refused.write_response(&mut response);
                    let _ = cx.output().push(&response);
                    self.stage = Stage::Refused;
                    return Step::Close;
                }
            }
        }
        match &mut self.stage {
            Stage::Open(conn) => {
                pump(conn, input);
                next(conn, cx)
            }
            Stage::Handshake(_) | Stage::Refused => Step::Close,
        }
    }

    fn on_writable(&mut self, cx: &mut SessionContext<'_>) -> Step {
        match &mut self.stage {
            Stage::Open(conn) => next(conn, cx),
            Stage::Handshake(_) => Step::Read,
            Stage::Refused => Step::Close,
        }
    }

    fn on_peer_closed(&mut self, cx: &mut SessionContext<'_>) -> Step {
        let Stage::Open(conn) = &mut self.stage else {
            return Step::Close;
        };
        // A FIN without a Close is a failure (1006); either way nothing more
        // arrives, so write what is queued and close.
        conn.feed_eof();
        let mut empty = Input::from_bytes(&[]);
        pump(conn, &mut empty);
        match next(conn, cx) {
            Step::Read => Step::Close,
            step => step,
        }
    }

    fn on_timeout(&mut self, cx: &mut SessionContext<'_>, which: TimeoutKind) -> Step {
        let _ = which;
        let Stage::Open(conn) = &mut self.stage else {
            return Step::Close;
        };
        if conn.state() != State::Open {
            // The second timeout: the peer did not answer our Close.
            return Step::Close;
        }
        // Idle past net-io's timeout: start the closing handshake with 1001.
        // `Write` re-arms the timeout, so a peer that never answers is
        // closed by the next one; returning `Close` here would close at once
        // without sending the frame.
        let _ = conn.close(CloseCode::GOING_AWAY, "idle");
        match next(conn, cx) {
            Step::Read => Step::Write,
            step => step,
        }
    }

    fn on_close(&mut self, _info: &ConnectionInfo, _reason: CloseReason) {
        if let Stage::Open(conn) = &mut self.stage {
            // Nothing of the conversation outlives the connection.
            conn.wipe();
        }
    }
}

/// An echo server on a free loopback port.
///
/// # Errors
///
/// What net-io's builder or listener returns.
pub fn start(driver: DriverKind, workers: u16) -> Result<(Server, SocketAddr), NetError> {
    // Every client of a loopback test comes from one address: lift the
    // per-source cap (16 on the blocking driver) out of the way.
    let limits = Limits::builder()
        .max_connections(4096)
        .max_per_source(4096, PrefixPolicy::DEFAULT)
        .build()?;
    start_with(driver, workers, limits)
}

/// [`start`] with net-io limits (an idle timeout, an output budget).
///
/// # Errors
///
/// What net-io's builder or listener returns.
pub fn start_with(
    driver: DriverKind,
    workers: u16,
    limits: Limits,
) -> Result<(Server, SocketAddr), NetError> {
    start_tuned(driver, workers, limits, ws_net::Limits::new())
}

/// As [`start_with`], with ws-net's budgets for every connection.
///
/// # Errors
///
/// As [`start_with`].
pub fn start_tuned(
    driver: DriverKind,
    workers: u16,
    limits: Limits,
    ws: ws_net::Limits,
) -> Result<(Server, SocketAddr), NetError> {
    let server = ServerBuilder::new()
        .listener(net_io::ListenerSpec::tcp("127.0.0.1:0").name("ws"))
        .driver(driver)
        .workers(workers)
        .limits(limits)
        .sessions(move |_: &ConnectionInfo| WsEcho::with_limits(ws))
        .gate(AllowAll)
        .build()?;
    server.open_door()?;
    let addr = match server.listeners().first().map(|l| &l.local) {
        Some(Endpoint::Ip(addr)) => *addr,
        _ => unreachable!("one TCP listener was configured"),
    };
    Ok((server, addr))
}
