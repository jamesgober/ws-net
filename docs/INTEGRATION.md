# ws-net - Integration Guide

How ws-net composes with the layers around it. ws-net owns the WebSocket
protocol and nothing else: no socket, no clock, no thread, no TLS, no HTTP
beyond the one strict upgrade head. Every integration below is the same
loop with a different owner of the bytes.

<sub>Copyright &copy; 2026 <strong>James Gober</strong>.</sub>

## Contents

- [The driver loop](#the-driver-loop)
- [http-net, sans-IO](#http-net-sans-io)
- [http-net, blocking](#http-net-blocking)
- [The blocking adapter on its own](#the-blocking-adapter-on-its-own)
- [A connection engine (serve-net and others)](#a-connection-engine-serve-net-and-others)
- [A gateway: policy, counters, wipe, revocation](#a-gateway-policy-counters-wipe-revocation)
- [TLS (tls-net)](#tls-tls-net)
- [Memory per connection](#memory-per-connection)

## The driver loop

Whatever reads the socket runs this loop for each connection:

1. Read into [`read_buf`](API.md#input) and [`commit`](API.md#input) the
   count (no copy), or [`feed`](API.md#input) bytes you already hold. A
   connection takes at most its input buffer (64 KiB by default) per call:
   feed a large leftover in a loop with polls between.
2. Call [`on_time(now)`](API.md#the-10-api-design-lock) with your monotonic
   milliseconds, if keepalive is configured.
3. [`poll`](API.md#connectionpoll) until `NeedInput`; hand each message to
   the application. Ping and Close replies queue themselves.
4. Write [`output`](API.md#output), report it with `advance_output`.
5. Sleep until the socket is readable or [`next_deadline`](API.md#the-10-api-design-lock),
   whichever comes first. An idle connection costs no CPU.
6. When [`should_close_transport`](API.md#the-10-api-design-lock) is true,
   close the socket.

A send refused with `WsError::OutputFull` means the peer is not reading:
stop producing for that connection until `buffered_output` falls, or close
it by policy (1008, or 1013 Try Again Later).

## http-net, sans-IO

http-net parses the request; ws-net validates the upgrade (http-net knows
only that one was asked for) and decides policy; http-net writes the `101`
with ws-net's fields; the bytes after the head go to a `Connection`.

```rust,ignore
// After ServerEvent::Request(req) with req.is_upgrade():
let handshake = ServerHandshake::from_request(req.method_str(), req.target(), req.headers())?;
let decision = policy.check(&handshake)?; // OriginRefused, HostRefused, ProtocolRequired
let mut response = Response::switching_protocols("websocket");
for (name, value) in handshake.response_fields(decision.protocol, &decision.extensions)? {
    if name.starts_with("sec-websocket-") {
        response = response.header(name, value); // upgrade and connection are written by http-net
    }
}
http.respond(&response, &mut out)?;
// ... poll http until ServerEvent::Upgraded, then:
let mut conn = Connection::server().with_limits(*policy.limits());
let mut rest = http.remaining_input();
while !rest.is_empty() {
    let n = conn.feed(rest);
    rest = &rest[n..];
    // poll conn here when n < rest.len()
}
```

A refusal is an ordinary response: `Response::new(error.status())` (403 for
Origin and Host, 400 otherwise, 426 for a version). ws-net refuses an
upgrade request that declares a body, so http-net and ws-net can never
disagree about where the frames start.

`tests/http_net.rs` runs this path against http-net 0.9 (a dev-dependency
only).

## http-net, blocking

http-net's blocking `Server` hands the socket over in `on_upgrade`; the
blocking adapter continues from there:

```rust,ignore
let server = Server::bind(addr)?.on_upgrade(|up| {
    let mut ws = blocking::WebSocket::from_upgraded(up.stream, &up.leftover, Connection::server());
    while let Ok(message) = ws.read() { /* ... */ }
});
server.serve(|req, _| { /* from_request, check, switching_protocols as above */ })?;
```

`examples/http_net_upgrade.rs` is the whole program. http-net restores the
socket's original read timeout before the hand-off; set your own, at most
the keepalive's ping interval, so the adapter can tick while the peer is
silent.

## The blocking adapter on its own

Without an HTTP server, `blocking::accept` reads the head itself (same-origin
policy, linear head scanning) and `blocking::connect` is the client:

```rust,ignore
let mut ws = blocking::accept(tcp_stream)?;                  // server
let mut ws = blocking::connect(tcp_stream, "host:port", "/")?; // client
```

`read` returns owned `Message`s and writes automatic replies before it
blocks again; `Error::Closed` ends the loop after the closing handshake.
See `examples/blocking_echo.rs` and `examples/blocking_client.rs`.

## A connection engine (serve-net and others)

An engine that owns many sockets on a reactor drives one `Connection` per
upgraded socket with the loop above:

- Build the handshake with `from_request` from the engine's own HTTP
  parsing, decide with `AcceptPolicy::check`, and write the `101` from
  `response_fields` or with `ServerHandshake::accept`.
- Put each connection's `next_deadline` in the timer wheel; call `on_time`
  when it fires and after each read.
- Use `release_memory` on connections that go idle (an idle connection then
  holds no heap), and `Limits::with_input_buffer` / `with_retain` to fit
  many connections in memory.
- On drain, `close(CloseCode::GOING_AWAY, "")` and keep polling until
  `should_close_transport`; the close timeout (5 s by default) bounds the
  wait.
- To zero a connection's buffers before dropping it, call `wipe()`.

## A gateway: policy, counters, wipe, revocation

A gateway in front of services uses the same mechanisms and applies its own
rules:

- **Admission.** The upgrade is an ordinary request through the gateway's
  checks; `AcceptPolicy` (Origin allowlist, `with_hosts`, `with_secure`,
  protocols, limits, keepalive per profile) decides. Refuse with 403, 400,
  426, or `write_refusal(503, Some(retry_after), ..)` when shedding load.
- **One request per message.** After `Event::Text` or `Event::Binary`,
  `detach_message(&mut buffer)` moves the bytes into the gateway's own
  buffer: a swap for reassembled messages, one copy of at most the input
  buffer otherwise. Or reply while holding the message with `poll_split`.
- **Rate limits.** `stats()` gives bytes, frames, messages, Pings, Pongs,
  and Closes in, and bytes and messages out, for per-connection rates
  (frame floods, Ping floods).
- **Revocation.** When a session ends, `close(CloseCode::POLICY_VIOLATION,
  "session ended")`, stop delivering messages, flush, and drop the transport
  after the close timeout. On eject, `wipe()` zeroes input, reassembly, and
  output buffers and the masking seed, and fails the connection.
- **Broadcast.** `PreparedMessage` encodes a server message once;
  `send_prepared` appends it to each connection with one copy, under each
  connection's own output budget.

## TLS (tls-net)

ws-net never sees TLS: `wss://` is a tls-net session whose plaintext side is
fed to ws-net. On close, flush ws-net's Close frame, then send TLS
`close_notify`, then close TCP. Close code 1015 (TLS handshake failure) is
reporting-only: the caller produces it from a tls-net error; ws-net never
sends it. A tls-net example lands once tls-net is published.

## Memory per connection

| Buffer | Bound | Released |
|---|---|---|
| input | `Limits::input_buffer` (64 KiB default; 256 B to 1 MiB) | `release_memory` (kept between reads otherwise) |
| reassembly | the message received so far, never above `max_message`, plus up to 1 MiB reserved ahead of arrived bytes | after delivery when larger than `retain`; `release_memory` |
| output | `max_output` + 256 bytes for automatic Pong and Close; capacity up to twice that (vector growth) plus 64 KiB of written prefix before compaction | when drained and larger than `retain`; `release_memory` |
| inline | `size_of::<Connection>()`, at most 512 bytes (tested) | never |

`tests/memory.rs` measures each scenario with a counting allocator: a 4 MiB
reassembled message peaks at the input buffer plus the message budget; a
slow consumer peaks at twice its output budget plus 64 KiB; an idle
connection after `release_memory` holds no heap; receiving and sending small
messages allocates nothing once the buffers have grown.

Worked example (a chat service: input 16 KiB, message 64 KiB, output
256 KiB, retain 4 KiB): about 16 + 64 + 512 + 64 KiB at the worst instant of
a busy connection, about 0.5 KiB for an idle one after `release_memory`.
