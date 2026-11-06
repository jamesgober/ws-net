//! A ws-net server and client talking through two tls-net sessions in
//! memory (the bytes a `wss://` socket would carry): the opening handshake
//! and messages over TLS, then the close order the integration guide gives
//! (ws-net's Close flushed, then TLS close_notify, then the transport).

use tls_net::{ClientSession, Event as TlsEvent, Progress, ServerSession, TlsError};
use ws_net::{
    AcceptPolicy, Acceptor, ClientHandshake, CloseCode, Connection, Event, HeadReader, OriginPolicy,
};

const CA: &[u8] = include_bytes!("../data/ca.pem");
const CHAIN: &[u8] = include_bytes!("../data/api.pem");
const KEY: &[u8] = include_bytes!("../data/api.key");
const NAME: &str = "api.other.test";

/// The two session types share their stepping methods.
trait Tls {
    fn step<'i>(
        &mut self,
        input: &'i mut [u8],
        output: &mut [u8],
    ) -> Result<Progress<'i>, TlsError>;
    fn encrypt(&mut self, plaintext: &[u8], output: &mut [u8]) -> Result<usize, TlsError>;
}

impl Tls for ServerSession {
    fn step<'i>(
        &mut self,
        input: &'i mut [u8],
        output: &mut [u8],
    ) -> Result<Progress<'i>, TlsError> {
        ServerSession::step(self, input, output)
    }
    fn encrypt(&mut self, plaintext: &[u8], output: &mut [u8]) -> Result<usize, TlsError> {
        ServerSession::encrypt(self, plaintext, output)
    }
}

impl Tls for ClientSession {
    fn step<'i>(
        &mut self,
        input: &'i mut [u8],
        output: &mut [u8],
    ) -> Result<Progress<'i>, TlsError> {
        ClientSession::step(self, input, output)
    }
    fn encrypt(&mut self, plaintext: &[u8], output: &mut [u8]) -> Result<usize, TlsError> {
        ClientSession::encrypt(self, plaintext, output)
    }
}

/// One end of the in-memory TLS link.
struct End<S> {
    tls: S,
    /// Ciphertext received, not yet consumed.
    input: Vec<u8>,
    /// Ciphertext to send to the peer.
    wire: Vec<u8>,
    /// Plaintext received.
    plain: Vec<u8>,
    ready: bool,
    peer_closed: bool,
}

impl<S: Tls> End<S> {
    fn new(tls: S) -> Self {
        Self {
            tls,
            input: Vec::new(),
            wire: Vec::new(),
            plain: Vec::new(),
            ready: false,
            peer_closed: false,
        }
    }

    /// Steps the session until it needs input.
    fn pump(&mut self) {
        let mut out = vec![0u8; 64 * 1024];
        for _ in 0..1000 {
            let mut buf = self.input.clone();
            let p = self.tls.step(&mut buf, &mut out).expect("tls step");
            let (consumed, written) = (p.consumed, p.written);
            let mut idle = false;
            match p.event {
                TlsEvent::HandshakeComplete => self.ready = true,
                TlsEvent::Data(plain) => self.plain.extend_from_slice(plain),
                TlsEvent::PeerClosed | TlsEvent::Closed => self.peer_closed = true,
                TlsEvent::NeedInput => idle = true,
                _ => {}
            }
            self.wire.extend_from_slice(&out[..written]);
            self.input.drain(..consumed);
            if idle && consumed == 0 && written == 0 {
                return;
            }
        }
        panic!("tls made no progress");
    }

    /// Encrypts `plaintext` for the peer.
    fn send(&mut self, plaintext: &[u8]) {
        let mut out = vec![0u8; plaintext.len() + 64 * 1024];
        let n = self.tls.encrypt(plaintext, &mut out).expect("encrypt");
        self.wire.extend_from_slice(&out[..n]);
    }
}

/// Moves each end's ciphertext to the other and pumps both, until quiet.
fn exchange<A: Tls, B: Tls>(a: &mut End<A>, b: &mut End<B>) {
    for _ in 0..100 {
        a.pump();
        b.pump();
        if a.wire.is_empty() && b.wire.is_empty() {
            return;
        }
        let to_b = std::mem::take(&mut a.wire);
        b.input.extend_from_slice(&to_b);
        let to_a = std::mem::take(&mut b.wire);
        a.input.extend_from_slice(&to_a);
    }
    panic!("no quiet point");
}

/// Feeds plaintext to a connection and collects text messages.
fn read_texts(conn: &mut Connection, plain: &mut Vec<u8>) -> Vec<String> {
    let mut texts = Vec::new();
    let mut rest = std::mem::take(plain);
    let mut at = 0;
    loop {
        let n = conn.feed(&rest[at..]);
        at += n;
        loop {
            match conn.poll().expect("protocol") {
                Event::Text(t) => texts.push(t.to_string()),
                Event::NeedInput | Event::Closed => break,
                _ => {}
            }
        }
        if at == rest.len() {
            break;
        }
    }
    rest.clear();
    texts
}

#[test]
fn test_ws_over_tls_echo_and_close_order() {
    let server = tls_net::server_from_pem(CHAIN, KEY).expect("server config");
    let client = tls_net::client_with_ca_pem(CA).expect("client config");
    let mut s = End::new(server.accept().expect("server session"));
    let mut c = End::new(client.connect(NAME).expect("client session"));

    // The TLS handshake.
    exchange(&mut c, &mut s);
    assert!(c.ready && s.ready, "TLS handshake");

    // The WebSocket opening handshake, as plaintext inside TLS. A `wss`
    // endpoint pins the page scheme to https.
    let hs = ClientHandshake::try_new()
        .unwrap()
        .with_origin(&format!("https://{NAME}"));
    let mut request = Vec::new();
    hs.write_request(NAME, "/rpc", &mut request).unwrap();
    c.send(&request);
    exchange(&mut c, &mut s);
    let policy = AcceptPolicy::new()
        .with_secure(true)
        .with_origins(OriginPolicy::same_origin());
    let accepted = Acceptor::with_policy(policy)
        .accept(&s.plain)
        .expect("accepted")
        .expect("complete head");
    s.plain.drain(..accepted.consumed);
    let mut server_ws = accepted.connection;
    s.send(&accepted.response);
    exchange(&mut c, &mut s);
    let (verified, len) = HeadReader::new()
        .client(&hs, &c.plain)
        .expect("verified")
        .expect("complete response");
    c.plain.drain(..len);
    let mut client_ws = hs.connection(&verified);

    // Messages both ways.
    client_ws.send_text("over tls").unwrap();
    let out = client_ws.output().to_vec();
    client_ws.advance_output(out.len());
    c.send(&out);
    exchange(&mut c, &mut s);
    let got = read_texts(&mut server_ws, &mut s.plain);
    assert_eq!(got, ["over tls"]);
    server_ws.send_text("echo: over tls").unwrap();
    let out = server_ws.output().to_vec();
    server_ws.advance_output(out.len());
    s.send(&out);
    exchange(&mut c, &mut s);
    assert_eq!(read_texts(&mut client_ws, &mut c.plain), ["echo: over tls"]);

    // The close order: the client's Close, the server's echo, then the
    // server (which closes first) sends close_notify.
    client_ws.close(CloseCode::NORMAL, "done").unwrap();
    let out = client_ws.output().to_vec();
    client_ws.advance_output(out.len());
    c.send(&out);
    exchange(&mut c, &mut s);
    let _ = read_texts(&mut server_ws, &mut s.plain);
    let echo = server_ws.output().to_vec();
    server_ws.advance_output(echo.len());
    assert!(server_ws.should_close_transport());
    s.send(&echo);
    let mut notify = vec![0u8; 1024];
    let n = s.tls.close(&mut notify).expect("close_notify");
    s.wire.extend_from_slice(&notify[..n]);
    exchange(&mut c, &mut s);
    let _ = read_texts(&mut client_ws, &mut c.plain);
    assert_eq!(client_ws.state(), ws_net::State::Closed);
    assert!(c.peer_closed, "close_notify reached the client");
    // The client saw the server's EOF next; it may close its transport.
    client_ws.feed_eof();
    assert!(client_ws.should_close_transport());
}
