# ws-net - Platform Notes

What differs between platforms and builds, and what does not.

<sub>Copyright &copy; 2026 <strong>James Gober</strong>.</sub>

## Supported

Linux, macOS, and Windows are first class: CI runs every test on each, on
Rust stable and on the MSRV (1.85), and builds the docs with default and
all features. A 32-bit target (`i686-unknown-linux-gnu`) is checked in CI
for `usize` paths, and the byte-order-sensitive code (frame header codec,
masking, SHA-1, base64, masking keys) is tested under Miri on a big-endian
target (`s390x-unknown-linux-gnu`). The engine touches no operating-system
mechanism, so behaviour is identical everywhere: the same input gives the
same events and output on every platform and for every split of the input
(a property test and the fuzz targets check the second part).

## `no_std`

Without default features the crate is `no_std` + `alloc`. Everything but
the OS randomness and the blocking adapter is available. A client then
takes a 32-byte seed (`Connection::client_with_seed`) and a 16-byte nonce
(`ClientHandshake::with_nonce`); both must come from a cryptographic
source. `--no-default-features` builds and tests run in CI.

## Randomness (feature `std`)

Masking keys and handshake nonces come from the operating system's
cryptographic random source through `mod-rand`'s OS tier:

| Platform | Source |
|---|---|
| Linux | `getrandom(2)` (or `/dev/urandom` where the call does not exist) |
| macOS | `getentropy(3)` |
| Windows | `BCryptGenRandom` |
| other Unix | `/dev/urandom` |

If the source fails (a sandbox that filters the call), `Connection::client`
returns a connection that refuses every send and `ClientHandshake::new` one
that refuses to write its request (`RandomUnavailable`); `try_client` and
`try_new` report it up front. There is never a weaker fallback. Keys are
read 1 KiB at a time (about 1.4 ns per key on Windows x86_64).

## 32-bit targets

Lengths from the wire are `u64`; every conversion to `usize` saturates, so
a 2^40-byte claim on a 32-bit target is refused by the budgets, never
truncated. The input buffer is at most 1 MiB on every target.

## Big-endian targets

Frame lengths are encoded and decoded with explicit big-endian conversions;
the masking loop widens the 4-byte key with `from_ne_bytes` on both the key
and the data words, so it is correct whatever the byte order (Miri on
s390x checks it). SHA-1 and base64 use explicit conversions.

## The blocking adapter (feature `std`)

`blocking::WebSocket` ticks the keepalive around every read. While blocked
in `read` nothing ticks, so give the stream a read timeout of at most the
ping interval (`TcpStream::set_read_timeout`); a timed-out read
(`WouldBlock` on Unix, `TimedOut` on Windows) ticks the keepalive and
reads again. `Interrupted` reads and writes are retried. A non-blocking
stream is not supported by this adapter: drive a `Connection` directly from
a reactor instead.

## Line endings and files

The repository uses LF line endings (`.gitattributes`); the crate reads no
files at run time.
