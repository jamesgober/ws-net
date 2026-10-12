//! A strict, bounded reader for the one HTTP/1.1 head each side of the
//! opening handshake sees: the client's request head and the server's
//! response head. It exists so the handshake works over raw bytes when no
//! HTTP layer is in front; with one (http-net), use the `(name, value)`
//! entry points instead and this module is not involved.
//!
//! Only what the handshake needs is accepted: CRLF line endings (a bare CR
//! or LF is refused the moment it arrives), a token method, a visible-ASCII
//! target, exactly `HTTP/1.1`, token field names with no whitespace before
//! the colon, no obsolete line folding, and no control bytes in values. The
//! whole head must fit in [`MAX_HEAD`] bytes. There are no bodies: a
//! handshake request has none, and a refused response's body is not read.

use crate::error::HandshakeError;

/// The largest head accepted, request line and fields together.
pub(crate) const MAX_HEAD: usize = 16 * 1024;

/// A complete head: the first line and the field lines, both without their
/// line endings, and the length of the head in bytes.
pub(crate) struct Head<'a> {
    pub(crate) first: &'a [u8],
    fields: &'a [u8],
    pub(crate) len: usize,
}

impl<'a> Head<'a> {
    /// The fields as `(name, value)` pairs, values trimmed of surrounding
    /// spaces and tabs. Every line was validated by [`split`].
    pub(crate) fn fields(&self) -> impl Iterator<Item = (&'a str, &'a [u8])> + use<'a> {
        lines(self.fields).filter_map(field)
    }
}

/// Splits the head off the front of `bytes`: `Ok(None)` until the blank
/// line that ends it has arrived. Each call scans at most [`MAX_HEAD`]
/// bytes, so a caller that retries after every read does bounded work per
/// read.
pub(crate) fn split(bytes: &[u8]) -> Result<Option<Head<'_>>, HandshakeError> {
    let window = bytes.get(..MAX_HEAD).unwrap_or(bytes);
    let mut line_start = 0;
    let mut end = None;
    let mut prev = 0u8;
    for (i, &b) in window.iter().enumerate() {
        match b {
            b'\n' if prev != b'\r' => return Err(HandshakeError::MalformedHead),
            b'\n' if i == line_start + 1 => {
                // An empty line: the head ends here.
                end = Some(i + 1);
                break;
            }
            b'\n' => line_start = i + 1,
            _ if prev == b'\r' => return Err(HandshakeError::MalformedHead),
            _ => {}
        }
        prev = b;
    }
    let Some(len) = end else {
        return if bytes.len() >= MAX_HEAD {
            Err(HandshakeError::HeadTooLarge)
        } else {
            Ok(None)
        };
    };
    // `len` is at least 2 (the blank line) and every line ends in CRLF.
    let head = bytes.get(..len.saturating_sub(2)).unwrap_or(&[]);
    let first_end = head
        .windows(2)
        .position(|w| w == b"\r\n")
        .ok_or(HandshakeError::MalformedHead)?;
    let first = head.get(..first_end).unwrap_or(&[]);
    let fields = head.get(first_end + 2..).unwrap_or(&[]);
    if first.is_empty() || lines(fields).any(|line| field(line).is_none()) {
        return Err(HandshakeError::MalformedHead);
    }
    Ok(Some(Head { first, fields, len }))
}

/// The lines of a CRLF-terminated block, without their endings.
fn lines(block: &[u8]) -> impl Iterator<Item = &[u8]> {
    // Every LF follows a CR (checked by `split`); the piece after the last
    // LF is empty and has no CR, so it drops out.
    block
        .split(|&b| b == b'\n')
        .filter_map(|line| line.strip_suffix(b"\r"))
}

/// Parses one field line, or `None` if it is malformed.
fn field(line: &[u8]) -> Option<(&str, &[u8])> {
    let colon = line.iter().position(|&b| b == b':')?;
    let (name, rest) = line.split_at_checked(colon)?;
    // A token name also refuses leading whitespace (obsolete line folding)
    // and whitespace before the colon.
    if !is_token(name) {
        return None;
    }
    let value = trim_ows(rest.get(1..).unwrap_or(&[]));
    if value.iter().any(|&b| is_control(b)) {
        return None;
    }
    Some((core::str::from_utf8(name).ok()?, value))
}

/// The method and target of a request line `METHOD SP target SP HTTP/1.1`.
pub(crate) fn request_line(line: &[u8]) -> Option<(&str, &str)> {
    let mut parts = line.split(|&b| b == b' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || !is_token(method) || !is_visible(target) || version != b"HTTP/1.1"
    {
        return None;
    }
    Some((
        core::str::from_utf8(method).ok()?,
        core::str::from_utf8(target).ok()?,
    ))
}

/// The status code of a status line `HTTP/1.1 SP 3DIGIT [SP reason]`.
pub(crate) fn status_line(line: &[u8]) -> Option<u16> {
    let rest = line.strip_prefix(b"HTTP/1.1 ")?;
    let (code, reason) = rest.split_at_checked(3)?;
    if !code.iter().all(u8::is_ascii_digit) {
        return None;
    }
    if !(reason.is_empty() || reason.first() == Some(&b' '))
        || reason.iter().any(|&b| is_control(b))
    {
        return None;
    }
    Some(code.iter().fold(0u16, |n, d| n * 10 + u16::from(d - b'0')))
}

/// An RFC 9110 token: one or more `tchar`.
pub(crate) fn is_token(s: &[u8]) -> bool {
    !s.is_empty()
        && s.iter()
            .all(|&b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// One or more visible ASCII characters (no space, no control).
pub(crate) fn is_visible(s: &[u8]) -> bool {
    !s.is_empty() && s.iter().all(u8::is_ascii_graphic)
}

/// A control byte not allowed in a field value (tab is allowed).
const fn is_control(b: u8) -> bool {
    (b < 0x20 && b != b'\t') || b == 0x7f
}

/// `s` without leading and trailing spaces and tabs.
pub(crate) fn trim_ows(s: &[u8]) -> &[u8] {
    let is_ows = |b: &u8| *b == b' ' || *b == b'\t';
    let start = s.iter().position(|b| !is_ows(b)).unwrap_or(s.len());
    let end = s.iter().rposition(|b| !is_ows(b)).map_or(start, |i| i + 1);
    s.get(start..end).unwrap_or(&[])
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn test_split_finds_the_end_and_the_fields() {
        let wire = b"GET / HTTP/1.1\r\nA: 1\r\nB:\t two \r\n\r\nrest";
        let head = split(wire).unwrap().unwrap();
        assert_eq!(head.first, b"GET / HTTP/1.1");
        assert_eq!(head.len, wire.len() - 4);
        let fields: Vec<_> = head.fields().collect();
        assert_eq!(fields, [("A", &b"1"[..]), ("B", b"two")]);
    }

    #[test]
    fn test_head_with_no_fields() {
        let head = split(b"HTTP/1.1 101 OK\r\n\r\n").unwrap().unwrap();
        assert_eq!(head.first, b"HTTP/1.1 101 OK");
        assert_eq!(head.fields().count(), 0);
    }

    #[test]
    fn test_status_lines() {
        assert_eq!(status_line(b"HTTP/1.1 101 Switching Protocols"), Some(101));
        assert_eq!(status_line(b"HTTP/1.1 404"), Some(404));
        assert_eq!(status_line(b"HTTP/1.1 999 "), Some(999));
        for bad in [
            &b"HTTP/1.1 10"[..],
            b"HTTP/1.1 1010",
            b"HTTP/1.1 -10",
            b"HTTP/1.0 101",
            b"HTTP/1.1  101",
            b"HTTP/1.1 101 a\x00b",
        ] {
            assert_eq!(status_line(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn test_trim_ows() {
        assert_eq!(trim_ows(b""), b"");
        assert_eq!(trim_ows(b" \t "), b"");
        assert_eq!(trim_ows(b" a b\t"), b"a b");
    }
}
