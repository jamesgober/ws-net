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

use parse_net::{
    class::{self, Class},
    scan,
    text::{is_token, trim_ows},
};

use crate::error::HandshakeError;

/// The largest head accepted, request line and fields together.
pub(crate) const MAX_HEAD: usize = 16 * 1024;

/// A complete head: the first line and the field lines, both without their
/// line endings, and the length of the head in bytes.
#[derive(Debug)]
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

/// How far the line scan got: carried between calls so that a head that
/// arrives in pieces is scanned once in total, not once per piece.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct Scan {
    /// Bytes scanned so far.
    pos: usize,
    /// Start of the line being scanned.
    line_start: usize,
    /// The byte before `pos`.
    prev: u8,
    /// Bytes examined over every call, for the linear-work test.
    #[cfg(test)]
    examined: usize,
}

/// Splits the head off the front of `bytes`: `Ok(None)` until the blank
/// line that ends it has arrived. One-shot: every call scans from the
/// start. [`split_resume`] is the resumable form.
pub(crate) fn split(bytes: &[u8]) -> Result<Option<Head<'_>>, HandshakeError> {
    split_resume(&mut Scan::default(), bytes)
}

/// As [`split`], continuing from `state`: `bytes` must be the buffer an
/// earlier call saw, grown at the end. Only the new bytes are scanned for
/// line endings, so the total work over all calls is linear in the head,
/// however it was cut (the slow-head CPU amplification of CVE-2023-43669
/// is not possible). The fields are validated once, when the head is
/// complete.
pub(crate) fn split_resume<'a>(
    state: &mut Scan,
    bytes: &'a [u8],
) -> Result<Option<Head<'a>>, HandshakeError> {
    if bytes.len() < state.pos {
        return Err(HandshakeError::InvalidRequest);
    }
    let window = bytes.get(..MAX_HEAD).unwrap_or(bytes);
    let mut end = None;
    for (i, &b) in window.iter().enumerate().skip(state.pos) {
        #[cfg(test)]
        {
            state.examined += 1;
        }
        match b {
            b'\n' if state.prev != b'\r' => return Err(HandshakeError::MalformedHead),
            b'\n' if i == state.line_start + 1 => {
                // An empty line: the head ends here.
                end = Some(i + 1);
                break;
            }
            b'\n' => state.line_start = i + 1,
            _ if state.prev == b'\r' => return Err(HandshakeError::MalformedHead),
            _ => {}
        }
        state.prev = b;
        state.pos = i + 1;
    }
    let Some(len) = end else {
        return if bytes.len() >= MAX_HEAD {
            Err(HandshakeError::HeadTooLarge)
        } else {
            Ok(None)
        };
    };
    state.pos = len;
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
    // Field text: no C0 control other than tab, no DEL.
    scan::check_field_value(value).ok()?;
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
        || scan::check_field_value(reason).is_err()
    {
        return None;
    }
    Some(code.iter().fold(0u16, |n, d| n * 10 + u16::from(d - b'0')))
}

/// One or more visible ASCII characters (no space, no control).
pub(crate) fn is_visible(s: &[u8]) -> bool {
    !s.is_empty() && class::all(s, Class::VCHAR)
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn test_split_complete_head_returns_fields() {
        let wire = b"GET / HTTP/1.1\r\nA: 1\r\nB:\t two \r\n\r\nrest";
        let head = split(wire).unwrap().unwrap();
        assert_eq!(head.first, b"GET / HTTP/1.1");
        assert_eq!(head.len, wire.len() - 4);
        let fields: Vec<_> = head.fields().collect();
        assert_eq!(fields, [("A", &b"1"[..]), ("B", b"two")]);
    }

    #[test]
    fn test_split_no_fields_accepted() {
        let head = split(b"HTTP/1.1 101 OK\r\n\r\n").unwrap().unwrap();
        assert_eq!(head.first, b"HTTP/1.1 101 OK");
        assert_eq!(head.fields().count(), 0);
    }

    #[test]
    fn test_split_resume_bytewise_scans_each_byte_once() {
        let mut wire = b"GET / HTTP/1.1\r\n".to_vec();
        while wire.len() < MAX_HEAD - 40 {
            wire.extend_from_slice(b"X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
        }
        wire.extend_from_slice(b"\r\n");
        let mut state = Scan::default();
        let mut len = None;
        for end in 1..=wire.len() {
            if let Some(head) = split_resume(&mut state, &wire[..end]).unwrap() {
                len = Some(head.len);
                break;
            }
        }
        assert_eq!(len, Some(wire.len()));
        // Linear: every byte examined once, not once per call (the one-shot
        // form would examine about n * n / 2 = 134 million bytes here).
        assert_eq!(state.examined, wire.len());
    }

    #[test]
    fn test_split_resume_matches_split_for_every_cut() {
        let wire = b"GET /a HTTP/1.1\r\nHost: x\r\nA:\tb\r\n\r\nframes";
        let whole = split(wire).unwrap().unwrap();
        for cut in 0..=wire.len() {
            let mut state = Scan::default();
            let early = split_resume(&mut state, &wire[..cut]).unwrap();
            let head = early
                .or_else(|| split_resume(&mut state, wire).unwrap())
                .unwrap();
            assert_eq!(
                (head.first, head.len),
                (whole.first, whole.len),
                "cut {cut}"
            );
        }
        // A bare CR split from what follows it is still refused.
        let mut state = Scan::default();
        assert!(
            split_resume(&mut state, b"GET / HTTP/1.1\r")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            split_resume(&mut state, b"GET / HTTP/1.1\rx").unwrap_err(),
            HandshakeError::MalformedHead
        );
    }

    #[test]
    fn test_status_line_forms_parsed_or_refused() {
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
}
