//! `Sec-WebSocket-Extensions` (RFC 6455 section 9.1): the offers a client
//! makes and what was negotiated.
//!
//! ```text
//! extension-list  = 1#extension
//! extension       = token *( ";" extension-param )
//! extension-param = token [ "=" ( token / quoted-string ) ]
//! ```
//!
//! The list itself (commas, quoted strings, whitespace) is read with
//! `parse-net`; a parameter's value may be absent (`client_max_window_bits`,
//! `server_no_context_takeover`), and a quoted value must be a token once
//! unquoted. A quoted value with a backslash escape is refused: no
//! registered extension needs one, and refusing it keeps every value a
//! borrowed `&str`. At most [`MAX_OFFERS`] offers of [`MAX_PARAMS`]
//! parameters each are accepted.
//!
//! # Examples
//!
//! ```
//! use ws_net::extension;
//!
//! let value = b"permessage-deflate; client_max_window_bits, x-webkit-deflate-frame";
//! let offers: Vec<_> = extension::parse(value).collect::<Result<_, _>>()?;
//! assert_eq!(offers[0].name(), "permessage-deflate");
//! let param = offers[0].params().next().expect("one parameter");
//! assert_eq!((param.name, param.value), ("client_max_window_bits", None));
//! assert_eq!(offers[1].name(), "x-webkit-deflate-frame");
//! # Ok::<(), ws_net::HandshakeError>(())
//! ```

use parse_net::text::{is_token, parse_quoted, parse_token, skip_ows};

use crate::error::HandshakeError;

/// The most extension offers accepted from one request, over all its
/// `Sec-WebSocket-Extensions` fields.
pub const MAX_OFFERS: usize = 16;

/// The most parameters accepted in one offer.
pub const MAX_PARAMS: usize = 16;

/// Parses a `Sec-WebSocket-Extensions` value into its offers, in order.
/// The iterator yields `Err(InvalidExtensions)` once and stops if the value
/// is malformed or holds more than [`MAX_OFFERS`] offers.
///
/// # Examples
///
/// ```
/// use ws_net::{HandshakeError, extension};
///
/// assert_eq!(extension::parse(b"").count(), 0);
/// let bad: Vec<_> = extension::parse(b"a; b=\"c d\"").collect();
/// assert_eq!(bad, [Err(HandshakeError::InvalidExtensions)]);
/// ```
#[must_use]
pub fn parse(value: &[u8]) -> Offers<'_> {
    match parse_net::list(value) {
        Ok(list) => Offers {
            elements: Some(list.iter()),
            seen: 0,
        },
        Err(_) => Offers {
            elements: None,
            seen: usize::MAX,
        },
    }
}

/// Checks a whole value: every offer and parameter well formed, at most
/// `budget` offers. Returns the number of offers.
pub(crate) fn validate(value: &[u8], budget: usize) -> Result<usize, HandshakeError> {
    let mut n = 0usize;
    for offer in parse(value) {
        let _ = offer?;
        n += 1;
        if n > budget {
            return Err(HandshakeError::InvalidExtensions);
        }
    }
    Ok(n)
}

/// The offers of a `Sec-WebSocket-Extensions` value; see [`parse`].
#[derive(Clone, Debug)]
pub struct Offers<'a> {
    /// `None` after an error.
    elements: Option<parse_net::list::Elements<'a>>,
    /// Offers yielded so far; `usize::MAX` means "report the error".
    seen: usize,
}

impl<'a> Iterator for Offers<'a> {
    type Item = Result<Offer<'a>, HandshakeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.seen == usize::MAX {
            self.seen = usize::MAX - 1;
            self.elements = None;
            return Some(Err(HandshakeError::InvalidExtensions));
        }
        let element = self.elements.as_mut()?.next()?;
        self.seen += 1;
        let offer = if self.seen > MAX_OFFERS {
            None
        } else {
            parse_offer(element)
        };
        match offer {
            Some(offer) => Some(Ok(offer)),
            None => {
                self.elements = None;
                Some(Err(HandshakeError::InvalidExtensions))
            }
        }
    }
}

/// One extension offer: a name and its parameters.
///
/// # Examples
///
/// See the [module](self).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Offer<'a> {
    name: &'a str,
    /// The validated parameter text after the name.
    params: &'a [u8],
}

impl<'a> Offer<'a> {
    /// The extension name, as sent (registered names are lowercase; compare
    /// exactly).
    ///
    /// # Examples
    ///
    /// See the [module](self).
    #[must_use]
    pub fn name(&self) -> &'a str {
        self.name
    }

    /// The parameters, in order.
    ///
    /// # Examples
    ///
    /// ```
    /// use ws_net::extension;
    ///
    /// let offer = extension::parse(b"e; a=1; b=\"x\"; c").next().expect("one")?;
    /// let params: Vec<_> = offer.params().map(|p| (p.name, p.value)).collect();
    /// assert_eq!(params, [("a", Some("1")), ("b", Some("x")), ("c", None)]);
    /// # Ok::<(), ws_net::HandshakeError>(())
    /// ```
    #[must_use]
    pub fn params(&self) -> Params<'a> {
        Params { rest: self.params }
    }
}

/// The parameters of an [`Offer`].
#[derive(Clone, Debug)]
pub struct Params<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Params<'a> {
    type Item = Param<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let (param, used) = parse_param(self.rest)?;
        self.rest = self.rest.get(used..).unwrap_or(&[]);
        Some(param)
    }
}

/// One extension parameter.
///
/// # Examples
///
/// See [`Offer::params`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Param<'a> {
    /// The parameter name.
    pub name: &'a str,
    /// The value, unquoted; `None` when the parameter has none.
    pub value: Option<&'a str>,
}

/// The extensions in force on a connection. In this version no extension
/// is ever negotiated, so it is always empty; permessage-deflate (feature
/// `deflate`) adds its parameters here.
///
/// # Examples
///
/// ```
/// let n = ws_net::extension::Negotiated::none();
/// assert!(n.is_empty());
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Negotiated {}

impl Negotiated {
    /// Nothing negotiated.
    ///
    /// # Examples
    ///
    /// See [`Negotiated`].
    #[must_use]
    pub const fn none() -> Self {
        Self {}
    }

    /// Whether nothing was negotiated.
    ///
    /// # Examples
    ///
    /// See [`Negotiated`].
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        true
    }
}

fn utf8(bytes: &[u8]) -> Option<&str> {
    core::str::from_utf8(bytes).ok()
}

/// Parses one list element as an offer, validating every parameter.
fn parse_offer(element: &[u8]) -> Option<Offer<'_>> {
    let (name, used) = parse_token(element).ok()?;
    let params = element.get(used..)?;
    let mut rest = params;
    let mut count = 0usize;
    loop {
        let after = rest.get(skip_ows(rest)..).unwrap_or(&[]);
        if after.is_empty() {
            break;
        }
        let (_, used) = parse_param(rest)?;
        count += 1;
        if count > MAX_PARAMS {
            return None;
        }
        rest = rest.get(used..).unwrap_or(&[]);
    }
    Some(Offer {
        name: utf8(name)?,
        params,
    })
}

/// Parses `OWS ";" OWS token [ "=" value ]` at the start of `s`, and the
/// bytes used. `None` at the end or on a malformed parameter.
fn parse_param(s: &[u8]) -> Option<(Param<'_>, usize)> {
    let mut at = skip_ows(s);
    if s.get(at) != Some(&b';') {
        return None;
    }
    at += 1;
    at += skip_ows(s.get(at..)?);
    let (name, used) = parse_token(s.get(at..)?).ok()?;
    at += used;
    let mut value = None;
    if s.get(at) == Some(&b'=') {
        at += 1;
        let rest = s.get(at..)?;
        let v = if rest.first() == Some(&b'"') {
            let (quoted, used) = parse_quoted(rest).ok()?;
            at += used;
            // RFC 6455 section 9.1: a quoted value is a token once unquoted.
            let plain = quoted.as_plain()?;
            is_token(plain).then_some(plain)?
        } else {
            let (token, used) = parse_token(rest).ok()?;
            at += used;
            token
        };
        value = Some(utf8(v)?);
    }
    Some((
        Param {
            name: utf8(name)?,
            value,
        },
        at,
    ))
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    fn offers(v: &[u8]) -> Result<Vec<(&str, Vec<Param<'_>>)>, HandshakeError> {
        parse(v)
            .map(|o| o.map(|o| (o.name(), o.params().collect())))
            .collect()
    }

    #[test]
    fn test_extension_parse_rfc7692_offers_accepted() {
        let v = b"permessage-deflate; client_max_window_bits; server_max_window_bits=10, \
                  permessage-deflate;server_no_context_takeover ; client_max_window_bits=\"12\"";
        let got = offers(v).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].1.len(), 2);
        assert_eq!(got[0].1[1].value, Some("10"));
        assert_eq!(
            got[1].1[0],
            Param {
                name: "server_no_context_takeover",
                value: None
            }
        );
        assert_eq!(got[1].1[1].value, Some("12"));
    }

    #[test]
    fn test_extension_parse_malformed_refused() {
        for bad in [
            &b"; a"[..],
            b"a;",
            b"a; =1",
            b"a; b =1",
            b"a; b= 1",
            b"a; b=",
            b"a; b=\"\"",
            b"a; b=\"x y\"",
            b"a; b=\"x\\y\"",
            b"a; b=\"x",
            b"a b",
            b"\"a\"",
            b"a; b=1 c",
            b"a\x00",
        ] {
            assert_eq!(
                offers(bad),
                Err(HandshakeError::InvalidExtensions),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn test_extension_parse_empty_elements_skipped() {
        assert_eq!(offers(b" , a ,, b ").unwrap().len(), 2);
        assert!(offers(b"").unwrap().is_empty());
    }

    #[test]
    fn test_extension_parse_counts_capped() {
        let sixteen: Vec<u8> = b"e,".repeat(16);
        assert_eq!(offers(&sixteen).unwrap().len(), 16);
        let seventeen: Vec<u8> = b"e,".repeat(17);
        assert_eq!(offers(&seventeen), Err(HandshakeError::InvalidExtensions));
        let mut many = b"e".to_vec();
        for _ in 0..16 {
            many.extend_from_slice(b"; p");
        }
        assert_eq!(offers(&many).unwrap()[0].1.len(), 16);
        many.extend_from_slice(b"; p");
        assert_eq!(offers(&many), Err(HandshakeError::InvalidExtensions));
        assert_eq!(validate(&sixteen, 16), Ok(16));
        assert_eq!(
            validate(&sixteen, 15),
            Err(HandshakeError::InvalidExtensions)
        );
    }
}
