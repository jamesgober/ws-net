//! The raw request head: a `HeadReader` fed in pieces gives what
//! `from_head` gives on the same bytes, nothing panics, and an accepted
//! request answers a 101 and goes through the default policy.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ws_net::{AcceptPolicy, HeadReader, ServerHandshake};

fuzz_target!(|data: &[u8]| {
    let Some((&step, bytes)) = data.split_first() else { return };
    let step = usize::from(step % 32) + 1;
    let mut reader = HeadReader::new();
    let mut end = 0;
    let got = loop {
        end = (end + step).min(bytes.len());
        let r = reader.server(&bytes[..end]);
        if !matches!(r, Ok(None)) || end == bytes.len() {
            break r;
        }
    };
    assert_eq!(got, ServerHandshake::from_head(&bytes[..end]));
    if let Ok(Some((h, len))) = got {
        assert!(len <= end);
        assert_eq!(h.accept_key().as_str().len(), 28);
        assert!(!h.host().is_empty());
        let mut out = Vec::new();
        h.write_response(None, &mut out).expect("101 without a protocol");
        let _ = AcceptPolicy::new().check(&h);
        let _ = h.extensions().count();
    }
});
