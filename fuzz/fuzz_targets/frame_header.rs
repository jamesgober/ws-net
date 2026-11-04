//! `FrameHeader::decode` never panics, and every header it accepts encodes
//! back to the same bytes (lengths are minimal, so each header has one
//! encoding).
#![no_main]

use libfuzzer_sys::fuzz_target;
use ws_net::frame::FrameHeader;

fuzz_target!(|data: &[u8]| {
    if let Ok(Some((header, len))) = FrameHeader::decode(data) {
        let mut out = Vec::new();
        header.encode(&mut out).expect("an accepted header encodes");
        assert_eq!(out, &data[..len]);
        assert_eq!(header.encoded_len(), len);
        // Every prefix of an accepted header asks for more bytes.
        for cut in 0..len {
            assert!(matches!(FrameHeader::decode(&data[..cut]), Ok(None)));
        }
    }
});
