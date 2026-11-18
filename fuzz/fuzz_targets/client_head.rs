//! The raw response head: no panic, the one-shot and the resumable reader
//! give the same result, and an accepted response named an offered
//! protocol (or none).
#![no_main]

use libfuzzer_sys::fuzz_target;
use ws_net::{ClientHandshake, HeadReader};

fuzz_target!(|data: &[u8]| {
    let client = ClientHandshake::with_nonce(*b"the sample nonce").with_protocols(&["chat", "v2"]);
    let one_shot = client.verify_head(data);
    let streamed = HeadReader::new().client(&client, data);
    assert_eq!(one_shot, streamed);
    if let Ok(Some((verified, _))) = one_shot {
        assert!(verified.protocol.is_none_or(|p| p == "chat" || p == "v2"));
        let text = String::from_utf8_lossy(data);
        assert!(text.contains("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
    }
});
