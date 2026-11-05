//! `OriginPolicy`: no panic; an Origin identical to an allowlist entry is
//! permitted; nothing but an http or https origin is ever permitted.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ws_net::OriginPolicy;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let mut parts = text.splitn(3, '\n');
    let entry = parts.next().unwrap_or("");
    let origin = parts.next();
    let host = parts.next().unwrap_or("");
    let same = OriginPolicy::same_origin().permits(origin, host);
    let _ = OriginPolicy::any_origin().permits(origin, host);
    // Origin is a field value: surrounding spaces and tabs are not part of
    // it (parse-net trims them, as the head reader does).
    let web = |o: &str| {
        let lower = o.trim_matches([' ', '\t']).to_ascii_lowercase();
        lower.starts_with("http://") || lower.starts_with("https://")
    };
    if let Some(o) = origin {
        if !web(o) {
            assert!(!same);
        }
    }
    if let Ok(list) = OriginPolicy::allow(&[entry]) {
        let permitted = list.permits(origin, host);
        if origin == Some(entry) {
            assert!(permitted, "{entry:?}");
        }
        if let Some(o) = origin {
            if !web(o) {
                assert!(!permitted);
            }
        }
    }
});
