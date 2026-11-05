//! `Sec-WebSocket-Extensions`: no panic; accepted offers have token names
//! and token values; the caps hold.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ws_net::extension;

fn token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

fuzz_target!(|data: &[u8]| {
    let mut offers = 0;
    for offer in extension::parse(data) {
        let Ok(offer) = offer else { break };
        offers += 1;
        assert!(offers <= extension::MAX_OFFERS);
        assert!(token(offer.name()));
        let mut params = 0;
        for p in offer.params() {
            params += 1;
            assert!(params <= extension::MAX_PARAMS);
            assert!(token(p.name));
            assert!(p.value.is_none_or(token));
        }
    }
});
