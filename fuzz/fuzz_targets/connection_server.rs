//! A server connection fed arbitrary bytes under three budget settings, in
//! pieces whose sizes come from the input: no panic, output that decodes
//! as whole frames, memory within the configured bounds, and the same
//! events and output as for the whole input fed at once.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ws_net::Connection;

#[path = "drive.rs"]
mod drive;

fuzz_target!(|data: &[u8]| {
    let Some((&select, rest)) = data.split_first() else { return };
    let limits = drive::limits(select);
    drive::check(|| Connection::server().with_limits(limits), rest, select);
});
