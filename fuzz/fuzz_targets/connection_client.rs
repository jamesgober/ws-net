//! As `connection_server`, for the client role.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ws_net::Connection;

#[path = "drive.rs"]
mod drive;

fuzz_target!(|data: &[u8]| {
    let Some((&select, rest)) = data.split_first() else { return };
    let limits = drive::limits(select);
    drive::check(
        || Connection::client_with_seed([select; 32]).with_limits(limits),
        rest,
        select,
    );
});
