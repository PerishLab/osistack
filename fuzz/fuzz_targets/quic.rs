#![no_main]

use libfuzzer_sys::fuzz_target;
use quic::{Frame, Header};

fuzz_target!(|data: &[u8]| {
    let _ = Frame::parse(data);
    let _ = Header::parse(data, 0);
});
