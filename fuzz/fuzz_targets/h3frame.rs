#![no_main]

use h3::Frame;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Frame::decode(data, data.len());
});
