#![no_main]

use libfuzzer_sys::fuzz_target;
use quic::Params;

fuzz_target!(|data: &[u8]| {
    let _ = Params::parse(data);
});
