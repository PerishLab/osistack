#![no_main]

use h2::Codec;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Codec::default().decode(data);
});
