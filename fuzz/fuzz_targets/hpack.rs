#![no_main]

use h2::Decoder;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Decoder::new(4096).decode(data);
});
