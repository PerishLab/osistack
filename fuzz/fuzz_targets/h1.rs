#![no_main]

use h1::{Head, Request};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Head::parse(data, 8192);
    let _ = Request::parse(data, 4096);
});
