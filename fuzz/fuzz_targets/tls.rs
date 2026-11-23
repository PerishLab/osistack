#![no_main]

use libfuzzer_sys::fuzz_target;
use tls::{Message, Record};

fuzz_target!(|data: &[u8]| {
    let _ = Record::parse(data);
    let _ = Message::parse(data, usize::MAX);
});
