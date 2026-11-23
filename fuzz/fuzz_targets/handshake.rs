#![no_main]

use libfuzzer_sys::fuzz_target;
use tls::x509::Certificate;
use tls::{Chain, Encrypted, Offer, Reply};

fuzz_target!(|data: &[u8]| {
    let Some((kind, body)) = data.split_first() else {
        return;
    };
    match kind % 5 {
        0 => {
            let _ = Offer::parse(body);
        }
        1 => {
            let _ = Reply::parse(body);
        }
        2 => {
            let _ = Encrypted::parse(body);
        }
        3 => {
            let _ = Chain::parse(body);
        }
        _ => {
            let _ = Certificate::parse(body);
        }
    }
});
