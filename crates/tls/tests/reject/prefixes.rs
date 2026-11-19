use crate::support::*;
use tls::{Offer, Reply};

#[test]
fn offers() {
    let parts = Parts {
        session: vec![3; 32],
        suites: hex("1301 1302"),
        extensions: [extension(0x0a, 4), extension(0x2b, 20)].concat(),
        ..Parts::default()
    };
    let body = parts.offer();
    assert!(Offer::parse(&body).is_ok());
    for cut in 0..body.len() {
        assert!(Offer::parse(&body[..cut]).is_err(), "{cut}");
    }
}

#[test]
fn replies() {
    let parts = Parts {
        session: vec![3; 32],
        extensions: [extension(0x0a, 4), extension(0x2b, 20)].concat(),
        ..Parts::default()
    };
    let body = parts.reply();
    assert!(Reply::parse(&body).is_ok());
    for cut in 0..body.len() {
        assert!(Reply::parse(&body[..cut]).is_err(), "{cut}");
    }
}
