use crate::behaviour::Check;
use crypto::Error as Auth;
use quic::{Error, Header, Retry};

pub fn table() -> Vec<(&'static str, Check)> {
    vec![
        ("retry-integrity", integrity as Check),
        ("retry-handshake", super::opening::retry as Check),
    ]
}

fn sample() -> Retry {
    Retry {
        unused: 0,
        dcid: Vec::new(),
        scid: vec![1; 8],
        token: b"token".to_vec(),
        tag: [0; 16],
    }
}

fn integrity() {
    let odcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let mut sender = sample();
    sender.fill(&odcid).unwrap();
    let wire = sender.write().unwrap();
    let Header::Retry(mut receiver) = Header::parse(&wire, 0).unwrap() else {
        panic!("not a retry packet");
    };
    assert!(receiver.check(&odcid).is_ok());
    receiver.tag[0] ^= 1;
    assert_eq!(receiver.check(&odcid), Err(Error::Crypto(Auth::Auth)));
    let mut other = odcid;
    other[7] ^= 1;
    assert_eq!(sender.check(&other), Err(Error::Crypto(Auth::Auth)));
}
