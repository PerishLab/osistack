use crate::common::hex;
use crate::data::*;
use crypto::{Error, Verifier};

fn full(bits: usize) -> Vec<u8> {
    let mut out = vec![0xff; bits / 8];
    if !bits.is_multiple_of(8) {
        out.insert(0, 0xff >> (8 - bits % 8));
    }
    out
}

#[test]
fn accepted() {
    assert!(Verifier::rsa(&hex(MODULUS), &hex(EXPONENT)).is_ok());
    for bits in [2048, 2049, 3072, 4096] {
        assert!(Verifier::rsa(&full(bits), &[1, 0, 1]).is_ok(), "{bits}");
    }
    assert!(Verifier::rsa(&full(2048), &[3]).is_ok());
}

#[test]
fn refused() {
    let modulus = full(2048);
    let cases: [(&str, Vec<u8>, Vec<u8>); 8] = [
        ("short", full(2047), vec![1, 0, 1]),
        ("long", full(4097), vec![1, 0, 1]),
        ("huge", full(8192), vec![1, 0, 1]),
        ("empty", vec![], vec![1, 0, 1]),
        ("even", [&modulus[..255], &[0xfe]].concat(), vec![1, 0, 1]),
        ("exponent one", modulus.clone(), vec![1]),
        ("exponent even", modulus.clone(), vec![1, 0, 0]),
        ("exponent wide", modulus.clone(), vec![1, 0, 0, 0, 3]),
    ];
    for (name, modulus, exponent) in cases {
        let made = Verifier::rsa(&modulus, &exponent);
        assert_eq!(made.err(), Some(Error::Key), "{name}");
    }
    assert_eq!(Verifier::rsa(&modulus, &[]).err(), Some(Error::Key));
}
