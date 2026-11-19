use crate::support::*;
use h3::{Decoder, Encoder, Error};

const ENTRIES: [(&str, &str); 2] = [("x-a", "1"), ("x-b", "2")];

fn full() -> Decoder {
    decoder(220, 0, &ENTRIES)
}

#[test]
fn beyond() {
    let mut decoder = full();
    assert_eq!(decoder.section(0, &hex("0201 80")), Err(Error::Reference));
    assert_eq!(decoder.section(0, &hex("0200 10")), Err(Error::Reference));
    assert_eq!(
        decoder.section(0, &hex("0201 01 01 39")),
        Err(Error::Reference)
    );
}

#[test]
fn before() {
    let mut decoder = full();
    assert_eq!(decoder.section(0, &hex("0300 82")), Err(Error::Reference));
    assert_eq!(
        decoder.section(0, &hex("0300 42 01 39")),
        Err(Error::Reference)
    );
}

#[test]
fn evicted() {
    let mut decoder = decoder(64, 0, &[("n", "0"), ("n", "1")]);
    assert_eq!(decoder.table().dropped(), 1);
    assert_eq!(decoder.section(0, &hex("0300 81")), Err(Error::Index));
    assert!(decoder.section(0, &hex("0300 80")).unwrap().is_some());
}

#[test]
fn negative() {
    let mut decoder = full();
    assert_eq!(decoder.section(0, &hex("0281 80")), Err(Error::Base));
    assert_eq!(decoder.section(0, &hex("03fe")), Err(Error::Base));
}

#[test]
fn impossible() {
    let mut decoder = full();
    assert_eq!(decoder.section(0, &hex("0d00")), Err(Error::Count));
    let mut empty = Decoder::new(0).blocked(1);
    assert_eq!(empty.section(0, &hex("0100")), Err(Error::Count));
}

#[test]
fn nothing() {
    let mut decoder = full();
    assert_eq!(decoder.section(0, &hex("0000 80")), Err(Error::Dynamic));
    assert_eq!(decoder.section(0, &hex("0000 10")), Err(Error::Dynamic));
    assert_eq!(decoder.decode(&hex("0000 80")), Err(Error::Dynamic));
    assert_eq!(decoder.decode(&hex("0300 80")), Err(Error::Dynamic));
}

#[test]
fn short() {
    let mut decoder = full();
    let result = decoder.section(0, &hex("0300 40"));
    assert_eq!(result, Err(Error::Wire(wire::Error::Truncated)));
    assert_eq!(
        decoder.section(0, &[]),
        Err(Error::Wire(wire::Error::Truncated))
    );
}

#[test]
fn writing() {
    let table = table(220, &ENTRIES);
    let encoder = Encoder::new(false);
    assert_eq!(encoder.reference(&table, 3, &[]), Err(Error::Base));
    let none = super::support::table(0, &[]);
    assert!(encoder.reference(&none, 0, &[field("x", "y")]).is_ok());
}
