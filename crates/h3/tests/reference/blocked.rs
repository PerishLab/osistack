use crate::support::*;
use h3::{Decoder, Error, Feedback};

const ENTRIES: [(&str, &str); 2] = [("x-a", "1"), ("x-b", "2")];
const BOTH: &str = "0381 10 11";
const ONE: &str = "0200 80";

fn bare(blocked: usize) -> Decoder {
    let mut decoder = Decoder::new(220).blocked(blocked);
    decoder.apply(&capacity(220)).unwrap();
    decoder
}

fn feed(decoder: &mut Decoder, entries: &[(&str, &str)]) {
    for (name, value) in entries {
        decoder.apply(&insert(name, value)).unwrap();
    }
}

#[test]
fn limit() {
    let mut decoder = bare(0);
    assert_eq!(decoder.section(4, &hex(BOTH)), Err(Error::Blocked));
    assert_eq!(decoder.waiting(), 0);
    let mut decoder = bare(2);
    assert_eq!(decoder.section(4, &hex(BOTH)), Ok(None));
    assert_eq!(decoder.section(8, &hex(BOTH)), Ok(None));
    assert_eq!(decoder.section(12, &hex(BOTH)), Err(Error::Blocked));
    assert_eq!(decoder.waiting(), 2);
}

#[test]
fn partial() {
    let mut decoder = bare(2);
    assert_eq!(decoder.section(4, &hex(BOTH)), Ok(None));
    assert_eq!(decoder.section(8, &hex(ONE)), Ok(None));
    feed(&mut decoder, &ENTRIES[..1]);
    let ready = decoder.ready().unwrap();
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].stream, 8);
    assert_eq!(ready[0].fields, [field("x-a", "1")]);
    assert_eq!(decoder.waiting(), 1);
    feed(&mut decoder, &ENTRIES[1..]);
    let ready = decoder.ready().unwrap();
    assert_eq!(ready[0].stream, 4);
    assert_eq!(ready[0].feedback, Some(Feedback::Acknowledge(4)));
    assert_eq!(decoder.waiting(), 0);
    assert!(decoder.ready().unwrap().is_empty());
}

#[test]
fn cancelling() {
    let mut decoder = bare(2);
    decoder.section(4, &hex(BOTH)).unwrap();
    decoder.section(8, &hex(BOTH)).unwrap();
    assert_eq!(decoder.cancel(4), Feedback::Cancel(4));
    assert_eq!(decoder.waiting(), 1);
    feed(&mut decoder, &ENTRIES);
    let ready = decoder.ready().unwrap();
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].stream, 8);
    assert_eq!(decoder.cancel(99), Feedback::Cancel(99));
}

#[test]
fn counting() {
    let mut decoder = bare(0);
    assert_eq!(decoder.increment(), None);
    feed(&mut decoder, &ENTRIES);
    assert_eq!(decoder.known(), 0);
    assert_eq!(decoder.increment(), Some(Feedback::Increment(2)));
    assert_eq!(decoder.known(), 2);
    assert_eq!(decoder.increment(), None);
    feed(&mut decoder, &[("x-c", "3")]);
    decoder.section(4, &hex("0380 80 10")).unwrap();
    assert_eq!(decoder.known(), 2);
    assert_eq!(decoder.increment(), Some(Feedback::Increment(1)));
}

#[test]
fn acknowledged() {
    let mut decoder = bare(0);
    feed(&mut decoder, &ENTRIES);
    let decoded = decoder.section(4, &hex("0300 80")).unwrap().unwrap();
    assert_eq!(decoded.feedback, Some(Feedback::Acknowledge(4)));
    assert_eq!(decoder.known(), 2);
    assert_eq!(decoder.increment(), None);
}

#[test]
fn plain() {
    let mut decoder = bare(0);
    let decoded = decoder.section(4, &hex("0000 d1")).unwrap().unwrap();
    assert_eq!(decoded.feedback, None);
    assert_eq!(decoded.fields, [field(":method", "GET")]);
    assert_eq!(decoder.known(), 0);
}

#[test]
fn wrapped() {
    let mut decoder = Decoder::new(64).blocked(1);
    decoder.apply(&capacity(64)).unwrap();
    for round in 0..9 {
        decoder.apply(&insert("n", &round.to_string())).unwrap();
    }
    assert_eq!(decoder.table().inserted(), 9);
    assert_eq!(decoder.section(0, &hex("0300 80")), Ok(None));
    assert!(decoder.ready().unwrap().is_empty());
    decoder.apply(&insert("n", "9")).unwrap();
    let ready = decoder.ready().unwrap();
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].fields, [field("n", "9")]);
    assert_eq!(decoder.known(), 10);
}
