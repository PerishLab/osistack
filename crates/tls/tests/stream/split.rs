use crate::data::*;
use tls::{Kind, Message, Record};

const LIMIT: usize = 1 << 16;

fn hex(text: &str) -> Vec<u8> {
    let clean: String = text.split_whitespace().collect();
    (0..clean.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&clean[at..at + 2], 16).unwrap())
        .collect()
}

#[test]
fn records() {
    for text in [
        CLIENT, SERVER, EARLY, FIRST, RETRY, SECOND, FINAL, FINISHED, PAYLOAD,
    ] {
        let wire = hex(text);
        let whole = Record::parse(&wire).unwrap().unwrap();
        assert_eq!(whole.1, wire.len());
        for cut in 0..wire.len() {
            assert_eq!(Record::parse(&wire[..cut]), Ok(None), "{cut}");
        }
    }
}

#[test]
fn messages() {
    for text in [CLIENT, SERVER, EARLY, FIRST, RETRY, SECOND, FINAL] {
        let (record, _) = Record::parse(&hex(text)).unwrap().unwrap();
        let body = record.fragment;
        let whole = Message::parse(&body, LIMIT).unwrap().unwrap();
        assert_eq!(whole.1, body.len());
        for cut in 0..body.len() {
            assert_eq!(Message::parse(&body[..cut], LIMIT), Ok(None), "{cut}");
        }
    }
}

#[test]
fn chained() {
    let mut wire = hex(CLIENT);
    wire.extend(hex(SERVER));
    let (first, used) = Record::parse(&wire).unwrap().unwrap();
    assert_eq!(used, 201);
    let (second, rest) = Record::parse(&wire[used..]).unwrap().unwrap();
    assert_eq!(rest, 95);
    assert_ne!(first, second);
    let mut pair = first.fragment.clone();
    pair.extend(&second.fragment);
    let (one, taken) = Message::parse(&pair, LIMIT).unwrap().unwrap();
    assert_eq!((one.kind, taken), (Kind::Offer, 196));
    let (two, last) = Message::parse(&pair[taken..], LIMIT).unwrap().unwrap();
    assert_eq!((two.kind, last), (Kind::Reply, 90));
}
