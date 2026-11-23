use crate::support::*;
use quic::{Header, Kind, Long, Negotiation, Number, Retry, Short};

fn number(dice: &mut Dice) -> Number {
    let length = 1 + dice.below(4);
    let mask = (1u64 << (8 * length)) - 1;
    Number {
        value: (dice.next() & mask) as u32,
        length,
    }
}

#[test]
fn long() {
    let mut dice = Dice::new(1);
    for round in 0..400 {
        let kind = if round % 2 == 0 {
            Kind::Initial
        } else {
            Kind::Handshake
        };
        let token = if round % 2 == 0 {
            dice.upto(80)
        } else {
            Vec::new()
        };
        let number = number(&mut dice);
        let length = number.length as u64 + dice.below(300) as u64;
        let mut header = Long {
            kind,
            dcid: dice.upto(21),
            scid: dice.upto(21),
            token,
            length,
            offset: 0,
        };
        let head = header.write(&number).unwrap();
        header.offset = head.len() - number.length;
        let data = fill(&head, header.offset + length as usize);
        assert_eq!(Header::parse(&data, 0), Ok(Header::Long(header)), "{round}");
        assert_eq!(
            Number::read(data[0], &data[head.len() - number.length..]),
            Ok(number)
        );
    }
}

#[test]
fn short() {
    let mut dice = Dice::new(2);
    for round in 0..400 {
        let local = round % 21;
        let number = number(&mut dice);
        let mut header = Short {
            spin: dice.below(2) == 1,
            phase: dice.below(2) == 1,
            dcid: dice.bytes(local),
            offset: 0,
        };
        let head = header.write(&number).unwrap();
        header.offset = local + 1;
        let data = fill(&head, head.len() + 30);
        assert_eq!(
            Header::parse(&data, local),
            Ok(Header::Short(header)),
            "{round}"
        );
        assert_eq!(Number::read(data[0], &data[local + 1..]), Ok(number));
    }
}

#[test]
fn retry() {
    let mut dice = Dice::new(3);
    for round in 0..200 {
        let header = Retry {
            unused: (round % 16) as u8,
            dcid: dice.upto(21),
            scid: dice.upto(21),
            token: dice.upto(60),
            tag: dice.bytes(16).try_into().unwrap(),
        };
        let wire = header.write().unwrap();
        assert_eq!(
            Header::parse(&wire, 0),
            Ok(Header::Retry(header)),
            "{round}"
        );
    }
}

#[test]
fn negotiation() {
    let mut dice = Dice::new(4);
    for round in 0..200 {
        let count = dice.below(6);
        let header = Negotiation {
            unused: (round % 128) as u8,
            dcid: dice.upto(256),
            scid: dice.upto(256),
            versions: (0..count).map(|_| dice.next() as u32).collect(),
        };
        let wire = header.write().unwrap();
        assert_eq!(
            Header::parse(&wire, 0),
            Ok(Header::Negotiation(header)),
            "{round}"
        );
    }
}

fn walk(data: &[u8], local: usize) {
    assert!(Header::parse(data, local).is_ok());
    for at in 0..data.len() {
        let _ = Header::parse(&data[..at], local);
    }
    for at in 0..6.min(data.len()) {
        assert!(
            Header::parse(&data[..at], local).is_err(),
            "{at} of {}",
            data.len()
        );
    }
}

#[test]
fn prefixes() {
    let mut dice = Dice::new(5);
    for round in 0..200 {
        let kind = if round % 2 == 0 {
            Kind::Initial
        } else {
            Kind::Handshake
        };
        let token = if round % 2 == 0 {
            dice.upto(80)
        } else {
            Vec::new()
        };
        let drawn = number(&mut dice);
        let length = drawn.length as u64 + dice.below(300) as u64;
        let mut header = Long {
            kind,
            dcid: dice.upto(21),
            scid: dice.upto(21),
            token,
            length,
            offset: 0,
        };
        let head = header.write(&drawn).unwrap();
        header.offset = head.len() - drawn.length;
        walk(&fill(&head, header.offset + length as usize), 0);

        let local = round % 21;
        let drawn = number(&mut dice);
        let header = Short {
            spin: dice.below(2) == 1,
            phase: dice.below(2) == 1,
            dcid: dice.bytes(local),
            offset: 0,
        };
        let head = header.write(&drawn).unwrap();
        assert!(Header::parse(&head, local).is_ok());
        let need = 1 + local + 1;
        for at in 0..need {
            assert!(Header::parse(&head[..at], local).is_err(), "{at} of {need}");
        }

        let retry = Retry {
            unused: (round % 16) as u8,
            dcid: dice.upto(21),
            scid: dice.upto(21),
            token: dice.upto(60),
            tag: dice.bytes(16).try_into().unwrap(),
        };
        walk(&retry.write().unwrap(), 0);

        let count = dice.below(6);
        let negotiation = Negotiation {
            unused: (round % 128) as u8,
            dcid: dice.upto(32),
            scid: dice.upto(32),
            versions: (0..count).map(|_| dice.next() as u32).collect(),
        };
        walk(&negotiation.write().unwrap(), 0);
    }
}
