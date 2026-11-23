use crate::support::*;
use quic::{Ack, Ecn, Error, Frame};

fn build(dice: &mut Dice) -> Ack {
    let largest = 20 + dice.next() % 10_000;
    let first = dice.next() % (largest + 1).min(40);
    let mut smallest = largest - first;
    let mut ranges = Vec::new();
    for _ in 0..dice.below(6) {
        if smallest < 2 {
            break;
        }
        let gap = dice.next() % (smallest - 1).min(20);
        let top = smallest - gap - 2;
        let length = dice.next() % (top + 1).min(20);
        ranges.push((gap, length));
        smallest = top - length;
    }
    let ecn = if dice.below(2) == 0 {
        Some(Ecn {
            ect0: dice.next() % 1_000,
            ect1: dice.next() % 1_000,
            ce: dice.next() % 1_000,
        })
    } else {
        None
    };
    Ack {
        largest,
        delay: dice.next() % 1_000,
        first,
        ranges,
        ecn,
    }
}

fn parse(bytes: &[u8]) -> Result<Ack, Error> {
    match Frame::parse(bytes) {
        Ok((Frame::Ack(found), used)) if used == bytes.len() => Ok(found),
        Ok(_) => Err(Error::Kind),
        Err(err) => Err(err),
    }
}

#[test]
fn trips() {
    let mut dice = Dice::new(29);
    for _ in 0..400 {
        let ack = build(&mut dice);
        ack.check().unwrap();
        let bytes = Frame::Ack(ack.clone()).write().unwrap();
        assert_eq!(parse(&bytes).unwrap(), ack);
        for cut in 0..bytes.len() {
            assert_eq!(
                parse(&bytes[..cut]),
                Err(Error::Wire(wire::Error::Truncated))
            );
        }
    }
}

#[test]
fn refuse() {
    let mut dice = Dice::new(31);
    for _ in 0..200 {
        let mut ack = build(&mut dice);
        ack.first = ack.largest.saturating_add(1);
        assert_eq!(ack.check(), Err(Error::Value));
        assert_eq!(Frame::Ack(ack).write(), Err(Error::Value));
        let mut ack = build(&mut dice);
        ack.ranges.push((ack.largest + 8, 0));
        assert_eq!(ack.check(), Err(Error::Value));
        assert_eq!(Frame::Ack(ack).write(), Err(Error::Value));
    }
}
