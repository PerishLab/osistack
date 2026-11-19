use crate::support::*;
use quic::{Direction, Param, Params, Side};

impl Dice {
    fn number(&mut self) -> u64 {
        let width = [6, 14, 30, 62][self.below(4)];
        self.next() >> (64 - width)
    }

    fn kind(&mut self) -> Direction {
        [Direction::Bidi, Direction::Uni][self.below(2)]
    }

    fn side(&mut self) -> Side {
        [Side::Local, Side::Remote, Side::Uni][self.below(3)]
    }

    fn pick(&mut self) -> Param {
        match self.below(15) {
            0 => Param::Original(self.upto(21)),
            1 => Param::Idle(self.number()),
            2 => Param::Reset(self.bytes(16).try_into().unwrap()),
            3 => Param::Payload(1200 + self.number() % 60000),
            4 => Param::Data(self.number()),
            5 => Param::Window(self.side(), self.number()),
            6 => Param::Streams(self.kind(), self.number() >> 3),
            7 => Param::Exponent(self.number() % 21),
            8 => Param::Delay(self.number() % 16384),
            9 => Param::Migration,
            10 => Param::Address(address(&self.span(1, 20))),
            11 => Param::Limit(2 + self.number() % 100),
            12 => Param::Source(self.upto(21)),
            13 => Param::Retry(self.upto(21)),
            _ => Param::Other(0x11 + self.number() % 100_000, self.upto(30)),
        }
    }

    fn identity(param: &Param) -> String {
        match param {
            Param::Other(id, _) => format!("other {id}"),
            Param::Window(side, _) => format!("window {side:?}"),
            Param::Streams(kind, _) => format!("streams {kind:?}"),
            _ => format!("{:?}", std::mem::discriminant(param)),
        }
    }
}

#[test]
fn trips() {
    let mut dice = Dice::new(5);
    for _ in 0..300 {
        let mut list: Vec<Param> = Vec::new();
        for _ in 0..dice.below(12) {
            let param = dice.pick();
            let seen = list
                .iter()
                .any(|other| Dice::identity(other) == Dice::identity(&param));
            if !seen {
                list.push(param);
            }
        }
        let params = Params { list };
        let bytes = params.write().unwrap();
        assert_eq!(Params::parse(&bytes).unwrap(), params);
    }
}

#[test]
fn damaged() {
    let mut dice = Dice::new(9);
    let mut kept = 0;
    for _ in 0..600 {
        let list = (0..1 + dice.below(8)).map(|_| dice.pick()).collect();
        let Ok(mut bytes) = (Params { list }).write() else {
            continue;
        };
        let at = dice.below(bytes.len());
        bytes[at] = dice.next() as u8;
        if let Ok(found) = Params::parse(&bytes) {
            kept += 1;
            assert_eq!(Params::parse(&found.write().unwrap()).unwrap(), found);
        }
    }
    assert!(kept > 20);
}

#[test]
fn noise() {
    let mut dice = Dice::new(13);
    for _ in 0..3000 {
        let bytes = dice.upto(40);
        if let Ok(found) = Params::parse(&bytes) {
            assert_eq!(Params::parse(&found.write().unwrap()).unwrap(), found);
        }
    }
}
