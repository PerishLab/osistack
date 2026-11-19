use tls::{Content, Extension, Kind, Message, Offer, Record, Reply};

struct Dice(u64);

impl Dice {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, limit: usize) -> usize {
        (self.next() % limit as u64) as usize
    }

    fn upto(&mut self, floor: usize, extra: usize) -> Vec<u8> {
        let count = floor + self.below(extra);
        self.bytes(count)
    }

    fn bytes(&mut self, count: usize) -> Vec<u8> {
        (0..count).map(|_| self.next() as u8).collect()
    }

    fn extensions(&mut self) -> Vec<Extension> {
        let mut found = vec![Extension {
            kind: 0x0a,
            data: self.upto(4, 40),
        }];
        for _ in 0..self.below(6) {
            let kind = (self.next() % 0xfff0) as u16 + 16;
            let size = [0, 1, 5, 300][self.below(4)];
            let data = self.bytes(size);
            found.push(Extension { kind, data });
        }
        let mut seen = Vec::new();
        found.retain(|extension| {
            let fresh = !seen.contains(&extension.kind);
            seen.push(extension.kind);
            fresh
        });
        found
    }
}

fn random(dice: &mut Dice) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&dice.bytes(32));
    bytes
}

#[test]
fn offers() {
    let mut dice = Dice(0x9e37_79b9_7f4a_7c15);
    for round in 0..500 {
        let count = 1 + dice.below(8);
        let offer = Offer {
            random: random(&mut dice),
            session: dice.upto(0, 33),
            suites: (0..count).map(|_| dice.next() as u16).collect(),
            extensions: dice.extensions(),
        };
        let body = offer.write().unwrap();
        assert_eq!(Offer::parse(&body), Ok(offer), "{round}");
        let message = Message {
            kind: Kind::Offer,
            body,
        };
        let record = Record {
            content: Content::Handshake,
            version: 0x0301,
            fragment: message.write().unwrap(),
        };
        let wire = record.write().unwrap();
        let (back, used) = Record::parse(&wire).unwrap().unwrap();
        assert_eq!((&back, used), (&record, wire.len()));
        let (again, _) = Message::parse(&back.fragment, 1 << 16).unwrap().unwrap();
        assert_eq!(again, message);
    }
}

#[test]
fn replies() {
    let mut dice = Dice(0x1234_5678_9abc_def1);
    for round in 0..500 {
        let reply = Reply {
            random: random(&mut dice),
            session: dice.upto(0, 33),
            suite: dice.next() as u16,
            extensions: dice.extensions(),
        };
        let body = reply.write().unwrap();
        assert_eq!(Reply::parse(&body), Ok(reply), "{round}");
    }
}

#[test]
fn records() {
    let mut dice = Dice(0x0fed_cba9_8765_4321);
    for round in 0..300 {
        let content = [
            Content::Change,
            Content::Alert,
            Content::Handshake,
            Content::Application,
        ][dice.below(4)];
        let size = [0, 1, 100, 16384, 16640][dice.below(5)];
        let record = Record {
            content,
            version: dice.next() as u16,
            fragment: dice.bytes(size),
        };
        let wire = record.write().unwrap();
        assert_eq!(
            Record::parse(&wire),
            Ok(Some((record, wire.len()))),
            "{round}"
        );
    }
}
