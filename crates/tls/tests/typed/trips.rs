use crate::support::*;
use tls::{Extension, Identity, Place, Share, Typed};

impl Dice {
    fn shares(&mut self) -> Vec<Share> {
        let mut found: Vec<Share> = Vec::new();
        for _ in 0..self.below(4) {
            let group = (self.next() % 5000) as u16;
            let key = self.span(1, 70);
            if found.iter().all(|seen| seen.group != group) {
                found.push(Share { group, key });
            }
        }
        found
    }

    fn shorts(&mut self) -> Vec<u16> {
        (0..1 + self.below(12))
            .map(|_| self.next() as u16)
            .collect()
    }

    fn offered(&mut self) -> Typed {
        let count = 1 + self.below(3);
        let identities = (0..count)
            .map(|_| Identity {
                label: self.span(1, 40),
                age: self.next() as u32,
            })
            .collect();
        let binders = (0..count).map(|_| self.span(32, 20)).collect();
        Typed::Offered {
            identities,
            binders,
        }
    }

    fn names(&mut self) -> Vec<Vec<u8>> {
        (0..1 + self.below(4)).map(|_| self.span(1, 30)).collect()
    }

    fn typed(&mut self) -> (Typed, Place) {
        match self.below(16) {
            0 => (Typed::Name(Some(self.span(1, 60))), Place::Offer),
            1 => (Typed::Name(None), Place::Encrypted),
            2 => (Typed::Groups(self.shorts()), Place::Offer),
            3 => (Typed::Algorithms(self.shorts()), Place::Request),
            4 => (Typed::Protocols(self.names()), Place::Offer),
            5 => (Typed::Protocols(vec![self.span(1, 30)]), Place::Encrypted),
            6 => (self.offered(), Place::Offer),
            7 => (Typed::Selected(self.next() as u16), Place::Reply),
            8 => (Typed::Early(Some(self.next() as u32)), Place::Ticket),
            9 => (Typed::Versions(self.shorts()), Place::Offer),
            10 => (Typed::Version(self.next() as u16), Place::Retry),
            11 => (Typed::Cookie(self.span(1, 120)), Place::Retry),
            12 => (Typed::Modes(self.span(1, 5)), Place::Offer),
            13 => (Typed::Shares(self.shares()), Place::Offer),
            14 => (
                Typed::Chosen(Share {
                    group: self.next() as u16,
                    key: self.span(1, 70),
                }),
                Place::Reply,
            ),
            _ => (Typed::Group(self.next() as u16), Place::Retry),
        }
    }
}

const PLACES: [Place; 6] = [
    Place::Offer,
    Place::Reply,
    Place::Retry,
    Place::Encrypted,
    Place::Ticket,
    Place::Request,
];

const KINDS: [u16; 10] = [0, 10, 13, 16, 41, 42, 43, 44, 45, 51];

fn stable(extension: &Extension, place: Place) -> usize {
    let Ok(Some(found)) = Typed::parse(extension, place) else {
        return 0;
    };
    let written = found.write().unwrap();
    assert_eq!(Typed::parse(&written, place), Ok(Some(found)));
    1
}

#[test]
fn trips() {
    let mut dice = Dice::new(2);
    for _ in 0..1500 {
        let (typed, place) = dice.typed();
        let extension = typed.write().unwrap();
        assert_eq!(Typed::parse(&extension, place), Ok(Some(typed)));
    }
}

#[test]
fn damaged() {
    let mut dice = Dice::new(4);
    let mut kept = 0;
    for _ in 0..1500 {
        let (typed, place) = dice.typed();
        let mut extension = typed.write().unwrap();
        if extension.data.is_empty() {
            continue;
        }
        let at = dice.below(extension.data.len());
        extension.data[at] = dice.next() as u8;
        kept += stable(&extension, place);
    }
    assert!(kept > 500);
}

#[test]
fn noise() {
    let mut dice = Dice::new(8);
    for _ in 0..3000 {
        let kind = KINDS[dice.below(KINDS.len())];
        let extension = Extension {
            kind,
            data: dice.span(0, 30),
        };
        for place in PLACES {
            let _ = stable(&extension, place);
        }
    }
}
