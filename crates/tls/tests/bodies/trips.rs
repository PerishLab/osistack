use crate::support::*;
use tls::{Alert, Chain, Encrypted, Entry, Extension, Finished, Request, Ticket, Update, Verify};

impl Dice {
    fn extensions(&mut self, required: bool) -> Vec<Extension> {
        let mut found: Vec<Extension> = Vec::new();
        if required {
            found.push(extension(13, &self.span(2, 20)));
        }
        for _ in 0..self.below(5) {
            let kind = 14 + (self.next() % 5000) as u16;
            let size = [0, 1, 5, 300][self.below(4)];
            let data = self.bytes(size);
            if found.iter().all(|other| other.kind != kind) {
                found.push(extension(kind, &data));
            }
        }
        found
    }

    fn chain(&mut self) -> Chain {
        let context = self.span(0, 6);
        let entries = (0..self.below(4))
            .map(|_| Entry {
                cert: self.span(1, 400),
                extensions: self.extensions(false),
            })
            .collect();
        Chain { context, entries }
    }

    fn ticket(&mut self) -> Ticket {
        Ticket {
            lifetime: (self.next() % 604_801) as u32,
            add: self.next() as u32,
            nonce: self.span(0, 20),
            ticket: self.span(1, 300),
            extensions: self.extensions(false),
        }
    }

    fn requested(&mut self) -> Request {
        Request {
            context: self.span(0, 6),
            extensions: self.extensions(true),
        }
    }

    fn encrypted(&mut self) -> Encrypted {
        Encrypted {
            extensions: self.extensions(false),
        }
    }

    fn signed(&mut self) -> Verify {
        Verify {
            algorithm: self.next() as u16,
            signature: self.span(0, 300),
        }
    }
}

#[test]
fn trips() {
    let mut dice = Dice::new(3);
    for _ in 0..300 {
        let chain = dice.chain();
        assert_eq!(Chain::parse(&chain.write().unwrap()).unwrap(), chain);
        let ticket = dice.ticket();
        assert_eq!(Ticket::parse(&ticket.write().unwrap()).unwrap(), ticket);
        let request = dice.requested();
        assert_eq!(Request::parse(&request.write().unwrap()).unwrap(), request);
        let encrypted = dice.encrypted();
        assert_eq!(
            Encrypted::parse(&encrypted.write().unwrap()).unwrap(),
            encrypted
        );
        let verify = dice.signed();
        assert_eq!(Verify::parse(&verify.write().unwrap()).unwrap(), verify);
        let data = dice.span(0, 64);
        let finished = Finished::parse(&data, data.len()).unwrap();
        assert_eq!(
            Finished::parse(&finished.write().unwrap(), data.len()).unwrap(),
            finished
        );
        let update = Update {
            request: dice.below(2) == 0,
        };
        assert_eq!(Update::parse(&update.write().unwrap()).unwrap(), update);
        let alert = Alert {
            level: dice.next() as u8,
            description: dice.next() as u8,
        };
        assert_eq!(Alert::parse(&alert.write().unwrap()).unwrap(), alert);
    }
}

#[test]
fn damaged() {
    let mut dice = Dice::new(5);
    let mut kept = 0;
    for _ in 0..600 {
        let mut bytes = match dice.below(4) {
            0 => dice.chain().write().unwrap(),
            1 => dice.ticket().write().unwrap(),
            2 => dice.requested().write().unwrap(),
            _ => dice.encrypted().write().unwrap(),
        };
        let at = dice.below(bytes.len());
        bytes[at] = dice.next() as u8;
        if let Ok(found) = Chain::parse(&bytes) {
            kept += 1;
            assert_eq!(Chain::parse(&found.write().unwrap()).unwrap(), found);
        }
        if let Ok(found) = Ticket::parse(&bytes) {
            kept += 1;
            assert_eq!(Ticket::parse(&found.write().unwrap()).unwrap(), found);
        }
        if let Ok(found) = Request::parse(&bytes) {
            kept += 1;
            assert_eq!(Request::parse(&found.write().unwrap()).unwrap(), found);
        }
        if let Ok(found) = Encrypted::parse(&bytes) {
            kept += 1;
            assert_eq!(Encrypted::parse(&found.write().unwrap()).unwrap(), found);
        }
    }
    assert!(kept > 100);
}

#[test]
fn noise() {
    let mut dice = Dice::new(9);
    for _ in 0..3000 {
        let bytes = dice.span(0, 40);
        if let Ok(found) = Verify::parse(&bytes) {
            assert_eq!(found.write().unwrap(), bytes);
        }
        if let Ok(found) = Chain::parse(&bytes) {
            assert_eq!(Chain::parse(&found.write().unwrap()).unwrap(), found);
        }
        if let Ok(found) = Ticket::parse(&bytes) {
            assert_eq!(Ticket::parse(&found.write().unwrap()).unwrap(), found);
        }
        let _ = (
            Update::parse(&bytes),
            Alert::parse(&bytes),
            Request::parse(&bytes),
        );
    }
}
