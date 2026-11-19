use crate::support::*;
use quic::{Fault, Peers};

struct Item {
    sequence: u64,
    cid: Vec<u8>,
    token: Option<[u8; 16]>,
    used: bool,
}

struct Model {
    limit: u64,
    zero: bool,
    prior: u64,
    current: u64,
    items: Vec<Item>,
    gone: Vec<u64>,
}

fn differs(item: &Item, cid: &[u8], token: [u8; 16]) -> bool {
    item.cid != cid || item.token != Some(token)
}

impl Model {
    fn receive(
        &mut self,
        sequence: u64,
        retire: u64,
        cid: &[u8],
        token: [u8; 16],
    ) -> Result<Vec<u64>, Fault> {
        if retire > sequence || cid.is_empty() || cid.len() > 20 {
            return Err(Fault::Encoding);
        }
        let mut items: Vec<Item> = self
            .items
            .iter()
            .map(|i| Item {
                sequence: i.sequence,
                cid: i.cid.clone(),
                token: i.token,
                used: i.used,
            })
            .collect();
        let clash = items.iter().any(|i| match i.sequence == sequence {
            true => differs(i, cid, token),
            false => i.cid == cid,
        });
        if self.zero || clash {
            return Err(Fault::Protocol);
        }
        let known = items.iter().any(|i| i.sequence == sequence) || self.gone.contains(&sequence);
        if !known {
            items.push(Item {
                sequence,
                cid: cid.to_vec(),
                token: Some(token),
                used: false,
            });
        }
        let prior = self.prior.max(retire);
        let mut freed: Vec<u64> = items
            .iter()
            .filter(|i| i.sequence < prior)
            .map(|i| i.sequence)
            .collect();
        freed.sort_unstable();
        items.retain(|i| i.sequence >= prior);
        if items.len() as u64 > self.limit {
            return Err(Fault::Ids);
        }
        let mut current = self.current;
        if !items.iter().any(|i| i.sequence == current) {
            items.sort_by_key(|i| i.sequence);
            let first = items.first_mut().ok_or(Fault::Protocol)?;
            first.used = true;
            current = first.sequence;
        }
        self.prior = prior;
        self.current = current;
        self.items = items;
        self.gone.extend(freed.iter().copied());
        Ok(freed)
    }

    fn fresh(&mut self) -> Option<(u64, Vec<u8>)> {
        self.items.sort_by_key(|i| i.sequence);
        let item = self.items.iter_mut().find(|i| !i.used)?;
        item.used = true;
        Some((item.sequence, item.cid.clone()))
    }

    fn rotate(&mut self) -> Option<u64> {
        let (sequence, _) = self.fresh()?;
        let old = self.current;
        self.items.retain(|i| i.sequence != old);
        self.gone.push(old);
        self.current = sequence;
        Some(old)
    }

    fn release(&mut self, sequence: u64) -> bool {
        let present = self.items.iter().any(|i| i.sequence == sequence);
        if sequence == self.current || !present {
            return false;
        }
        self.items.retain(|i| i.sequence != sequence);
        self.gone.push(sequence);
        true
    }

    fn live(&self) -> Vec<u64> {
        let mut found: Vec<u64> = self.items.iter().map(|i| i.sequence).collect();
        found.sort_unstable();
        found
    }
}

fn step(dice: &mut Dice, real: &mut Peers, model: &mut Model) {
    match dice.below(8) {
        0..=3 => {
            let sequence = dice.below(9);
            let retire = (dice.below(sequence + 2)).min(sequence + 1);
            let n = if dice.below(6) == 0 {
                dice.below(9)
            } else {
                sequence
            } as u8;
            let key = if dice.below(8) == 0 { 99 } else { n };
            let cid = if dice.below(12) == 0 { vec![] } else { cid(n) };
            let want = model.receive(sequence, retire, &cid, token(key));
            assert_eq!(
                real.receive(sequence, retire, &cid, token(key)),
                want,
                "{sequence} {retire} {n}"
            );
        }
        4 => assert_eq!(real.fresh(), model.fresh()),
        5 => assert_eq!(real.rotate(), model.rotate()),
        _ => {
            let sequence = dice.below(9);
            assert_eq!(real.release(sequence), model.release(sequence));
        }
    }
    assert_eq!(real.live(), model.live());
    assert_eq!(real.current().0, model.current);
    assert_eq!(real.active(), model.items.len());
}

#[test]
fn random() {
    for seed in 1..=120 {
        let mut dice = Dice::new(seed);
        let limit = dice.within(2, 5);
        let mut real = Peers::new(cid(0), Some(token(0)), limit);
        let first = Item {
            sequence: 0,
            cid: cid(0),
            token: Some(token(0)),
            used: true,
        };
        let mut model = Model {
            limit,
            zero: false,
            prior: 0,
            current: 0,
            items: vec![first],
            gone: vec![],
        };
        for _ in 0..100 {
            step(&mut dice, &mut real, &mut model);
        }
    }
}
