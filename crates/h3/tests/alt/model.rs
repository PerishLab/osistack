use crate::support::Dice;
use h3::{Alternative, Cache, Directive, Origin};
use std::collections::HashMap;

const SECOND: u64 = 1_000_000;

type Held = (u64, Vec<(Alternative, u128)>);

struct Model {
    limit: usize,
    stamp: u64,
    held: HashMap<(String, u16), Held>,
}

impl Model {
    fn new(limit: usize) -> Model {
        Model {
            limit,
            stamp: 0,
            held: HashMap::new(),
        }
    }

    fn key(origin: &Origin) -> (String, u16) {
        (origin.host.clone(), origin.port)
    }

    fn put(&mut self, origin: &Origin, alts: Vec<Alternative>, now: u64) {
        self.held.remove(&Model::key(origin));
        if self.limit == 0 {
            return;
        }
        if self.held.len() >= self.limit {
            let oldest = self
                .held
                .iter()
                .min_by_key(|(_, held)| held.0)
                .map(|(key, _)| key.clone());
            self.held.remove(&oldest.unwrap());
        }
        self.stamp += 1;
        let list = alts
            .into_iter()
            .map(|alt| {
                let due = now as u128 + alt.age as u128 * SECOND as u128;
                (alt, due)
            })
            .collect();
        self.held.insert(Model::key(origin), (self.stamp, list));
    }

    fn clear(&mut self, origin: &Origin) {
        self.held.remove(&Model::key(origin));
    }

    fn fresh(&self, origin: &Origin, now: u64) -> Vec<Alternative> {
        let Some((_, list)) = self.held.get(&Model::key(origin)) else {
            return Vec::new();
        };
        let live = list.iter().filter(|(_, due)| (now as u128) < *due);
        live.map(|(alt, _)| alt.clone()).collect()
    }

    fn purge(&mut self, now: u64) {
        for (_, list) in self.held.values_mut() {
            list.retain(|(_, due)| (now as u128) < *due);
        }
        self.held.retain(|_, held| !held.1.is_empty());
    }

    fn change(&mut self) {
        for (_, list) in self.held.values_mut() {
            list.retain(|(alt, _)| alt.persist);
        }
        self.held.retain(|_, held| !held.1.is_empty());
    }
}

fn agree(cache: &Cache, model: &Model, origins: &[Origin], now: u64) {
    assert_eq!(cache.count(), model.held.len());
    for origin in origins {
        let want = model.fresh(origin, now);
        let have: Vec<Alternative> = cache.fresh(origin, now).into_iter().cloned().collect();
        assert_eq!(have, want, "{origin:?}");
        let best = want.iter().find(|alt| alt.protocol == b"h3");
        assert_eq!(cache.best(origin, now), best);
    }
}

struct Rig {
    cache: Cache,
    model: Model,
    dice: Dice,
    origins: Vec<Origin>,
}

impl Rig {
    fn new(seed: u64, origins: &[Origin]) -> Rig {
        let mut dice = Dice::new(seed);
        let limit = dice.below(5);
        Rig {
            cache: Cache::new(limit),
            model: Model::new(limit),
            dice,
            origins: origins.to_vec(),
        }
    }

    fn offer(&mut self, origin: &Origin, now: u64) {
        let made = self.dice.build(origin, 100);
        self.cache.receive(origin, &made.text, now).unwrap();
        self.model.put(origin, made.alts, now);
    }

    fn erase(&mut self, origin: &Origin, now: u64) {
        self.cache.receive(origin, "clear", now).unwrap();
        self.model.clear(origin);
    }

    fn empty(&mut self, origin: &Origin, now: u64) {
        self.cache.store(origin, Directive::Offer(Vec::new()), now);
        self.model.clear(origin);
    }

    fn sweep(&mut self, now: u64) {
        self.cache.purge(now);
        self.model.purge(now);
    }

    fn roam(&mut self) {
        self.cache.change();
        self.model.change();
    }

    fn act(&mut self, now: u64) {
        let origin = self.origins[self.dice.below(self.origins.len())].clone();
        match self.dice.below(10) {
            0..=5 => self.offer(&origin, now),
            6 => self.erase(&origin, now),
            7 => self.sweep(now),
            8 => self.roam(),
            _ => self.empty(&origin, now),
        }
        agree(&self.cache, &self.model, &self.origins, now);
    }
}

#[test]
fn drive() {
    let origins: Vec<Origin> = [
        ("a.example", 443),
        ("b.example", 443),
        ("a.example", 8443),
        ("c.example", 1),
    ]
    .iter()
    .map(|(host, port)| Origin::new(host, *port))
    .collect();
    for seed in 1..=64u64 {
        let mut rig = Rig::new(seed, &origins);
        let mut now = rig.dice.next() % (1 << 40);
        for _ in 0..200 {
            now += rig.dice.below(30) as u64 * SECOND + rig.dice.below(1000) as u64;
            rig.act(now);
        }
    }
}
