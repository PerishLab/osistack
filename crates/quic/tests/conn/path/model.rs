use crate::support::{Dice, token};
use quic::{Amplify, Error, MINIMUM, Path, Validity};

struct Count {
    recv: u128,
    sent: u128,
    valid: bool,
}

impl Count {
    fn room(&self) -> u128 {
        if self.valid {
            return u128::from(u64::MAX);
        }
        3 * self.recv - self.sent
    }

    fn step(&mut self, real: &mut Amplify, dice: &mut Dice) {
        let size = u128::from(dice.below(5000));
        match dice.below(10) {
            0..=3 => {
                real.receive(size as u64);
                self.recv += size;
            }
            4..=8 => {
                let expect = self.valid || size <= self.room();
                assert_eq!(real.send(size as u64), expect);
                self.sent += if expect { size } else { 0 };
            }
            _ if dice.below(20) == 0 => {
                real.validate();
                self.valid = true;
            }
            _ => {}
        }
    }
}

#[test]
fn amplify() {
    for seed in 1..=64 {
        let mut dice = Dice::new(seed);
        let mut real = Amplify::new(false);
        let mut count = Count {
            recv: 0,
            sent: 0,
            valid: false,
        };
        for _ in 0..400 {
            count.step(&mut real, &mut dice);
            assert_eq!(u128::from(real.room()), count.room(), "seed {seed}");
            assert_eq!(real.blocked(), !count.valid && count.room() == 0);
            assert!(count.valid || count.sent <= 3 * count.recv);
        }
    }
}

struct Model {
    state: Validity,
    live: Vec<([u8; 8], bool)>,
    limit: Option<u64>,
    mtu: bool,
}

impl Model {
    fn challenge(&mut self, now: u64, data: [u8; 8], room: u64) -> Result<bool, Error> {
        if self.state == Validity::Failed {
            return Err(Error::Value);
        }
        if self.state != Validity::Pending {
            self.state = Validity::Pending;
            self.live.clear();
            self.limit = Some(now + 2_997_000);
        }
        if self.live.iter().any(|(held, _)| *held == data) {
            return Err(Error::Duplicate);
        }
        if self.live.len() == 8 {
            return Err(Error::Value);
        }
        self.live.push((data, room >= MINIMUM));
        Ok(room >= MINIMUM)
    }

    fn response(&mut self, data: [u8; 8]) -> bool {
        let found = self.live.iter().find(|(held, _)| *held == data).copied();
        let Some((_, expanded)) = found else {
            return false;
        };
        if self.state != Validity::Pending {
            return false;
        }
        self.mtu = self.mtu || expanded;
        self.state = Validity::Valid;
        self.live.clear();
        self.limit = None;
        true
    }

    fn expire(&mut self, now: u64) -> bool {
        let due = self.limit.is_some_and(|limit| now >= limit);
        if self.state == Validity::Pending && due {
            self.drop();
            return true;
        }
        false
    }

    fn abandon(&mut self) {
        if self.state == Validity::Pending {
            self.drop();
        }
    }

    fn drop(&mut self) {
        self.state = Validity::Failed;
        self.live.clear();
        self.limit = None;
    }

    fn step(&mut self, real: &mut Path, dice: &mut Dice, now: u64) {
        let data = token(dice.below(12));
        match dice.below(10) {
            0..=4 => {
                let room = [0, MINIMUM - 1, MINIMUM, u64::MAX][dice.below(4) as usize];
                let got = real.challenge(now, data, room).map(|probe| probe.expand);
                assert_eq!(got, self.challenge(now, data, room));
            }
            5..=7 => assert_eq!(real.response(data), self.response(data)),
            8 => assert_eq!(real.expire(now), self.expire(now)),
            _ => {
                real.abandon();
                self.abandon();
            }
        }
    }
}

#[test]
fn path() {
    for seed in 1..=64 {
        let mut dice = Dice::new(seed);
        let mut real = Path::new(0);
        let mut model = Model {
            state: Validity::Idle,
            live: Vec::new(),
            limit: None,
            mtu: false,
        };
        let mut now = 0u64;
        for _ in 0..300 {
            now += dice.below(900_000);
            model.step(&mut real, &mut dice, now);
            assert_eq!(real.validity(), model.state, "seed {seed}");
            assert_eq!(real.deadline(), model.limit, "seed {seed}");
            assert_eq!(real.mtu(), model.mtu, "seed {seed}");
        }
    }
}
