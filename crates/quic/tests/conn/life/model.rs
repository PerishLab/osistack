use crate::support::Dice;
use quic::{Frame, Idle, Life, Mode};

const CAP: u128 = u64::MAX as u128;

struct Rule {
    state: u8,
    until: u128,
    count: u64,
    fitted: bool,
}

impl Rule {
    fn new() -> Self {
        Self {
            state: 0,
            until: 0,
            count: 0,
            fitted: false,
        }
    }

    fn end(now: u64, pto: u64) -> u128 {
        (now as u128 + 3 * pto as u128).min(CAP)
    }

    fn close(&mut self, now: u64, pto: u64, good: bool) -> bool {
        if !good || self.state != 0 {
            return false;
        }
        self.state = 1;
        self.until = Self::end(now, pto);
        self.fitted = true;
        true
    }

    fn receive(&mut self) -> bool {
        if self.state != 1 {
            return false;
        }
        self.count += 1;
        self.count & (self.count - 1) == 0
    }

    fn peer(&mut self, now: u64, pto: u64) {
        if self.state > 1 {
            return;
        }
        if self.state == 0 {
            self.until = Self::end(now, pto);
        }
        self.state = 2;
    }

    fn idle(&mut self) {
        if self.state == 0 {
            self.state = 3;
        }
    }

    fn expire(&mut self, now: u64) -> bool {
        let live = self.state == 1 || self.state == 2;
        if live && now as u128 >= self.until {
            self.state = 3;
            return true;
        }
        false
    }

    fn mode(&self) -> Mode {
        [Mode::Open, Mode::Closing, Mode::Draining, Mode::Closed][self.state as usize]
    }

    fn deadline(&self) -> Option<u64> {
        let live = self.state == 1 || self.state == 2;
        live.then_some(self.until as u64)
    }
}

fn frame(dice: &mut Dice) -> (Frame, bool) {
    match dice.below(4) {
        0 => (Frame::Ping, false),
        1 => (Frame::Done, false),
        2 => (
            Frame::Application {
                code: 1,
                reason: vec![1],
            },
            true,
        ),
        _ => (
            Frame::Transport {
                code: 2,
                frame: 0,
                reason: vec![],
            },
            true,
        ),
    }
}

fn check(life: &Life, rule: &Rule, seed: u64) {
    assert_eq!(life.mode(), rule.mode(), "seed {seed}");
    assert_eq!(life.deadline(), rule.deadline(), "seed {seed}");
    assert_eq!(
        life.frame().is_some(),
        rule.state == 1 && rule.fitted,
        "seed {seed}"
    );
}

fn step(life: &mut Life, rule: &mut Rule, now: u64, dice: &mut Dice) {
    let pto = dice.below(4_000);
    match dice.below(7) {
        0 => {
            let (shut, good) = frame(dice);
            assert_eq!(
                life.close(now, pto, shut).is_ok(),
                rule.close(now, pto, good)
            );
        }
        1 | 2 => assert_eq!(life.receive().is_some(), rule.receive()),
        3 => {
            life.peer(now, pto);
            rule.peer(now, pto);
        }
        4 => {
            life.reset(now, pto);
            rule.peer(now, pto);
        }
        5 => {
            life.idle();
            rule.idle();
        }
        _ => assert_eq!(life.expire(now), rule.expire(now)),
    }
}

#[test]
fn life() {
    for seed in 1..=64 {
        let mut dice = Dice::new(seed);
        let mut life = Life::default();
        let mut rule = Rule::new();
        let mut now = 0;
        for _ in 0..200 {
            now += dice.below(3_000);
            step(&mut life, &mut rule, now, &mut dice);
            check(&life, &rule, seed);
        }
    }
}

fn pick(dice: &mut Dice) -> u64 {
    if dice.below(4) == 0 {
        0
    } else {
        dice.below(500) + 1
    }
}

fn span(local: u64, peer: u64) -> Option<u128> {
    let both: Vec<u64> = [local, peer].into_iter().filter(|ms| *ms != 0).collect();
    both.into_iter().min().map(|ms| ms as u128 * 1000)
}

struct Clock {
    idle: Idle,
    span: Option<u128>,
    last: u128,
    fresh: bool,
}

impl Clock {
    fn new(local: u64, peer: u64) -> Self {
        Self {
            idle: Idle::new(0, local, peer),
            span: span(local, peer),
            last: 0,
            fresh: true,
        }
    }

    fn step(&mut self, now: u64, dice: &mut Dice) {
        if dice.below(2) == 0 {
            self.idle.receive(now);
            self.last = now as u128;
            self.fresh = true;
            return;
        }
        let eliciting = dice.below(2) == 0;
        self.idle.send(now, eliciting);
        if eliciting && self.fresh {
            self.last = now as u128;
            self.fresh = false;
        }
    }

    fn check(&self, now: u64, pto: u64, seed: u64) {
        let want = self
            .span
            .map(|len| (self.last + len.max(3 * pto as u128)).min(CAP) as u64);
        assert_eq!(self.idle.deadline(pto), want, "seed {seed}");
        let due = want.is_some_and(|due| now >= due);
        assert_eq!(self.idle.expired(now, pto), due, "seed {seed}");
    }
}

#[test]
fn clock() {
    for seed in 1..=64 {
        let mut dice = Dice::new(seed + 1000);
        let (local, peer) = (pick(&mut dice), pick(&mut dice));
        let mut clock = Clock::new(local, peer);
        let mut now = 0u64;
        for _ in 0..200 {
            now += dice.below(100_000);
            clock.step(now, &mut dice);
            clock.check(now, dice.below(300_000), seed);
        }
    }
}
