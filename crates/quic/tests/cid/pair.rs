use crate::support::*;
use quic::{Frame, Issued, Peers};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Act {
    Idle,
    Issue(u64),
    Rotate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Issued(u64, u64),
    Refused,
    Received(Vec<u64>),
    Rotated(u64),
    Retired(u64),
}

struct Pair {
    near: Issued,
    far: Peers,
    down: Vec<(u64, Vec<u8>)>,
    up: Vec<(u64, Vec<u8>, Vec<u8>)>,
    events: Vec<(u64, Event)>,
    count: u8,
    limit: u64,
}

impl Pair {
    fn new(limit: u64) -> Self {
        Self {
            near: Issued::new(cid(0), limit),
            far: Peers::new(cid(0), Some(token(0)), limit),
            down: Vec::new(),
            up: Vec::new(),
            events: Vec::new(),
            count: 0,
            limit,
        }
    }

    fn drain<T: Clone>(queue: &mut Vec<(u64, T)>, now: u64) -> Vec<T> {
        let due: Vec<T> = queue
            .iter()
            .filter(|item| item.0 <= now)
            .map(|item| item.1.clone())
            .collect();
        queue.retain(|item| item.0 > now);
        due
    }

    fn deliver(&mut self, now: u64, delay: u64) {
        let due = Pair::drain(&mut self.down, now);
        for bytes in due {
            let (frame, _) = Frame::parse(&bytes).unwrap();
            let Frame::Issue {
                sequence,
                retire,
                cid,
                token,
            } = frame
            else {
                panic!("not an issue frame");
            };
            let freed = self.far.receive(sequence, retire, &cid, token).unwrap();
            self.events.push((now, Event::Received(freed.clone())));
            for seq in freed {
                self.reply(now + delay, seq);
            }
        }
        let back: Vec<(u64, Vec<u8>, Vec<u8>)> =
            self.up.iter().filter(|u| u.0 <= now).cloned().collect();
        self.up.retain(|item| item.0 > now);
        for (_, bytes, dcid) in back {
            let (frame, _) = Frame::parse(&bytes).unwrap();
            let Frame::Retire(sequence) = frame else {
                panic!("not a retire frame");
            };
            assert_eq!(self.near.retire(sequence, &dcid), Ok(true));
            self.events.push((now, Event::Retired(sequence)));
        }
    }

    fn reply(&mut self, arrival: u64, sequence: u64) {
        let bytes = Frame::Retire(sequence).write().unwrap();
        let dcid = self.far.current().1.to_vec();
        self.up.push((arrival, bytes, dcid));
    }

    fn issue(&mut self, now: u64, delay: u64, retire: u64) {
        self.count += 1;
        let n = self.count;
        let Ok(frame) = self.near.issue(cid(n), token(n), retire) else {
            self.events.push((now, Event::Refused));
            return;
        };
        let Frame::Issue {
            sequence, retire, ..
        } = frame
        else {
            panic!("not an issue frame");
        };
        self.events.push((now, Event::Issued(sequence, retire)));
        self.down.push((now + delay, frame.write().unwrap()));
    }

    fn rotate(&mut self, now: u64, delay: u64) {
        if let Some(old) = self.far.rotate() {
            self.events.push((now, Event::Rotated(old)));
            self.reply(now + delay, old);
        }
    }

    fn act(&mut self, now: u64, delay: u64, act: Act) {
        match act {
            Act::Idle => {}
            Act::Issue(retire) => self.issue(now, delay, retire),
            Act::Rotate => self.rotate(now, delay),
        }
    }

    fn check(&self) {
        assert!(self.far.active() as u64 <= self.limit);
        assert!(self.near.active() as u64 <= self.limit);
        let held = self.near.live();
        assert!(self.far.live().iter().all(|seq| held.contains(seq)));
    }

    fn step(&mut self, now: u64, delay: u64, first: Act, second: Act) {
        self.deliver(now, delay);
        self.act(now, delay, first);
        self.act(now, delay, second);
        self.check();
    }
}

#[test]
fn scripted() {
    let mut pair = Pair::new(2);
    let script = [
        (Act::Issue(0), Act::Idle),
        (Act::Issue(0), Act::Idle),
        (Act::Idle, Act::Rotate),
        (Act::Idle, Act::Idle),
        (Act::Issue(0), Act::Idle),
        (Act::Issue(u64::MAX), Act::Idle),
        (Act::Idle, Act::Idle),
        (Act::Idle, Act::Idle),
        (Act::Idle, Act::Idle),
        (Act::Idle, Act::Idle),
    ];
    for (now, (first, second)) in script.into_iter().enumerate() {
        pair.step(now as u64, 2, first, second);
    }
    let expected = vec![
        (0, Event::Issued(1, 0)),
        (1, Event::Refused),
        (2, Event::Received(vec![])),
        (2, Event::Rotated(0)),
        (4, Event::Retired(0)),
        (4, Event::Issued(2, 0)),
        (5, Event::Issued(3, 3)),
        (6, Event::Received(vec![])),
        (7, Event::Received(vec![1, 2])),
        (9, Event::Retired(1)),
        (9, Event::Retired(2)),
    ];
    assert_eq!(pair.events, expected);
    assert_eq!(pair.near.live(), vec![3]);
    assert_eq!(pair.far.live(), vec![3]);
    assert_eq!(pair.far.current().0, 3);
    assert_eq!(pair.near.active(), 1);
}

fn pick(dice: &mut Dice) -> Act {
    match dice.below(10) {
        0..=3 => Act::Issue(0),
        4 => Act::Issue(u64::MAX),
        5..=6 => Act::Rotate,
        _ => Act::Idle,
    }
}

#[test]
fn shuffled() {
    for seed in 1..=60 {
        let mut dice = Dice::new(seed);
        let limit = dice.within(2, 5);
        let delay = dice.below(7);
        let mut pair = Pair::new(limit);
        let mut now = 0;
        while now < 150 {
            let first = pick(&mut dice);
            let second = pick(&mut dice);
            let wait = dice.below(delay + 1);
            pair.step(now, wait, first, second);
            now += 1;
        }
        while !pair.down.is_empty() || !pair.up.is_empty() {
            assert!(now < 1000, "stuck");
            pair.step(now, 0, Act::Idle, Act::Idle);
            now += 1;
        }
        assert_eq!(pair.near.live(), pair.far.live(), "seed {seed}");
        let (seq, held) = pair.far.current();
        assert!(pair.far.live().contains(&seq), "seed {seed}");
        assert_eq!(pair.near.find(held), Some(seq), "seed {seed}");
    }
}
