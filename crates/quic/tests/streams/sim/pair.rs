use crate::support::{Dice, payload};
use quic::{Phase, Piece, Receiving, Sending, Stage};

#[derive(Clone)]
pub enum Event {
    Deliver(Piece),
    Ack(Piece),
    Lose(Piece),
    Grant(u64),
    Cut(u64, u64),
    Done,
    Stop(u64),
}

pub struct Net {
    pub now: u64,
    pub queue: Vec<(u64, Event)>,
}

impl Net {
    pub fn push(&mut self, delay: u64, event: Event) {
        self.queue.push((self.now + delay, event));
    }

    pub fn due(&mut self) -> Vec<Event> {
        self.now += 1;
        let now = self.now;
        let (due, rest): (Vec<_>, Vec<_>) =
            self.queue.drain(..).partition(|(time, _)| *time <= now);
        self.queue = rest;
        due.into_iter().map(|(_, event)| event).collect()
    }
}

pub struct Pair {
    pub sending: Sending,
    pub receiving: Receiving,
    pub net: Net,
    pub dice: Dice,
    pub out: Vec<u8>,
    pub sum: u64,
    pub top: u64,
}

pub fn header(piece: &Piece) -> Piece {
    Piece {
        offset: piece.offset,
        data: vec![0; piece.data.len()],
        fin: piece.fin,
    }
}

impl Pair {
    pub fn new(seed: u64, size: usize) -> (Self, Vec<u8>) {
        let mut dice = Dice::new(seed);
        let whole = payload(size, seed);
        let window = dice.within(50, 600);
        let mut sending = Sending::new(window);
        sending.write(&whole);
        sending.finish();
        let net = Net {
            now: 0,
            queue: Vec::new(),
        };
        let pair = Self {
            sending,
            receiving: Receiving::new(window),
            net,
            dice,
            out: Vec::new(),
            sum: 0,
            top: 0,
        };
        (pair, whole)
    }

    pub fn send(&mut self) {
        let max = self.dice.within(1, 300) as usize;
        let Some(piece) = self.sending.next(max) else {
            return;
        };
        let end = piece.offset + piece.data.len() as u64;
        if end > self.top {
            assert!(end <= self.sending.limit());
            self.top = end;
        }
        if self.dice.below(10) < 3 {
            let delay = self.dice.within(1, 40);
            self.net.push(delay, Event::Lose(header(&piece)));
            return;
        }
        let copies = if self.dice.below(10) == 0 { 2 } else { 1 };
        for _ in 0..copies {
            let delay = self.dice.within(1, 40);
            self.net.push(delay, Event::Deliver(piece.clone()));
            let back = delay + self.dice.within(1, 20);
            self.net.push(back, Event::Ack(header(&piece)));
        }
    }

    fn arrive(&mut self, piece: &Piece) {
        let fresh = self
            .receiving
            .data(piece.offset, &piece.data, piece.fin)
            .unwrap();
        self.sum += fresh;
    }

    fn drain(&mut self) {
        let want = self.dice.below(200) as usize;
        self.out.extend(self.receiving.read(want));
        if let Some(limit) = self.receiving.grant() {
            let delay = self.dice.within(1, 40);
            self.net.push(delay, Event::Grant(limit));
        }
    }

    fn handle(&mut self, event: Event) {
        match event {
            Event::Deliver(piece) => self.arrive(&piece),
            Event::Ack(piece) => {
                self.sending
                    .acked(piece.offset, piece.data.len() as u64, piece.fin)
            }
            Event::Lose(piece) => {
                self.sending
                    .lost(piece.offset, piece.data.len() as u64, piece.fin)
            }
            Event::Grant(limit) => {
                self.sending.raise(limit);
            }
            Event::Cut(code, size) => {
                let fresh = self.receiving.reset(code, size).unwrap();
                self.sum += fresh;
                self.net.push(3, Event::Done);
            }
            Event::Done => self.sending.settle(),
            Event::Stop(code) => {
                if self.sending.stop(code) {
                    self.cut();
                }
            }
        }
    }

    pub fn cut(&mut self) {
        let (code, size) = self.sending.frame().unwrap();
        let delay = self.dice.within(1, 40);
        self.net.push(delay, Event::Cut(code, size));
    }

    pub fn tick(&mut self) {
        self.send();
        for event in self.net.due() {
            self.handle(event);
        }
        self.drain();
    }
}

#[test]
fn lossy() {
    for seed in 1..=64 {
        let size = Dice::new(seed + 100).within(1, 4000) as usize;
        let (mut pair, whole) = Pair::new(seed, size);
        let mut ticks = 0;
        while pair.sending.stage() != Stage::Acked || pair.receiving.phase() != Phase::Read {
            pair.tick();
            ticks += 1;
            assert!(ticks < 100_000, "seed {seed} stuck");
        }
        assert_eq!(pair.out, whole, "seed {seed}");
        assert_eq!(pair.sum, size as u64, "seed {seed}");
        assert_eq!(pair.sending.buffered(), 0);
        assert_eq!(pair.receiving.size(), Some(size as u64));
    }
}
