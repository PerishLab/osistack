use crate::support::{Dice, payload};
use quic::Sending;

#[derive(Clone, Copy, PartialEq)]
enum Cell {
    Fresh,
    Flying,
    Lost,
    Done,
}

struct Ledger {
    cells: Vec<Cell>,
    limit: u64,
}

impl Ledger {
    fn sent(&self) -> u64 {
        self.cells
            .iter()
            .filter(|cell| **cell != Cell::Fresh)
            .count() as u64
    }

    fn next(&mut self, max: usize) -> Option<(u64, usize)> {
        if let Some(at) = self.cells.iter().position(|cell| *cell == Cell::Lost) {
            let run = self.cells[at..]
                .iter()
                .take(max)
                .take_while(|cell| **cell == Cell::Lost)
                .count();
            self.cells[at..at + run].fill(Cell::Flying);
            return (run > 0).then_some((at as u64, run));
        }
        let sent = self.sent();
        let room = (self.cells.len() as u64)
            .min(self.limit)
            .saturating_sub(sent);
        let size = room.min(max as u64) as usize;
        self.cells[sent as usize..sent as usize + size].fill(Cell::Flying);
        (size > 0).then_some((sent, size))
    }

    fn mark(&mut self, offset: u64, size: u64, done: bool) {
        let end = offset.saturating_add(size).min(self.sent());
        for at in offset..end {
            let cell = &mut self.cells[at as usize];
            if done {
                *cell = Cell::Done;
            } else if *cell != Cell::Done {
                *cell = Cell::Lost;
            }
        }
    }

    fn buffered(&self) -> usize {
        self.cells.len()
            - self
                .cells
                .iter()
                .take_while(|cell| **cell == Cell::Done)
                .count()
    }
}

fn step(sending: &mut Sending, ledger: &mut Ledger, whole: &[u8], dice: &mut Dice) {
    match dice.below(20) {
        0..=1 => {
            let more = dice.below(40) as usize;
            let at = ledger.cells.len();
            assert_eq!(sending.write(&whole[at..at + more]), more);
            ledger.cells.resize(at + more, Cell::Fresh);
        }
        2..=8 => {
            let max = dice.below(30) as usize;
            let got = sending
                .next(max)
                .map(|piece| (piece.offset, piece.data.len()));
            assert_eq!(got, ledger.next(max));
        }
        9..=13 => {
            let (offset, size) = (dice.below(300), dice.below(60));
            sending.acked(offset, size, false);
            ledger.mark(offset, size, true);
        }
        14..=18 => {
            let (offset, size) = (dice.below(300), dice.below(60));
            sending.lost(offset, size, false);
            ledger.mark(offset, size, false);
        }
        _ => {
            ledger.limit += dice.below(40);
            sending.raise(ledger.limit);
        }
    }
}

#[test]
fn walk() {
    for seed in 1..=64 {
        let mut dice = Dice::new(seed);
        let whole = payload(4000, seed);
        let limit = dice.within(1, 50);
        let mut sending = Sending::new(limit);
        let mut ledger = Ledger {
            cells: Vec::new(),
            limit,
        };
        for _ in 0..400 {
            step(&mut sending, &mut ledger, &whole, &mut dice);
            assert_eq!(sending.sent(), ledger.sent(), "seed {seed}");
            assert_eq!(sending.written(), ledger.cells.len() as u64, "seed {seed}");
            assert_eq!(sending.buffered(), ledger.buffered(), "seed {seed}");
            assert_eq!(sending.limit(), ledger.limit, "seed {seed}");
        }
    }
}
