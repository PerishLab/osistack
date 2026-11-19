use crate::support::*;
use h2::{Connection, State};

struct Dice(u64);

impl Dice {
    fn roll(&mut self, sides: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % sides
    }
}

fn live(state: State) -> bool {
    matches!(state, State::Open | State::Local | State::Remote)
}

fn check(connection: &Connection, most: usize) {
    let mut count = 0;
    for stream in [1, 3, 5, 7, 9] {
        let open = live(connection.streams().state(stream));
        assert_eq!(connection.flow().outgoing(stream).is_some(), open);
        assert_eq!(connection.flow().incoming(stream).is_some(), open);
        count += usize::from(open);
    }
    assert_eq!(connection.streams().active(), count);
    assert!(count <= most);
}

fn step(connection: &mut Connection, dice: &mut Dice) {
    let stream = [1u32, 3, 5, 7, 9][dice.roll(5) as usize];
    let size = dice.roll(3000) as usize;
    let fin = dice.roll(4) == 0;
    match dice.roll(7) {
        0 | 1 => drop(connection.send(&Stream(stream).headers(fin))),
        2 | 3 => drop(connection.send(&Stream(stream).data(size, fin))),
        4 => drop(connection.send(&Stream(stream).reset())),
        5 => drop(connection.receive(&Stream(stream).data(size, fin))),
        _ => drop(connection.receive(&Stream(stream).window(size as u32 + 1))),
    }
    if dice.roll(9) == 0 {
        drop(connection.receive(&Stream(stream).headers(fin)));
    }
}

#[test]
fn tracked() {
    for seed in 1..=40u64 {
        let mut dice = Dice(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        let mut connection = ready(&[(3, 3), (4, 5000)]);
        for _ in 0..800 {
            step(&mut connection, &mut dice);
            check(&connection, 3);
        }
    }
}
