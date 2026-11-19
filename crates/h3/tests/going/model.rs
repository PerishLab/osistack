use crate::support::*;
use h3::{Going, Streams};

struct Model {
    next: u64,
    open: Vec<u64>,
    going: Option<u64>,
}

impl Model {
    fn goaway(&mut self, id: u64) -> Option<Vec<u64>> {
        let raised = self.going.map(|before| id > before).unwrap_or(false);
        if id & 3 != 0 || raised {
            return None;
        }
        self.going = Some(id);
        let gone: Vec<u64> = self.open.iter().copied().filter(|n| *n >= id).collect();
        self.open.retain(|n| *n < id);
        Some(gone)
    }

    fn open(&mut self) -> Result<u64, Going> {
        if let Some(id) = self.going {
            return Err(Going(id));
        }
        self.next += 4;
        self.open.push(self.next - 4);
        Ok(self.next - 4)
    }
}

fn step(dice: &mut Dice, real: &mut Streams, model: &mut Model) {
    match dice.roll(6) {
        0..=2 => assert_eq!(real.open(), model.open()),
        3 => {
            let stream = dice.roll(12) * 2;
            let had = model.open.iter().position(|n| *n == stream);
            let removed = had.map(|at| model.open.remove(at)).is_some();
            assert_eq!(real.close(stream), removed);
        }
        _ => {
            let id = dice.roll(40) + dice.roll(2) * 3;
            let want = model.goaway(id);
            let got = real.goaway(id);
            assert_eq!(got.ok(), want, "goaway {id}");
        }
    }
    assert_eq!(real.going(), model.going);
    assert_eq!(real.active(), model.open);
}

#[test]
fn random() {
    for seed in 1..=60u64 {
        let mut dice = Dice(seed * 0x9e37_79b9 + 7);
        let mut real = Streams::new();
        let mut model = Model {
            next: 0,
            open: Vec::new(),
            going: None,
        };
        for _ in 0..80 {
            step(&mut dice, &mut real, &mut model);
        }
    }
}
