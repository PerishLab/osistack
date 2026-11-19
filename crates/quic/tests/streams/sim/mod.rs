mod ledger;
mod pair;

use crate::support::Dice;
use pair::{Event, Pair};
use quic::{Phase, Stage};

fn settled(pair: &Pair) -> bool {
    let sender = pair.sending.stage();
    let phase = pair.receiving.phase();
    let gone = sender == Stage::Gone && matches!(phase, Phase::Gone | Phase::Read);
    gone || (sender == Stage::Acked && phase == Phase::Read)
}

fn run(pair: &mut Pair, ticks: u64) -> Option<u64> {
    for _ in 0..ticks {
        pair.tick();
    }
    let mut code = None;
    let mut spent = 0;
    while !settled(pair) {
        pair.tick();
        if pair.receiving.phase() == Phase::Reset {
            code = pair.receiving.broken();
            assert!(code.is_some());
        }
        spent += 1;
        assert!(spent < 100_000, "stuck");
    }
    code
}

#[test]
fn aborted() {
    let mut cut = 0;
    for seed in 1..=64 {
        let size = Dice::new(seed + 200).within(1, 4000) as usize;
        let (mut pair, _) = Pair::new(seed, size);
        let ticks = pair.dice.below(60);
        for _ in 0..ticks {
            pair.tick();
        }
        if pair.sending.reset(77) {
            pair.cut();
        }
        let code = run(&mut pair, 0);
        assert!(code.is_none_or(|code| code == 77), "seed {seed}");
        cut += usize::from(code.is_some());
        assert!(pair.sum <= size as u64, "seed {seed}");
        assert_eq!(pair.sum, pair.receiving.highest(), "seed {seed}");
    }
    assert!(cut > 20, "{cut}");
}

#[test]
fn stopped() {
    let mut cut = 0;
    for seed in 1..=64 {
        let size = Dice::new(seed + 300).within(1, 4000) as usize;
        let (mut pair, _) = Pair::new(seed, size);
        let ticks = pair.dice.below(60);
        for _ in 0..ticks {
            pair.tick();
        }
        if let Some(code) = pair.receiving.stop(55) {
            let delay = pair.dice.within(1, 40);
            pair.net.push(delay, Event::Stop(code));
        }
        let code = run(&mut pair, 0);
        assert!(code.is_none_or(|code| code == 55), "seed {seed}");
        cut += usize::from(code.is_some());
        assert_eq!(pair.sum, pair.receiving.highest(), "seed {seed}");
    }
    assert!(cut > 20, "{cut}");
}
