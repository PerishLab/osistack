use crate::support::*;
use quic::{Arrival, Mark, Marking, Received, Space, Status};

const DATA: Space = Space::Data;

enum Net {
    Honest,
    Bleach,
    Remark,
    Blackhole,
}

fn deliver(net: &Net, mark: Mark, dice: &mut Dice) -> Option<Mark> {
    match net {
        Net::Honest if dice.below(5) == 0 => Some(Mark::Ce),
        Net::Honest => Some(mark),
        Net::Bleach => Some(Mark::Plain),
        Net::Remark => Some(Mark::Ect1),
        Net::Blackhole if mark == Mark::Plain => Some(mark),
        Net::Blackhole => None,
    }
}

struct Run {
    status: Status,
    congested: bool,
    marked: bool,
    ce: bool,
}

fn model(seed: u64) -> (Run, usize) {
    let kind = [Net::Honest, Net::Bleach, Net::Remark, Net::Blackhole];
    let net = &kind[seed as usize % 4];
    let mut dice = Dice::new(seed);
    let mut marking = Marking::new(10, false);
    let mut peer = Received::new(25_000, 3, 64);
    let mut run = Run {
        status: Status::Testing,
        congested: false,
        marked: false,
        ce: false,
    };
    let mut dropped = Vec::new();
    for number in 0..40 {
        let mark = marking.send(DATA, number);
        run.marked |= mark != Mark::Plain;
        let seen = if dice.below(6) == 0 && !matches!(net, Net::Blackhole) {
            None
        } else {
            deliver(net, mark, &mut dice)
        };
        let Some(arrived) = seen else {
            dropped.push(number);
            continue;
        };
        run.ce |= arrived == Mark::Ce;
        let arrival = Arrival {
            number,
            time: number * 100,
            eliciting: true,
            mark: arrived,
        };
        peer.receive(DATA, arrival);
        if number % 3 == 2 {
            let frame = peer.frame(DATA, number * 100).unwrap();
            let report = marking.acked(DATA, &frame);
            run.congested |= report.congested;
        }
    }
    if let Some(frame) = peer.frame(DATA, 4_000) {
        run.congested |= marking.acked(DATA, &frame).congested;
    }
    marking.lost(DATA, &dropped);
    run.status = marking.status();
    (run, dropped.len())
}

#[test]
fn network() {
    for seed in 0..64 {
        let (run, _) = model(seed);
        assert!(run.marked, "{seed}");
        match seed % 4 {
            0 => {
                assert_eq!(run.status, Status::Capable, "{seed}");
                assert_eq!(run.congested, run.ce, "{seed}");
            }
            _ => assert_eq!(run.status, Status::Failed, "{seed}"),
        }
    }
}
