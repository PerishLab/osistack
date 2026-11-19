use quic::{Reno, Rtt, Sent};

const SIZE: u64 = 1200;
const DELAY: u64 = 25_000;

fn sent(number: u64, time: u64, eliciting: bool) -> Sent {
    Sent {
        number,
        time,
        size: SIZE,
        eliciting,
        flight: eliciting,
    }
}

fn period() {
    let mut clock = Rtt::new();
    clock.update(2_000_000, 100_000, 0);
    let width = 3 * (100_000 + 4 * 50_000 + DELAY);
    let window = |packets: Vec<Sent>| {
        let mut control = Reno::new(SIZE, DELAY);
        packets.iter().for_each(|packet| control.sent(packet));
        control.lost(9_000_000, &packets, &clock);
        control.window()
    };
    let pair =
        |gap: u64, high: u64| vec![sent(0, 3_000_000, true), sent(high, 3_000_000 + gap, true)];
    assert_eq!(window(pair(width, 1)), 5 * SIZE);
    assert_eq!(window(pair(width + 1, 1)), 2 * SIZE);
    assert_eq!(window(pair(width + 1, 5)), 5 * SIZE);
    let quiet = vec![
        sent(0, 2_500_000, false),
        sent(1, 3_000_000, true),
        sent(2, 3_000_100, true),
        sent(3, 5_000_000, false),
    ];
    assert_eq!(window(quiet), 5 * SIZE);
    let early = vec![
        sent(0, 100, true),
        sent(1, 3_000_000, true),
        sent(2, 3_000_100, true),
    ];
    assert_eq!(window(early), 5 * SIZE);
}

pub fn rules() {
    let rtt = Rtt::new();
    let mut control = Reno::new(SIZE, DELAY);
    let all: Vec<Sent> = (0..10).map(|number| sent(number, number, true)).collect();
    all.iter().for_each(|packet| control.sent(packet));
    control.lost(100, &all[..1], &rtt);
    assert_eq!(
        (control.window(), control.threshold()),
        (5 * SIZE, Some(5 * SIZE))
    );
    assert_eq!(control.start(), Some(100));
    control.lost(101, &all[1..2], &rtt);
    control.acked(&all[2..7]);
    assert_eq!(control.window(), 5 * SIZE);
    let fresh: Vec<Sent> = (10..15).map(|number| sent(number, 101, true)).collect();
    fresh.iter().for_each(|packet| control.sent(packet));
    control.acked(&fresh[..1]);
    assert_eq!(control.window(), 5 * SIZE);
    control.acked(&fresh[1..]);
    assert_eq!(control.window(), 6 * SIZE);
    let edge: Vec<Sent> = (20..26).map(|number| sent(number, 100, true)).collect();
    edge.iter().for_each(|packet| control.sent(packet));
    control.acked(&edge);
    assert_eq!(control.window(), 6 * SIZE);
    let mut deep = Reno::new(SIZE, DELAY);
    let mut seen = Vec::new();
    for round in 1..=5 {
        let packet = sent(round, round * 10, true);
        deep.sent(&packet);
        deep.lost(round * 10 + 5, std::slice::from_ref(&packet), &rtt);
        seen.push(deep.window());
    }
    assert_eq!(seen, [6000, 3000, 2400, 2400, 2400]);
    period();
}
