use crate::support::*;
use quic::{Ecn, Mark, Received, Seen, Space};

const DATA: Space = Space::Data;

fn fresh(delay: u64, limit: usize) -> Received {
    Received::new(delay, 3, limit)
}

fn feed(got: &mut Received, numbers: &[u64]) {
    for &number in numbers {
        assert_eq!(
            got.receive(DATA, silent(number, 0)),
            Seen::Fresh,
            "{number}"
        );
    }
}

#[test]
fn inserted() {
    let mut got = fresh(25_000, 8);
    feed(&mut got, &[5]);
    assert_eq!(got.ranges(DATA), [(5, 5)]);
    feed(&mut got, &[7]);
    assert_eq!(got.ranges(DATA), [(5, 5), (7, 7)]);
    feed(&mut got, &[6]);
    assert_eq!(got.ranges(DATA), [(5, 7)]);
    feed(&mut got, &[3]);
    assert_eq!(got.ranges(DATA), [(3, 3), (5, 7)]);
    feed(&mut got, &[4]);
    assert_eq!(got.ranges(DATA), [(3, 7)]);
    feed(&mut got, &[9, 0, 8, 1]);
    assert_eq!(got.ranges(DATA), [(0, 1), (3, 9)]);
    feed(&mut got, &[2]);
    assert_eq!(got.ranges(DATA), [(0, 9)]);
}

#[test]
fn repeats() {
    let mut got = fresh(25_000, 8);
    feed(&mut got, &[1, 2, 3, 7]);
    got.frame(DATA, 0).unwrap();
    for number in [1, 2, 3, 7] {
        let again = marked(number, 9, Mark::Ce);
        assert_eq!(got.receive(DATA, again), Seen::Repeat, "{number}");
    }
    assert_eq!(got.ranges(DATA), [(1, 3), (7, 7)]);
    assert_eq!(got.deadline(DATA), None);
    assert_eq!(got.frame(DATA, 9), None);
    feed(&mut got, &[5]);
    assert_eq!(got.frame(DATA, 9).unwrap().ecn, None);
}

#[test]
fn spaces() {
    let mut got = fresh(25_000, 8);
    for space in [Space::Initial, Space::Handshake, DATA] {
        assert_eq!(got.receive(space, arrival(4, 0)), Seen::Fresh);
    }
    assert_eq!(got.receive(Space::Handshake, arrival(4, 0)), Seen::Repeat);
    assert_eq!(got.receive(Space::Initial, arrival(5, 0)), Seen::Fresh);
    assert_eq!(got.ranges(Space::Initial), [(4, 5)]);
    assert_eq!(got.ranges(Space::Handshake), [(4, 4)]);
    assert_eq!(got.ranges(DATA), [(4, 4)]);
}

#[test]
fn bounded() {
    let mut got = fresh(25_000, 3);
    feed(&mut got, &[0, 2, 4, 6]);
    assert_eq!(got.ranges(DATA), [(2, 2), (4, 4), (6, 6)]);
    assert_eq!(got.receive(DATA, arrival(0, 0)), Seen::Repeat);
    assert_eq!(got.receive(DATA, arrival(1, 0)), Seen::Fresh);
    assert_eq!(got.ranges(DATA), [(1, 2), (4, 4), (6, 6)]);
    feed(&mut got, &[8]);
    assert_eq!(got.ranges(DATA), [(4, 4), (6, 6), (8, 8)]);
    for number in [1, 2] {
        assert_eq!(got.receive(DATA, arrival(number, 0)), Seen::Repeat);
    }
    assert_eq!(got.receive(DATA, arrival(3, 0)), Seen::Fresh);
    assert_eq!(got.ranges(DATA), [(3, 4), (6, 6), (8, 8)]);
    assert_eq!(got.receive(DATA, arrival(4, 0)), Seen::Repeat);
    assert_eq!(got.receive(DATA, arrival(5, 0)), Seen::Fresh);
    assert_eq!(got.ranges(DATA), [(3, 6), (8, 8)]);
}

#[test]
fn lowest() {
    let mut got = fresh(25_000, 2);
    feed(&mut got, &[10, 20]);
    got.frame(DATA, 0).unwrap();
    assert_eq!(got.receive(DATA, arrival(5, 0)), Seen::Repeat);
    assert_eq!(got.ranges(DATA), [(10, 10), (20, 20)]);
    assert_eq!(got.deadline(DATA), None);
    assert_eq!(got.frame(DATA, 0), None);
    assert_eq!(got.receive(DATA, arrival(10, 0)), Seen::Repeat);
    assert_eq!(got.receive(DATA, arrival(8, 0)), Seen::Repeat);
}

#[test]
fn floor() {
    let mut got = fresh(25_000, 0);
    feed(&mut got, &[3]);
    assert_eq!(got.receive(DATA, arrival(5, 0)), Seen::Fresh);
    assert_eq!(got.ranges(DATA), [(5, 5)]);
    assert_eq!(got.receive(DATA, arrival(3, 0)), Seen::Repeat);
    assert_eq!(got.receive(DATA, arrival(4, 0)), Seen::Fresh);
    assert_eq!(got.ranges(DATA), [(4, 5)]);
    assert_eq!(got.receive(DATA, arrival(6, 0)), Seen::Fresh);
    assert_eq!(got.ranges(DATA), [(4, 6)]);
}

#[test]
fn confirmed() {
    let mut got = fresh(25_000, 8);
    feed(&mut got, &[0, 1, 2, 4, 5, 6, 8, 9]);
    got.carried(DATA, 100, 5);
    got.carried(DATA, 101, 9);
    got.confirmed(DATA, 77);
    assert_eq!(got.ranges(DATA), [(0, 2), (4, 6), (8, 9)]);
    got.confirmed(DATA, 100);
    assert_eq!(got.ranges(DATA), [(6, 6), (8, 9)]);
    assert_eq!(got.receive(DATA, arrival(3, 0)), Seen::Repeat);
    assert_eq!(got.receive(DATA, arrival(5, 0)), Seen::Repeat);
    assert_eq!(got.receive(DATA, arrival(7, 0)), Seen::Fresh);
    assert_eq!(got.ranges(DATA), [(6, 9)]);
    got.confirmed(DATA, 100);
    assert_eq!(got.ranges(DATA), [(6, 9)]);
    got.confirmed(DATA, 101);
    assert_eq!(got.ranges(DATA), [(9, 9)]);
    assert_eq!(got.receive(DATA, arrival(8, 0)), Seen::Repeat);
}

#[test]
fn straddled() {
    let mut got = fresh(25_000, 8);
    feed(&mut got, &[0, 1, 2, 3, 4, 5, 6, 7]);
    got.carried(DATA, 1, 3);
    got.confirmed(DATA, 1);
    assert_eq!(got.ranges(DATA), [(4, 7)]);
    got.carried(DATA, 2, 7);
    got.confirmed(DATA, 2);
    assert_eq!(got.ranges(DATA), [(7, 7)]);
}

#[test]
fn newest() {
    let mut got = fresh(25_000, 8);
    feed(&mut got, &[0, 1, 2]);
    got.carried(DATA, 1, 40);
    got.confirmed(DATA, 1);
    assert_eq!(got.ranges(DATA), [(2, 2)]);
    assert_eq!(got.frame(DATA, 0).unwrap().largest, 2);
    feed(&mut got, &[3]);
    assert_eq!(got.ranges(DATA), [(2, 3)]);
    let mut none = fresh(25_000, 8);
    none.carried(DATA, 1, 3);
    none.confirmed(DATA, 1);
    assert_eq!(none.ranges(DATA), []);
}

#[test]
fn lower() {
    let mut got = fresh(25_000, 8);
    feed(&mut got, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    got.carried(DATA, 1, 8);
    got.carried(DATA, 2, 6);
    got.confirmed(DATA, 2);
    assert_eq!(got.ranges(DATA), [(7, 9)]);
    got.confirmed(DATA, 1);
    assert_eq!(got.ranges(DATA), [(7, 9)]);
}

#[test]
fn capped() {
    let mut got = fresh(25_000, 2);
    feed(&mut got, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    got.carried(DATA, 1, 4);
    got.carried(DATA, 2, 5);
    got.carried(DATA, 3, 6);
    got.confirmed(DATA, 1);
    assert_eq!(got.ranges(DATA), [(0, 9)]);
    got.confirmed(DATA, 2);
    assert_eq!(got.ranges(DATA), [(6, 9)]);
    got.confirmed(DATA, 3);
    assert_eq!(got.ranges(DATA), [(7, 9)]);
}

#[test]
fn discarded() {
    let mut got = fresh(25_000, 8);
    got.receive(DATA, marked(1, 0, Mark::Ect0));
    got.receive(Space::Initial, arrival(1, 0));
    got.carried(DATA, 1, 1);
    got.discard(DATA);
    assert_eq!(got.ranges(DATA), []);
    assert_eq!(got.deadline(DATA), None);
    assert_eq!(got.frame(DATA, 0), None);
    assert_eq!(got.ranges(Space::Initial), [(1, 1)]);
    assert_eq!(got.receive(DATA, arrival(1, 10)), Seen::Fresh);
    assert_eq!(got.deadline(DATA), Some(25_010));
    assert_eq!(got.frame(DATA, 10).unwrap().ecn, None);
    got.discard(Space::Initial);
    assert_eq!(got.receive(Space::Initial, arrival(2, 10)), Seen::Fresh);
    assert_eq!(got.deadline(Space::Initial), Some(10));
    got.confirmed(DATA, 1);
    assert_eq!(got.ranges(DATA), [(1, 1)]);
}

#[test]
fn counted() {
    let mut got = fresh(25_000, 8);
    got.receive(DATA, silent(0, 0));
    assert_eq!(got.frame(DATA, 0).unwrap().ecn, None);
    got.receive(DATA, marked(1, 0, Mark::Ect0));
    got.receive(DATA, marked(2, 0, Mark::Ect0));
    got.receive(DATA, marked(3, 0, Mark::Ect1));
    got.receive(DATA, marked(4, 0, Mark::Ce));
    got.receive(DATA, marked(4, 0, Mark::Ce));
    got.receive(DATA, marked(5, 0, Mark::Plain));
    let want = Ecn {
        ect0: 2,
        ect1: 1,
        ce: 1,
    };
    assert_eq!(got.frame(DATA, 0).unwrap().ecn, Some(want));
    got.receive(DATA, silent(6, 0));
    assert_eq!(got.frame(DATA, 0).unwrap().ecn, Some(want));
    got.receive(Space::Initial, marked(0, 0, Mark::Ce));
    assert_eq!(got.frame(Space::Handshake, 0), None);
    let other = Ecn {
        ect0: 0,
        ect1: 0,
        ce: 1,
    };
    assert_eq!(got.frame(Space::Initial, 0).unwrap().ecn, Some(other));
}
