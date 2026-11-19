use crate::support::*;
use quic::{Mark, Marking, Space, Status};

const DATA: Space = Space::Data;

#[test]
fn testing() {
    let mut marking = Marking::new(3, false);
    assert_eq!(marking.status(), Status::Testing);
    for number in 0..2 {
        assert_eq!(marking.send(DATA, number), Mark::Ect0);
        assert_eq!(marking.status(), Status::Testing);
    }
    assert_eq!(marking.send(DATA, 2), Mark::Ect0);
    assert_eq!(marking.status(), Status::Unknown);
    assert_eq!(marking.send(DATA, 3), Mark::Plain);
    let report = marking.acked(DATA, &reply(3, 0, only(0)));
    assert_eq!(report, verdict(Status::Unknown, false));
}

#[test]
fn nothing() {
    let mut marking = Marking::new(0, false);
    assert_eq!(marking.status(), Status::Unknown);
    assert_eq!(marking.send(DATA, 0), Mark::Plain);
    assert_eq!(marking.lost(DATA, &[1]), Status::Unknown);
    marking.restart();
    assert_eq!(marking.status(), Status::Unknown);
}

#[test]
fn early() {
    let mut marking = Marking::new(3, false);
    for number in 0..2 {
        marking.send(DATA, number);
    }
    let report = marking.acked(DATA, &reply(0, 0, only(1)));
    assert_eq!(report, verdict(Status::Testing, false));
    assert_eq!(marking.send(DATA, 2), Mark::Ect0);
    assert_eq!(marking.status(), Status::Capable);
}

#[test]
fn lost() {
    let mut marking = armed(2, 2);
    assert_eq!(marking.lost(DATA, &[0]), Status::Unknown);
    assert_eq!(marking.lost(DATA, &[0, 7]), Status::Unknown);
    assert_eq!(marking.lost(DATA, &[1]), Status::Failed);
    let mut marking = armed(3, 2);
    assert_eq!(marking.lost(DATA, &[0, 1]), Status::Testing);
    let mut marking = armed(2, 2);
    marking.acked(DATA, &reply(0, 0, only(1)));
    assert_eq!(marking.lost(DATA, &[1]), Status::Capable);
    let mut marking = Marking::new(2, false);
    assert_eq!(marking.lost(DATA, &[1]), Status::Testing);
}

#[test]
fn discard() {
    let mut marking = Marking::new(2, false);
    marking.send(Space::Initial, 0);
    marking.send(DATA, 0);
    assert_eq!(marking.status(), Status::Unknown);
    assert_eq!(marking.lost(DATA, &[0]), Status::Unknown);
    let mut marking = Marking::new(2, false);
    marking.send(Space::Initial, 0);
    marking.send(DATA, 0);
    marking.discard(Space::Initial);
    assert_eq!(marking.lost(DATA, &[0]), Status::Failed);
    let report = marking.acked(Space::Initial, &reply(0, 0, None));
    assert_eq!(report.status, Status::Failed);
    let mut marking = Marking::new(2, false);
    marking.send(Space::Initial, 0);
    marking.send(DATA, 0);
    marking.discard(Space::Initial);
    assert_eq!(marking.lost(Space::Initial, &[0]), Status::Unknown);
    let report = marking.acked(Space::Initial, &reply(0, 0, None));
    assert_eq!(report.status, Status::Unknown);
}

#[test]
fn restart() {
    let mut marking = armed(1, 1);
    marking.acked(DATA, &reply(0, 0, only(1)));
    marking.send(DATA, 2);
    marking.acked(DATA, &reply(2, 0, None));
    assert_eq!(marking.status(), Status::Failed);
    marking.restart();
    assert_eq!(marking.status(), Status::Testing);
    assert_eq!(marking.send(DATA, 5), Mark::Ect0);
    assert_eq!(marking.status(), Status::Unknown);
    let mut flat = marking.clone();
    let report = marking.acked(DATA, &reply(5, 0, only(2)));
    assert_eq!(report, verdict(Status::Capable, false));
    let report = flat.acked(DATA, &reply(5, 0, only(1)));
    assert_eq!(report.status, Status::Failed);
}

#[test]
fn again() {
    let mut marking = armed(2, 2);
    assert_eq!(marking.lost(DATA, &[0, 1]), Status::Failed);
    marking.restart();
    assert_eq!(marking.send(DATA, 5), Mark::Ect0);
    assert_eq!(marking.status(), Status::Testing);
    assert_eq!(marking.send(DATA, 6), Mark::Ect0);
    assert_eq!(marking.status(), Status::Unknown);
    assert_eq!(marking.lost(DATA, &[5]), Status::Unknown);
    assert_eq!(marking.lost(DATA, &[6]), Status::Failed);
    let mut marking = armed(1, 1);
    marking.acked(DATA, &reply(0, 0, None));
    assert_eq!(marking.status(), Status::Failed);
    marking.restart();
    assert_eq!(marking.send(DATA, 5), Mark::Ect0);
    assert_eq!(marking.lost(DATA, &[5]), Status::Unknown);
}
