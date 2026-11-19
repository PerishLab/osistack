use crate::support::*;
use quic::{Mark, Marking, Space, Status};

const DATA: Space = Space::Data;

#[test]
fn capable() {
    let mut marking = armed(2, 2);
    assert_eq!(marking.status(), Status::Unknown);
    let report = marking.acked(DATA, &reply(1, 1, only(2)));
    assert_eq!(report, verdict(Status::Capable, false));
    assert_eq!(marking.send(DATA, 2), Mark::Ect0);
    let report = marking.acked(DATA, &reply(2, 0, only(3)));
    assert_eq!(report, verdict(Status::Capable, false));
    assert_eq!(marking.send(DATA, 3), Mark::Ect0);
}

#[test]
fn missing() {
    let mut marking = armed(2, 2);
    let report = marking.acked(DATA, &reply(1, 1, None));
    assert_eq!(report, verdict(Status::Failed, false));
    assert_eq!(marking.status(), Status::Failed);
    assert_eq!(marking.send(DATA, 9), Mark::Plain);
    let report = marking.acked(DATA, &reply(9, 0, counts(1, 0, 1)));
    assert_eq!(report, verdict(Status::Failed, false));
}

#[test]
fn unmarked() {
    let mut marking = Marking::new(1, false);
    assert_eq!(marking.send(DATA, 5), Mark::Ect0);
    for ecn in [None, only(0)] {
        let report = marking.acked(DATA, &reply(3, 3, ecn));
        assert_eq!(report, verdict(Status::Unknown, false));
    }
}

#[test]
fn cleared() {
    let mut marking = armed(2, 2);
    let report = marking.acked(DATA, &reply(1, 1, only(0)));
    assert_eq!(report.status, Status::Failed);
}

#[test]
fn short() {
    let mut marking = armed(3, 3);
    let report = marking.acked(DATA, &reply(2, 2, only(2)));
    assert_eq!(report.status, Status::Failed);
    let mut marking = armed(3, 3);
    let report = marking.acked(DATA, &reply(2, 2, only(3)));
    assert_eq!(report, verdict(Status::Capable, false));
}

#[test]
fn turned() {
    let mut marking = armed(3, 3);
    let report = marking.acked(DATA, &reply(2, 2, counts(2, 0, 1)));
    assert_eq!(report, verdict(Status::Capable, true));
    let mut marking = armed(3, 3);
    let report = marking.acked(DATA, &reply(2, 2, counts(1, 0, 1)));
    assert_eq!(report.status, Status::Failed);
}

#[test]
fn ectone() {
    let mut marking = Marking::new(2, true);
    assert_eq!(marking.send(DATA, 0), Mark::Ect1);
    assert_eq!(marking.send(DATA, 1), Mark::Ect1);
    let report = marking.acked(DATA, &reply(1, 1, counts(0, 1, 1)));
    assert_eq!(report, verdict(Status::Capable, true));
    let report = marking.acked(DATA, &reply(1, 1, counts(0, 0, 0)));
    assert_eq!(report, verdict(Status::Capable, false));
    let mut marking = Marking::new(2, true);
    marking.send(DATA, 0);
    marking.send(DATA, 1);
    let report = marking.acked(DATA, &reply(1, 1, counts(2, 0, 0)));
    assert_eq!(report.status, Status::Failed);
    let mut marking = Marking::new(2, true);
    marking.send(DATA, 0);
    marking.send(DATA, 1);
    let report = marking.acked(DATA, &reply(1, 1, counts(0, 1, 0)));
    assert_eq!(report.status, Status::Failed);
    let mut marking = Marking::new(2, true);
    marking.send(DATA, 0);
    marking.send(DATA, 1);
    marking.acked(DATA, &reply(1, 1, counts(0, 2, 0)));
    marking.send(DATA, 2);
    let report = marking.acked(DATA, &reply(2, 0, counts(0, 1, 0)));
    assert_eq!(report.status, Status::Failed);
}

#[test]
fn excess() {
    let mut marking = armed(5, 5);
    let report = marking.acked(DATA, &reply(1, 1, only(4)));
    assert_eq!(report, verdict(Status::Capable, false));
    let report = marking.acked(DATA, &reply(4, 2, only(4)));
    assert_eq!(report.status, Status::Failed);
}

#[test]
fn overcount() {
    let mut marking = armed(2, 2);
    let report = marking.acked(DATA, &reply(1, 1, only(3)));
    assert_eq!(report.status, Status::Failed);
    let mut marking = armed(2, 2);
    let report = marking.acked(DATA, &reply(1, 1, counts(2, 1, 0)));
    assert_eq!(report.status, Status::Failed);
    let mut marking = armed(2, 2);
    let report = marking.acked(DATA, &reply(1, 1, only(2)));
    assert_eq!(report.status, Status::Capable);
}

#[test]
fn shrunk() {
    let mut marking = armed(4, 4);
    marking.acked(DATA, &reply(1, 1, only(2)));
    let report = marking.acked(DATA, &reply(3, 1, only(1)));
    assert_eq!(report.status, Status::Failed);
    let mut marking = armed(4, 4);
    marking.acked(DATA, &reply(1, 1, counts(1, 0, 1)));
    let report = marking.acked(DATA, &reply(3, 1, counts(2, 0, 0)));
    assert_eq!(report.status, Status::Failed);
    let mut marking = armed(4, 4);
    marking.acked(DATA, &reply(1, 1, counts(1, 0, 1)));
    let report = marking.acked(DATA, &reply(2, 0, counts(2, 0, 0)));
    assert_eq!(report.status, Status::Failed);
}

#[test]
fn reordered() {
    let mut marking = armed(9, 9);
    marking.acked(DATA, &reply(7, 0, only(1)));
    assert_eq!(marking.status(), Status::Capable);
    let report = marking.acked(DATA, &reply(6, 1, only(0)));
    assert_eq!(report, verdict(Status::Capable, false));
    let report = marking.acked(DATA, &reply(7, 7, None));
    assert_eq!(report, verdict(Status::Capable, false));
    let mut late = marking.clone();
    let report = marking.acked(DATA, &reply(8, 8, only(9)));
    assert_eq!(report, verdict(Status::Capable, false));
    let report = late.acked(DATA, &reply(8, 8, only(8)));
    assert_eq!(report.status, Status::Failed);
}

#[test]
fn congest() {
    let mut marking = armed(6, 6);
    let report = marking.acked(DATA, &reply(1, 1, counts(1, 0, 1)));
    assert_eq!(report, verdict(Status::Capable, true));
    let report = marking.acked(DATA, &reply(2, 0, counts(2, 0, 1)));
    assert_eq!(report, verdict(Status::Capable, false));
    let report = marking.acked(DATA, &reply(3, 0, counts(2, 0, 2)));
    assert_eq!(report, verdict(Status::Capable, true));
    let report = marking.acked(DATA, &reply(5, 1, counts(3, 0, 3)));
    assert_eq!(report, verdict(Status::Capable, true));
}

#[test]
fn spaces() {
    let mut marking = Marking::new(2, false);
    marking.send(Space::Initial, 0);
    marking.send(DATA, 0);
    let report = marking.acked(Space::Initial, &reply(0, 0, only(1)));
    assert_eq!(report.status, Status::Capable);
    let report = marking.acked(DATA, &reply(0, 0, only(1)));
    assert_eq!(report.status, Status::Capable);
    let mut marking = Marking::new(2, false);
    marking.send(Space::Initial, 0);
    marking.send(DATA, 0);
    let report = marking.acked(Space::Handshake, &reply(0, 0, only(1)));
    assert_eq!(report.status, Status::Failed);
}

#[test]
fn invalid() {
    let mut marking = armed(2, 2);
    let report = marking.acked(DATA, &reply(1, 5, None));
    assert_eq!(report, verdict(Status::Unknown, false));
    let report = marking.acked(DATA, &reply(1, 1, only(2)));
    assert_eq!(report.status, Status::Capable);
}
