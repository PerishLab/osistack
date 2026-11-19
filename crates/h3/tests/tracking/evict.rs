use crate::support::*;
use h3::{Error, Feedback, Instruction};

#[test]
fn pinned() {
    let mut tracker = tracker(105, 4, 3);
    section(&mut tracker, 4, &[0]).unwrap();
    let outcome = tracker.apply(&put("k3", "v"));
    assert_eq!(outcome, Err(Error::Pinned));
    assert_eq!(tracker.table().inserted(), 3);
    assert_eq!(tracker.table().dropped(), 0);
    tracker.feedback(Feedback::Acknowledge(4)).unwrap();
    tracker.apply(&put("k3", "v")).unwrap();
    assert_eq!(tracker.table().dropped(), 1);
}

#[test]
fn cancelled() {
    let mut tracker = tracker(105, 4, 3);
    section(&mut tracker, 4, &[0]).unwrap();
    assert_eq!(tracker.apply(&put("k3", "v")), Err(Error::Pinned));
    tracker.feedback(Feedback::Cancel(4)).unwrap();
    tracker.apply(&put("k3", "v")).unwrap();
}

#[test]
fn shrink() {
    let mut tracker = tracker(105, 4, 3);
    section(&mut tracker, 4, &[0]).unwrap();
    let outcome = tracker.apply(&Instruction::Capacity(70));
    assert_eq!(outcome, Err(Error::Pinned));
    assert_eq!(tracker.table().capacity(), 105);
    assert_eq!(tracker.table().size(), 105);
    tracker.feedback(Feedback::Cancel(4)).unwrap();
    tracker.apply(&Instruction::Capacity(70)).unwrap();
    assert_eq!(tracker.table().size(), 70);
    assert_eq!(tracker.table().dropped(), 1);
}

#[test]
fn drafted() {
    let mut tracker = tracker(105, 4, 3);
    tracker.cite(0).unwrap();
    assert!(tracker.held(0));
    assert_eq!(tracker.apply(&put("k3", "v")), Err(Error::Pinned));
    tracker.abandon();
    assert!(!tracker.held(0));
    tracker.apply(&put("k3", "v")).unwrap();
}

#[test]
fn free() {
    let mut tracker = tracker(105, 4, 3);
    assert_eq!(tracker.known(), 0);
    tracker.apply(&put("k3", "v")).unwrap();
    tracker.apply(&put("k4", "v")).unwrap();
    assert_eq!(tracker.table().dropped(), 2);
    assert_eq!(tracker.table().inserted(), 5);
}

#[test]
fn middle() {
    let mut tracker = tracker(105, 4, 3);
    section(&mut tracker, 4, &[1]).unwrap();
    tracker.apply(&put("k3", "v")).unwrap();
    assert_eq!(tracker.table().dropped(), 1);
    assert_eq!(tracker.apply(&put("k4", "v")), Err(Error::Pinned));
    assert_eq!(tracker.table().dropped(), 1);
    assert_eq!(tracker.table().inserted(), 4);
}

#[test]
fn twice() {
    let mut tracker = tracker(105, 4, 3);
    section(&mut tracker, 4, &[0]).unwrap();
    section(&mut tracker, 5, &[0]).unwrap();
    tracker.feedback(Feedback::Acknowledge(4)).unwrap();
    assert_eq!(tracker.apply(&put("k3", "v")), Err(Error::Pinned));
    tracker.feedback(Feedback::Acknowledge(5)).unwrap();
    tracker.apply(&put("k3", "v")).unwrap();
}

#[test]
fn duplicate() {
    let mut tracker = tracker(105, 4, 3);
    section(&mut tracker, 4, &[0]).unwrap();
    assert_eq!(
        tracker.apply(&Instruction::Duplicate(2)),
        Err(Error::Pinned)
    );
    tracker.feedback(Feedback::Acknowledge(4)).unwrap();
    tracker.apply(&Instruction::Duplicate(2)).unwrap();
    assert_eq!(tracker.table().get(3), Some(&field("k0", "v")));
}

#[test]
fn limits() {
    let mut tracker = tracker(105, 4, 1);
    let outcome = tracker.apply(&Instruction::Capacity(106));
    assert_eq!(outcome, Err(Error::Capacity));
    assert_eq!(
        tracker.apply(&put("k", &"x".repeat(100))),
        Err(Error::Oversize)
    );
    assert_eq!(tracker.cite(7), Err(Error::Index));
    assert!(!tracker.held(7));
    assert_eq!(tracker.apply(&Instruction::Duplicate(4)), Err(Error::Index));
}
