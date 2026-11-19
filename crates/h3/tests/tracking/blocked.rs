use crate::support::*;
use h3::{Error, Feedback};

#[test]
fn limit() {
    let mut tracker = tracker(350, 1, 3);
    assert_eq!(section(&mut tracker, 4, &[0]), Ok(1));
    assert_eq!(tracker.blocked(), 1);
    assert_eq!(section(&mut tracker, 8, &[1]), Err(Error::Blocked));
    assert_eq!(tracker.outstanding(8), 0);
    assert!(!tracker.held(1));
    assert_eq!(tracker.blocked(), 1);
}

#[test]
fn same() {
    let mut tracker = tracker(350, 1, 3);
    section(&mut tracker, 4, &[0]).unwrap();
    assert_eq!(section(&mut tracker, 4, &[2]), Ok(3));
    assert_eq!(tracker.outstanding(4), 2);
    assert_eq!(tracker.blocked(), 1);
}

#[test]
fn known() {
    let mut tracker = tracker(350, 1, 3);
    section(&mut tracker, 4, &[2]).unwrap();
    tracker.feedback(Feedback::Increment(2)).unwrap();
    assert_eq!(section(&mut tracker, 8, &[1]), Ok(2));
    assert_eq!(tracker.blocked(), 1);
    assert_eq!(section(&mut tracker, 9, &[0, 1]), Ok(2));
}

#[test]
fn nothing() {
    let mut tracker = tracker(350, 0, 3);
    assert_eq!(section(&mut tracker, 4, &[0]), Err(Error::Blocked));
    assert!(!tracker.admits(4));
    tracker.feedback(Feedback::Increment(1)).unwrap();
    assert_eq!(section(&mut tracker, 4, &[0]), Ok(1));
    assert_eq!(section(&mut tracker, 4, &[1]), Err(Error::Blocked));
    assert_eq!(tracker.blocked(), 0);
}

#[test]
fn admits() {
    let mut tracker = tracker(350, 1, 3);
    assert!(tracker.admits(4) && tracker.admits(8));
    section(&mut tracker, 4, &[0]).unwrap();
    assert!(tracker.admits(4));
    assert!(!tracker.admits(8));
    tracker.feedback(Feedback::Acknowledge(4)).unwrap();
    assert_eq!(tracker.blocked(), 0);
    assert!(tracker.admits(8));
    assert_eq!(section(&mut tracker, 8, &[2]), Ok(3));
}

#[test]
fn counted() {
    let mut tracker = tracker(350, 3, 4);
    section(&mut tracker, 4, &[0]).unwrap();
    section(&mut tracker, 4, &[1]).unwrap();
    section(&mut tracker, 8, &[2]).unwrap();
    assert_eq!(tracker.blocked(), 2);
    tracker.feedback(Feedback::Acknowledge(4)).unwrap();
    assert_eq!(tracker.blocked(), 2);
    tracker.feedback(Feedback::Acknowledge(4)).unwrap();
    assert_eq!(tracker.blocked(), 1);
    tracker.feedback(Feedback::Acknowledge(8)).unwrap();
    assert_eq!(tracker.blocked(), 0);
}
