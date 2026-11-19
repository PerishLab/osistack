use crate::support::*;
use h3::{Error, Feedback};

#[test]
fn ordered() {
    let mut tracker = tracker(350, 4, 4);
    assert_eq!(section(&mut tracker, 4, &[0]), Ok(1));
    assert_eq!(section(&mut tracker, 4, &[1, 2]), Ok(3));
    assert_eq!(tracker.outstanding(4), 2);
    assert_eq!(tracker.known(), 0);
    tracker.feedback(Feedback::Acknowledge(4)).unwrap();
    assert_eq!((tracker.known(), tracker.outstanding(4)), (1, 1));
    tracker.feedback(Feedback::Acknowledge(4)).unwrap();
    assert_eq!((tracker.known(), tracker.outstanding(4)), (3, 0));
    let outcome = tracker.feedback(Feedback::Acknowledge(4));
    assert_eq!(outcome, Err(Error::Feedback));
}

#[test]
fn steady() {
    let mut tracker = tracker(350, 4, 4);
    section(&mut tracker, 1, &[0]).unwrap();
    section(&mut tracker, 2, &[2]).unwrap();
    tracker.feedback(Feedback::Acknowledge(2)).unwrap();
    assert_eq!(tracker.known(), 3);
    tracker.feedback(Feedback::Acknowledge(1)).unwrap();
    assert_eq!(tracker.known(), 3);
}

#[test]
fn plain() {
    let mut tracker = tracker(350, 4, 2);
    assert_eq!(tracker.sent(4), Ok(0));
    assert_eq!(tracker.outstanding(4), 0);
    let outcome = tracker.feedback(Feedback::Acknowledge(4));
    assert_eq!(outcome, Err(Error::Feedback));
}

#[test]
fn unknown() {
    let mut tracker = tracker(350, 1, 2);
    section(&mut tracker, 4, &[1]).unwrap();
    let before = (tracker.known(), tracker.blocked(), tracker.outstanding(4));
    let outcome = tracker.feedback(Feedback::Acknowledge(8));
    assert_eq!(outcome, Err(Error::Feedback));
    let after = (tracker.known(), tracker.blocked(), tracker.outstanding(4));
    assert_eq!(before, after);
    assert!(tracker.held(1));
}

#[test]
fn released() {
    let mut tracker = tracker(350, 4, 2);
    section(&mut tracker, 4, &[0]).unwrap();
    assert!(tracker.held(0));
    tracker.feedback(Feedback::Acknowledge(4)).unwrap();
    assert!(!tracker.held(0));
}
