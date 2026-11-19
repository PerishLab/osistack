use crate::support::*;
use h3::Feedback;

#[test]
fn drops() {
    let mut tracker = tracker(350, 2, 3);
    section(&mut tracker, 4, &[0]).unwrap();
    section(&mut tracker, 4, &[1]).unwrap();
    assert_eq!(tracker.blocked(), 1);
    tracker.feedback(Feedback::Cancel(4)).unwrap();
    assert_eq!(tracker.outstanding(4), 0);
    assert!(!tracker.held(0) && !tracker.held(1));
    assert_eq!(tracker.blocked(), 0);
    assert_eq!(tracker.known(), 0);
}

#[test]
fn absent() {
    let mut tracker = tracker(350, 2, 1);
    assert_eq!(tracker.feedback(Feedback::Cancel(9)), Ok(()));
    assert_eq!(tracker.known(), 0);
}

#[test]
fn others() {
    let mut tracker = tracker(350, 2, 3);
    section(&mut tracker, 4, &[0]).unwrap();
    section(&mut tracker, 5, &[1]).unwrap();
    tracker.feedback(Feedback::Cancel(4)).unwrap();
    assert_eq!(tracker.outstanding(5), 1);
    assert!(tracker.held(1) && !tracker.held(0));
    assert_eq!(tracker.blocked(), 1);
}

#[test]
fn unblocks() {
    let mut tracker = tracker(350, 1, 2);
    section(&mut tracker, 4, &[0]).unwrap();
    assert!(!tracker.admits(5));
    tracker.feedback(Feedback::Cancel(4)).unwrap();
    assert!(tracker.admits(5));
    assert_eq!(section(&mut tracker, 5, &[1]), Ok(2));
}

#[test]
fn shared() {
    let mut tracker = tracker(350, 2, 2);
    section(&mut tracker, 4, &[0]).unwrap();
    section(&mut tracker, 5, &[0]).unwrap();
    tracker.feedback(Feedback::Cancel(4)).unwrap();
    assert!(tracker.held(0));
    tracker.feedback(Feedback::Cancel(5)).unwrap();
    assert!(!tracker.held(0));
}
