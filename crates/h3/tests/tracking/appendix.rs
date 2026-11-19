use crate::support::*;
use h3::{Error, Feedback, Instruction, Tracker};
use wire::Huffman;

const FIRST: &str = "3fbd01 c00f 7777772e6578616d706c652e636f6d c10c 2f73616d706c652f70617468";
const CUSTOM: &str = "4a 637573746f6d2d6b6579 0c 637573746f6d2d76616c7565";
const DUPLICATE: &str = "02";
const EVICTING: &str = "810d 637573746f6d2d76616c756532";

fn run(tracker: &mut Tracker, text: &str) -> Result<(), Error> {
    let huffman = Huffman::new();
    let bytes = hex(text);
    let mut used = 0;
    while let Some((instruction, size)) = Instruction::decode(&bytes[used..], &huffman)? {
        tracker.apply(&instruction)?;
        used += size;
    }
    assert_eq!(used, bytes.len());
    Ok(())
}

fn first() -> Tracker {
    let mut tracker = Tracker::new(220, 1);
    run(&mut tracker, FIRST).unwrap();
    assert_eq!(tracker.table().size(), 106);
    tracker.cite(0).unwrap();
    tracker.cite(1).unwrap();
    assert_eq!(tracker.sent(4), Ok(2));
    tracker
}

#[test]
fn replay() {
    let mut tracker = first();
    assert_eq!(tracker.receive(&hex("84")), Ok(1));
    assert_eq!((tracker.known(), tracker.outstanding(4)), (2, 0));
    run(&mut tracker, CUSTOM).unwrap();
    assert_eq!(tracker.table().size(), 160);
    assert_eq!(tracker.receive(&hex("01")), Ok(1));
    assert_eq!(tracker.known(), 3);
    run(&mut tracker, DUPLICATE).unwrap();
    assert_eq!(tracker.table().size(), 217);
    tracker.cite(3).unwrap();
    tracker.cite(2).unwrap();
    assert_eq!(tracker.sent(8), Ok(4));
    assert_eq!(tracker.blocked(), 1);
    run(&mut tracker, EVICTING).unwrap();
    assert_eq!(tracker.table().size(), 215);
    assert_eq!(tracker.table().dropped(), 1);
    assert!(tracker.held(3) && tracker.held(2));
}

#[test]
fn unacknowledged() {
    let mut tracker = first();
    run(&mut tracker, CUSTOM).unwrap();
    assert_eq!(tracker.receive(&hex("01")), Ok(1));
    run(&mut tracker, DUPLICATE).unwrap();
    assert!(tracker.held(0) && tracker.held(1));
    assert_eq!(run(&mut tracker, EVICTING), Err(Error::Pinned));
    assert_eq!(tracker.table().size(), 217);
    assert_eq!(tracker.table().dropped(), 0);
    tracker.feedback(Feedback::Acknowledge(4)).unwrap();
    run(&mut tracker, EVICTING).unwrap();
    assert_eq!(tracker.table().size(), 215);
}
