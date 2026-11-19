use quic::{Choked, Direction, Fault, Lanes, Role};

fn client(open: [u64; 2], admit: [u64; 2]) -> Lanes {
    Lanes::new(Role::Client, open, admit)
}

fn server(open: [u64; 2], admit: [u64; 2]) -> Lanes {
    Lanes::new(Role::Server, open, admit)
}

#[test]
fn numbers() {
    let mut lanes = client([9, 9], [0, 0]);
    let bidi: Vec<u64> = (0..3)
        .map(|_| lanes.open(Direction::Bidi).unwrap())
        .collect();
    let uni: Vec<u64> = (0..3)
        .map(|_| lanes.open(Direction::Uni).unwrap())
        .collect();
    assert_eq!((bidi, uni), (vec![0, 4, 8], vec![2, 6, 10]));
    let mut lanes = server([9, 9], [0, 0]);
    let uni: Vec<u64> = (0..2)
        .map(|_| lanes.open(Direction::Uni).unwrap())
        .collect();
    assert_eq!(uni, vec![3, 7]);
    assert_eq!(lanes.open(Direction::Bidi), Ok(1));
    assert_eq!(lanes.open(Direction::Bidi), Ok(5));
    assert_eq!(lanes.open(Direction::Uni), Ok(11));
}

#[test]
fn choked() {
    let mut lanes = client([2, 1], [0, 0]);
    assert_eq!(lanes.open(Direction::Bidi), Ok(0));
    assert_eq!(lanes.open(Direction::Bidi), Ok(4));
    assert_eq!(lanes.open(Direction::Bidi), Err(Choked(2)));
    assert_eq!(lanes.open(Direction::Uni), Ok(2));
    assert_eq!(lanes.open(Direction::Uni), Err(Choked(1)));
    assert!(!lanes.raise(Direction::Bidi, 2));
    assert!(!lanes.raise(Direction::Bidi, 1));
    assert_eq!(lanes.open(Direction::Bidi), Err(Choked(2)));
    assert!(lanes.raise(Direction::Bidi, 3));
    assert_eq!(lanes.open(Direction::Bidi), Ok(8));
    assert_eq!(lanes.open(Direction::Bidi), Err(Choked(3)));
    assert_eq!(lanes.open(Direction::Uni), Err(Choked(1)));
}

#[test]
fn stalled() {
    let mut lanes = client([1, 0], [0, 0]);
    assert_eq!(lanes.stalled(Direction::Bidi), None);
    assert_eq!(lanes.stalled(Direction::Uni), Some(0));
    assert_eq!(lanes.stalled(Direction::Uni), None);
    lanes.open(Direction::Bidi).unwrap();
    assert_eq!(lanes.stalled(Direction::Bidi), Some(1));
    assert_eq!(lanes.stalled(Direction::Bidi), None);
    assert!(lanes.raise(Direction::Bidi, 2));
    assert_eq!(lanes.stalled(Direction::Bidi), None);
    lanes.open(Direction::Bidi).unwrap();
    assert_eq!(lanes.stalled(Direction::Bidi), Some(2));
}

#[test]
fn implicit() {
    let mut lanes = server([0, 0], [10, 10]);
    assert_eq!(lanes.admit(8), Ok(vec![0, 4, 8]));
    assert_eq!(lanes.admit(4), Ok(vec![]));
    assert_eq!(lanes.admit(8), Ok(vec![]));
    assert_eq!(lanes.admit(12), Ok(vec![12]));
    assert_eq!(lanes.admit(10), Ok(vec![2, 6, 10]));
    assert_eq!(lanes.admit(14), Ok(vec![14]));
    assert_eq!(lanes.admit(0), Ok(vec![]));
}

#[test]
fn limited() {
    let mut lanes = server([0, 0], [2, 1]);
    assert_eq!(lanes.admit(4), Ok(vec![0, 4]));
    assert_eq!(lanes.admit(8), Err(Fault::Limit));
    assert_eq!(lanes.admit(0), Ok(vec![]));
    assert_eq!(lanes.admit(2), Ok(vec![2]));
    assert_eq!(lanes.admit(6), Err(Fault::Limit));
    assert_eq!(lanes.admit(1 << 40), Err(Fault::Limit));
    let mut none = server([0, 0], [0, 0]);
    assert_eq!(none.admit(0), Err(Fault::Limit));
    assert_eq!(none.admit(2), Err(Fault::Limit));
}

#[test]
fn ours() {
    let mut lanes = client([2, 1], [2, 2]);
    assert_eq!(lanes.admit(0), Err(Fault::State));
    assert_eq!(lanes.open(Direction::Bidi), Ok(0));
    assert_eq!(lanes.admit(0), Ok(vec![]));
    assert_eq!(lanes.admit(4), Err(Fault::State));
    assert_eq!(lanes.admit(2), Err(Fault::State));
    assert_eq!(lanes.open(Direction::Uni), Ok(2));
    assert_eq!(lanes.admit(2), Err(Fault::State));
    assert_eq!(lanes.admit(6), Err(Fault::State));
    assert_eq!(lanes.admit(1), Ok(vec![1]));
    assert_eq!(lanes.admit(3), Ok(vec![3]));
}

#[test]
fn closing() {
    let mut lanes = server([4, 4], [4, 4]);
    assert_eq!(lanes.admit(12), Ok(vec![0, 4, 8, 12]));
    lanes.close(0);
    assert_eq!(lanes.grant(Direction::Bidi), None);
    lanes.close(4);
    assert_eq!(lanes.grant(Direction::Bidi), Some(6));
    assert_eq!(lanes.grant(Direction::Bidi), None);
    assert_eq!(lanes.grant(Direction::Uni), None);
    assert_eq!(lanes.admit(20), Ok(vec![16, 20]));
    assert_eq!(lanes.admit(24), Err(Fault::Limit));
}

#[test]
fn kinds() {
    let mut lanes = server([4, 4], [4, 4]);
    assert_eq!(lanes.admit(6), Ok(vec![2, 6]));
    lanes.close(2);
    lanes.close(6);
    assert_eq!(lanes.grant(Direction::Bidi), None);
    assert_eq!(lanes.grant(Direction::Uni), Some(6));
}

#[test]
fn own() {
    let mut lanes = server([4, 4], [4, 4]);
    let first = lanes.open(Direction::Bidi).unwrap();
    let second = lanes.open(Direction::Uni).unwrap();
    assert_eq!((first, second), (1, 3));
    lanes.admit(12).unwrap();
    lanes.close(first);
    lanes.close(second);
    lanes.close(0);
    assert_eq!(lanes.grant(Direction::Bidi), None);
    assert_eq!(lanes.grant(Direction::Uni), None);
    lanes.close(4);
    assert_eq!(lanes.grant(Direction::Bidi), Some(6));
}
