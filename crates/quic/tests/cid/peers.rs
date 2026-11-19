use crate::support::*;
use quic::{Fault, Peers};

fn started(limit: u64) -> Peers {
    Peers::new(cid(0), Some(token(0)), limit)
}

fn give(peers: &mut Peers, sequence: u64, retire: u64) -> Result<Vec<u64>, Fault> {
    let n = sequence as u8;
    peers.receive(sequence, retire, &cid(n), token(n))
}

#[test]
fn ordered() {
    let mut peers = started(4);
    assert_eq!(peers.live(), vec![0]);
    assert_eq!(give(&mut peers, 1, 0), Ok(vec![]));
    assert_eq!(give(&mut peers, 2, 0), Ok(vec![]));
    assert_eq!(give(&mut peers, 3, 0), Ok(vec![]));
    assert_eq!((peers.live(), peers.active()), (vec![0, 1, 2, 3], 4));
    assert_eq!(give(&mut peers, 4, 0), Err(Fault::Ids));
    assert_eq!((peers.live(), peers.active()), (vec![0, 1, 2, 3], 4));
}

#[test]
fn shuffled() {
    let mut peers = started(4);
    assert_eq!(give(&mut peers, 3, 0), Ok(vec![]));
    assert_eq!(give(&mut peers, 1, 0), Ok(vec![]));
    assert_eq!(give(&mut peers, 2, 0), Ok(vec![]));
    assert_eq!(peers.live(), vec![0, 1, 2, 3]);
}

#[test]
fn repeated() {
    let mut peers = started(4);
    assert_eq!(give(&mut peers, 1, 0), Ok(vec![]));
    assert_eq!(give(&mut peers, 1, 0), Ok(vec![]));
    assert_eq!(peers.active(), 2);
    assert_eq!(give(&mut peers, 1, 1), Ok(vec![0]));
    assert_eq!(peers.live(), vec![1]);
    assert_eq!(peers.current(), (1, cid(1).as_slice()));
    assert_eq!(give(&mut peers, 1, 1), Ok(vec![]));
}

#[test]
fn conflicts() {
    let mut peers = started(4);
    give(&mut peers, 1, 0).unwrap();
    let wrong = [
        peers.receive(1, 0, &cid(9), token(1)),
        peers.receive(1, 0, &cid(1), token(9)),
        peers.receive(2, 0, &cid(1), token(1)),
        peers.receive(2, 0, &cid(0), token(2)),
        peers.receive(0, 0, &cid(0), token(9)),
    ];
    assert_eq!(wrong, vec![Err(Fault::Protocol); 5].as_slice());
    assert_eq!(peers.live(), vec![0, 1]);
    assert_eq!(give(&mut peers, 2, 0), Ok(vec![]));
}

#[test]
fn encoding() {
    let mut peers = started(4);
    assert_eq!(peers.receive(1, 2, &cid(1), token(1)), Err(Fault::Encoding));
    assert_eq!(peers.receive(1, 0, &[], token(1)), Err(Fault::Encoding));
    assert_eq!(
        peers.receive(1, 0, &[1; 21], token(1)),
        Err(Fault::Encoding)
    );
    assert_eq!(peers.live(), vec![0]);
    assert_eq!(peers.receive(1, 0, &[1; 20], token(1)), Ok(vec![]));
    assert_eq!(peers.receive(2, 0, &[2], token(2)), Ok(vec![]));
    assert_eq!(peers.live(), vec![0, 1, 2]);
}

#[test]
fn zero() {
    let mut peers = Peers::new(vec![], None, 4);
    assert_eq!(give(&mut peers, 1, 0), Err(Fault::Protocol));
    assert_eq!(peers.live(), vec![0]);
    assert_eq!(peers.current(), (0, [].as_slice()));
}

#[test]
fn prior() {
    let mut peers = started(4);
    give(&mut peers, 1, 0).unwrap();
    give(&mut peers, 2, 0).unwrap();
    assert_eq!(peers.current().0, 0);
    assert_eq!(give(&mut peers, 3, 2), Ok(vec![0, 1]));
    assert_eq!(peers.live(), vec![2, 3]);
    assert_eq!(peers.current(), (2, cid(2).as_slice()));
    assert_eq!(give(&mut peers, 4, 1), Ok(vec![]));
    assert_eq!(peers.live(), vec![2, 3, 4]);
    assert_eq!(give(&mut peers, 5, 5), Ok(vec![2, 3, 4]));
    assert_eq!(peers.live(), vec![5]);
    assert_eq!(peers.current().0, 5);
}

#[test]
fn late() {
    let mut peers = started(4);
    assert_eq!(give(&mut peers, 5, 5), Ok(vec![0]));
    assert_eq!(peers.live(), vec![5]);
    assert_eq!(give(&mut peers, 2, 0), Ok(vec![2]));
    assert_eq!(give(&mut peers, 2, 0), Ok(vec![]));
    assert_eq!(give(&mut peers, 3, 0), Ok(vec![3]));
    assert_eq!(peers.live(), vec![5]);
    assert_eq!(give(&mut peers, 5, 5), Ok(vec![]));
}

#[test]
fn replaced() {
    let mut peers = started(2);
    assert_eq!(give(&mut peers, 1, 0), Ok(vec![]));
    assert_eq!(give(&mut peers, 2, 0), Err(Fault::Ids));
    assert_eq!(peers.live(), vec![0, 1]);
    assert_eq!(give(&mut peers, 2, 2), Ok(vec![0, 1]));
    assert_eq!(peers.live(), vec![2]);
    assert_eq!(peers.current().0, 2);
}

#[test]
fn rotated() {
    let mut peers = started(4);
    assert_eq!(peers.current(), (0, cid(0).as_slice()));
    assert_eq!(peers.fresh(), None);
    assert_eq!(peers.rotate(), None);
    give(&mut peers, 1, 0).unwrap();
    give(&mut peers, 2, 0).unwrap();
    assert_eq!(peers.rotate(), Some(0));
    assert_eq!(peers.current(), (1, cid(1).as_slice()));
    assert_eq!(peers.live(), vec![1, 2]);
    assert_eq!(peers.rotate(), Some(1));
    assert_eq!(peers.current().0, 2);
    assert_eq!(peers.rotate(), None);
    assert_eq!((peers.current().0, peers.live()), (2, vec![2]));
}

#[test]
fn fresh() {
    let mut peers = started(4);
    give(&mut peers, 1, 0).unwrap();
    give(&mut peers, 2, 0).unwrap();
    assert_eq!(peers.fresh(), Some((1, cid(1))));
    assert_eq!(peers.fresh(), Some((2, cid(2))));
    assert_eq!(peers.fresh(), None);
    assert_eq!(peers.current().0, 0);
    assert_eq!(peers.live(), vec![0, 1, 2]);
    assert_eq!(peers.rotate(), None);
}

#[test]
fn released() {
    let mut peers = started(4);
    give(&mut peers, 1, 0).unwrap();
    give(&mut peers, 2, 0).unwrap();
    assert!(!peers.release(0));
    assert!(peers.release(1));
    assert!(!peers.release(1));
    assert!(!peers.release(9));
    assert_eq!(peers.live(), vec![0, 2]);
    assert_eq!(give(&mut peers, 1, 0), Ok(vec![]));
    assert_eq!(peers.live(), vec![0, 2]);
}

#[test]
fn matched() {
    let mut peers = started(4);
    assert!(peers.matches(&token(0)));
    assert!(!peers.matches(&token(1)));
    give(&mut peers, 1, 0).unwrap();
    assert!(peers.matches(&token(1)));
    give(&mut peers, 2, 1).unwrap();
    assert!(!peers.matches(&token(0)));
    assert!(peers.matches(&token(2)));
    assert!(peers.release(2));
    assert!(!peers.matches(&token(2)));
    assert!(peers.matches(&token(1)));
    let none = Peers::new(cid(0), None, 4);
    assert!(!none.matches(&[0; 16]));
}

#[test]
fn emptied() {
    let mut peers = started(4);
    give(&mut peers, 1, 0).unwrap();
    assert!(peers.release(1));
    assert_eq!(give(&mut peers, 1, 1), Err(Fault::Protocol));
    assert_eq!(peers.live(), vec![0]);
    assert_eq!(peers.current(), (0, cid(0).as_slice()));
    assert_eq!(give(&mut peers, 2, 2), Ok(vec![0]));
    assert_eq!(peers.live(), vec![2]);
}
