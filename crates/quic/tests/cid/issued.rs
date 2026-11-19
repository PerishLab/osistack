use crate::support::*;
use quic::{Fault, Frame, Issued, Refused};

fn issue(sequence: u64, retire: u64, n: u8) -> Frame {
    Frame::Issue {
        sequence,
        retire,
        cid: cid(n),
        token: token(n),
    }
}

#[test]
fn numbered() {
    let mut issued = Issued::new(cid(0), 4);
    assert_eq!(issued.issue(cid(1), token(1), 0), Ok(issue(1, 0, 1)));
    assert_eq!(issued.issue(cid(2), token(2), 0), Ok(issue(2, 0, 2)));
    assert_eq!(issued.issue(cid(3), token(3), 0), Ok(issue(3, 0, 3)));
    assert_eq!(issued.issue(cid(4), token(4), 0), Err(Refused));
    assert_eq!(issued.live(), vec![0, 1, 2, 3]);
    assert_eq!(issued.active(), 4);
}

#[test]
fn encoded() {
    let mut issued = Issued::new(cid(0), 3);
    let frame = issued.issue(cid(7), token(9), 0).unwrap();
    let bytes = frame.write().unwrap();
    let mut expected = vec![0x18, 0x01, 0x00, 0x08];
    expected.extend([7; 8]);
    expected.extend([9; 16]);
    assert_eq!(bytes, expected);
    assert_eq!(Frame::parse(&bytes), Ok((frame, bytes.len())));
}

#[test]
fn room() {
    let mut issued = Issued::new(cid(0), 2);
    assert_eq!(issued.issue(cid(1), token(1), 0), Ok(issue(1, 0, 1)));
    assert_eq!(issued.issue(cid(2), token(2), 0), Err(Refused));
    assert_eq!(issued.retire(0, &cid(1)), Ok(true));
    assert_eq!(issued.live(), vec![1]);
    assert_eq!(issued.issue(cid(2), token(2), 0), Ok(issue(2, 0, 2)));
    assert_eq!(issued.issue(cid(3), token(3), 0), Err(Refused));
}

#[test]
fn shapes() {
    let mut issued = Issued::new(cid(0), 9);
    assert_eq!(issued.issue(vec![], token(1), 0), Err(Refused));
    assert_eq!(issued.issue(vec![5; 21], token(1), 0), Err(Refused));
    assert_eq!(issued.issue(cid(0), token(1), 0), Err(Refused));
    assert_eq!(issued.live(), vec![0]);
    let long = issued.issue(vec![5; 20], token(1), 0).unwrap();
    assert_eq!(
        long,
        Frame::Issue {
            sequence: 1,
            retire: 0,
            cid: vec![5; 20],
            token: token(1)
        }
    );
    let short = issued.issue(vec![6], token(2), 0).unwrap();
    assert_eq!(
        short,
        Frame::Issue {
            sequence: 2,
            retire: 0,
            cid: vec![6],
            token: token(2)
        }
    );
    assert_eq!(issued.issue(vec![6], token(3), 0), Err(Refused));
    assert_eq!(issued.issue(cid(8), token(8), 0), Ok(issue(3, 0, 8)));
}

#[test]
fn zero() {
    let mut issued = Issued::new(vec![], 8);
    assert_eq!(issued.issue(cid(1), token(1), 0), Err(Refused));
    assert_eq!(issued.retire(0, &[]), Err(Fault::Protocol));
    assert_eq!(issued.retire(1, &[]), Err(Fault::Protocol));
    assert_eq!(issued.retire(0, &cid(1)), Err(Fault::Protocol));
    assert_eq!(issued.live(), vec![0]);
}

#[test]
fn forced() {
    let mut issued = Issued::new(cid(0), 2);
    assert_eq!(issued.issue(cid(1), token(1), 0), Ok(issue(1, 0, 1)));
    assert_eq!(issued.issue(cid(2), token(2), 2), Ok(issue(2, 2, 2)));
    assert_eq!(issued.live(), vec![0, 1, 2]);
    assert_eq!(issued.active(), 1);
    assert_eq!(issued.find(&cid(0)), Some(0));
    assert_eq!(issued.find(&cid(1)), Some(1));
    assert_eq!(issued.issue(cid(3), token(3), 0), Ok(issue(3, 2, 3)));
    assert_eq!(issued.active(), 2);
    assert_eq!(issued.issue(cid(4), token(4), 0), Err(Refused));
    assert_eq!(issued.retire(0, &cid(3)), Ok(true));
    assert_eq!(issued.retire(1, &cid(3)), Ok(true));
    assert_eq!(issued.live(), vec![2, 3]);
}

#[test]
fn clamped() {
    let mut issued = Issued::new(cid(0), 9);
    assert_eq!(issued.issue(cid(1), token(1), 100), Ok(issue(1, 1, 1)));
    assert_eq!(issued.issue(cid(2), token(2), 0), Ok(issue(2, 1, 2)));
    assert_eq!(issued.issue(cid(3), token(3), 3), Ok(issue(3, 3, 3)));
    assert_eq!(issued.issue(cid(4), token(4), u64::MAX), Ok(issue(4, 4, 4)));
    assert_eq!(issued.active(), 1);
}

#[test]
fn retiring() {
    let mut issued = Issued::new(cid(0), 4);
    issued.issue(cid(1), token(1), 0).unwrap();
    assert_eq!(issued.retire(2, &cid(1)), Err(Fault::Protocol));
    assert_eq!(issued.retire(9, &cid(1)), Err(Fault::Protocol));
    assert_eq!(issued.retire(1, &cid(1)), Err(Fault::Protocol));
    assert_eq!(issued.live(), vec![0, 1]);
    assert_eq!(issued.retire(1, &cid(0)), Ok(true));
    assert_eq!(issued.retire(1, &cid(0)), Ok(false));
    assert_eq!(issued.retire(0, &cid(9)), Ok(true));
    assert_eq!(issued.retire(0, &cid(9)), Ok(false));
    assert!(issued.live().is_empty());
}

#[test]
fn found() {
    let mut issued = Issued::new(cid(0), 4);
    issued.issue(cid(1), token(1), 0).unwrap();
    assert_eq!(issued.find(&cid(0)), Some(0));
    assert_eq!(issued.find(&cid(1)), Some(1));
    assert_eq!(issued.find(&cid(2)), None);
    assert_eq!(issued.find(&[]), None);
    issued.retire(0, &cid(1)).unwrap();
    assert_eq!(issued.find(&cid(0)), None);
    assert_eq!(issued.find(&cid(1)), Some(1));
}

#[test]
fn unchanged() {
    let mut issued = Issued::new(cid(0), 2);
    issued.issue(cid(1), token(1), 0).unwrap();
    assert_eq!(issued.issue(cid(2), token(2), 2), Ok(issue(2, 2, 2)));
    let before = (issued.live(), issued.active());
    assert_eq!(issued.issue(vec![], token(3), 0), Err(Refused));
    assert_eq!(issued.issue(cid(2), token(3), 0), Err(Refused));
    assert_eq!((issued.live(), issued.active()), before);
    assert_eq!(issued.retire(5, &cid(9)), Err(Fault::Protocol));
    assert_eq!((issued.live(), issued.active()), before);
    assert_eq!(issued.issue(cid(3), token(3), 0), Ok(issue(3, 2, 3)));
}
