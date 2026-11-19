use crate::support::{Dice, payload};
use quic::Receiving;

#[test]
fn first() {
    let mut receiving = Receiving::new(100);
    receiving.data(0, b"aaaa", false).unwrap();
    assert_eq!(receiving.data(2, b"bbbb", false), Ok(2));
    assert_eq!(receiving.read(100), b"aaaabb");
}

#[test]
fn cover() {
    let mut receiving = Receiving::new(100);
    receiving.data(2, b"bb", false).unwrap();
    assert_eq!(receiving.data(0, b"aaaaaa", false), Ok(2));
    assert_eq!(receiving.readable(), 6);
    assert_eq!(receiving.read(100), b"aabbaa");
}

#[test]
fn trim() {
    let mut receiving = Receiving::new(100);
    receiving.data(0, b"abcdef", false).unwrap();
    assert_eq!(receiving.read(3), b"abc");
    assert_eq!(receiving.data(1, b"XXXXXXXX", false), Ok(3));
    assert_eq!(receiving.read(100), b"defXXX");
}

#[test]
fn join() {
    let mut receiving = Receiving::new(100);
    receiving.data(0, b"ab", false).unwrap();
    receiving.data(4, b"ef", false).unwrap();
    receiving.data(2, b"cd", false).unwrap();
    assert_eq!(receiving.readable(), 6);
    assert_eq!(receiving.read(3), b"abc");
    assert_eq!(receiving.read(10), b"def");
}

#[test]
fn gaps() {
    let mut receiving = Receiving::new(100);
    receiving.data(10, b"klmno", false).unwrap();
    receiving.data(0, b"abcde", false).unwrap();
    assert_eq!(receiving.readable(), 5);
    assert_eq!(receiving.read(100), b"abcde");
    assert_eq!(receiving.readable(), 0);
    receiving.data(5, b"fghij", false).unwrap();
    assert_eq!(receiving.readable(), 10);
    assert_eq!(receiving.read(100), b"fghijklmno");
}

#[test]
fn reverse() {
    let mut receiving = Receiving::new(100);
    for at in (0..5).rev() {
        receiving
            .data(at * 2, &[b'a' + at as u8; 2], false)
            .unwrap();
    }
    assert_eq!(receiving.read(100), b"aabbccddee");
}

#[test]
fn sweep() {
    for seed in 1..=64 {
        let mut dice = Dice::new(seed);
        let size = dice.within(1, 3000);
        let whole = payload(size as usize, seed);
        let mut receiving = Receiving::new(size);
        let mut sum = 0;
        let mut out = Vec::new();
        for _ in 0..400 {
            let from = dice.below(size);
            let to = (from + dice.within(0, 200)).min(size);
            let fin = to == size && dice.below(2) == 0;
            sum += receiving
                .data(from, &whole[from as usize..to as usize], fin)
                .unwrap();
            assert_eq!(sum, receiving.highest(), "seed {seed}");
            if dice.below(3) == 0 {
                let want = dice.below(300) as usize;
                let got = receiving.read(want);
                assert!(got.len() <= want);
                out.extend(got);
            }
            assert_eq!(&out[..], &whole[..out.len()], "seed {seed}");
        }
        receiving.data(0, &whole, true).unwrap();
        out.extend(receiving.read(size as usize));
        assert_eq!(out, whole, "seed {seed}");
        assert_eq!(receiving.readable(), 0);
    }
}

#[test]
fn again() {
    let mut receiving = Receiving::new(100);
    receiving.data(5, b"fghij", false).unwrap();
    receiving.data(0, b"abcde", false).unwrap();
    assert_eq!(receiving.data(0, b"abcde", false), Ok(0));
    assert_eq!(receiving.readable(), 10);
    assert_eq!(receiving.read(100), b"abcdefghij");
}
