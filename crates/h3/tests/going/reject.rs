use crate::support::*;
use h3::Going;

#[test]
fn raised() {
    let mut streams = opened(5);
    streams.goaway(8).unwrap();
    assert_eq!(streams.goaway(12), Err(fault()));
    assert_eq!(streams.goaway(1 << 40), Err(fault()));
    assert_eq!(streams.going(), Some(8));
    assert_eq!(streams.active(), vec![0, 4]);
    assert_eq!(streams.open(), Err(Going(8)));
}

#[test]
fn unaligned() {
    for id in [1, 2, 3, 5, 6, 7, 9, 10, (1 << 62) - 1, (1 << 62) - 2] {
        let mut streams = opened(3);
        assert_eq!(streams.goaway(id), Err(fault()), "{id}");
        assert_eq!(streams.going(), None);
        assert_eq!(streams.active(), vec![0, 4, 8]);
        assert_eq!(streams.open(), Ok(12));
    }
}

#[test]
fn aligned() {
    let mut streams = opened(3);
    assert_eq!(streams.goaway((1 << 62) - 4), Ok(vec![]));
    assert_eq!(streams.goaway(8), Ok(vec![8]));
    assert_eq!(streams.goaway(5), Err(fault()));
    assert_eq!(streams.going(), Some(8));
}
