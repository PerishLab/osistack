use h2::{Code, Fault, Frame, Setting, Settings};

fn apply(settings: &mut Settings, pairs: &[(u16, u32)]) -> Result<(), Fault> {
    let Frame::Settings { list, .. } = crate::support::settings(pairs) else {
        unreachable!()
    };
    settings.apply(&list)
}

const PROTOCOL: Fault = Fault::Connection {
    code: Code::Protocol,
};
const FLOW: Fault = Fault::Connection { code: Code::Flow };

#[test]
fn defaults() {
    let base = Settings::default();
    assert_eq!(base.table, 4096);
    assert!(base.push);
    assert_eq!(base.streams, None);
    assert_eq!(base.window, 65_535);
    assert_eq!(base.frame, 16_384);
    assert_eq!(base.header, None);
    assert!(base.list().is_empty());
}

#[test]
fn values() {
    let mut base = Settings::default();
    let all = [
        (1, 0),
        (2, 0),
        (3, 100),
        (4, 1_048_576),
        (5, 32_768),
        (6, 8000),
    ];
    apply(&mut base, &all).unwrap();
    assert_eq!(base.table, 0);
    assert!(!base.push);
    assert_eq!(base.streams, Some(100));
    assert_eq!(base.window, 1_048_576);
    assert_eq!(base.frame, 32_768);
    assert_eq!(base.header, Some(8000));
}

#[test]
fn listing() {
    let mut base = Settings::default();
    apply(&mut base, &[(2, 0), (4, 1000), (3, 0)]).unwrap();
    let expect = vec![
        Setting { id: 2, value: 0 },
        Setting { id: 3, value: 0 },
        Setting { id: 4, value: 1000 },
    ];
    assert_eq!(base.list(), expect);
    let mut again = Settings::default();
    again.apply(&expect).unwrap();
    assert_eq!(again, base);
}

#[test]
fn unknown() {
    let mut base = Settings::default();
    apply(&mut base, &[(0, 5), (7, 9), (0xffff, 1), (3, 4)]).unwrap();
    assert_eq!(base.streams, Some(4));
    assert_eq!(
        Settings {
            streams: None,
            ..base
        },
        Settings::default()
    );
}

#[test]
fn last() {
    let mut base = Settings::default();
    apply(&mut base, &[(4, 10), (4, 20), (3, 1), (3, 2)]).unwrap();
    assert_eq!(base.window, 20);
    assert_eq!(base.streams, Some(2));
}

#[test]
fn bounds() {
    let mut base = Settings::default();
    apply(&mut base, &[(4, 0x7fff_ffff), (5, 16_384)]).unwrap();
    apply(&mut base, &[(5, 0xff_ffff), (4, 0)]).unwrap();
    assert_eq!(base.frame, 16_777_215);
    assert_eq!(base.window, 0);
}

#[test]
fn rejected() {
    let mut base = Settings::default();
    assert_eq!(apply(&mut base, &[(2, 1)]), Err(PROTOCOL));
    assert_eq!(apply(&mut base, &[(2, 2)]), Err(PROTOCOL));
    assert_eq!(apply(&mut base, &[(5, 16_383)]), Err(PROTOCOL));
    assert_eq!(apply(&mut base, &[(5, 0x100_0000)]), Err(PROTOCOL));
    assert_eq!(apply(&mut base, &[(4, 0x8000_0000)]), Err(FLOW));
}

#[test]
fn atomic() {
    let mut base = Settings::default();
    assert_eq!(apply(&mut base, &[(1, 1), (3, 3), (5, 1)]), Err(PROTOCOL));
    assert_eq!(base, Settings::default());
}
