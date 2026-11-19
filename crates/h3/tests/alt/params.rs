use crate::support::{one, parse};
use h3::Defect;

fn with(params: &str) -> String {
    format!("h3=\":443\"; {params}")
}

#[test]
fn default() {
    let found = one("h3=\":443\"");
    assert_eq!(found.age, 86400);
    assert!(!found.persist);
}

#[test]
fn ages() {
    for (text, age) in [
        ("ma=0", 0),
        ("ma=1", 1),
        ("ma=3600", 3600),
        ("ma=\"3600\"", 3600),
        ("ma=007", 7),
        ("ma=2147483647", 2_147_483_647),
        ("ma=2147483648", 2_147_483_648),
        ("ma=2147483649", 2_147_483_648),
        ("ma=4294967296", 2_147_483_648),
        ("ma=99999999999999999999999", 2_147_483_648),
        ("ma=4294967296000000000000", 2_147_483_648),
    ] {
        assert_eq!(one(&with(text)).age, age, "{text}");
    }
}

#[test]
fn faults() {
    for text in [
        "ma=\"\"",
        "ma=x",
        "ma=-1",
        "ma=1.5",
        "ma=+1",
        "ma=\"1 2\"",
        "ma=1e3",
        "ma=0x10",
    ] {
        assert_eq!(parse(&with(text)).unwrap_err(), Defect::Age, "{text}");
    }
    assert_eq!(parse(&with("ma=")).unwrap_err(), Defect::Syntax);
    assert_eq!(parse(&with("ma=1 2")).unwrap_err(), Defect::Syntax);
}

#[test]
fn persist() {
    for (text, held) in [
        ("persist=1", true),
        ("persist=\"1\"", true),
        ("persist=0", false),
        ("persist=2", false),
        ("persist=01", false),
        ("persist=true", false),
        ("persist=\"\"", false),
        ("persist=\"1 \"", false),
    ] {
        assert_eq!(one(&with(text)).persist, held, "{text}");
    }
    assert_eq!(parse(&with("persist=")).unwrap_err(), Defect::Syntax);
}

#[test]
fn repeat() {
    assert_eq!(parse(&with("ma=1; ma=2")).unwrap_err(), Defect::Repeat);
    assert_eq!(parse(&with("ma=1; ma=1")).unwrap_err(), Defect::Repeat);
    assert_eq!(
        parse(&with("persist=1; persist=0")).unwrap_err(),
        Defect::Repeat
    );
    assert_eq!(
        parse(&with("persist=0; persist=0")).unwrap_err(),
        Defect::Repeat
    );
    assert_eq!(
        parse(&with("ma=1; persist=1; ma=1")).unwrap_err(),
        Defect::Repeat
    );
    assert_eq!(
        parse(&with("persist=1; ma=1; persist=1")).unwrap_err(),
        Defect::Repeat
    );
    assert_eq!(parse(&with("ma=1; ma=x")).unwrap_err(), Defect::Age);
    assert_eq!(one(&with("x=1; x=2")).age, 86400);
    let found = crate::support::offer("h3=\":443\"; ma=1, h3=\":444\"; ma=2");
    assert_eq!((found[0].age, found[1].age), (1, 2));
}

#[test]
fn unknown() {
    assert_eq!(one(&with("foo=bar; ma=5")).age, 5);
    assert_eq!(one(&with("ma=5; foo=bar")).age, 5);
    assert_eq!(one(&with("foo=\"quoted, value; with\"; ma=5")).age, 5);
    assert!(one(&with("x-y.z=1; persist=1")).persist);
    assert_eq!(parse(&with("foo=")).unwrap_err(), Defect::Syntax);
    assert_eq!(parse(&with("foo")).unwrap_err(), Defect::Syntax);
    assert_eq!(parse(&with("foo bar=1")).unwrap_err(), Defect::Syntax);
    assert_eq!(parse(&with("foo=a b")).unwrap_err(), Defect::Syntax);
}

#[test]
fn names() {
    let found = one(&with("MA=5; Persist=1; Ma=7"));
    assert_eq!(found.age, 86400);
    assert!(!found.persist);
}

#[test]
fn order() {
    assert_eq!(one(&with("persist=1; ma=5")), one(&with("ma=5; persist=1")));
    assert_eq!(one(&with("persist=1; ma=5")).age, 5);
}

#[test]
fn stray() {
    assert_eq!(parse("h3=\":443\";").unwrap_err(), Defect::Syntax);
    assert_eq!(parse("h3=\":443\"; ").unwrap_err(), Defect::Syntax);
    assert_eq!(parse("h3=\":443\";;ma=1").unwrap_err(), Defect::Syntax);
    assert_eq!(parse("h3=\":443\"; =1").unwrap_err(), Defect::Syntax);
    assert_eq!(parse("h3=\":443\"; ma =1").unwrap_err(), Defect::Syntax);
    assert_eq!(parse("h3=\":443\"; ma= 1").unwrap_err(), Defect::Syntax);
    assert_eq!(parse("h3=\":443\" ma=1").unwrap_err(), Defect::Syntax);
    assert_eq!(parse("h3=\":443\", ;ma=1").unwrap_err(), Defect::Syntax);
    assert_eq!(one("h3=\":443\" ;ma=1").age, 1);
    assert_eq!(one("h3=\":443\"\t;\tma=1").age, 1);
}
