use crate::support::{offer, parse};
use h3::Defect;

#[test]
fn empty() {
    for text in ["", " ", "\t", ",", " , ,", ",,,", " \t , \t "] {
        assert_eq!(parse(text).unwrap_err(), Defect::Empty, "{text:?}");
    }
}

#[test]
fn limit() {
    let prefix = "h3=\":443\"; x=";
    let fits = format!("{prefix}{}", "a".repeat(8192 - prefix.len()));
    assert_eq!(fits.len(), 8192);
    assert_eq!(offer(&fits).len(), 1);
    let over = format!("{prefix}{}", "a".repeat(8193 - prefix.len()));
    assert_eq!(parse(&over).unwrap_err(), Defect::Large);
    assert_eq!(parse(&"x".repeat(100_000)).unwrap_err(), Defect::Large);
}

#[test]
fn bytes() {
    for text in [
        "h3=\":443\"\n",
        "h3=\":443\"\r\n",
        "h3=\":443\"; x=\u{e9}",
        "h3=\":4\u{e9}43\"",
        "h3=\":443\"; x=\"\u{1}\"",
        "h3=\":443\"\u{7f}",
        "h3=\":443\"; x=\"\u{7f}\"",
        "h3=\":443\"\0",
        "h3=\":443\"; x=\"\u{1f600}\"",
    ] {
        assert_eq!(parse(text).unwrap_err(), Defect::Syntax, "{text:?}");
    }
    assert_eq!(offer("h3=\":443\"\t").len(), 1);
    assert_eq!(offer("h3=\":443\"; x=\"a\tb\"").len(), 1);
}

#[test]
fn blanks() {
    for text in [
        "h3 =\":443\"",
        "h3= \":443\"",
        "h3 = \":443\"",
        "h3=\":443\"; ma = 1",
        "h3=\":443\" ; ma =1",
        "h3=\":443\" h3=\":444\"",
        "h3=\":443\" \"\"",
        "h 3=\":443\"",
    ] {
        assert_eq!(parse(text).unwrap_err(), Defect::Syntax, "{text}");
    }
    assert_eq!(offer(" \t h3=\":443\" \t ; \t ma=1 \t ").len(), 1);
}

#[test]
fn first() {
    assert_eq!(parse("h3=\":443\", junk").unwrap_err(), Defect::Syntax);
    assert_eq!(parse("junk, h3=\":443\"").unwrap_err(), Defect::Syntax);
    assert_eq!(parse("h3=\":443\", h3=\":0\"").unwrap_err(), Defect::Port);
    assert_eq!(parse("h3=\":0\", h3=\":x\"").unwrap_err(), Defect::Port);
    assert_eq!(parse("h3=\":x\", h3=\"-:1\"").unwrap_err(), Defect::Port);
    assert_eq!(parse("h3=\"-:1\", h3=\":x\"").unwrap_err(), Defect::Host);
    assert_eq!(parse("h%32=\":1\", h3=\":x\"").unwrap_err(), Defect::Escape);
    assert_eq!(
        parse("h3=\":1\"; ma=x, h3=\":x\"").unwrap_err(),
        Defect::Age
    );
}
