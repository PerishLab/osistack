use crate::support::{one, parse};
use h3::Defect;

fn with(protocol: &str) -> String {
    format!("{protocol}=\":443\"")
}

#[test]
fn plain() {
    assert_eq!(one(&with("h2")).protocol, b"h2");
    assert_eq!(one(&with("h3")).protocol, b"h3");
    assert_eq!(one(&with("h3-29")).protocol, b"h3-29");
    assert_eq!(one(&with("H3")).protocol, b"H3");
    let every = "a!#$&'*+-.^_`|~b";
    assert_eq!(one(&with(every)).protocol, every.as_bytes());
}

#[test]
fn escaped() {
    assert_eq!(one(&with("w%3Dx%3Ay#z")).protocol, b"w=x:y#z");
    assert_eq!(one(&with("x%25y")).protocol, b"x%y");
    assert_eq!(one(&with("http%2F1.1")).protocol, b"http/1.1");
    assert_eq!(one(&with("%25%25")).protocol, b"%%");
}

#[test]
fn octets() {
    assert_eq!(one(&with("%00%FF")).protocol, [0, 255]);
    assert_eq!(one(&with("%20%22%2C%3B")).protocol, b" \",;");
    assert_eq!(one(&with("a%7Fb")).protocol, b"a\x7fb");
    assert_eq!(one(&with("%80%FE")).protocol, [0x80, 0xfe]);
}

#[test]
fn reject() {
    for text in [
        "h%32", "%41", "%3dx", "x%3", "x%", "x%zz", "x%G0", "%%41", "x%2", "%7e", "%2D",
    ] {
        assert_eq!(parse(&with(text)).unwrap_err(), Defect::Escape, "{text}");
    }
}

#[test]
fn nothing() {
    assert_eq!(parse("=\":443\"").unwrap_err(), Defect::Syntax);
    assert_eq!(parse(" =\":443\"").unwrap_err(), Defect::Syntax);
    for text in ["h 3", "h(3", "h3:", "h/3", "h\"3", "h@3", "h,3"] {
        assert_eq!(parse(&with(text)).unwrap_err(), Defect::Syntax, "{text}");
    }
    assert_eq!(parse("h(3=\":443\"").unwrap_err(), Defect::Syntax);
    assert_eq!(parse("h 3=\":443\"").unwrap_err(), Defect::Syntax);
}
