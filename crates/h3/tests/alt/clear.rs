use crate::support::{offer, parse};
use h3::{Defect, Directive};

#[test]
fn alone() {
    for text in [
        "clear",
        " clear ",
        "\tclear\t",
        "clear,",
        ",clear",
        " , clear , ",
    ] {
        assert_eq!(parse(text), Ok(Directive::Clear), "{text:?}");
    }
}

#[test]
fn case() {
    for text in ["Clear", "CLEAR", "cleaR"] {
        assert_eq!(parse(text).unwrap_err(), Defect::Syntax, "{text}");
    }
}

#[test]
fn mixed() {
    for text in [
        "h3=\":443\", clear",
        "clear, h3=\":443\"",
        "clear, junk(",
        "junk(, clear",
        "h3=\":0\", clear",
        "clear, h3=\"x",
        "h3=\":443\", clear, h3=\":444\"",
    ] {
        assert_eq!(parse(text), Ok(Directive::Clear), "{text}");
    }
}

#[test]
fn other() {
    assert_eq!(parse("clear;ma=1").unwrap_err(), Defect::Syntax);
    assert_eq!(parse("\"clear\"").unwrap_err(), Defect::Syntax);
    assert_eq!(parse("clear x").unwrap_err(), Defect::Syntax);
    assert_eq!(parse("clearr").unwrap_err(), Defect::Syntax);
    let found = offer("clear=\":443\"");
    assert_eq!(found[0].protocol, b"clear");
    let found = offer("h3=\":443\"; x=\"clear\"");
    assert_eq!(found.len(), 1);
    let found = offer("h3=\":443\"; clear=1");
    assert_eq!(found.len(), 1);
}
