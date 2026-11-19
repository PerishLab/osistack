use crate::support::{one, parse};
use h3::Defect;

fn at(content: &str) -> String {
    format!("h3=\"{content}\"")
}

#[test]
fn hosts() {
    for (text, host) in [
        (":443", "www.example.com"),
        ("a.example:443", "a.example"),
        ("A.EXAMPLE:443", "a.example"),
        ("localhost:443", "localhost"),
        ("a-b.c1.example:443", "a-b.c1.example"),
        ("1a.example:443", "1a.example"),
        ("example.1a:443", "example.1a"),
        ("192.0.2.1:443", "192.0.2.1"),
        ("[2001:db8::1]:443", "2001:db8::1"),
        ("[2001:DB8:0:0:0:0:0:1]:443", "2001:db8::1"),
        ("[::1]:443", "::1"),
        ("[::ffff:192.0.2.1]:443", "::ffff:192.0.2.1"),
    ] {
        assert_eq!(one(&at(text)).host, host, "{text}");
    }
}

#[test]
fn hostile() {
    for text in [
        "[::1:443",
        "::1:443",
        "[::1]x:443",
        "[1.2.3.4]:443",
        "[]:443",
        "[:::1]:443",
        "a b:443",
        "a_b:443",
        "-a:443",
        "a-:443",
        "a..b:443",
        ".a:443",
        "a.:443",
        "1.2.3.256:443",
        "1.2.3:443",
        "example.123:443",
        "01.2.3.4:443",
        "a:b:443",
        "*.example:443",
        "a/b:443",
        "a@b:443",
        "a%41:443",
    ] {
        assert_eq!(parse(&at(text)).unwrap_err(), Defect::Host, "{text}");
    }
}

#[test]
fn limits() {
    let label = "a".repeat(63);
    assert_eq!(one(&at(&format!("{label}.example:443"))).host.len(), 71);
    assert_eq!(
        parse(&at(&format!("{}.example:443", "a".repeat(64)))).unwrap_err(),
        Defect::Host
    );
    let fits = format!("{0}.{0}.{0}.{1}", label, "b".repeat(61));
    assert_eq!(fits.len(), 253);
    assert_eq!(one(&at(&format!("{fits}:443"))).host, fits);
    let over = format!("{0}.{0}.{0}.{1}", label, "b".repeat(62));
    assert_eq!(
        parse(&at(&format!("{over}:443"))).unwrap_err(),
        Defect::Host
    );
}

#[test]
fn ports() {
    for (text, port) in [
        (":1", 1),
        (":80", 80),
        (":443", 443),
        (":65535", 65535),
        (":00080", 80),
        (":0443", 443),
        ("a.example:08000", 8000),
    ] {
        assert_eq!(one(&at(text)).port, port, "{text}");
    }
    for text in [
        ":0",
        ":000",
        ":65536",
        ":99999999999999999999",
        ":",
        ":+80",
        ":-1",
        ":8x",
        ":4 4",
        ":0x50",
        "a.example",
        "",
        "443",
        ":80.0",
    ] {
        assert_eq!(parse(&at(text)).unwrap_err(), Defect::Port, "{text:?}");
    }
}

#[test]
fn quoting() {
    assert_eq!(parse("h3=:443").unwrap_err(), Defect::Syntax);
    assert_eq!(parse("h3=\":443").unwrap_err(), Defect::Syntax);
    assert_eq!(parse("h3=':443'").unwrap_err(), Defect::Syntax);
    assert_eq!(parse("h3=\":443\"x").unwrap_err(), Defect::Syntax);
    assert_eq!(parse("h3=\":443\"\"\"").unwrap_err(), Defect::Syntax);
    assert_eq!(parse("h3= \":443\"").unwrap_err(), Defect::Syntax);
    assert_eq!(parse("h3 =\":443\"").unwrap_err(), Defect::Syntax);
    assert_eq!(parse("h3").unwrap_err(), Defect::Syntax);
    assert_eq!(parse("h3=").unwrap_err(), Defect::Syntax);
}
