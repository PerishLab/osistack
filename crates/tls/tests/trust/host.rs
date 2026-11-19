use tls::x509::General;
use tls::x509::trust::{Host, Refusal, matches};

fn dns(text: &str) -> General {
    General::Dns(text.to_string())
}

fn name(text: &str) -> Host {
    Host::parse(text).unwrap()
}

fn seen(presented: &str, reference: &str) -> bool {
    matches(&[dns(presented)], &name(reference))
}

#[test]
fn parse() {
    assert_eq!(
        Host::parse("Example.COM"),
        Ok(Host::Dns("example.com".into()))
    );
    assert_eq!(
        Host::parse("example.com."),
        Ok(Host::Dns("example.com".into()))
    );
    assert_eq!(Host::parse("localhost"), Ok(Host::Dns("localhost".into())));
    assert_eq!(
        Host::parse("a-b.c1.example"),
        Ok(Host::Dns("a-b.c1.example".into()))
    );
    assert_eq!(
        Host::parse("xn--bcher-kva.example"),
        Ok(Host::Dns("xn--bcher-kva.example".into()))
    );
    assert_eq!(
        Host::parse("1a.example"),
        Ok(Host::Dns("1a.example".into()))
    );
    assert_eq!(
        Host::parse("example.1a"),
        Ok(Host::Dns("example.1a".into()))
    );
}

#[test]
fn address() {
    assert_eq!(Host::parse("192.0.2.1"), Ok(Host::Ip(vec![192, 0, 2, 1])));
    assert_eq!(Host::parse("0.0.0.0"), Ok(Host::Ip(vec![0; 4])));
    let mut loopback = vec![0; 15];
    loopback.push(1);
    assert_eq!(Host::parse("::1"), Ok(Host::Ip(loopback)));
    let documentation = Host::parse("2001:db8::1").unwrap();
    let Host::Ip(octets) = documentation else {
        panic!("not an address");
    };
    assert_eq!(octets.len(), 16);
    assert_eq!(&octets[..4], &[0x20, 0x01, 0x0d, 0xb8]);
    assert_eq!(octets[15], 1);
    let mapped = Host::parse("::ffff:192.0.2.1").unwrap();
    assert_eq!(
        mapped,
        Host::Ip(vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192, 0, 2, 1])
    );
}

#[test]
fn refuse() {
    let long = "a".repeat(64);
    let wide = format!("{}.example.com", long);
    let many = format!("{0}.{0}.{0}.{1}.com", "a".repeat(63), "b".repeat(61));
    for text in [
        "",
        " 127.0.0.1",
        "127.0.0.1 ",
        " ::1",
        ".",
        "..",
        "a..b",
        ".a.com",
        "-a.com",
        "a-.com",
        "*.example.com",
        "ex*.com",
        "exa mple.com",
        "ex_ample.com",
        "b\u{fc}cher.example",
        "1.2.3.256",
        "256.256.256.256",
        "1.2.3",
        "example.123",
        "[::1]",
        "fe80::1%eth0",
        "example.com..",
        "1.2.3.4.",
        &wide,
        &many,
    ] {
        assert_eq!(Host::parse(text), Err(Refusal::Host), "{text}");
    }
}

#[test]
fn limits() {
    let label = "a".repeat(63);
    assert!(Host::parse(&format!("{label}.example")).is_ok());
    let fits = format!("{0}.{0}.{0}.{1}", label, "b".repeat(61));
    assert_eq!(fits.len(), 253);
    assert!(Host::parse(&fits).is_ok());
    let over = format!("{0}.{0}.{0}.{1}", label, "b".repeat(62));
    assert_eq!(over.len(), 254);
    assert_eq!(Host::parse(&over), Err(Refusal::Host));
}

#[test]
fn exact() {
    assert!(seen("example.com", "example.com"));
    assert!(seen("EXAMPLE.com", "example.com"));
    assert!(seen("example.com", "Example.COM"));
    assert!(seen("www.example.com", "www.example.com"));
    assert!(!seen("example.org", "example.com"));
    assert!(!seen("www.example.com", "example.com"));
    assert!(!seen("example.com", "www.example.com"));
    assert!(!seen("xexample.com", "example.com"));
    assert!(!seen("example.comx", "example.com"));
    assert!(!seen("example.com.", "example.com"));
    assert!(!seen("", "example.com"));
}

#[test]
fn wild() {
    assert!(seen("*.example.com", "www.example.com"));
    assert!(seen("*.EXAMPLE.com", "www.example.com"));
    assert!(seen("*.example.com", "a.example.com"));
    assert!(!seen("*.example.com", "example.com"));
    assert!(!seen("*.example.com", "a.b.example.com"));
    assert!(!seen("*.example.com", "www.example.org"));
    assert!(!seen("*.example.com", "wwwexample.com"));
    assert!(!seen("*.example.com", "www.xexample.com"));
}

#[test]
fn partial() {
    for presented in [
        "f*.example.com",
        "*w.example.com",
        "w*w.example.com",
        "xn--*.example.com",
        "www.*.com",
        "*.*.example.com",
        "**.example.com",
        "*",
        "*.example.*",
        "www.*",
    ] {
        for reference in [
            "foo.example.com",
            "www.example.com",
            "www.com",
            "example.com",
        ] {
            assert!(!seen(presented, reference), "{presented} {reference}");
        }
    }
}

#[test]
fn suffix() {
    assert!(!seen("*.com", "example.com"));
    assert!(!seen("*.", "example.com"));
    assert!(!seen("*.com", "com"));
    assert!(seen("*.co.uk", "example.co.uk"));
    assert!(seen("*.example.com", "www.example.com"));
}

#[test]
fn blanks() {
    for presented in [
        "*..example.com",
        "*.example..com",
        "*.example.com.",
        "*.example.com..",
        "*..",
    ] {
        assert!(!seen(presented, "www.example.com"), "{presented}");
        assert!(!seen(presented, "a.example.com"), "{presented}");
    }
}

#[test]
fn octets() {
    let host = name("192.0.2.1");
    assert!(matches(&[General::Ip(vec![192, 0, 2, 1])], &host));
    assert!(!matches(&[General::Ip(vec![192, 0, 2, 2])], &host));
    assert!(!matches(&[General::Ip(vec![192, 0, 2])], &host));
    assert!(!matches(
        &[General::Ip(vec![192, 0, 2, 1, 255, 255, 255, 0])],
        &host
    ));
    let mapped = name("::ffff:192.0.2.1");
    assert!(!matches(&[General::Ip(vec![192, 0, 2, 1])], &mapped));
    assert!(matches(&[General::Ip(ffff())], &mapped));
    assert!(!matches(&[General::Ip(ffff())], &host));
    let wide = name("2001:db8::1");
    let mut full = vec![0x20, 0x01, 0x0d, 0xb8];
    full.extend([0; 11]);
    full.push(1);
    assert!(matches(&[General::Ip(full.clone())], &wide));
    full.push(0);
    assert!(!matches(&[General::Ip(full)], &wide));
}

fn ffff() -> Vec<u8> {
    vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192, 0, 2, 1]
}

#[test]
fn kinds() {
    let text = [dns("192.0.2.1")];
    assert!(!matches(&text, &name("192.0.2.1")));
    let bytes = [General::Ip(b"example.com".to_vec())];
    assert!(!matches(&bytes, &name("example.com")));
    let rest = [
        General::Email("example.com".into()),
        General::Uri("https://example.com".into()),
        General::Other(0xa0, b"example.com".to_vec()),
    ];
    assert!(!matches(&rest, &name("example.com")));
}

#[test]
fn any() {
    let names = [
        dns("one.example"),
        General::Ip(vec![10, 0, 0, 1]),
        dns("*.two.example"),
    ];
    assert!(matches(&names, &name("one.example")));
    assert!(matches(&names, &name("10.0.0.1")));
    assert!(matches(&names, &name("www.two.example")));
    assert!(!matches(&names, &name("three.example")));
    assert!(!matches(&names, &name("10.0.0.2")));
    assert!(!matches(&[], &name("one.example")));
}

#[test]
fn built() {
    let star = Host::Dns("*".to_string());
    assert!(!matches(&[dns("*")], &star));
    let gap = Host::Dns("www..com".to_string());
    assert!(!matches(&[dns("*..com")], &gap));
    let hole = Host::Dns("www.a..b".to_string());
    assert!(!matches(&[dns("*.a..b")], &hole));
    let inner = Host::Dns("www.*.com".to_string());
    assert!(!matches(&[dns("*.*.com")], &inner));
}
