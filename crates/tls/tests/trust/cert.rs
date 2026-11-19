use crate::support::{build, dns, email, ip, name, named, uri};
use tls::x509::Certificate;
use tls::x509::trust::{Host, Refusal, verify};

fn host(text: &str) -> Host {
    Host::parse(text).unwrap()
}

fn parsed(subject: &str, names: Option<&[Vec<u8>]>) -> Certificate {
    Certificate::parse(&build(&name(subject), "ca", names, 1)).unwrap()
}

#[test]
fn listed() {
    let names = [
        dns("www.example.com"),
        dns("*.shop.example.com"),
        ip(&[192, 0, 2, 1]),
    ];
    let cert = parsed("leaf", Some(&names));
    assert_eq!(verify(&cert, &host("www.example.com")), Ok(()));
    assert_eq!(verify(&cert, &host("WWW.Example.com")), Ok(()));
    assert_eq!(verify(&cert, &host("a.shop.example.com")), Ok(()));
    assert_eq!(verify(&cert, &host("192.0.2.1")), Ok(()));
    assert_eq!(verify(&cert, &host("example.com")), Err(Refusal::Mismatch));
    assert_eq!(
        verify(&cert, &host("shop.example.com")),
        Err(Refusal::Mismatch)
    );
    assert_eq!(verify(&cert, &host("192.0.2.2")), Err(Refusal::Mismatch));
}

#[test]
fn common() {
    let cert = parsed("example.com", None);
    assert_eq!(verify(&cert, &host("example.com")), Err(Refusal::Missing));
    let names = [dns("other.example")];
    let cert = parsed("example.com", Some(&names));
    assert_eq!(verify(&cert, &host("example.com")), Err(Refusal::Mismatch));
    assert_eq!(verify(&cert, &host("other.example")), Ok(()));
}

#[test]
fn unusable() {
    let names = [email("example.com"), uri("https://example.com")];
    let cert = parsed("example.com", Some(&names));
    assert_eq!(verify(&cert, &host("example.com")), Err(Refusal::Missing));
    let cert = parsed("leaf", None);
    assert_eq!(verify(&cert, &host("192.0.2.1")), Err(Refusal::Missing));
}

#[test]
fn bare() {
    let names = [ip(&[192, 0, 2, 1])];
    let cert = parsed("leaf", Some(&names));
    assert_eq!(verify(&cert, &host("example.com")), Err(Refusal::Mismatch));
    assert_eq!(verify(&cert, &host("192.0.2.1")), Ok(()));
    let names = [dns("example.com")];
    let cert = parsed("leaf", Some(&names));
    assert_eq!(verify(&cert, &host("192.0.2.1")), Err(Refusal::Mismatch));
}

#[test]
fn mixed() {
    let names = [email("a@example.com"), dns("example.com")];
    let cert = parsed("leaf", Some(&names));
    assert_eq!(verify(&cert, &host("example.com")), Ok(()));
    let cert =
        Certificate::parse(&build(&named("printable", 0x13), "ca", Some(&names), 2)).unwrap();
    assert_eq!(verify(&cert, &host("example.com")), Ok(()));
}
