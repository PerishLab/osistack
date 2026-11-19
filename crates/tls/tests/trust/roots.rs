use crate::support::{build, dns, name, named, pem};
use tls::x509::trust::{Refusal, Roots};
use tls::x509::{Certificate, Name};

fn der(subject: &str, seed: u8) -> Vec<u8> {
    build(&name(subject), "root", Some(&[dns("x.example")]), seed)
}

fn subject(raw: &[u8]) -> Name {
    Name::parse(raw).unwrap()
}

fn cert(text: &str, seed: u8) -> String {
    pem("CERTIFICATE", &der(text, seed), 64, "\n")
}

#[test]
fn load() {
    let text = format!(
        "Root bundle\nissued in 2026\n{}{}{}end of file\n",
        cert("ca1", 1),
        pem("PRIVATE KEY", b"secret", 64, "\n"),
        cert("ca2", 2)
    );
    let roots = Roots::pem(&text).unwrap();
    assert_eq!(roots.count(), 2);
    assert_ne!(roots.count(), 0);
    assert!(roots.contains(&der("ca1", 1)));
    assert!(roots.contains(&der("ca2", 2)));
    assert!(!roots.contains(&der("ca3", 3)));
    assert!(!roots.contains(&der("ca1", 2)));
    let held = der("ca1", 1);
    assert!(!roots.contains(&held[..held.len() - 1]));
    assert!(!roots.contains(&[held.clone(), vec![0]].concat()));
    assert!(!roots.contains(&[]));
}

#[test]
fn anchors() {
    let text = format!("{}{}{}", cert("ca1", 1), cert("ca2", 2), cert("ca1", 3));
    let roots = Roots::pem(&text).unwrap();
    assert_eq!(roots.count(), 3);
    let found = roots.anchors(&subject(&name("ca1")));
    assert_eq!(found.len(), 2);
    for each in &found {
        assert_eq!(each.subject.der, name("ca1"));
    }
    assert_eq!(found[0].serial, vec![1, 1]);
    assert_eq!(found[1].serial, vec![1, 3]);
    assert_eq!(roots.anchors(&subject(&name("ca2"))).len(), 1);
    assert!(roots.anchors(&subject(&name("ca3"))).is_empty());
    assert!(roots.anchors(&subject(&name("ca"))).is_empty());
}

#[test]
fn dupes() {
    let mut roots = Roots::default();
    assert_eq!(roots.add(&der("ca1", 1)), Ok(true));
    assert_eq!(roots.add(&der("ca1", 1)), Ok(false));
    assert_eq!(roots.add(&der("ca1", 2)), Ok(true));
    assert_eq!(roots.count(), 2);
    let twice = format!("{}{}", cert("ca1", 1), cert("ca1", 1));
    assert_eq!(Roots::pem(&twice).unwrap().count(), 1);
}

#[test]
fn bad() {
    let flaw = Certificate::parse(&[1, 2, 3]).unwrap_err();
    let text = pem("CERTIFICATE", &[1, 2, 3], 64, "\n");
    assert_eq!(Roots::pem(&text).unwrap_err(), Refusal::Certificate(flaw));
    let flaw = Certificate::parse(&[]).unwrap_err();
    let mut roots = Roots::default();
    assert_eq!(roots.add(&[]), Err(Refusal::Certificate(flaw)));
    assert_eq!(roots.count(), 0);
    let mut chopped = der("ca1", 1);
    chopped.truncate(40);
    let flaw = Certificate::parse(&chopped).unwrap_err();
    let text = pem("CERTIFICATE", &chopped, 64, "\n");
    assert_eq!(Roots::pem(&text).unwrap_err(), Refusal::Certificate(flaw));
}

#[test]
fn empty() {
    assert_eq!(Roots::default().count(), 0);
    assert_eq!(Roots::pem("").unwrap().count(), 0);
    assert_eq!(Roots::pem("only words\nand more\n").unwrap().count(), 0);
    assert_eq!(Roots::default().count(), 0);
    assert!(Roots::default().anchors(&subject(&name("ca1"))).is_empty());
}

#[test]
fn others() {
    for label in [
        "TRUSTED CERTIFICATE",
        "X509 CERTIFICATE",
        "certificate",
        "CERTIFICATE REQUEST",
        "PRIVATE KEY",
    ] {
        let text = pem(label, &der("ca1", 1), 64, "\n");
        assert_eq!(Roots::pem(&text).unwrap().count(), 0, "{label}");
    }
}

#[test]
fn frame() {
    assert_eq!(
        Roots::pem("-----BEGIN CERTIFICATE-----\n").unwrap_err(),
        Refusal::Frame
    );
    let text = "-----BEGIN CERTIFICATE-----\nZg==\n-----END X-----\n";
    assert_eq!(Roots::pem(text).unwrap_err(), Refusal::Label);
    let text = "-----BEGIN CERTIFICATE-----\nZg=\n-----END CERTIFICATE-----\n";
    assert_eq!(Roots::pem(text).unwrap_err(), Refusal::Base64);
    let text = format!("{}-----END CERTIFICATE-----\n", cert("ca1", 1));
    assert_eq!(Roots::pem(&text).unwrap_err(), Refusal::Frame);
}

#[test]
fn encoding() {
    let printable = build(&named("ca1", 0x13), "root", None, 1);
    let mut roots = Roots::default();
    roots.add(&printable).unwrap();
    assert!(roots.anchors(&subject(&name("ca1"))).is_empty());
    assert_eq!(roots.anchors(&subject(&named("ca1", 0x13))).len(), 1);
}

#[test]
fn stored() {
    let mut roots = Roots::default();
    roots.add(&der("ca1", 1)).unwrap();
    let copy = roots.clone();
    roots.add(&der("ca2", 2)).unwrap();
    assert_eq!(copy.count(), 1);
    assert_eq!(roots.count(), 2);
    assert!(!copy.contains(&der("ca2", 2)));
}
