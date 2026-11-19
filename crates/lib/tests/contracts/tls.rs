use crate::behaviour::Check;
use tls::x509::trust::{Host, Refusal, Roots, verify};
use tls::x509::{Certificate, Oid};
use tls::{Chain, Entry, Kind, Message};

const ECDSA: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const CURVE: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const ALT: &[u8] = &[0x55, 0x1d, 0x11];
const COMMON: &[u8] = &[0x55, 0x04, 0x03];
const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn table() -> Vec<(&'static str, Check)> {
    vec![
        ("explicit-pem-roots", roots as Check),
        ("hostname-validation", hostname as Check),
    ]
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let size = content.len();
    let mut out = vec![tag];
    if size < 128 {
        out.push(size as u8);
    } else if size < 256 {
        out.extend([0x81, size as u8]);
    } else {
        out.extend([0x82, (size >> 8) as u8, size as u8]);
    }
    out.extend_from_slice(content);
    out
}

fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn oid(content: &[u8]) -> Vec<u8> {
    tlv(0x06, content)
}

fn bits(unused: u8, data: &[u8]) -> Vec<u8> {
    tlv(0x03, &[&[unused][..], data].concat())
}

fn alg(id: &[u8], params: &[u8]) -> Vec<u8> {
    seq(&[&oid(id), params])
}

fn name(common: &str) -> Vec<u8> {
    let pair = seq(&[&oid(COMMON), &tlv(0x0c, common.as_bytes())]);
    seq(&[&tlv(0x31, &pair)])
}

fn dns(text: &str) -> Vec<u8> {
    tlv(0x82, text.as_bytes())
}

fn email(text: &str) -> Vec<u8> {
    tlv(0x81, text.as_bytes())
}

fn ip(octets: &[u8]) -> Vec<u8> {
    tlv(0x87, octets)
}

fn der(subject: &str, issuer: &str, names: &[Vec<u8>], seed: u8) -> Vec<u8> {
    let validity = seq(&[&tlv(0x17, b"260101000000Z"), &tlv(0x17, b"300101000000Z")]);
    let mut point = vec![0x04];
    point.extend((1..=64u8).map(|byte| byte.wrapping_add(seed)));
    let spki = seq(&[&alg(EC, &oid(CURVE)), &bits(0, &point)]);
    let refs: Vec<&[u8]> = names.iter().map(|each| each.as_slice()).collect();
    let listed = seq(&[&oid(ALT), &tlv(0x04, &seq(&refs))]);
    let extra = if names.is_empty() {
        Vec::new()
    } else {
        tlv(0xa3, &seq(&[&listed]))
    };
    let tbs = seq(&[
        &tlv(0xa0, &tlv(0x02, &[2])),
        &tlv(0x02, &[1, seed | 1]),
        &alg(ECDSA, &[]),
        &name(issuer),
        &validity,
        &name(subject),
        &spki,
        &extra,
    ]);
    seq(&[&tbs, &alg(ECDSA, &[]), &bits(0, &[1, 2, 3, 4])])
}

fn encode(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let word = chunk
            .iter()
            .fold(0u32, |acc, byte| (acc << 8) | *byte as u32)
            << (8 * (3 - chunk.len()));
        for at in 0..4 {
            let live = at <= chunk.len();
            out.push(if live {
                TABLE[((word >> (18 - 6 * at)) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    out
}

fn pem(label: &str, data: &[u8], width: usize, eol: &str) -> String {
    let mut out = format!("-----BEGIN {label}-----{eol}");
    for line in encode(data).as_bytes().chunks(width) {
        out.push_str(std::str::from_utf8(line).unwrap());
        out.push_str(eol);
    }
    out.push_str(&format!("-----END {label}-----{eol}"));
    out
}

fn roots() {
    let empty = Roots::default();
    assert_eq!(empty.count(), 0);
    let first = der("Root A", "Root A", &[], 1);
    let second = der("Root B", "Root B", &[], 2);
    let one = Certificate::parse(&first).unwrap();
    let bundle = format!(
        "# trusted\n{}\nnote\r\n{}{}",
        pem("CERTIFICATE", &first, 64, "\n"),
        pem("PRIVATE KEY", &[9, 9, 9], 64, "\n"),
        pem("CERTIFICATE", &second, 76, "\r\n"),
    );
    let held = Roots::pem(&bundle).unwrap();
    assert_eq!(held.count(), 2);
    assert!(held.contains(&first) && held.contains(&second));
    assert!(!held.contains(&der("Root C", "Root C", &[], 3)));
    assert_eq!(held.anchors(&one.subject).len(), 1);
    assert_eq!(held.anchors(&one.subject)[0].serial, one.serial);
    let other = Certificate::parse(&der("Nobody", "Nobody", &[], 4)).unwrap();
    assert!(held.anchors(&other.subject).is_empty());
    assert!(empty.anchors(&one.subject).is_empty());
    let twice = format!(
        "{}{}",
        pem("CERTIFICATE", &first, 64, "\n"),
        pem("CERTIFICATE", &first, 64, "\n")
    );
    assert_eq!(Roots::pem(&twice).unwrap().count(), 1);
    assert_eq!(Roots::pem("").unwrap().count(), 0);
    let mut grown = Roots::default();
    assert_eq!(grown.add(&first), Ok(true));
    assert_eq!(grown.add(&first), Ok(false));
    let broken = pem("CERTIFICATE", &first, 64, "\n").replace("MI", "M*");
    assert_eq!(Roots::pem(&broken).unwrap_err(), Refusal::Base64);
    let cut = pem("CERTIFICATE", &first, 64, "\n").replace("-----END CERTIFICATE-----\n", "");
    assert_eq!(Roots::pem(&cut).unwrap_err(), Refusal::Frame);
    let junk = pem("CERTIFICATE", &[1, 2, 3, 4], 64, "\n");
    assert!(matches!(Roots::pem(&junk), Err(Refusal::Certificate(_))));
    let whole = pem("CERTIFICATE", &first, 64, "\n");
    let gap = whole.replacen('\n', "\n\n", 2);
    assert_eq!(Roots::pem(&gap).unwrap_err(), Refusal::Base64);
    let nested = whole.replacen('\n', "\n-----BEGIN CERTIFICATE-----\n", 1);
    assert_eq!(Roots::pem(&nested).unwrap_err(), Refusal::Frame);
    let short = whole.replacen("MI", "M", 1);
    assert_eq!(Roots::pem(&short).unwrap_err(), Refusal::Base64);
    let spaced = whole.replacen("-----\n", "-----  \t\n", 2);
    assert_eq!(Roots::pem(&spaced).unwrap().count(), 1);
    let lone = "-----END CERTIFICATE-----\n";
    assert_eq!(Roots::pem(lone).unwrap_err(), Refusal::Frame);
    let wrong = pem("CERTIFICATE", &first, 64, "\n").replace("END CERTIFICATE", "END TRUSTED");
    assert_eq!(Roots::pem(&wrong).unwrap_err(), Refusal::Label);
}

fn presented(certs: &[Vec<u8>]) -> Vec<u8> {
    let entries = certs
        .iter()
        .map(|cert| Entry {
            cert: cert.clone(),
            extensions: Vec::new(),
        })
        .collect();
    let chain = Chain {
        context: Vec::new(),
        entries,
    };
    let message = Message {
        kind: Kind::Certificate,
        body: chain.write().unwrap(),
    };
    message.write().unwrap()
}

fn received(bytes: &[u8]) -> Vec<Certificate> {
    assert_eq!(
        Message::parse(&bytes[..bytes.len() - 1], 1 << 16).unwrap(),
        None
    );
    let (message, used) = Message::parse(bytes, 1 << 16).unwrap().unwrap();
    assert_eq!((message.kind, used), (Kind::Certificate, bytes.len()));
    let chain = Chain::parse(&message.body).unwrap();
    chain
        .entries
        .iter()
        .map(|entry| Certificate::parse(&entry.cert).unwrap())
        .collect()
}

fn tried(cert: &Certificate, host: Host) -> Result<(), Refusal> {
    verify(cert, &host)
}

fn judged(cert: &Certificate, host: &str) -> Result<(), Refusal> {
    verify(cert, &Host::parse(host)?)
}

fn hostname() {
    let names = [dns("example.test"), dns("*.wild.test"), ip(&[192, 0, 2, 7])];
    let leaf = der("ignored.test", "Issuer", &names, 5);
    let issuer = der("Issuer", "Issuer", &[], 6);
    let seen = received(&presented(&[leaf, issuer]));
    assert_eq!(seen.len(), 2);
    let cert = &seen[0];
    let common = Oid::from(&[2, 5, 4, 3]);
    assert_eq!(cert.subject.text(&common).unwrap(), "ignored.test");
    for host in [
        "example.test",
        "EXAMPLE.test",
        "example.test.",
        "a.wild.test",
        "192.0.2.7",
    ] {
        assert_eq!(judged(cert, host), Ok(()), "{host}");
    }
    for host in [
        "wild.test",
        "a.b.wild.test",
        "ignored.test",
        "other.test",
        "192.0.2.8",
        "::1",
    ] {
        assert_eq!(judged(cert, host), Err(Refusal::Mismatch), "{host}");
    }
    assert_eq!(judged(cert, "bad_host"), Err(Refusal::Host));
    assert_eq!(judged(cert, ""), Err(Refusal::Host));
    let odd = [
        dns("f*.test"),
        dns("*.com"),
        dns("*.*.test"),
        dns("EXAMPLE2.TEST"),
    ];
    let cert = &received(&presented(&[der("x", "Issuer", &odd, 8)]))[0];
    for host in ["foo.test", "a.com", "a.b.test", "b.test"] {
        assert_eq!(judged(cert, host), Err(Refusal::Mismatch), "{host}");
    }
    assert_eq!(judged(cert, "example2.test"), Ok(()));
    let literal = |text: &str| tried(cert, Host::Dns(text.to_string()));
    assert_eq!(literal("f*.test"), Err(Refusal::Mismatch));
    assert_eq!(literal("a.*.test"), Err(Refusal::Mismatch));
    let mail = [email("a@example.test")];
    let cert = &received(&presented(&[der("x", "Issuer", &mail, 9)]))[0];
    assert_eq!(judged(cert, "example.test"), Err(Refusal::Missing));
    assert_eq!(judged(cert, "192.0.2.999"), Err(Refusal::Host));
    assert_eq!(judged(cert, "-a.test"), Err(Refusal::Host));
    assert_eq!(
        judged(cert, &format!("{}.test", "a".repeat(64))),
        Err(Refusal::Host)
    );
    let bare = received(&presented(&[der("example.test", "Issuer", &[], 7)]));
    assert_eq!(judged(&bare[0], "example.test"), Err(Refusal::Missing));
}
