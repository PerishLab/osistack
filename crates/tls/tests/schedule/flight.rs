use crate::support::{HOST, accepted, bodies, cert, message, now, packed, roots, sealed, shared};
use crypto::Hash;
use tls::x509::trust::Roots;
use tls::{Accepted, Chain, Content, Encrypted, Entry, Error, Finished, Kind, Message, Verify};

#[test]
fn verifies() {
    let (hello, accepted) = accepted();
    let der = cert(HOST);
    let record = packed(&hello, &accepted, &der, false);
    let verified = accepted
        .verify(HOST, &roots(&der), now(), &[record])
        .unwrap();
    assert_eq!(verified.digest().len(), 32);
}

#[test]
fn forged() {
    let (hello, accepted) = accepted();
    let der = cert(HOST);
    let record = packed(&hello, &accepted, &der, true);
    assert!(
        accepted
            .verify(HOST, &roots(&der), now(), &[record])
            .is_err()
    );
    let mut damaged = der.clone();
    *damaged.last_mut().unwrap() ^= 1;
    let record = packed(&hello, &accepted, &damaged, false);
    assert!(
        accepted
            .verify(HOST, &roots(&der), now(), &[record])
            .is_err()
    );
}

#[test]
fn finishes() {
    let (hello, accepted) = accepted();
    let der = cert(HOST);
    let record = packed(&hello, &accepted, &der, false);
    let verified = accepted
        .verify(HOST, &roots(&der), now(), &[record])
        .unwrap();
    let complete = verified.finish().unwrap();
    let (message, used) = Message::parse(complete.spoken(), 1 << 16).unwrap().unwrap();
    assert_eq!(used, complete.spoken().len());
    assert_eq!(message.kind, Kind::Finished);
    accepted
        .client()
        .check(&verified.digest(), &message.body)
        .unwrap();
    let master = tls::Schedule::new(Hash::Sha256, &shared())
        .unwrap()
        .master()
        .unwrap();
    let through = verified.digest();
    assert_eq!(
        complete.client().secret(),
        master.client(&through).unwrap().secret()
    );
    assert_eq!(
        complete.server().secret(),
        master.server(&through).unwrap().secret()
    );
    assert_eq!(complete.exporter(), master.exporter(&through).unwrap());
    assert_eq!(
        complete.resumption(),
        master.resumption(&complete.digest()).unwrap()
    );
}

fn empty() -> Encrypted {
    Encrypted {
        extensions: Vec::new(),
    }
}

fn extensions() -> Vec<u8> {
    message(Kind::Extensions, empty().write().unwrap())
}

fn certificate(der: &[u8], context: Vec<u8>) -> Vec<u8> {
    message(
        Kind::Certificate,
        Chain {
            context,
            entries: vec![Entry {
                cert: der.to_vec(),
                extensions: Vec::new(),
            }],
        }
        .write()
        .unwrap(),
    )
}

fn blank() -> Vec<u8> {
    message(
        Kind::Certificate,
        Chain {
            context: Vec::new(),
            entries: Vec::new(),
        }
        .write()
        .unwrap(),
    )
}

fn verify() -> Vec<u8> {
    message(
        Kind::Verify,
        Verify {
            algorithm: 0x0403,
            signature: vec![0; 64],
        }
        .write()
        .unwrap(),
    )
}

fn finished() -> Vec<u8> {
    message(
        Kind::Finished,
        Finished { data: vec![0; 32] }.write().unwrap(),
    )
}

fn join(parts: &[&[u8]]) -> Vec<u8> {
    let mut data = Vec::new();
    for part in parts {
        data.extend_from_slice(part);
    }
    data
}

fn checked(accepted: &Accepted, roots: &Roots, flight: &[u8]) -> Error {
    accepted
        .checked(HOST, roots, now(), flight)
        .err()
        .expect("refused")
}

#[test]
fn order() {
    let (_, accepted) = accepted();
    let der = cert(HOST);
    let roots = roots(&der);
    let extensions = extensions();
    let certificate = certificate(&der, Vec::new());
    let verify = verify();
    let finished = finished();
    let first = join(&[&certificate, &extensions, &verify, &finished]);
    assert_eq!(checked(&accepted, &roots, &first), Error::Kind);
    let early = join(&[&finished, &extensions, &certificate, &verify]);
    assert_eq!(checked(&accepted, &roots, &early), Error::Kind);
    let swapped = join(&[&extensions, &verify, &certificate, &finished]);
    assert_eq!(checked(&accepted, &roots, &swapped), Error::Kind);
}

fn prior(flight: &[u8]) -> &[u8] {
    let mut at = 0;
    let mut last = 0;
    while at < flight.len() {
        let (_, used) = Message::parse(&flight[at..], usize::MAX).unwrap().unwrap();
        last = at;
        at += used;
    }
    &flight[..last]
}

#[test]
fn missing() {
    let (hello, accepted) = accepted();
    let der = cert(HOST);
    let roots = roots(&der);
    let extensions = extensions();
    assert_eq!(checked(&accepted, &roots, &[]), Error::Length);
    assert_eq!(checked(&accepted, &roots, &extensions), Error::Length);
    let flight = bodies(&hello, &accepted, &der, false);
    assert_eq!(checked(&accepted, &roots, prior(&flight)), Error::Length);
    assert!(
        accepted
            .checked(HOST, &roots, now(), &extensions[..3])
            .is_err()
    );
}

#[test]
fn trailing() {
    let (hello, accepted) = accepted();
    let der = cert(HOST);
    let roots = roots(&der);
    let mut flight = bodies(&hello, &accepted, &der, false);
    assert!(accepted.checked(HOST, &roots, now(), &flight).is_ok());
    flight.push(0);
    assert_eq!(checked(&accepted, &roots, &flight), Error::Trailing);
}

#[test]
fn records() {
    let (hello, accepted) = accepted();
    let der = cert(HOST);
    let roots = roots(&der);
    let data = bodies(&hello, &accepted, &der, false);
    let alert = sealed(&accepted, Content::Alert, &data);
    assert_eq!(
        accepted.verify(HOST, &roots, now(), &[alert]).err(),
        Some(Error::Kind)
    );
    assert_eq!(
        accepted.verify(HOST, &roots, now(), &[]).err(),
        Some(Error::Length)
    );
}

#[test]
fn context() {
    let (_, accepted) = accepted();
    let der = cert(HOST);
    let roots = roots(&der);
    let flight = join(&[
        &extensions(),
        &certificate(&der, vec![1]),
        &verify(),
        &finished(),
    ]);
    assert_eq!(checked(&accepted, &roots, &flight), Error::Value);
}

#[test]
fn chain() {
    let (_, accepted) = accepted();
    let der = cert(HOST);
    let roots = roots(&der);
    let flight = join(&[&extensions(), &blank(), &verify(), &finished()]);
    assert_eq!(checked(&accepted, &roots, &flight), Error::Missing);
}

#[test]
fn host() {
    let (hello, accepted) = accepted();
    let der = cert(HOST);
    let roots = roots(&der);
    let record = packed(&hello, &accepted, &der, false);
    assert_eq!(
        accepted
            .verify("other.test", &roots, now(), &[record])
            .err(),
        Some(Error::Value)
    );
}
