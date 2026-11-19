use crate::support::Dice;
use quic::{Client, Error, Header, Negotiation, Verdict, answer};

const OTHER: u32 = 0x6b33_43cf;
const GREASE: u32 = 0x1a2a_3a4a;

fn initial(version: u32, dcid: &[u8], scid: &[u8], size: usize) -> Vec<u8> {
    let mut data = vec![0xc3];
    data.extend(version.to_be_bytes());
    data.push(dcid.len() as u8);
    data.extend(dcid);
    data.push(scid.len() as u8);
    data.extend(scid);
    if data.len() < size {
        data.resize(size, 0);
    }
    data
}

fn packet(dcid: &[u8], scid: &[u8], versions: &[u32]) -> Negotiation {
    Negotiation {
        unused: 0x40,
        dcid: dcid.to_vec(),
        scid: scid.to_vec(),
        versions: versions.to_vec(),
    }
}

fn client() -> Client {
    Client::new(1, &[1, 2, 3, 4], &[9, 8])
}

#[test]
fn abandon() {
    let mut client = client();
    let found = packet(&[9, 8], &[1, 2, 3, 4], &[OTHER, 2]);
    assert_eq!(client.receive(&found), Verdict::Abandon);
}

#[test]
fn lists() {
    let mut client = client();
    assert_eq!(
        client.receive(&packet(&[9, 8], &[1, 2, 3, 4], &[2, 1])),
        Verdict::Ignore
    );
}

#[test]
fn empty() {
    let mut client = client();
    assert_eq!(
        client.receive(&packet(&[9, 8], &[1, 2, 3, 4], &[])),
        Verdict::Abandon
    );
}

#[test]
fn processed() {
    let mut client = client();
    client.processed();
    assert_eq!(
        client.receive(&packet(&[9, 8], &[1, 2, 3, 4], &[2])),
        Verdict::Ignore
    );
}

#[test]
fn earlier() {
    let mut client = client();
    let found = packet(&[9, 8], &[1, 2, 3, 4], &[2]);
    assert_eq!(client.receive(&found), Verdict::Abandon);
    assert_eq!(client.receive(&found), Verdict::Ignore);
}

#[test]
fn skipped() {
    let mut client = client();
    assert_eq!(
        client.receive(&packet(&[9, 8], &[1, 2, 3, 4], &[1])),
        Verdict::Ignore
    );
    assert_eq!(
        client.receive(&packet(&[0], &[1, 2, 3, 4], &[2])),
        Verdict::Ignore
    );
    assert_eq!(
        client.receive(&packet(&[9, 8], &[1, 2, 3, 4], &[2])),
        Verdict::Abandon
    );
}

#[test]
fn echo() {
    let mut client = client();
    assert_eq!(
        client.receive(&packet(&[9, 7], &[1, 2, 3, 4], &[2])),
        Verdict::Ignore
    );
    assert_eq!(
        client.receive(&packet(&[9, 8], &[1, 2, 3, 5], &[2])),
        Verdict::Ignore
    );
    assert_eq!(
        client.receive(&packet(&[1, 2, 3, 4], &[9, 8], &[2])),
        Verdict::Ignore
    );
    assert_eq!(
        client.receive(&packet(&[9], &[1, 2, 3, 4], &[2])),
        Verdict::Ignore
    );
    assert_eq!(
        client.receive(&packet(&[9, 8], &[1, 2, 3], &[2])),
        Verdict::Ignore
    );
}

#[test]
fn zero() {
    let mut client = Client::new(1, &[], &[]);
    assert_eq!(client.receive(&packet(&[], &[], &[2])), Verdict::Abandon);
    let mut client = Client::new(1, &[], &[]);
    assert_eq!(client.receive(&packet(&[1], &[], &[2])), Verdict::Ignore);
}

#[test]
fn unused() {
    for unused in [0, 0x40, 0x7f] {
        let mut client = client();
        let mut found = packet(&[9, 8], &[1, 2, 3, 4], &[2]);
        found.unused = unused;
        assert_eq!(client.receive(&found), Verdict::Abandon);
    }
}

#[test]
fn reserved() {
    let mut client = client();
    let found = packet(&[9, 8], &[1, 2, 3, 4], &[GREASE]);
    assert_eq!(client.receive(&found), Verdict::Abandon);
}

#[test]
fn reply() {
    let data = initial(OTHER, &[1; 8], &[2; 5], 1200);
    let got = answer(&data, &[1], GREASE).unwrap();
    assert_eq!(got, Some(packet(&[2; 5], &[1; 8], &[1, GREASE])));
}

#[test]
fn wire() {
    let data = initial(OTHER, &[1; 8], &[2; 5], 1200);
    let got = answer(&data, &[1, 2], GREASE).unwrap().unwrap();
    let bytes = got.write().unwrap();
    assert_eq!(bytes[0], 0xc0);
    assert_eq!(Header::parse(&bytes, 0), Ok(Header::Negotiation(got)));
}

#[test]
fn size() {
    for (size, found) in [(1199, false), (1200, true), (1201, true), (40, false)] {
        let data = initial(OTHER, &[1; 8], &[2; 5], size);
        assert_eq!(
            answer(&data, &[1], GREASE).unwrap().is_some(),
            found,
            "{size}"
        );
    }
}

#[test]
fn known() {
    let data = initial(1, &[1; 8], &[2; 5], 1200);
    assert_eq!(answer(&data, &[1], GREASE), Ok(None));
    let data = initial(2, &[1; 8], &[2; 5], 1200);
    assert_eq!(answer(&data, &[1, 2], GREASE), Ok(None));
    assert!(answer(&data, &[1], GREASE).unwrap().is_some());
}

#[test]
fn nought() {
    let data = initial(0, &[1; 8], &[2; 5], 1200);
    assert_eq!(answer(&data, &[1], GREASE), Ok(None));
}

#[test]
fn short() {
    for first in [0x00, 0x40, 0x7f] {
        let mut data = initial(OTHER, &[1; 8], &[2; 5], 1200);
        data[0] = first;
        assert_eq!(answer(&data, &[1], GREASE), Ok(None));
    }
}

#[test]
fn bits() {
    for first in [0x80, 0xc0, 0xff] {
        let mut data = initial(OTHER, &[1; 8], &[2; 5], 1200);
        data[0] = first;
        assert!(answer(&data, &[1], GREASE).unwrap().is_some());
    }
}

#[test]
fn cut() {
    for version in [OTHER, 2] {
        let whole = initial(version, &[1; 8], &[2; 5], 0);
        for size in 0..whole.len() {
            let got = answer(&whole[..size], &[1], GREASE);
            assert!(matches!(got, Err(Error::Wire(_))), "{version:#x} {size}");
        }
        assert!(answer(&whole, &[1], GREASE).is_ok());
    }
}

#[test]
fn long() {
    for size in [21, 255] {
        let (dcid, scid) = (vec![3; size], vec![4; size]);
        let data = initial(OTHER, &dcid, &scid, 1200);
        let got = answer(&data, &[1], GREASE).unwrap().unwrap();
        assert_eq!((got.dcid, got.scid), (scid, dcid));
    }
}

#[test]
fn grease() {
    let data = initial(OTHER, &[1; 8], &[2; 5], 1200);
    assert_eq!(
        answer(&data, &[1], 0x0102_0304).unwrap().unwrap().versions,
        vec![1]
    );
    let same = answer(&data, &[1, GREASE], GREASE).unwrap().unwrap();
    assert_eq!(same.versions, vec![1, GREASE]);
    for added in [0x0a0a_0a0a, 0xfafa_fafa, 0x3a4a_5a6a, 0x1a2a_3a5a] {
        let got = answer(&data, &[1], added).unwrap().unwrap();
        assert_eq!(got.versions, vec![1, added]);
    }
    for near in [0x1a2a_3a4b, 0x1a2a_3b4a, 0x1a2b_3a4a, 0x1b2a_3a4a, 0, 1] {
        let got = answer(&data, &[2], near).unwrap().unwrap();
        assert_eq!(got.versions, vec![2], "{near:#x}");
    }
}

#[test]
fn order() {
    let data = initial(OTHER, &[1; 8], &[2; 5], 1200);
    let got = answer(&data, &[3, 1, 2], GREASE).unwrap().unwrap();
    assert_eq!(got.versions, vec![3, 1, 2, GREASE]);
    let got = answer(&data, &[], GREASE).unwrap().unwrap();
    assert_eq!(got.versions, vec![GREASE]);
}

#[test]
fn sweep() {
    for seed in 1..=64 {
        let mut dice = Dice::new(seed);
        let dcid = dice.upto(256);
        let scid = dice.upto(256);
        let version = 2 + dice.below(1000) as u32;
        let data = initial(version, &dcid, &scid, 1200 + dice.below(300));
        let got = answer(&data, &[1], GREASE).unwrap().unwrap();
        assert_eq!((&got.dcid, &got.scid), (&scid, &dcid), "seed {seed}");
        let bytes = got.write().unwrap();
        assert_eq!(Header::parse(&bytes, 0), Ok(Header::Negotiation(got)));
    }
}
