use crate::seeds::*;
use crate::support::*;
use crypto::{Aead, Hash};
use quic::{Header, Initial, Keys, Opened};

const DCID: &str = "8394c8f03e515708";
const CLIENTHEAD: &str = "c300000001088394c8f03e5157080000449e00000002";
const SERVERHEAD: &str = "c1000000010008f067a5502a4262b50040750001";
const SECRET: &str = "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b";
const SHORTPACKET: &str = "4cfe4189655e5cd55c41f69080575d7999c25a5bfb";

struct Known {
    secret: &'static str,
    key: &'static str,
    iv: &'static str,
    hp: &'static str,
}

const CLIENT: Known = Known {
    secret: "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
    key: "1f369613dd76d5467730efcbe3b1a22d",
    iv: "fa044b2f42a3fd3b46fb255c",
    hp: "9f50449e04a0e810283a1e9933adedd2",
};

const SERVER: Known = Known {
    secret: "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b",
    key: "cf3a5331653c364c88f0f379b6067e37",
    iv: "0ac1493ca1905853b0bba03e",
    hp: "c206b8d9b9f0f37644430b490eeaa314",
};

const SHORT: Known = Known {
    secret: SECRET,
    key: "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8",
    iv: "e0459b3474bdd0e44a41c144",
    hp: "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4",
};

fn known(keys: &Keys, want: &Known) {
    assert_eq!(keys.secret(), hex(want.secret));
    assert_eq!(keys.key(), hex(want.key));
    assert_eq!(keys.iv(), hex(want.iv));
    assert_eq!(keys.hp(), hex(want.hp));
}

fn offset(packet: &[u8]) -> usize {
    match Header::parse(packet, 0).unwrap() {
        Header::Long(long) => long.offset,
        Header::Short(short) => short.offset,
        other => panic!("{other:?}"),
    }
}

fn through(keys: &Keys, number: u64, head: &str, payload: &[u8]) -> Vec<u8> {
    let header = hex(head);
    let packet = keys.protect(number, &header, payload).unwrap();
    let largest = number.checked_sub(1);
    let opened = keys.unprotect(&packet, offset(&packet), largest).unwrap();
    let wanted = Opened {
        number,
        header,
        payload: payload.to_vec(),
    };
    assert_eq!(opened, wanted);
    packet
}

#[test]
fn initial() {
    let initial = Initial::new(&hex(DCID)).unwrap();
    known(&initial.client, &CLIENT);
    known(&initial.server, &SERVER);
}

#[test]
fn client() {
    let keys = Initial::new(&hex(DCID)).unwrap().client;
    let payload = fill(&hex(CRYPTO), 1162);
    let packet = through(&keys, 2, CLIENTHEAD, &payload);
    assert_eq!(packet, hex(CLIENTPACKET));
    assert_eq!(offset(&packet), 18);
}

#[test]
fn server() {
    let keys = Initial::new(&hex(DCID)).unwrap().server;
    let packet = through(&keys, 1, SERVERHEAD, &hex(SERVERPAYLOAD));
    assert_eq!(packet, hex(SERVERPACKET));
    assert_eq!(offset(&packet), 18);
}

#[test]
fn short() {
    let keys = Keys::derive(Hash::Sha256, Aead::Chacha, &hex(SECRET)).unwrap();
    known(&keys, &SHORT);
    let packet = through(&keys, 654360564, "4200bff4", &[1]);
    assert_eq!(packet, hex(SHORTPACKET));
    assert_eq!(offset(&packet), 1);
    let opened = keys.unprotect(&packet, 1, Some(654360563)).unwrap();
    assert_eq!(opened.number, 654360564);
    assert_eq!(opened.header, hex("4200bff4"));
}

#[test]
fn update() {
    let keys = Keys::derive(Hash::Sha256, Aead::Chacha, &hex(SECRET)).unwrap();
    let next = keys.update().unwrap();
    let ku = "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9";
    let key = "777ec1a510f50ec05d08d554ea5ef34a42c12200bb0f5a59c95908c9cd9189d2";
    assert_eq!(next.secret(), hex(ku));
    assert_eq!(next.key(), hex(key));
    assert_eq!(next.iv(), hex("4159d18afd0156a1e564d16c"));
    assert_eq!(next.hp(), keys.hp());
    let twice = next.update().unwrap();
    assert_eq!(
        twice.secret(),
        hex("ef172661d26526b8adddf9497f88649df5786fa7d2f49a2341da624e8d7f3f94")
    );
    assert_eq!(keys.secret(), hex(SECRET));
}

#[test]
fn widened() {
    let keys = Initial::new(&hex(DCID)).unwrap().client;
    let payload = vec![0x42; 30];
    let packet = through(
        &keys,
        0x1_0000_0002,
        "c300000001088394c8f03e51570800004032 00000002",
        &payload,
    );
    let at = offset(&packet);
    let opened = keys.unprotect(&packet, at, Some(0xffff_ffff)).unwrap();
    assert_eq!(opened.number, 0x1_0000_0002);
    assert!(keys.unprotect(&packet, at, Some(0)).is_err());
    assert!(keys.unprotect(&packet, at, None).is_err());
}

#[test]
fn empty() {
    let keys = Initial::new(&hex(DCID)).unwrap().client;
    let packet = through(
        &keys,
        2,
        "c300000001088394c8f03e51570800004014 00000002",
        &[],
    );
    assert_eq!(packet.len(), 22 + 16);
}

#[test]
fn bits() {
    let keys = Keys::derive(Hash::Sha256, Aead::Chacha, &hex(SECRET)).unwrap();
    let mut short = 0;
    let mut long = 0;
    for number in 0..64u8 {
        let payload = [number, 0, 0, 0];
        let head = hex(&format!("42{number:06x}"));
        let packet = keys.protect(u64::from(number), &head, &payload).unwrap();
        assert_eq!((packet[0] ^ head[0]) & 0xe0, 0, "{number}");
        short |= packet[0] ^ head[0];
        let opened = keys.unprotect(&packet, 1, Some(0)).unwrap();
        assert_eq!(opened.header, head, "{number}");
        let head = hex(&format!("c300000001000000 40ff {number:08x}"));
        let packet = keys.protect(u64::from(number), &head, &payload).unwrap();
        assert_eq!((packet[0] ^ head[0]) & 0xf0, 0, "{number}");
        long |= packet[0] ^ head[0];
        let opened = keys.unprotect(&packet, 10, Some(0)).unwrap();
        assert_eq!(opened.header, head, "{number}");
    }
    assert_eq!((short, long), (0x1f, 0x0f));
}

#[test]
fn phase() {
    let keys = Initial::new(&hex(DCID)).unwrap().client;
    let rows = [
        ("40", "05"),
        ("44", "05"),
        ("41", "0005"),
        ("45", "0005"),
        ("65", "0005"),
        ("43", "00000005"),
        ("47", "00000005"),
    ];
    for (first, number) in rows {
        let head = format!("{first}{number}");
        let packet = through(&keys, 5, &head, &[1, 2, 3, 4]);
        assert_eq!(packet.len(), head.len() / 2 + 4 + 16, "{first}");
    }
}

#[test]
fn wide() {
    let secret = [7u8; 48];
    let keys = Keys::derive(Hash::Sha384, Aead::Aes256, &secret).unwrap();
    let head = hex("42000005");
    let packet = keys.protect(5, &head, b"ping").unwrap();
    let opened = keys.unprotect(&packet, 1, Some(4)).unwrap();
    assert_eq!(
        (opened.number, opened.payload.as_slice()),
        (5, b"ping".as_slice())
    );
    let next = keys.update().unwrap();
    assert!(next.unprotect(&packet, 1, Some(4)).is_err());
    let again = next.protect(6, &hex("42000006"), b"pong").unwrap();
    let peer = Keys::derive(Hash::Sha384, Aead::Aes256, &secret)
        .unwrap()
        .update()
        .unwrap();
    let opened = peer.unprotect(&again, 1, Some(5)).unwrap();
    assert_eq!(opened.payload, b"pong");
}
