use crate::behaviour::Check;
use crypto::{Aead, Hash};
use quic::{Header, Initial, Keys, Kind, Long, Number, Short};

pub fn table() -> Vec<(&'static str, Check)> {
    vec![("packet-protection", protection as Check)]
}

fn first(keys: &Keys, text: &[u8], dcid: &[u8]) -> Vec<u8> {
    let number = Number::new(0, None).unwrap();
    let long = Long {
        kind: Kind::Initial,
        dcid: dcid.to_vec(),
        scid: vec![9; 4],
        token: Vec::new(),
        length: (number.length + text.len() + 16) as u64,
        offset: 0,
    };
    keys.protect(0, &long.write(&number).unwrap(), text)
        .unwrap()
}

fn handshake() {
    let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let client = Initial::new(&dcid).unwrap();
    let server = Initial::new(&dcid).unwrap();
    let hello = vec![0x11; 300];
    let packet = first(&client.client, &hello, &dcid);
    let Header::Long(long) = Header::parse(&packet, 8).unwrap() else {
        panic!("not long");
    };
    assert_eq!(long.dcid, dcid);
    let opened = server.client.unprotect(&packet, long.offset, None).unwrap();
    assert_eq!((opened.number, opened.payload), (0, hello));
    assert!(client.client.unprotect(&packet, long.offset, None).is_ok());
    assert!(client.server.unprotect(&packet, long.offset, None).is_err());
    let reply = first(&server.server, b"server hello", &dcid);
    let Header::Long(heard) = Header::parse(&reply, 8).unwrap() else {
        panic!("not long");
    };
    let back = client.server.unprotect(&reply, heard.offset, None).unwrap();
    assert_eq!(back.payload, b"server hello");
}

fn stream(hash: Hash, aead: Aead, seed: u8) {
    let secret = vec![seed; hash.size()];
    let sender = Keys::derive(hash, aead, &secret).unwrap();
    let receiver = Keys::derive(hash, aead, &secret).unwrap();
    let mut largest = Some(0xffff_ffefu64);
    for full in 0xffff_fff0u64..0x1_0000_0010 {
        let number = Number::new(full, largest).unwrap();
        let short = Short {
            spin: false,
            phase: false,
            dcid: vec![4; 8],
            offset: 0,
        };
        let header = short.write(&number).unwrap();
        let text = full.to_be_bytes().to_vec();
        let packet = sender.protect(full, &header, &text).unwrap();
        let opened = receiver.unprotect(&packet, 9, largest).unwrap();
        assert_eq!((opened.number, opened.payload), (full, text), "{aead:?}");
        largest = Some(full);
    }
}

fn rotate(hash: Hash, aead: Aead) {
    let secret = vec![7u8; hash.size()];
    let sender = Keys::derive(hash, aead, &secret).unwrap();
    let receiver = Keys::derive(hash, aead, &secret).unwrap();
    let number = Number::new(5, Some(4)).unwrap();
    let short = Short {
        spin: false,
        phase: true,
        dcid: vec![4; 8],
        offset: 0,
    };
    let header = short.write(&number).unwrap();
    let next = sender.update().unwrap();
    let packet = next.protect(5, &header, b"after update").unwrap();
    assert!(receiver.unprotect(&packet, 9, Some(4)).is_err());
    let moved = receiver.update().unwrap();
    let opened = moved.unprotect(&packet, 9, Some(4)).unwrap();
    assert_eq!(opened.payload, b"after update");
    let mut bad = packet.clone();
    bad[10] ^= 1;
    assert!(moved.unprotect(&bad, 9, Some(4)).is_err());
}

fn protection() {
    handshake();
    for (hash, aead, seed) in [
        (Hash::Sha256, Aead::Aes128, 1),
        (Hash::Sha256, Aead::Chacha, 2),
        (Hash::Sha384, Aead::Aes256, 3),
    ] {
        stream(hash, aead, seed);
        rotate(hash, aead);
    }
}
