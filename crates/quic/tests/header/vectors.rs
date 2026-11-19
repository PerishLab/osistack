use crate::support::*;
use quic::{Header, Kind, Long, Negotiation, Number, Retry, Short};

const CRYPTO: &str = "060040f1010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868
    04fe3a47f06a2b69484c000004130113 02010000c000000010000e00000b6578
    616d706c652e636f6dff01000100000a 00080006001d00170018001000070005
    04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba
    baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400
    0d0010000e0403050306030203080408 050806002d00020101001c0002400100
    3900320408ffffffffffffffff050480 00ffff07048000ffff08011001048000
    75300901100f088394c8f03e51570806 048000ffff";

fn client() -> Header {
    Header::Long(Long {
        kind: Kind::Initial,
        dcid: hex("8394c8f03e515708"),
        scid: Vec::new(),
        token: Vec::new(),
        length: 1182,
        offset: 18,
    })
}

#[test]
fn initial() {
    let head = hex("c300000001088394c8f03e5157080000449e00000002");
    let mut data = head.clone();
    data.extend(hex(CRYPTO));
    let data = fill(&data, 18 + 1182);
    assert_eq!(Header::parse(&data, 8), Ok(client()));
    let number = Number::read(data[0], &data[18..]).unwrap();
    assert_eq!(
        number,
        Number {
            value: 2,
            length: 4
        }
    );
    let Header::Long(long) = client() else {
        panic!()
    };
    assert_eq!(long.write(&number), Ok(head));
}

#[test]
fn protected() {
    let head = hex("c000000001088394c8f03e5157080000449e7b9aec34");
    let data = fill(&head, 18 + 1182);
    assert_eq!(Header::parse(&data, 8), Ok(client()));
}

#[test]
fn server() {
    let head = hex("c1000000010008f067a5502a4262b50040750001");
    let data = fill(&head, 18 + 117);
    let expected = Header::Long(Long {
        kind: Kind::Initial,
        dcid: Vec::new(),
        scid: hex("f067a5502a4262b5"),
        token: Vec::new(),
        length: 117,
        offset: 18,
    });
    assert_eq!(Header::parse(&data, 0), Ok(expected.clone()));
    let number = Number::read(data[0], &data[18..]).unwrap();
    assert_eq!(
        number,
        Number {
            value: 1,
            length: 2
        }
    );
    let Header::Long(long) = expected else {
        panic!()
    };
    assert_eq!(long.write(&number), Ok(head));
}

#[test]
fn retry() {
    let wire = hex("ff000000010008f067a5502a4262b574 6f6b656e04a265ba2eff4d829058fb3f 0f2496ba");
    let retry = Retry {
        unused: 0xf,
        dcid: Vec::new(),
        scid: hex("f067a5502a4262b5"),
        token: b"token".to_vec(),
        tag: hex("04a265ba2eff4d829058fb3f0f2496ba").try_into().unwrap(),
    };
    assert_eq!(Header::parse(&wire, 0), Ok(Header::Retry(retry.clone())));
    assert_eq!(retry.write(), Ok(wire));
}

#[test]
fn short() {
    let head = hex("4200bff4");
    let data = fill(&head, 1 + 3 + 17);
    let expected = Short {
        spin: false,
        phase: false,
        dcid: Vec::new(),
        offset: 1,
    };
    assert_eq!(Header::parse(&data, 0), Ok(Header::Short(expected.clone())));
    let number = Number::read(data[0], &data[1..]).unwrap();
    assert_eq!(
        number,
        Number {
            value: 49140,
            length: 3
        }
    );
    assert_eq!(number.restore(Some(654360563)), 654360564);
    assert_eq!(expected.write(&number), Ok(head));
}

#[test]
fn versions() {
    let wire = hex("80 00000000 04 01020304 02 0a0b 00000001 6b3343cf");
    let expected = Negotiation {
        unused: 0,
        dcid: hex("01020304"),
        scid: hex("0a0b"),
        versions: vec![1, 0x6b3343cf],
    };
    assert_eq!(
        Header::parse(&wire, 0),
        Ok(Header::Negotiation(expected.clone()))
    );
    assert_eq!(expected.write(), Ok(wire));
}
