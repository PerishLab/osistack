use tls::{Content, Error, Kind, Message, Record};

#[test]
fn content() {
    for code in [0u8, 19, 24, 25, 255] {
        let header = [code, 3, 3, 0, 0];
        assert_eq!(Record::parse(&header), Err(Error::Kind), "{code}");
        assert_eq!(Record::parse(&header[..1]), Err(Error::Kind), "{code}");
    }
    for code in [20u8, 21, 22, 23] {
        assert_eq!(Record::parse(&[code, 3, 3, 0, 0]).unwrap().unwrap().1, 5);
    }
    assert_eq!(Record::parse(&[]), Ok(None));
}

#[test]
fn oversize() {
    assert_eq!(Record::parse(&[22, 3, 3, 0x41, 0x01]), Err(Error::Length));
    assert_eq!(Record::parse(&[22, 3, 3, 0xff, 0xff]), Err(Error::Length));
    assert_eq!(Record::parse(&[22, 3, 3, 0x41, 0x00]), Ok(None));
    let mut full = vec![23, 3, 3, 0x41, 0x00];
    full.resize(5 + 16640, 0);
    let (record, used) = Record::parse(&full).unwrap().unwrap();
    assert_eq!((record.fragment.len(), used), (16640, 5 + 16640));
}

#[test]
fn version() {
    let data = [22, 0x12, 0x34, 0, 1, 9];
    let (record, _) = Record::parse(&data).unwrap().unwrap();
    assert_eq!(record.version, 0x1234);
    assert_eq!(record.write().unwrap(), data.to_vec());
    assert_eq!(record.content, Content::Handshake);
}

#[test]
fn types() {
    for code in [0u8, 3, 6, 7, 9, 10, 12, 14, 16, 19, 21, 25, 253, 255] {
        let header = [code, 0, 0, 0];
        assert_eq!(Message::parse(&header, 255), Err(Error::Kind), "{code}");
        assert_eq!(
            Message::parse(&header[..1], 255),
            Err(Error::Kind),
            "{code}"
        );
    }
    let known = [1u8, 2, 4, 5, 8, 11, 13, 15, 20, 24, 254];
    for code in known {
        let found = Message::parse(&[code, 0, 0, 0], 255).unwrap().unwrap();
        assert_eq!(found.0.body.len(), 0, "{code}");
    }
    assert_eq!(Message::parse(&[], 255), Ok(None));
}

#[test]
fn limit() {
    assert_eq!(Message::parse(&[1, 0, 1, 0], 255), Err(Error::Length));
    assert_eq!(
        Message::parse(&[1, 0xff, 0xff, 0xff], 255),
        Err(Error::Length)
    );
    assert_eq!(Message::parse(&[1, 0, 0, 255], 255), Ok(None));
    let mut full = vec![1, 0, 0, 255];
    full.resize(4 + 255, 0);
    let (message, used) = Message::parse(&full, 255).unwrap().unwrap();
    assert_eq!(
        (message.kind, message.body.len(), used),
        (Kind::Offer, 255, 259)
    );
}
