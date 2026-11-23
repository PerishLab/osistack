use crypto::Hash;
use tls::{Error, Hello, Kind, Message, Offer, Place, Share, Typed};

fn share() -> Share {
    Share {
        group: 0x001d,
        key: vec![1; 32],
    }
}

fn start() -> Hello {
    Hello::start(
        b"example.test",
        &[b"h2".to_vec(), b"http/1.1".to_vec()],
        share(),
        [7u8; 32],
    )
    .unwrap()
}

fn typed(offer: &Offer, kind: u16) -> Typed {
    let found = offer
        .extensions
        .iter()
        .find(|item| item.kind == kind)
        .unwrap();
    Typed::parse(found, Place::Offer).unwrap().unwrap()
}

#[test]
fn starts() {
    let hello = start();
    let (message, used) = Message::parse(hello.spoken(), 1 << 16).unwrap().unwrap();
    assert_eq!(used, hello.spoken().len());
    assert_eq!(message.kind, Kind::Offer);
    let offer = Offer::parse(&message.body).unwrap();
    assert_eq!(offer, *hello.offer());
    assert_eq!(offer.random, [7u8; 32]);
    assert_eq!(offer.suites, vec![0x1301, 0x1303, 0x1302]);
    assert_eq!(
        typed(&offer, 0),
        Typed::Name(Some(b"example.test".to_vec()))
    );
    assert_eq!(typed(&offer, 10), Typed::Groups(vec![0x001d]));
    assert_eq!(
        typed(&offer, 16),
        Typed::Protocols(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
    );
    assert_eq!(typed(&offer, 43), Typed::Versions(vec![0x0304]));
    assert_eq!(typed(&offer, 51), Typed::Shares(vec![share()]));
    assert_eq!(hello.digest(), Hash::Sha256.digest(hello.spoken()));
}

#[test]
fn refused() {
    let protocols = [b"h2".to_vec()];
    assert!(matches!(
        Hello::start(b"", &protocols, share(), [0; 32]),
        Err(Error::Length)
    ));
    assert!(matches!(
        Hello::start(b"a", &[], share(), [0; 32]),
        Err(Error::Length)
    ));
    let empty = Share {
        group: 0x001d,
        key: Vec::new(),
    };
    assert!(matches!(
        Hello::start(b"a", &protocols, empty, [0; 32]),
        Err(Error::Length)
    ));
}
