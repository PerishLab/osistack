use crate::data::*;
use crate::support::*;
use tls::{Encrypted, Place, Request, Share, Ticket, Typed};

const ALGORITHMS: [u16; 15] = [
    0x0403, 0x0503, 0x0603, 0x0203, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0201, 0x0402,
    0x0502, 0x0602, 0x0202,
];

const GROUPS: [u16; 9] = [
    0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101, 0x0102, 0x0103, 0x0104,
];

fn share(group: u16, key: &str) -> Share {
    Share {
        group,
        key: hex(key),
    }
}

#[test]
fn client() {
    let list = offered(CLIENT, true);
    let host = Typed::Name(Some(b"server".to_vec()));
    check(&list, 0, Place::Offer, host);
    check(&list, 10, Place::Offer, Typed::Groups(GROUPS.to_vec()));
    let key = "99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c";
    let shares = Typed::Shares(vec![share(0x1d, key)]);
    check(&list, 51, Place::Offer, shares);
    check(&list, 43, Place::Offer, Typed::Versions(vec![0x0304]));
    check(
        &list,
        13,
        Place::Offer,
        Typed::Algorithms(ALGORITHMS.to_vec()),
    );
    check(&list, 45, Place::Offer, Typed::Modes(vec![1]));
    for kind in [0xff01, 0x0023, 0x001c] {
        blank(&list, kind, Place::Offer);
    }
}

#[test]
fn server() {
    let list = replied(SERVER, true);
    let key = "c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f";
    check(&list, 51, Place::Reply, Typed::Chosen(share(0x1d, key)));
    check(&list, 43, Place::Reply, Typed::Version(0x0304));
}

#[test]
fn early() {
    let list = offered(EARLY, true);
    check(&list, 42, Place::Offer, Typed::Early(None));
    let found = Typed::parse(find(&list, 41), Place::Offer)
        .unwrap()
        .unwrap();
    let Typed::Offered {
        identities,
        binders,
    } = &found
    else {
        panic!("{found:?}");
    };
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].label.len(), 178);
    assert_eq!(identities[0].age, 0xfad6aacb);
    assert_eq!(binders.len(), 1);
    assert_eq!(binders[0].len(), 32);
    assert_eq!(&found.write().unwrap(), find(&list, 41));
}

#[test]
fn resumed() {
    let list = replied(RESUMED, false);
    check(&list, 41, Place::Reply, Typed::Selected(0));
    check(&list, 43, Place::Reply, Typed::Version(0x0304));
    let key = "121761ee42c333e1b9e77b60dd57c2053cd94512ab47f115e86eff50942cea31";
    check(&list, 51, Place::Reply, Typed::Chosen(share(0x1d, key)));
}

#[test]
fn retry() {
    let list = replied(RETRY, true);
    check(&list, 51, Place::Retry, Typed::Group(0x0017));
    check(&list, 43, Place::Retry, Typed::Version(0x0304));
    let Some(Typed::Cookie(cookie)) = Typed::parse(find(&list, 44), Place::Retry).unwrap() else {
        panic!("cookie");
    };
    assert_eq!(cookie.len(), 114);
    assert_eq!(Typed::Cookie(cookie).write().unwrap(), *find(&list, 44));
}

#[test]
fn second() {
    let list = offered(SECOND, true);
    let Some(Typed::Cookie(cookie)) = Typed::parse(find(&list, 44), Place::Offer).unwrap() else {
        panic!("cookie");
    };
    assert_eq!(cookie.len(), 114);
    let found = Typed::parse(find(&list, 51), Place::Offer)
        .unwrap()
        .unwrap();
    let Typed::Shares(shares) = &found else {
        panic!("{found:?}");
    };
    assert_eq!(
        (shares.len(), shares[0].group, shares[0].key.len()),
        (1, 0x0017, 65)
    );
    assert_eq!(&found.write().unwrap(), find(&list, 51));
}

#[test]
fn last() {
    let list = replied(FINAL, true);
    let found = Typed::parse(find(&list, 51), Place::Reply)
        .unwrap()
        .unwrap();
    let Typed::Chosen(chosen) = &found else {
        panic!("{found:?}");
    };
    assert_eq!((chosen.group, chosen.key.len()), (0x0017, 65));
    assert_eq!(&found.write().unwrap(), find(&list, 51));
    check(&list, 43, Place::Reply, Typed::Version(0x0304));
}

#[test]
fn encrypted() {
    for (text, size) in [(SMALL, 40), (BIG, 44)] {
        assert_eq!(hex(text).len(), size);
        let found = Encrypted::parse(&body(text, false)).unwrap();
        check(
            &found.extensions,
            10,
            Place::Encrypted,
            Typed::Groups(GROUPS.to_vec()),
        );
        check(&found.extensions, 0, Place::Encrypted, Typed::Name(None));
        blank(&found.extensions, 0x1c, Place::Encrypted);
        if size == 44 {
            check(&found.extensions, 42, Place::Encrypted, Typed::Early(None));
        }
    }
}

#[test]
fn ticket() {
    let found = Ticket::parse(&body(TICKET, false)).unwrap();
    check(
        &found.extensions,
        42,
        Place::Ticket,
        Typed::Early(Some(0x400)),
    );
}

#[test]
fn request() {
    let found = Request::parse(&body(REQUEST, false)).unwrap();
    check(
        &found.extensions,
        13,
        Place::Request,
        Typed::Algorithms(ALGORITHMS.to_vec()),
    );
}

#[test]
fn quic() {
    let list = offered(QUICCLIENT, false);
    check(
        &list,
        0,
        Place::Offer,
        Typed::Name(Some(b"example.com".to_vec())),
    );
    check(
        &list,
        10,
        Place::Offer,
        Typed::Groups(vec![0x1d, 0x17, 0x18]),
    );
    check(
        &list,
        16,
        Place::Offer,
        Typed::Protocols(vec![b"alpn".to_vec()]),
    );
    let key = "9370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748";
    check(
        &list,
        51,
        Place::Offer,
        Typed::Shares(vec![share(0x1d, key)]),
    );
    check(&list, 43, Place::Offer, Typed::Versions(vec![0x0304]));
    let seven = vec![0x0403, 0x0503, 0x0603, 0x0203, 0x0804, 0x0805, 0x0806];
    check(&list, 13, Place::Offer, Typed::Algorithms(seven));
    check(&list, 45, Place::Offer, Typed::Modes(vec![1]));
    blank(&list, 0x0005, Place::Offer);
    blank(&list, 0x0039, Place::Offer);
    let reply = replied(QUICSERVER, false);
    let key = "9d3c940d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a";
    check(&reply, 51, Place::Reply, Typed::Chosen(share(0x1d, key)));
    check(&reply, 43, Place::Reply, Typed::Version(0x0304));
}
