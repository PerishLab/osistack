use crypto::Hash;
use tls::{Error, Hello, Kind, Message, Place, Reply, Share, Typed};

const RETRY: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

fn share(group: u16) -> Share {
    Share {
        group,
        key: vec![3; 32],
    }
}

fn hello() -> Hello {
    Hello::start(b"example.test", &[b"h2".to_vec()], share(0x001d), [7u8; 32]).unwrap()
}

fn extensions(items: Vec<Typed>) -> Vec<tls::Extension> {
    items
        .into_iter()
        .map(|item| item.write().unwrap())
        .collect()
}

fn server(suite: u16, group: u16, random: [u8; 32]) -> Reply {
    Reply {
        random,
        session: Vec::new(),
        suite,
        extensions: extensions(vec![
            Typed::Chosen(Share {
                group,
                key: vec![9; 32],
            }),
            Typed::Version(0x0304),
        ]),
    }
}

fn retry(group: u16, cookie: Option<Vec<u8>>) -> Reply {
    let mut items = vec![Typed::Group(group), Typed::Version(0x0304)];
    if let Some(cookie) = cookie {
        items.push(Typed::Cookie(cookie));
    }
    Reply {
        random: RETRY,
        session: Vec::new(),
        suite: 0x1301,
        extensions: extensions(items),
    }
}

fn message(kind: Kind, body: Vec<u8>) -> Vec<u8> {
    Message { kind, body }.write().unwrap()
}

fn joined(parts: &[&[u8]], hash: Hash) -> Vec<u8> {
    let mut data = Vec::new();
    for part in parts {
        data.extend_from_slice(part);
    }
    hash.digest(&data)
}

#[test]
fn accepts() {
    let hello = hello();
    let reply = server(0x1301, 0x001d, [5u8; 32]);
    let spoken = message(Kind::Reply, reply.write().unwrap());
    let accepted = hello.accept(&reply, &[1; 32]).unwrap();
    assert_eq!(
        accepted.digest(),
        joined(&[hello.spoken(), &spoken], Hash::Sha256)
    );
    let schedule = tls::Schedule::new(Hash::Sha256, &[1; 32]).unwrap();
    assert_eq!(
        accepted.client().secret(),
        schedule.client(&accepted.digest()).unwrap().secret()
    );
    assert_eq!(
        accepted.server().secret(),
        schedule.server(&accepted.digest()).unwrap().secret()
    );
}

#[test]
fn switches() {
    let hello = hello();
    let reply = server(0x1302, 0x001d, [5u8; 32]);
    let spoken = message(Kind::Reply, reply.write().unwrap());
    let accepted = hello.accept(&reply, &[1; 48]).unwrap();
    assert_eq!(
        accepted.digest(),
        joined(&[hello.spoken(), &spoken], Hash::Sha384)
    );
    assert_eq!(accepted.digest().len(), 48);
}

#[test]
fn retries() {
    let hello = hello();
    let request = retry(0x0017, Some(vec![8, 9, 10]));
    let second = hello.retry(&request, share(0x0017)).unwrap();
    assert_eq!(second.offer().random, hello.offer().random);
    let offer = second.offer();
    let shares = offer
        .extensions
        .iter()
        .find_map(|item| match Typed::parse(item, Place::Offer).unwrap() {
            Some(Typed::Shares(items)) => Some(items),
            _ => None,
        })
        .unwrap();
    assert_eq!(shares, vec![share(0x0017)]);
    let cookie = offer
        .extensions
        .iter()
        .find_map(|item| match Typed::parse(item, Place::Offer).unwrap() {
            Some(Typed::Cookie(item)) => Some(item),
            _ => None,
        })
        .unwrap();
    assert_eq!(cookie, vec![8, 9, 10]);
    let hashed = message(Kind::Hash, Hash::Sha256.digest(hello.spoken()));
    let asked = message(Kind::Reply, request.write().unwrap());
    assert_eq!(
        second.digest(),
        joined(&[&hashed, &asked, second.spoken()], Hash::Sha256)
    );
    let reply = server(0x1301, 0x0017, [11u8; 32]);
    let spoken = message(Kind::Reply, reply.write().unwrap());
    let accepted = second.accept(&reply, &[2; 32]).unwrap();
    assert_eq!(
        accepted.digest(),
        joined(&[&hashed, &asked, second.spoken(), &spoken], Hash::Sha256)
    );
}

#[test]
fn refused() {
    let hello = hello();
    let request = retry(0x0017, None);
    assert!(matches!(
        hello.accept(&request, &[1; 32]),
        Err(Error::Value)
    ));
    assert!(matches!(
        hello.retry(&server(0x1301, 0x001d, [1; 32]), share(0x0017)),
        Err(Error::Value)
    ));
    assert!(matches!(
        hello.retry(&request, share(0x001d)),
        Err(Error::Value)
    ));
    let mut bad = server(0x1301, 0x0017, [1; 32]);
    assert!(matches!(hello.accept(&bad, &[1; 32]), Err(Error::Value)));
    bad = server(0xc02f, 0x001d, [1; 32]);
    assert!(matches!(hello.accept(&bad, &[1; 32]), Err(Error::Suites)));
}
