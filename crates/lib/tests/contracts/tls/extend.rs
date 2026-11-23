use crate::behaviour::Check;
use tls::{Error, Kind, Message, Offer, Place, Typed};

pub fn table() -> Vec<(&'static str, Check)> {
    vec![("sni", sni as Check), ("alpn", alpn as Check)]
}

fn offer(typed: Typed) -> Offer {
    Offer {
        random: [7; 32],
        session: Vec::new(),
        suites: vec![0x1301],
        extensions: vec![typed.write().unwrap()],
    }
}

fn round(typed: Typed) -> Typed {
    let hello = offer(typed);
    let message = Message {
        kind: Kind::Offer,
        body: hello.write().unwrap(),
    };
    let wire = message.write().unwrap();
    let (parsed, used) = Message::parse(&wire, 1 << 16).unwrap().unwrap();
    assert_eq!((parsed.kind, used), (Kind::Offer, wire.len()));
    let again = Offer::parse(&parsed.body).unwrap();
    Typed::parse(&again.extensions[0], Place::Offer)
        .unwrap()
        .unwrap()
}

fn sni() {
    let host = b"example.test".to_vec();
    let typed = Typed::Name(Some(host.clone()));
    assert_eq!(round(typed), Typed::Name(Some(host)));
    assert_eq!(Typed::Name(Some(vec![])).write(), Err(Error::Length));
    let mut cut = Typed::Name(Some(b"ok".to_vec())).write().unwrap();
    cut.data.truncate(cut.data.len() - 1);
    assert!(Typed::parse(&cut, Place::Offer).is_err());
}

fn alpn() {
    let names = vec![b"h3".to_vec(), b"h2".to_vec()];
    assert_eq!(
        round(Typed::Protocols(names.clone())),
        Typed::Protocols(names)
    );
    assert_eq!(Typed::Protocols(vec![]).write(), Err(Error::Length));
    assert_eq!(Typed::Protocols(vec![vec![]]).write(), Err(Error::Length));
    let mut cut = Typed::Protocols(vec![b"h2".to_vec()]).write().unwrap();
    cut.data.truncate(cut.data.len() - 1);
    assert!(Typed::parse(&cut, Place::Offer).is_err());
}
