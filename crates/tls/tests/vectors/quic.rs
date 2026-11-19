use crate::data::*;
use crate::support::*;
use tls::{Kind, Message, Offer, Reply};

#[test]
fn client() {
    let wire = hex(QUICCLIENT);
    assert_eq!(wire.len(), 241);
    let (message, used) = Message::parse(&wire, LIMIT).unwrap().unwrap();
    assert_eq!(
        (message.kind, used, message.body.len()),
        (Kind::Offer, 241, 237)
    );
    assert_eq!(message.write().unwrap(), wire);
    let offer = Offer::parse(&message.body).unwrap();
    assert_eq!(offer.write().unwrap(), message.body);
    assert_eq!(offer.suites, vec![0x1301, 0x1302]);
    let random = "ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c";
    assert_eq!(offer.random.to_vec(), hex(random));
    let expected = [
        0x0000, 0xff01, 0x000a, 0x0010, 0x0005, 0x0033, 0x002b, 0x000d, 0x002d, 0x001c, 0x0039,
    ];
    assert_eq!(kinds(&offer.extensions), expected.to_vec());
}

#[test]
fn server() {
    let wire = hex(QUICSERVER);
    assert_eq!(wire.len(), 90);
    let (message, used) = Message::parse(&wire, LIMIT).unwrap().unwrap();
    assert_eq!(
        (message.kind, used, message.body.len()),
        (Kind::Reply, 90, 86)
    );
    assert_eq!(message.write().unwrap(), wire);
    let reply = Reply::parse(&message.body).unwrap();
    assert_eq!(reply.write().unwrap(), message.body);
    assert_eq!(reply.suite, 0x1301);
    assert_eq!(kinds(&reply.extensions), vec![0x33, 0x2b]);
    assert!(!reply.retry());
}
