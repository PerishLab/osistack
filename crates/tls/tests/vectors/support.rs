use tls::{Content, Extension, Kind, Message, Offer, Record, Reply};

pub const LIMIT: usize = 1 << 16;

pub fn hex(text: &str) -> Vec<u8> {
    let clean: String = text.split_whitespace().collect();
    (0..clean.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&clean[at..at + 2], 16).unwrap())
        .collect()
}

pub fn kinds(extensions: &[Extension]) -> Vec<u16> {
    extensions.iter().map(|extension| extension.kind).collect()
}

pub fn unframe(wire: &[u8]) -> (Record, Message) {
    let (record, used) = Record::parse(wire).unwrap().unwrap();
    assert_eq!(used, wire.len());
    assert_eq!(record.content, Content::Handshake);
    assert_eq!(record.write().unwrap(), wire);
    let (message, taken) = Message::parse(&record.fragment, LIMIT).unwrap().unwrap();
    assert_eq!(taken, record.fragment.len());
    assert_eq!(message.write().unwrap(), record.fragment);
    (record, message)
}

pub fn offer(wire: &[u8]) -> (Record, Offer) {
    let (record, message) = unframe(wire);
    assert_eq!(message.kind, Kind::Offer);
    let offer = Offer::parse(&message.body).unwrap();
    assert_eq!(offer.write().unwrap(), message.body);
    (record, offer)
}

pub fn reply(wire: &[u8]) -> (Record, Reply) {
    let (record, message) = unframe(wire);
    assert_eq!(message.kind, Kind::Reply);
    let reply = Reply::parse(&message.body).unwrap();
    assert_eq!(reply.write().unwrap(), message.body);
    (record, reply)
}
