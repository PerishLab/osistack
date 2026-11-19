use crate::data::*;
use crate::support::*;
use tls::{Content, Record};

#[test]
fn sealed() {
    let wire = hex(FINISHED);
    assert_eq!(wire.len(), 58);
    let (record, used) = Record::parse(&wire).unwrap().unwrap();
    assert_eq!(used, 58);
    assert_eq!(record.content, Content::Application);
    assert_eq!(record.version, 0x0303);
    assert_eq!(record.fragment.len(), 53);
    assert_eq!(record.write().unwrap(), wire);
}

#[test]
fn bulk() {
    let wire = hex(PAYLOAD);
    assert_eq!(wire.len(), 72);
    let (record, used) = Record::parse(&wire).unwrap().unwrap();
    assert_eq!(used, 72);
    assert_eq!(record.content, Content::Application);
    assert_eq!(record.fragment.len(), 67);
    assert_eq!(record.write().unwrap(), wire);
}
