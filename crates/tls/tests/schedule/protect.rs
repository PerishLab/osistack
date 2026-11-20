use crate::data::*;
use crate::support::{hex, master, schedule};
use crypto::Aead;
use tls::{Content, Keys, Layer, Opened, Record};

fn keys(key: &str, iv: &str) -> Keys {
    Keys {
        key: hex(key),
        iv: hex(iv),
    }
}

fn layer(key: &str, iv: &str) -> Layer {
    Layer::new(Aead::Aes128, &keys(key, iv)).unwrap()
}

fn wire(record: &str) -> Record {
    let data = hex(record);
    let (record, used) = Record::parse(&data).unwrap().unwrap();
    assert_eq!(used, data.len());
    record
}

fn opened(content: Content, plain: &str) -> Opened {
    Opened {
        content,
        payload: hex(plain),
    }
}

fn check(layer: &mut Layer, record: &str, content: Content, plain: &str) {
    let made = wire(record);
    assert_eq!(layer.unprotect(&made).unwrap(), opened(content, plain));
}

fn round(layer: &mut Layer, record: &str, content: Content, plain: &str) {
    let want = hex(record);
    let data = hex(plain);
    assert_eq!(
        layer.protect(content, &data, 0).unwrap().write().unwrap(),
        want
    );
}

#[test]
fn traces() {
    let mut server = layer(SHSKEY, SHSIV);
    check(&mut server, SERVERHS, Content::Handshake, SERVERHSPLAIN);
    let mut client = layer(CHSKEY, CHSIV);
    check(&mut client, CLIENTHS, Content::Handshake, CLIENTHSPLAIN);
    let mut writer = layer(SAPKEY, SAPIV);
    check(
        &mut writer,
        SERVERTICKET,
        Content::Handshake,
        SERVERTICKETPLAIN,
    );
    check(&mut writer, SERVERAPP, Content::Application, SERVERAPPPLAIN);
    check(&mut writer, SERVERALERT, Content::Alert, SERVERALERTPLAIN);
    let mut reader = layer(CAPKEY, CAPIV);
    check(&mut reader, CLIENTAPP, Content::Application, CLIENTAPPPLAIN);
    check(&mut reader, CLIENTALERT, Content::Alert, CLIENTALERTPLAIN);
}

#[test]
fn sealed() {
    let mut server = layer(SHSKEY, SHSIV);
    round(&mut server, SERVERHS, Content::Handshake, SERVERHSPLAIN);
    let mut client = layer(CHSKEY, CHSIV);
    round(&mut client, CLIENTHS, Content::Handshake, CLIENTHSPLAIN);
    let mut writer = layer(SAPKEY, SAPIV);
    round(
        &mut writer,
        SERVERTICKET,
        Content::Handshake,
        SERVERTICKETPLAIN,
    );
    round(&mut writer, SERVERAPP, Content::Application, SERVERAPPPLAIN);
    round(&mut writer, SERVERALERT, Content::Alert, SERVERALERTPLAIN);
    let mut reader = layer(CAPKEY, CAPIV);
    round(&mut reader, CLIENTAPP, Content::Application, CLIENTAPPPLAIN);
    round(&mut reader, CLIENTALERT, Content::Alert, CLIENTALERTPLAIN);
}

#[test]
fn padded() {
    let mut sender = layer(CAPKEY, CAPIV);
    let mut receiver = layer(CAPKEY, CAPIV);
    let data = hex(CLIENTAPPPLAIN);
    let record = sender.protect(Content::Application, &data, 32).unwrap();
    assert_eq!(record.fragment.len(), data.len() + 1 + 32 + 16);
    assert_eq!(
        receiver.unprotect(&record).unwrap(),
        Opened {
            content: Content::Application,
            payload: data,
        }
    );
    assert_ne!(record.write().unwrap(), hex(CLIENTAPP));
}

#[test]
fn counted() {
    let mut first = layer(CAPKEY, CAPIV);
    let mut second = layer(CAPKEY, CAPIV);
    let one = first.protect(Content::Application, b"one", 0).unwrap();
    let two = first.protect(Content::Application, b"two", 0).unwrap();
    assert_ne!(one.fragment, two.fragment);
    assert_eq!(second.unprotect(&one).unwrap().payload, b"one");
    assert_eq!(second.unprotect(&two).unwrap().payload, b"two");
}

#[test]
fn derived() {
    let client = schedule(SHARED).client(&hex(HELLOS)).unwrap();
    let mut layer = Layer::new(Aead::Aes128, &client.keys(Aead::Aes128).unwrap()).unwrap();
    check(&mut layer, CLIENTHS, Content::Handshake, CLIENTHSPLAIN);
    let server = master(SHARED).server(&hex(SERVERDONE)).unwrap();
    let mut layer = Layer::new(Aead::Aes128, &server.keys(Aead::Aes128).unwrap()).unwrap();
    check(
        &mut layer,
        SERVERTICKET,
        Content::Handshake,
        SERVERTICKETPLAIN,
    );
}
