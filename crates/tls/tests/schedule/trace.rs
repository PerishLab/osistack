use crate::data::*;
use crate::support::*;
use crypto::Aead;
use tls::Keys;

fn keys(key: &str, iv: &str) -> Keys {
    Keys {
        key: hex(key),
        iv: hex(iv),
    }
}

#[test]
fn handshake() {
    let schedule = schedule(SHARED);
    let client = schedule.client(&hex(HELLOS)).unwrap();
    let server = schedule.server(&hex(HELLOS)).unwrap();
    assert_eq!(client.secret(), hex(CHS));
    assert_eq!(server.secret(), hex(SHS));
    assert_eq!(server.keys(Aead::Aes128).unwrap(), keys(SHSKEY, SHSIV));
    assert_eq!(client.keys(Aead::Aes128).unwrap(), keys(CHSKEY, CHSIV));
}

#[test]
fn application() {
    let master = master(SHARED);
    let client = master.client(&hex(SERVERDONE)).unwrap();
    let server = master.server(&hex(SERVERDONE)).unwrap();
    assert_eq!(client.secret(), hex(CAP));
    assert_eq!(server.secret(), hex(SAP));
    assert_eq!(client.keys(Aead::Aes128).unwrap(), keys(CAPKEY, CAPIV));
    assert_eq!(server.keys(Aead::Aes128).unwrap(), keys(SAPKEY, SAPIV));
    assert_eq!(master.exporter(&hex(SERVERDONE)).unwrap(), hex(EXPORTER));
    assert_eq!(
        master.resumption(&hex(CLIENTDONE)).unwrap(),
        hex(RESUMPTION)
    );
}

#[test]
fn finished() {
    let schedule = schedule(SHARED);
    let server = schedule.server(&hex(HELLOS)).unwrap();
    let client = schedule.client(&hex(HELLOS)).unwrap();
    assert_eq!(server.finished(&hex(VERIFIED)).unwrap(), hex(SERVERFIN));
    assert_eq!(client.finished(&hex(SERVERDONE)).unwrap(), hex(CLIENTFIN));
    assert!(server.check(&hex(VERIFIED), &hex(SERVERFIN)).is_ok());
    assert!(client.check(&hex(SERVERDONE), &hex(CLIENTFIN)).is_ok());
}

#[test]
fn wide() {
    let server = schedule(SHARED).server(&hex(HELLOS)).unwrap();
    let wanted = hex(SHSWIDE);
    for aead in [Aead::Aes256, Aead::Chacha] {
        let made = server.keys(aead).unwrap();
        assert_eq!(made.key, wanted, "{aead:?}");
        assert_eq!(made.iv, hex(SHSIV), "{aead:?}");
    }
}

#[test]
fn updates() {
    let master = master(SHARED);
    let server = master.server(&hex(SERVERDONE)).unwrap();
    let next = server.update().unwrap();
    assert_eq!(next.secret(), hex(UPDATED));
    assert_eq!(
        next.keys(Aead::Aes128).unwrap(),
        keys(UPDATEDKEY, UPDATEDIV)
    );
    assert_eq!(next.update().unwrap().secret(), hex(TWICE));
    assert_eq!(server.secret(), hex(SAP));
}
