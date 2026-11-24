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

use super::{der, pem};
use osistack::http::{Method, Uri};
use osistack::{Client, Roots, load};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

pub fn system() {
    let base = scratch();
    file(&base);
    absent(&base);
    packed(&base);
    vacant();
    refused();
    let _ = fs::remove_dir_all(&base);
}

fn scratch() -> PathBuf {
    let base = std::env::temp_dir().join(format!(
        "osistack-330-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&base).unwrap();
    base
}

fn first() -> (Vec<u8>, String) {
    let der = der("Root A", "Root A", &[], 1);
    let text = pem("CERTIFICATE", &der, 64, "\n");
    (der, text)
}

fn file(base: &Path) {
    let (der, text) = first();
    let path = base.join("ca.pem");
    fs::write(&path, text).unwrap();
    let held = load(Some(&path), None);
    assert_eq!(held.count(), 1);
    assert!(held.contains(&der));
}

fn absent(base: &Path) {
    let missing = base.join("absent.pem");
    assert_eq!(load(Some(&missing), None).count(), 0);
    let folder = base.join("empty");
    fs::create_dir_all(&folder).unwrap();
    fs::write(folder.join("junk"), b"not a certificate").unwrap();
    assert_eq!(load(None, Some(&folder)).count(), 0);
}

fn packed(base: &Path) {
    let (der, text) = first();
    let folder = base.join("certs");
    fs::create_dir_all(&folder).unwrap();
    fs::write(folder.join("one.pem"), text).unwrap();
    fs::write(folder.join("one.der"), der).unwrap();
    fs::write(folder.join("junk"), b"????").unwrap();
    assert_eq!(load(None, Some(&folder)).count(), 1);
}

fn vacant() {
    let folder = scratch();
    assert_eq!(load(None, Some(&folder)).count(), 0);
    let _ = fs::remove_dir_all(&folder);
}

fn refused() {
    let client = Client {
        roots: Roots::default(),
        ..Client::default()
    };
    let uri = Uri::parse("https://example.test/").unwrap();
    let method = Method::new("GET").unwrap();
    let outcome = client.fetch(method, &uri, b"");
    assert!(
        matches!(outcome, Err(osistack::Error::Trust)),
        "{outcome:?}"
    );
}
