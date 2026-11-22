use crate::support::hex;
use crypto::{Aead, Hash};
use tls::{Content, Layer, Schedule};

const DHE: &str = "90726F73F09F6E819A385FF1372056EB25F1182399814DB302C0318B5A03FED8";
const HCLIENT: &str = "448ECF921DD869C578F588F65C1EE26ED53FB669DEC17CFEF48697497C264FC2";
const HSERVER: &str = "2F6169BEE0B6AE5A3A9915519182C92FCB31599D74382BCF54DB75F2D3D6F0DB";
const FSERVER: &str = "6695FABE43799C57C5F2FD4DC8ED0C386BDA814FCA8DC906F8E36CDF78037DED";
const FCLIENT: &str = "0B3A9FF243213D8AF0E1987BB1A84AD3D9EACE88888A89E6C3EBB856208709CA";
const CLIENTHS: &str = "994D4B6C4CBFE65BBED765DDD37829AEA7359CC9A44AEF4BD984B9C0F7C516B1B9A17B78570A44AFB2C1E70447961951";
const SERVERHS: &str = "AC566692327804C5FBAAF4AC880F900BD6B23C9FA1F61B073A50401A5574F80035B721A89C0CECAF4A117895A8BE94F6";
const CLIENTAP: &str = "2F747244C09D8B3056DF955595E4DA251EC92207A109EEEFD0CCF111D0F1AC540E2BD03AB3FB28D8EE24BD33FC6C60C2";
const SERVERAP: &str = "1562AED53988067C226C65EB86F0D9C5FA7BA74C17614EFABC3BCCCA2911A6A6378C378C4B5A4058B3C440DCDECA1AA2";
const EXPORTER: &str = "EBB23721D61CC860C290F2C17F04D5FCC1A6269B476322645B6B4CC059EE7A1898DF058C1812DCB347CC51DC5945013E";
const RESUMPTION: &str = "D03CC399EA36E93F98C7CACE6998E17AFFC225D4274E86F258B5B22375EFA07D01117C7D4D7613B052AE3264AE8397A4";

fn hash(parts: &[&str]) -> Vec<u8> {
    let mut data = Vec::new();
    for part in parts {
        data.extend_from_slice(&hex(part));
    }
    Hash::Sha384.digest(&data)
}

fn schedule() -> Schedule {
    Schedule::new(Hash::Sha384, &hex(DHE)).unwrap()
}

#[test]
fn acvp() {
    let schedule = schedule();
    let hellos = hash(&[HCLIENT, HSERVER]);
    let client = schedule.client(&hellos).unwrap();
    let server = schedule.server(&hellos).unwrap();
    assert_eq!(client.secret(), hex(CLIENTHS));
    assert_eq!(server.secret(), hex(SERVERHS));
    let keys = server.keys(Aead::Aes256).unwrap();
    assert_eq!((keys.key.len(), keys.iv.len()), (32, 12));
    let master = schedule.master().unwrap();
    let done = hash(&[HCLIENT, HSERVER, FSERVER]);
    let client = master.client(&done).unwrap();
    let server = master.server(&done).unwrap();
    assert_eq!(client.secret(), hex(CLIENTAP));
    assert_eq!(server.secret(), hex(SERVERAP));
    assert_eq!(master.exporter(&done).unwrap(), hex(EXPORTER));
    let close = hash(&[HCLIENT, HSERVER, FSERVER, FCLIENT]);
    assert_eq!(master.resumption(&close).unwrap(), hex(RESUMPTION));
}

#[test]
fn records() {
    let schedule = schedule();
    let hellos = hash(&[HCLIENT, HSERVER]);
    let traffic = schedule.server(&hellos).unwrap();
    let keys = traffic.keys(Aead::Aes256).unwrap();
    let mut sender = Layer::new(Aead::Aes256, &keys).unwrap();
    let mut receiver = Layer::new(Aead::Aes256, &keys).unwrap();
    let data = b"sha384 record";
    let record = sender.protect(Content::Application, data, 4).unwrap();
    let opened = receiver.unprotect(&record).unwrap();
    assert_eq!(opened.content, Content::Application);
    assert_eq!(opened.payload, data);
}

#[test]
fn finished() {
    let schedule = schedule();
    let hellos = hash(&[HCLIENT, HSERVER]);
    let server = schedule.server(&hellos).unwrap();
    let client = schedule.client(&hellos).unwrap();
    let transcript = hash(&[HCLIENT, HSERVER, FSERVER]);
    let tag = server.finished(&transcript).unwrap();
    assert_eq!(tag.len(), 48);
    assert!(server.check(&transcript, &tag).is_ok());
    assert!(client.check(&transcript, &tag).is_err());
}
