mod common;

use common::hex;
use crypto::{Aead, Error};

const PLAIN: &str = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
const AAD: &str = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
const NONCE: &str = "cafebabefacedbaddecaf888";

struct Known {
    aead: Aead,
    key: &'static str,
    cipher: &'static str,
    tag: &'static str,
}

const GCM: [Known; 2] = [
    Known {
        aead: Aead::Aes128,
        key: "feffe9928665731c6d6a8f9467308308",
        cipher: "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        tag: "5bc94fbc3221a5db94fae95ae7121a47",
    },
    Known {
        aead: Aead::Aes256,
        key: "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        cipher: "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        tag: "76fc6ece0f4e1768cddf8853bb2d551b",
    },
];

const SUNSCREEN: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

const CHACHA: &str = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116";

fn nonce(text: &str) -> [u8; 12] {
    hex(text).try_into().unwrap()
}

struct Rfc8439 {
    key: Vec<u8>,
    nonce: [u8; 12],
    aad: Vec<u8>,
}

fn chacha() -> Rfc8439 {
    let key: Vec<u8> = (0x80..0xa0).collect();
    Rfc8439 {
        key,
        nonce: nonce("070000004041424344454647"),
        aad: hex("50515253c0c1c2c3c4c5c6c7"),
    }
}

#[test]
fn gcm() {
    for known in GCM {
        let Known {
            aead,
            key,
            cipher,
            tag,
        } = known;
        let sealer = aead.cipher(&hex(key)).unwrap();
        let mut data = hex(PLAIN);
        let made = sealer.seal(&nonce(NONCE), &hex(AAD), &mut data).unwrap();
        assert_eq!(data, hex(cipher), "{aead:?}");
        assert_eq!(made.to_vec(), hex(tag), "{aead:?}");
        sealer
            .open(&nonce(NONCE), &hex(AAD), &mut data, &made)
            .unwrap();
        assert_eq!(data, hex(PLAIN), "{aead:?}");
    }
}

#[test]
fn rfc8439() {
    let Rfc8439 {
        key,
        nonce: number,
        aad,
    } = chacha();
    let sealer = Aead::Chacha.cipher(&key).unwrap();
    let mut data = SUNSCREEN.to_vec();
    let tag = sealer.seal(&number, &aad, &mut data).unwrap();
    assert_eq!(data, hex(CHACHA));
    assert_eq!(tag.to_vec(), hex("1ae10b594f09e26a7e902ecbd0600691"));
    sealer.open(&number, &aad, &mut data, &tag).unwrap();
    assert_eq!(data, SUNSCREEN);
}

#[test]
fn short() {
    let key = hex("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8");
    let sealer = Aead::Chacha.cipher(&key).unwrap();
    let mut data = vec![1u8];
    let tag = sealer
        .seal(
            &nonce("e0459b3474bdd0e46d417eb0"),
            &hex("4200bff4"),
            &mut data,
        )
        .unwrap();
    let whole = [data, tag.to_vec()].concat();
    assert_eq!(whole, hex("655e5cd55c41f69080575d7999c25a5bfb"));
}

#[test]
fn tampers() {
    let Rfc8439 {
        key,
        nonce: number,
        aad,
    } = chacha();
    let keys = [vec![7u8; 16], vec![7u8; 32], key];
    let kinds = [Aead::Aes128, Aead::Aes256, Aead::Chacha];
    for (aead, key) in kinds.into_iter().zip(keys) {
        let cipher = aead.cipher(&key).unwrap();
        let mut sealed = SUNSCREEN.to_vec();
        let tag = cipher.seal(&number, &aad, &mut sealed).unwrap();
        let open = |nonce: &[u8; 12], aad: &[u8], data: &[u8], tag: &[u8]| {
            let mut copy = data.to_vec();
            cipher.open(nonce, aad, &mut copy, tag)
        };
        assert_eq!(open(&number, &aad, &sealed, &tag), Ok(()), "{aead:?}");
        let mut text = sealed.clone();
        text[3] ^= 1;
        assert_eq!(
            open(&number, &aad, &text, &tag),
            Err(Error::Auth),
            "{aead:?}"
        );
        let mut other = tag;
        other[15] ^= 0x80;
        assert_eq!(
            open(&number, &aad, &sealed, &other),
            Err(Error::Auth),
            "{aead:?}"
        );
        assert_eq!(
            open(&number, b"other", &sealed, &tag),
            Err(Error::Auth),
            "{aead:?}"
        );
        let mut moved = number;
        moved[11] ^= 1;
        assert_eq!(
            open(&moved, &aad, &sealed, &tag),
            Err(Error::Auth),
            "{aead:?}"
        );
        assert_eq!(
            open(&number, &aad, &sealed, &tag[..15]),
            Err(Error::Length),
            "{aead:?}"
        );
        assert_eq!(
            open(&number, &aad, &sealed, &[]),
            Err(Error::Length),
            "{aead:?}"
        );
        let long = [tag.to_vec(), vec![0]].concat();
        assert_eq!(
            open(&number, &aad, &sealed, &long),
            Err(Error::Length),
            "{aead:?}"
        );
    }
}

#[test]
fn keys() {
    let wanted = [(Aead::Aes128, 16), (Aead::Aes256, 32), (Aead::Chacha, 32)];
    for (aead, size) in wanted {
        assert_eq!(aead.key(), size, "{aead:?}");
        assert!(aead.cipher(&vec![0; size]).is_ok());
        for wrong in [0, 1, 16, size - 1, size + 1, 32, 48, 64] {
            if wrong != size {
                let made = aead.cipher(&vec![0; wrong]);
                assert_eq!(made.err(), Some(Error::Length), "{aead:?} {wrong}");
            }
        }
    }
    assert_eq!((Aead::NONCE, Aead::TAG), (12, 16));
}

#[test]
fn empty() {
    for (aead, size) in [(Aead::Aes128, 16), (Aead::Aes256, 32), (Aead::Chacha, 32)] {
        let cipher = aead.cipher(&vec![9; size]).unwrap();
        let number = [3u8; 12];
        let mut nothing = [0u8; 0];
        let tag = cipher.seal(&number, b"header", &mut nothing).unwrap();
        assert_eq!(cipher.open(&number, b"header", &mut nothing, &tag), Ok(()));
        assert_eq!(
            cipher.open(&number, b"other", &mut nothing, &tag),
            Err(Error::Auth)
        );
    }
}

#[test]
#[ignore = "wycheproof"]
fn proving() {
    let Some(aes) = common::cases::rows("aes_gcm_test.txt") else {
        return;
    };
    let Some(chacha) = common::cases::rows("chacha20_poly1305_test.txt") else {
        return;
    };
    assert!(checked(Aead::Aes128, &aes) > 0);
    assert!(checked(Aead::Aes256, &aes) > 0);
    assert!(checked(Aead::Chacha, &chacha) > 0);
}

fn checked(aead: Aead, rows: &[common::cases::Case]) -> usize {
    let mut seen = 0;
    for case in rows {
        let key = case.bytes("key");
        let iv = case.bytes("iv");
        if key.len() != aead.key() || iv.len() != Aead::NONCE {
            continue;
        }
        let nonce: [u8; 12] = iv.try_into().unwrap();
        let aad = case.bytes("aad");
        let tag = case.bytes("tag");
        let cipher = aead.cipher(&key).unwrap();
        seen += 1;
        if case.result() == "valid" {
            let mut data = case.bytes("msg");
            let made = cipher.seal(&nonce, &aad, &mut data).unwrap();
            assert_eq!(
                (data, made.as_slice()),
                (case.bytes("ct"), tag.as_slice()),
                "{}",
                case.id
            );
            let mut data = case.bytes("ct");
            cipher.open(&nonce, &aad, &mut data, &tag).unwrap();
            assert_eq!(data, case.bytes("msg"), "{}", case.id);
        } else {
            let mut data = case.bytes("ct");
            assert!(
                cipher.open(&nonce, &aad, &mut data, &tag).is_err(),
                "{}",
                case.id
            );
        }
    }
    seen
}
