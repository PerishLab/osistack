mod common;

use common::hex;
use crypto::{Error, Hash, Secret};

const SALT: &str = "38762cf7f55934b34d179ae6a4c80cadccbb7f0a";
const CID: &str = "8394c8f03e515708";
const INITIAL: &str = "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44";

struct Case {
    ikm: String,
    salt: String,
    info: String,
    length: usize,
    okm: &'static str,
}

fn span(from: u8, to: u8) -> String {
    (from..=to).map(|byte| format!("{byte:02x}")).collect()
}

fn rfc5869() -> Vec<Case> {
    vec![
        Case {
            ikm: "0b".repeat(22),
            salt: "000102030405060708090a0b0c".into(),
            info: "f0f1f2f3f4f5f6f7f8f9".into(),
            length: 42,
            okm: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        },
        Case {
            ikm: span(0x00, 0x4f),
            salt: span(0x60, 0xaf),
            info: span(0xb0, 0xff),
            length: 82,
            okm: "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
        },
        Case {
            ikm: "0b".repeat(22),
            salt: String::new(),
            info: String::new(),
            length: 42,
            okm: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        },
    ]
}

const PRK: [&str; 3] = [
    "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
    "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
    "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
];

#[test]
fn rfc5869case() {
    for (at, case) in rfc5869().into_iter().enumerate() {
        let Case {
            ikm,
            salt,
            info,
            length,
            okm,
        } = case;
        let secret = Secret::extract(Hash::Sha256, &hex(&salt), &hex(&ikm)).unwrap();
        let out = secret.expand(&hex(&info), length).unwrap();
        assert_eq!(out, hex(okm), "case {at}");
        let direct = Secret::new(Hash::Sha256, &hex(PRK[at])).unwrap();
        assert_eq!(
            direct.expand(&hex(&info), length).unwrap(),
            hex(okm),
            "case {at}"
        );
    }
}

#[test]
fn limits() {
    let secret = Secret::new(Hash::Sha256, &[7; 32]).unwrap();
    assert_eq!(secret.expand(b"info", 255 * 32).unwrap().len(), 255 * 32);
    assert_eq!(secret.expand(b"info", 255 * 32 + 1), Err(Error::Length));
    assert!(secret.expand(b"info", 0).unwrap().is_empty());
    assert_eq!(secret.expand(b"info", 33).unwrap().len(), 33);
    let long = secret.expand(b"info", 100).unwrap();
    assert_eq!(secret.expand(b"info", 40).unwrap(), long[..40]);
    assert_ne!(secret.expand(b"other", 40).unwrap(), long[..40]);
    assert_eq!(
        Secret::new(Hash::Sha256, &[7; 31]).err(),
        Some(Error::Length)
    );
    assert!(Secret::new(Hash::Sha256, &[7; 64]).is_ok());
}

fn initial() -> Secret {
    Secret::extract(Hash::Sha256, &hex(SALT), &hex(CID)).unwrap()
}

#[test]
fn rfc9001() {
    let secret = initial();
    let client = secret.label(b"client in", b"", 32).unwrap();
    assert_eq!(
        client,
        hex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
    );
    let server = secret.label(b"server in", b"", 32).unwrap();
    assert_eq!(
        server,
        hex("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
    );
    let sides = [
        (
            &client,
            "1f369613dd76d5467730efcbe3b1a22d",
            "fa044b2f42a3fd3b46fb255c",
        ),
        (
            &server,
            "cf3a5331653c364c88f0f379b6067e37",
            "0ac1493ca1905853b0bba03e",
        ),
    ];
    let heads = [
        "9f50449e04a0e810283a1e9933adedd2",
        "c206b8d9b9f0f37644430b490eeaa314",
    ];
    for ((secret, key, iv), hp) in sides.into_iter().zip(heads) {
        let side = Secret::new(Hash::Sha256, secret).unwrap();
        assert_eq!(side.label(b"quic key", b"", 16).unwrap(), hex(key));
        assert_eq!(side.label(b"quic iv", b"", 12).unwrap(), hex(iv));
        assert_eq!(side.label(b"quic hp", b"", 16).unwrap(), hex(hp));
    }
}

#[test]
fn extracted() {
    let direct = Secret::new(Hash::Sha256, &hex(INITIAL)).unwrap();
    let client = direct.label(b"client in", b"", 32).unwrap();
    assert_eq!(client, initial().label(b"client in", b"", 32).unwrap());
}

#[test]
fn rfc9001chacha() {
    let secret = hex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
    let side = Secret::new(Hash::Sha256, &secret).unwrap();
    let key = side.label(b"quic key", b"", 32).unwrap();
    assert_eq!(
        key,
        hex("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8")
    );
    let iv = side.label(b"quic iv", b"", 12).unwrap();
    assert_eq!(iv, hex("e0459b3474bdd0e44a41c144"));
    let hp = side.label(b"quic hp", b"", 32).unwrap();
    assert_eq!(
        hp,
        hex("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4")
    );
    let ku = side.label(b"quic ku", b"", 32).unwrap();
    assert_eq!(
        ku,
        hex("1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9")
    );
}

#[test]
fn encoding() {
    let secret = initial();
    let label = secret.label(b"abc", b"xyz", 20).unwrap();
    let info = [&[0, 20, 9][..], b"tls13 abc", &[3], b"xyz"].concat();
    assert_eq!(label, secret.expand(&info, 20).unwrap());
    let empty = secret.label(b"", b"", 8).unwrap();
    let plain = [&[0, 8, 6][..], b"tls13 ", &[0]].concat();
    assert_eq!(empty, secret.expand(&plain, 8).unwrap());
}

#[test]
fn bounds() {
    let secret = initial();
    assert!(secret.label(&[b'a'; 249], b"", 8).is_ok());
    assert_eq!(secret.label(&[b'a'; 250], b"", 8), Err(Error::Length));
    assert!(secret.label(b"x", &[0; 255], 8).is_ok());
    assert_eq!(secret.label(b"x", &[0; 256], 8), Err(Error::Length));
    assert_eq!(secret.label(b"x", b"", 65536), Err(Error::Length));
    assert_eq!(secret.label(b"x", b"", 255 * 32 + 1), Err(Error::Length));
    assert_ne!(
        secret.label(b"x", b"a", 8).unwrap(),
        secret.label(b"x", b"b", 8).unwrap()
    );
    assert_ne!(
        secret.label(b"x", b"", 8).unwrap(),
        secret.label(b"y", b"", 8).unwrap()
    );
}

#[test]
fn wide() {
    let secret = Secret::extract(Hash::Sha384, b"salt", b"ikm").unwrap();
    let out = secret.label(b"key", b"", 32).unwrap();
    assert_eq!(out.len(), 32);
    let prk = Secret::new(Hash::Sha384, &[7; 48]).unwrap();
    assert_eq!(prk.label(b"key", b"", 32).unwrap().len(), 32);
    assert_eq!(
        Secret::new(Hash::Sha384, &[7; 47]).err(),
        Some(Error::Length)
    );
}

#[test]
fn others() {
    assert_eq!(
        Secret::extract(Hash::Sha512, b"salt", b"ikm").err(),
        Some(Error::Unsupported)
    );
    assert_eq!(
        Secret::new(Hash::Sha512, &[0; 64]).err(),
        Some(Error::Unsupported)
    );
}
