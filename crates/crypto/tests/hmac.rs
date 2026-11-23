mod common;

use common::hex;
use crypto::{Error, Hash, hmac};

fn cases() -> Vec<(String, String, &'static str)> {
    let text =
        |bytes: &[u8]| -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() };
    vec![
        (
            "0b".repeat(20),
            text(b"Hi There"),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        ),
        (
            text(b"Jefe"),
            text(b"what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        ),
        (
            "aa".repeat(20),
            "dd".repeat(50),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
        ),
        (
            text(&(1..=25).collect::<Vec<u8>>()),
            "cd".repeat(50),
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
        ),
        (
            "aa".repeat(131),
            text(b"Test Using Larger Than Block-Size Key - Hash Key First"),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        ),
    ]
}

#[test]
fn rfc4231() {
    for (at, (key, data, tag)) in cases().into_iter().enumerate() {
        let tag = hex(tag);
        let signed = hmac::sign(Hash::Sha256, &hex(&key), &hex(&data)).unwrap();
        assert_eq!(signed, tag, "case {at}");
        assert_eq!(
            hmac::verify(Hash::Sha256, &hex(&key), &hex(&data), &tag),
            Ok(())
        );
    }
}

#[test]
fn tampered() {
    let (key, data, tag) = cases().swap_remove(1);
    let (key, data, tag) = (hex(&key), hex(&data), hex(tag));
    let verify = |key: &[u8], data: &[u8], tag: &[u8]| hmac::verify(Hash::Sha256, key, data, tag);
    for at in 0..tag.len() {
        let mut flipped = tag.clone();
        flipped[at] ^= 1;
        assert_eq!(verify(&key, &data, &flipped), Err(Error::Auth), "{at}");
    }
    assert_eq!(verify(&key, &data, &tag[..31]), Err(Error::Auth));
    assert_eq!(
        verify(&key, &data, &[tag.clone(), vec![0]].concat()),
        Err(Error::Auth)
    );
    assert_eq!(verify(&key, &data, &[]), Err(Error::Auth));
    assert_eq!(verify(&key, b"other", &tag), Err(Error::Auth));
    assert_eq!(verify(b"Jeff", &data, &tag), Err(Error::Auth));
}

fn wide() -> Vec<(String, String, &'static str)> {
    let text =
        |bytes: &[u8]| -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() };
    vec![
        (
            "0b".repeat(20),
            text(b"Hi There"),
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
        ),
        (
            text(b"Jefe"),
            text(b"what do ya want for nothing?"),
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
        ),
        (
            "aa".repeat(20),
            "dd".repeat(50),
            "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27",
        ),
        (
            text(&(1..=25).collect::<Vec<u8>>()),
            "cd".repeat(50),
            "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb",
        ),
        (
            "aa".repeat(131),
            text(b"Test Using Larger Than Block-Size Key - Hash Key First"),
            "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952",
        ),
    ]
}

#[test]
fn sha384() {
    for (at, (key, data, tag)) in wide().into_iter().enumerate() {
        let tag = hex(tag);
        let signed = hmac::sign(Hash::Sha384, &hex(&key), &hex(&data)).unwrap();
        assert_eq!(signed, tag, "case {at}");
        assert_eq!(
            hmac::verify(Hash::Sha384, &hex(&key), &hex(&data), &tag),
            Ok(())
        );
    }
}

#[test]
fn sha512() {
    let cases = [
        (
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "4869205468657265",
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
        ),
        (
            "4a656665",
            "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
        ),
    ];
    for (at, (key, data, tag)) in cases.into_iter().enumerate() {
        let tag = hex(tag);
        let signed = hmac::sign(Hash::Sha512, &hex(key), &hex(data)).unwrap();
        assert_eq!(signed, tag, "case {at}");
        assert_eq!(
            hmac::verify(Hash::Sha512, &hex(key), &hex(data), &tag),
            Ok(())
        );
        let mut flipped = tag.clone();
        flipped[0] ^= 1;
        assert_eq!(
            hmac::verify(Hash::Sha512, &hex(key), &hex(data), &flipped),
            Err(Error::Auth)
        );
    }
}
