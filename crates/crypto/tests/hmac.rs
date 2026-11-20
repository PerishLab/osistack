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

#[test]
fn others() {
    for hash in [Hash::Sha384, Hash::Sha512] {
        assert_eq!(hmac::sign(hash, b"key", b"data"), Err(Error::Unsupported));
        assert_eq!(
            hmac::verify(hash, b"key", b"data", &[0; 48]),
            Err(Error::Unsupported)
        );
    }
}
