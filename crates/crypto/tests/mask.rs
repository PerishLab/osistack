mod common;

use common::hex;
use crypto::{Aead, Error, Mask};

fn sample(text: &str) -> [u8; 16] {
    hex(text).try_into().unwrap()
}

#[test]
fn aes() {
    let key = hex("9f50449e04a0e810283a1e9933adedd2");
    let mask = Mask::new(Aead::Aes128, &key).unwrap();
    assert_eq!(
        mask.mask(&sample("d1b1c98dd7689fb8ec11d242b123dc9b"))
            .to_vec(),
        hex("437b9aec36")
    );
    let server = Mask::new(Aead::Aes128, &hex("c206b8d9b9f0f37644430b490eeaa314")).unwrap();
    let other = sample("d1b1c98dd7689fb8ec11d242b123dc9b");
    assert_ne!(server.mask(&other), mask.mask(&other));
}

#[test]
fn wide() {
    let key = hex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    let mask = Mask::new(Aead::Aes256, &key).unwrap();
    let probe = sample("000102030405060708090a0b0c0d0e0f");
    assert_eq!(mask.mask(&probe).to_vec(), hex("0639e87d0e"));
    let narrow = Mask::new(Aead::Aes128, &key[..16]).unwrap();
    assert_ne!(narrow.mask(&probe), mask.mask(&probe));
}

#[test]
fn chacha() {
    let key = hex("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");
    let mask = Mask::new(Aead::Chacha, &key).unwrap();
    assert_eq!(
        mask.mask(&sample("5e5cd55c41f69080575d7999c25a5bfb"))
            .to_vec(),
        hex("aefefe7d03")
    );
}

#[test]
fn keys() {
    for (aead, size) in [(Aead::Aes128, 16), (Aead::Aes256, 32), (Aead::Chacha, 32)] {
        assert!(Mask::new(aead, &vec![1; size]).is_ok(), "{aead:?}");
        for wrong in [0, 16, size - 1, size + 1, 32] {
            if wrong == size {
                continue;
            }
            let made = Mask::new(aead, &vec![1; wrong]);
            assert_eq!(made.err(), Some(Error::Length), "{aead:?} {wrong}");
        }
    }
}
