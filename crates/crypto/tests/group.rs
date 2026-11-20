mod common;

use common::hex;
use crypto::{Error, Group};

const ALICE: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
const BOB: &str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
const ALICEPUB: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
const BOBPUB: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
const SHARED: &str = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

const FIRST: &str = "c88f01f510d9ac3f70a292daa2316de544e9aab8afe84049c62a9c57862d1433";
const SECOND: &str = "c6ef9c5d78ae012a011164acb397ce2088685d8f06bf9be0b283ab46476bee53";
const FIRSTPUB: &str = "04dad0b65394221cf9b051e1feca5787d098dfe637fc90b9ef945d0c37725811805271a0461cdb8252d61f1c456fa3e59ab1f45b33accf5f58389e0577b8990bb3";
const SECONDPUB: &str = "04d12dfb5289c8d4f81208b70270398c342296970a0bccb74c736fc7554494bf6356fbf3ca366cc23e8157854c13c58d6aac23f046ada30f8353e74f33039872ab";
const AGREED: &str = "d6840f6b42f6edafd13116e0e12565202fef8e9ece7dce03812464d04b9442de";

#[test]
fn rfc7748() {
    let group = Group::X25519;
    assert_eq!(group.public(&hex(ALICE)).unwrap(), hex(ALICEPUB));
    assert_eq!(group.public(&hex(BOB)).unwrap(), hex(BOBPUB));
    assert_eq!(group.agree(&hex(ALICE), &hex(BOBPUB)).unwrap(), hex(SHARED));
    assert_eq!(group.agree(&hex(BOB), &hex(ALICEPUB)).unwrap(), hex(SHARED));
}

#[test]
fn rfc5903() {
    let group = Group::Secp256r1;
    assert_eq!(group.public(&hex(FIRST)).unwrap(), hex(FIRSTPUB));
    assert_eq!(group.public(&hex(SECOND)).unwrap(), hex(SECONDPUB));
    let left = group.agree(&hex(FIRST), &hex(SECONDPUB)).unwrap();
    let right = group.agree(&hex(SECOND), &hex(FIRSTPUB)).unwrap();
    assert_eq!(left, hex(AGREED));
    assert_eq!(right, hex(AGREED));
}

#[test]
fn zero() {
    let group = Group::X25519;
    assert_eq!(group.agree(&hex(ALICE), &[0; 32]), Err(Error::Zero));
    let mut one = [0u8; 32];
    one[0] = 1;
    assert_eq!(group.agree(&hex(ALICE), &one), Err(Error::Zero));
}

#[test]
fn lengths() {
    for group in [Group::X25519, Group::Secp256r1] {
        assert_eq!(group.secret(), 32);
        for wrong in [0, 31, 33, 64] {
            let secret = vec![5u8; wrong];
            assert_eq!(
                group.public(&secret),
                Err(Error::Length),
                "{group:?} {wrong}"
            );
            let good = vec![5u8; group.share()];
            assert_eq!(
                group.agree(&secret, &good),
                Err(Error::Length),
                "{group:?} {wrong}"
            );
        }
    }
    assert_eq!((Group::X25519.share(), Group::Secp256r1.share()), (32, 65));
    assert_eq!(
        Group::X25519.agree(&hex(ALICE), &[9; 31]),
        Err(Error::Length)
    );
    assert_eq!(
        Group::X25519.agree(&hex(ALICE), &[9; 33]),
        Err(Error::Length)
    );
}

#[test]
fn points() {
    let group = Group::Secp256r1;
    let secret = hex(FIRST);
    let good = hex(SECONDPUB);
    assert!(group.agree(&secret, &good).is_ok());
    let mut off = good.clone();
    off[64] ^= 1;
    assert_eq!(group.agree(&secret, &off), Err(Error::Point));
    let mut tagged = good.clone();
    tagged[0] = 0x02;
    assert_eq!(group.agree(&secret, &tagged), Err(Error::Point));
    assert_eq!(group.agree(&secret, &good[..33]), Err(Error::Point));
    assert_eq!(group.agree(&secret, &good[1..]), Err(Error::Point));
    assert!(
        group
            .agree(&secret, &[good.clone(), vec![0]].concat())
            .is_err()
    );
    let mut infinity = vec![0u8; 65];
    infinity[0] = 0x04;
    assert_eq!(group.agree(&secret, &infinity), Err(Error::Point));
    let mut wide = good.clone();
    wide[1..33].copy_from_slice(&[0xff; 32]);
    assert_eq!(group.agree(&secret, &wide), Err(Error::Point));
}

#[test]
fn scalars() {
    let group = Group::Secp256r1;
    assert_eq!(group.public(&[0; 32]), Err(Error::Scalar));
    assert_eq!(group.public(&[0xff; 32]), Err(Error::Scalar));
    let peer = hex(SECONDPUB);
    assert_eq!(group.agree(&[0; 32], &peer), Err(Error::Scalar));
    assert_eq!(group.agree(&[0xff; 32], &peer), Err(Error::Scalar));
}

#[test]
fn symmetry() {
    for group in [Group::X25519, Group::Secp256r1] {
        let secrets: Vec<Vec<u8>> = (1..=6u8)
            .map(|seed| {
                (0..32u8)
                    .map(|at| at.wrapping_mul(seed).wrapping_add(seed * 17) | 1)
                    .map(|byte| byte & 0x7f)
                    .collect()
            })
            .collect();
        for left in &secrets {
            for right in &secrets {
                let one = group.agree(left, &group.public(right).unwrap()).unwrap();
                let two = group.agree(right, &group.public(left).unwrap()).unwrap();
                assert_eq!(one, two, "{group:?}");
                assert_eq!(one.len(), 32);
            }
        }
    }
}

#[test]
fn groups() {
    let x = Group::X25519.public(&hex(ALICE)).unwrap();
    let p = Group::Secp256r1.public(&hex(ALICE)).unwrap();
    assert_eq!((x.len(), p.len()), (32, 65));
    assert_eq!(p[0], 4);
}
