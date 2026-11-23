use crate::behaviour::Check;
use crypto::Group;

pub fn table() -> Vec<(&'static str, Check)> {
    vec![("x25519", x25519 as Check), ("p256", p256 as Check)]
}

fn secret(seed: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (at, slot) in out.iter_mut().enumerate() {
        *slot = (at as u8).wrapping_mul(seed).wrapping_add(seed * 17) | 1;
        *slot &= 0x7f;
    }
    out
}

fn shared(group: Group, left: &[u8; 32], right: &[u8; 32]) -> Vec<u8> {
    let one = group.agree(left, &group.public(right).unwrap()).unwrap();
    let two = group.agree(right, &group.public(left).unwrap()).unwrap();
    assert_eq!(one, two);
    assert_eq!(one.len(), 32);
    one
}

fn damaged(group: Group, secret: &[u8; 32], peer: &[u8]) {
    let good = group.agree(secret, peer).unwrap();
    let mut flipped = peer.to_vec();
    *flipped.last_mut().unwrap() ^= 1;
    if let Ok(other) = group.agree(secret, &flipped) {
        assert_ne!(other, good);
    }
}

fn x25519() {
    let group = Group::X25519;
    let alice = secret(1);
    let bob = secret(2);
    assert_eq!(group.public(&alice).unwrap().len(), 32);
    shared(group, &alice, &bob);
    damaged(group, &alice, &group.public(&bob).unwrap());
    assert!(group.agree(&alice, &[0; 32]).is_err());
}

fn p256() {
    let group = Group::Secp256r1;
    let alice = secret(1);
    let bob = secret(2);
    let share = group.public(&bob).unwrap();
    assert_eq!(share.len(), 65);
    shared(group, &alice, &bob);
    damaged(group, &alice, &share);
}
