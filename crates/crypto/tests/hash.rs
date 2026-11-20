mod common;

use common::hex;
use crypto::{Hash, Running};

const ALL: [Hash; 3] = [Hash::Sha256, Hash::Sha384, Hash::Sha512];

const ABC: [&str; 3] = [
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
];

const EMPTY: [&str; 3] = [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
];

const TWO: [&str; 3] = [
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b",
    "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445",
];

const MILLION: [&str; 3] = [
    "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
    "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985",
    "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
];

#[test]
fn known() {
    let long = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    for (at, hash) in ALL.into_iter().enumerate() {
        assert_eq!(hash.digest(b"abc"), hex(ABC[at]), "{hash:?}");
        assert_eq!(hash.digest(b""), hex(EMPTY[at]), "{hash:?}");
        assert_eq!(hash.digest(long), hex(TWO[at]), "{hash:?}");
    }
}

#[test]
fn million() {
    let data = vec![b'a'; 1_000_000];
    for (at, hash) in ALL.into_iter().enumerate() {
        assert_eq!(hash.digest(&data), hex(MILLION[at]), "{hash:?}");
    }
}

#[test]
fn sizes() {
    let wanted = [(32, 64), (48, 128), (64, 128)];
    for (hash, (size, block)) in ALL.into_iter().zip(wanted) {
        assert_eq!((hash.size(), hash.block()), (size, block), "{hash:?}");
        assert_eq!(hash.digest(b"x").len(), size, "{hash:?}");
        assert_eq!(Running::new(hash).hash(), hash);
    }
}

#[test]
fn pieces() {
    let data: Vec<u8> = (0..1000u32).map(|n| (n * 7) as u8).collect();
    for hash in ALL {
        let whole = hash.digest(&data);
        for cut in [0, 1, 63, 64, 65, 127, 128, 129, 500, 1000] {
            let mut running = Running::new(hash);
            running.update(&data[..cut]);
            running.update(&data[cut..]);
            assert_eq!(running.finish(), whole, "{hash:?} {cut}");
        }
        let mut bytes = Running::new(hash);
        data.iter().for_each(|byte| bytes.update(&[*byte]));
        assert_eq!(bytes.finish(), whole, "{hash:?}");
    }
}

#[test]
fn peek() {
    for hash in ALL {
        let mut running = Running::new(hash);
        running.update(b"first");
        let early = running.peek();
        assert_eq!(early, hash.digest(b"first"));
        assert_eq!(running.peek(), early);
        running.update(b"second");
        assert_eq!(running.peek(), hash.digest(b"firstsecond"));
        assert_eq!(running.finish(), hash.digest(b"firstsecond"));
    }
}

#[test]
fn cloned() {
    for hash in ALL {
        let mut left = Running::new(hash);
        left.update(b"shared");
        let mut right = left.clone();
        left.update(b" left");
        right.update(b" right");
        assert_eq!(left.finish(), hash.digest(b"shared left"));
        assert_eq!(right.finish(), hash.digest(b"shared right"));
    }
}

#[test]
fn distinct() {
    let data = b"same input";
    let outputs: Vec<Vec<u8>> = ALL.iter().map(|hash| hash.digest(data)).collect();
    assert_ne!(outputs[0], outputs[1][..32]);
    assert_ne!(outputs[1], outputs[2][..48]);
}
