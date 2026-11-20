use crate::behaviour::Check;
use crypto::{Aead, Error, Group, Hash, Mask, Running, Scheme, Secret, Verifier, hmac};

const MODULUS: &str = "\
    babeb17e39bdaab90a08a1529a3d6807b5154145cd574e86d1ebe6515223d44a\
    a1f9d41319a7ee694d6907422ea305285a9479be96ed69f9ebdd09ab7b74fde8\
    6229b2320494a85c84f7d7cecefccb2d7a432e573580ebb4fb745ffd25c79d67\
    26afdcadd65eceee506743df9fd4e5cd0b57fc39e1b500ff1acf00677820b037\
    04053f5478caf763499564cdd3c23a27093771242938c359579043d6a77da8c8\
    556e789c64ffb7676530a17b708becccfc298585d95dd03335fc6a12276df4c1\
    aa75745465c10e3f57c3fd0a8fade4fae7bc8b8b8bd650a70dc47ee7052b5d31\
    19a50e85b7a297b33d5c3f69384966590acce314a3103c7a1889ee8b06807ca1";
const PKCS: &str = "\
    3720ef5bbbb8726ff9c9561d1c466baba6b41ce266449c02d96a2e9ddc0cf978\
    4334abbce5dde94e7eed2609f2e55b6a1bbece9b610d88a5b0aba12540cf6df0\
    89f42f0f23b4578d2f3f9e0585f013e8b69e3e513749821710a43dc75bfdbbb2\
    9d69b73408feee754a660d5fae1e29a55af8d1713cd178084e6cefcbd5d892f4\
    4a34c1389defa4f9d8a4afd07d4ed785f2c70bd2e93b7fd9e98f7a06bc2b3121\
    cf8d654cd892cc3c1d61d3121f587935b822ff0bf80f88836217756a53f1a59a\
    89035f8a066955a6abb5fdf8f08e3e41b84c6ff7d2cfcc39d84425570e1b3af5\
    5b2eb7e5f094c53f0a01a7924a70f6e6e58a646086b8ca67cb8797618d601338";
const PSS: &str = "\
    807051706d4d08bfc1068fa647d141f0297a7a40cfc6dbedd869649a734433f4\
    b16e9919a74fc58e8e4d241d7443617a71f03d33624917402203ee5c1974ed37\
    5b06bf0221049eb243ee8ac203f87714cdcc0b5728ecb7f5b93313e2f7a6e428\
    2b0fcb693745c2ef6d696a6784c37df3a9ead5b60209dd2125055733fcf9b8cd\
    854930f5f7f081a94945176368d494f94add0dc429790b9874d49070d47e5248\
    7e759942dbe8000fa3632e57e254528a34ba868a5169385c92cbb1edb467388f\
    ac38b18c5a5b18bdc6cb94306f432178d26e5cf21c8057cfb7dc2faf0591ddb4\
    4b06fb1b384322334bb88f35f31970ebdcede692fbf3d91bec7b2d3697abef6a";
const POINT: &str = "\
    0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29f\
    b67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d44622\
    99";
const SIGNED: &str = "\
    3046022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0e\
    a84eaf3716022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff406\
    4dc4ab2f843acda8";

const MESSAGE: &[u8] = b"osistack seam";

pub fn table() -> Vec<(&'static str, Check)> {
    vec![("seam", seam as Check)]
}

fn hex(text: &str) -> Vec<u8> {
    let clean: String = text.split_whitespace().collect();
    (0..clean.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&clean[at..at + 2], 16).unwrap())
        .collect()
}

struct End {
    secret: Vec<u8>,
    share: Vec<u8>,
    group: Group,
}

impl End {
    fn new(group: Group, seed: u8) -> Self {
        let secret: Vec<u8> = (0..32u8)
            .map(|at| (at ^ seed).wrapping_mul(3) | 1)
            .collect();
        let secret: Vec<u8> = secret.iter().map(|byte| byte & 0x7f).collect();
        let share = group.public(&secret).unwrap();
        End {
            secret,
            share,
            group,
        }
    }

    fn agree(&self, peer: &[u8]) -> Vec<u8> {
        self.group.agree(&self.secret, peer).unwrap()
    }
}

fn keys(shared: &[u8], aead: Aead) -> (Vec<u8>, [u8; 12], Vec<u8>) {
    let early = Secret::extract(Hash::Sha256, &[0; 32], shared).unwrap();
    let derived = early
        .label(b"derived", &Hash::Sha256.digest(b""), 32)
        .unwrap();
    let master = Secret::extract(Hash::Sha256, &derived, &[0; 32]).unwrap();
    let traffic = master
        .label(b"c ap traffic", &Hash::Sha256.digest(b"hello"), 32)
        .unwrap();
    let traffic = Secret::new(Hash::Sha256, &traffic).unwrap();
    let key = traffic.label(b"key", b"", aead.key()).unwrap();
    let iv: [u8; 12] = traffic.label(b"iv", b"", 12).unwrap().try_into().unwrap();
    (key, iv, traffic.label(b"hp", b"", aead.key()).unwrap())
}

fn exchange(group: Group) -> Vec<u8> {
    let client = End::new(group, 1);
    let server = End::new(group, 2);
    let one = client.agree(&server.share);
    let two = server.agree(&client.share);
    assert_eq!(one, two);
    assert_ne!(client.share, server.share);
    one
}

fn protect(aead: Aead, shared: &[u8]) {
    let (key, iv, hp) = keys(shared, aead);
    let (other, again, mask) = keys(shared, aead);
    assert_eq!((&key, iv, &hp), (&other, again, &mask));
    let client = aead.cipher(&key).unwrap();
    let server = aead.cipher(&other).unwrap();
    let mut data = b"GET / HTTP/1.1".to_vec();
    let tag = client.seal(&iv, b"header", &mut data).unwrap();
    assert_ne!(data, b"GET / HTTP/1.1");
    let mut copy = data.clone();
    assert_eq!(server.open(&iv, b"header", &mut copy, &tag), Ok(()));
    assert_eq!(copy, b"GET / HTTP/1.1");
    let mut bad = data.clone();
    bad[0] ^= 1;
    assert_eq!(
        server.open(&iv, b"header", &mut bad, &tag),
        Err(Error::Auth)
    );
    assert_eq!(
        server.open(&iv, b"other", &mut data, &tag),
        Err(Error::Auth)
    );
    let sample = [7u8; 16];
    let left = Mask::new(aead, &hp).unwrap().mask(&sample);
    assert_eq!(left, Mask::new(aead, &mask).unwrap().mask(&sample));
}

fn finished(shared: &[u8]) {
    let mut client = Running::new(Hash::Sha256);
    let mut server = client.clone();
    for part in [&b"client hello"[..], b"server hello", b"certificate"] {
        client.update(part);
        server.update(part);
    }
    assert_eq!(client.peek(), server.peek());
    let base = Secret::extract(Hash::Sha256, b"", shared).unwrap();
    let key = base.label(b"finished", b"", 32).unwrap();
    let tag = hmac::sign(Hash::Sha256, &key, &client.peek()).unwrap();
    assert_eq!(
        hmac::verify(Hash::Sha256, &key, &server.peek(), &tag),
        Ok(())
    );
    server.update(b"tampered");
    let outcome = hmac::verify(Hash::Sha256, &key, &server.finish(), &tag);
    assert_eq!(outcome, Err(Error::Auth));
}

fn signed() {
    let ecdsa = Verifier::ecdsa(&hex(POINT)).unwrap();
    assert_eq!(ecdsa.check(Scheme::Ecdsa, b"sample", &hex(SIGNED)), Ok(()));
    assert_eq!(
        ecdsa.check(Scheme::Ecdsa, b"other", &hex(SIGNED)),
        Err(Error::Auth)
    );
    let rsa = Verifier::rsa(&hex(MODULUS), &[1, 0, 1]).unwrap();
    let rows = [
        (Scheme::Pkcs1(Hash::Sha256), hex(PKCS)),
        (Scheme::Pss(Hash::Sha256), hex(PSS)),
    ];
    for (scheme, signature) in rows {
        assert_eq!(rsa.check(scheme, MESSAGE, &signature), Ok(()), "{scheme:?}");
        let mut flipped = signature.clone();
        flipped[10] ^= 1;
        assert_eq!(
            rsa.check(scheme, MESSAGE, &flipped),
            Err(Error::Auth),
            "{scheme:?}"
        );
        assert_eq!(
            rsa.check(scheme, b"other", &signature),
            Err(Error::Auth),
            "{scheme:?}"
        );
    }
}

fn seam() {
    for group in [Group::X25519, Group::Secp256r1] {
        let shared = exchange(group);
        for aead in [Aead::Aes128, Aead::Aes256, Aead::Chacha] {
            protect(aead, &shared);
        }
        finished(&shared);
    }
    signed();
}
