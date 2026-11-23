use crate::behaviour::Check;
use crypto::{Error, Hash, Scheme, Verifier};

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
    vec![
        ("ecdsa-verify", ecdsa as Check),
        ("rsa-verify", rsa as Check),
    ]
}

fn hex(text: &str) -> Vec<u8> {
    let clean: String = text.split_whitespace().collect();
    (0..clean.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&clean[at..at + 2], 16).unwrap())
        .collect()
}

fn rejects(verifier: &Verifier, scheme: Scheme, message: &[u8], signature: &[u8]) {
    assert_eq!(verifier.check(scheme, message, signature), Ok(()));
    let mut flipped = signature.to_vec();
    flipped[10] ^= 1;
    assert_eq!(verifier.check(scheme, message, &flipped), Err(Error::Auth));
    assert_eq!(
        verifier.check(scheme, b"other", signature),
        Err(Error::Auth)
    );
}

fn ecdsa() {
    let verifier = Verifier::ecdsa(&hex(POINT)).unwrap();
    rejects(&verifier, Scheme::Ecdsa, b"sample", &hex(SIGNED));
}

fn rsa() {
    let verifier = Verifier::rsa(&hex(MODULUS), &[1, 0, 1]).unwrap();
    rejects(&verifier, Scheme::Pkcs1(Hash::Sha256), MESSAGE, &hex(PKCS));
    rejects(&verifier, Scheme::Pss(Hash::Sha256), MESSAGE, &hex(PSS));
}
