use crypto::{Group, Hash};

#[derive(Clone, Copy)]
struct Word([u64; 4]);

const N: Word = Word([
    0xF3B9CAC2FC632551,
    0xBCE6FAADA7179E84,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFF00000000,
]);

const C: Word = Word([
    0x0C46353D039CDAAF,
    0x4319055258E8617B,
    0x0000000000000000,
    0x00000000FFFFFFFF,
]);

impl Word {
    fn load(bytes: &[u8; 32]) -> Self {
        Self([
            u64::from_be_bytes(bytes[24..32].try_into().unwrap()),
            u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
            u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
            u64::from_be_bytes(bytes[0..8].try_into().unwrap()),
        ])
    }

    fn store(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&self.0[3].to_be_bytes());
        out[8..16].copy_from_slice(&self.0[2].to_be_bytes());
        out[16..24].copy_from_slice(&self.0[1].to_be_bytes());
        out[24..32].copy_from_slice(&self.0[0].to_be_bytes());
        out
    }

    fn cmp(self, other: Self) -> i8 {
        for index in (0..4).rev() {
            if self.0[index] < other.0[index] {
                return -1;
            }
            if self.0[index] > other.0[index] {
                return 1;
            }
        }
        0
    }

    fn zero(self) -> bool {
        self.0.iter().all(|limb| *limb == 0)
    }

    fn sub(self, other: Self) -> Self {
        let mut out = [0u64; 4];
        let mut borrow = 0u64;
        for (slot, (mine, theirs)) in out.iter_mut().zip(self.0.into_iter().zip(other.0)) {
            let (part, lost) = mine.overflowing_sub(theirs);
            let (part, again) = part.overflowing_sub(borrow);
            *slot = part;
            borrow = u64::from(lost || again);
        }
        Self(out)
    }

    fn shrink(self) -> Self {
        let mut out = self;
        while out.cmp(N) >= 0 {
            out = out.sub(N);
        }
        out
    }

    fn plus(self, other: Self) -> Self {
        let mut out = [0u64; 4];
        let mut carry = 0u64;
        for (slot, (mine, theirs)) in out.iter_mut().zip(self.0.into_iter().zip(other.0)) {
            let (part, overflow) = mine.overflowing_add(theirs);
            let (part, again) = part.overflowing_add(carry);
            *slot = part;
            carry = u64::from(overflow || again);
        }
        let out = Self(out);
        if carry > 0 || out.cmp(N) >= 0 {
            out.sub(N)
        } else {
            out
        }
    }

    fn product(self, other: Self) -> [u64; 8] {
        let mut out = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let sum = out[i + j] as u128 + self.0[i] as u128 * other.0[j] as u128 + carry;
                out[i + j] = sum as u64;
                carry = sum >> 64;
            }
            let mut slot = i + 4;
            while carry > 0 {
                let sum = out[slot] as u128 + carry;
                out[slot] = sum as u64;
                carry = sum >> 64;
                slot += 1;
            }
        }
        out
    }

    fn times(self, other: Self) -> Self {
        let wide = self.product(other);
        let lo = Self([wide[0], wide[1], wide[2], wide[3]]);
        let hi = Self([wide[4], wide[5], wide[6], wide[7]]);
        lo.fold(hi)
    }

    fn fold(self, high: Self) -> Self {
        if high.zero() {
            return self.shrink();
        }
        let wide = high.product(C);
        let mid = Self([wide[0], wide[1], wide[2], wide[3]]);
        let top = Self([wide[4], wide[5], wide[6], wide[7]]);
        self.shrink()
            .plus(mid.shrink())
            .plus(Self([0; 4]).fold(top))
    }

    fn invert(self) -> Self {
        let mut exponent = N;
        exponent.0[0] -= 2;
        let mut base = self;
        let mut acc = Self([1, 0, 0, 0]);
        for limb in exponent.0 {
            let mut rest = limb;
            for _ in 0..64 {
                if rest & 1 != 0 {
                    acc = acc.times(base);
                }
                base = base.times(base);
                rest >>= 1;
            }
        }
        acc
    }

    fn hashed(raw: &[u8]) -> Self {
        let mut padded = [0u8; 32];
        padded.copy_from_slice(&raw[..32]);
        Self::load(&padded).shrink()
    }

    fn integer(self) -> Vec<u8> {
        let raw = self.store();
        let start = raw.iter().position(|byte| *byte != 0).unwrap_or(31);
        let mut body = raw[start..].to_vec();
        if body[0] & 0x80 != 0 {
            body.insert(0, 0);
        }
        let mut out = vec![0x02, body.len() as u8];
        out.extend(body);
        out
    }
}

fn secret(name: &str) -> [u8; 32] {
    let mut value = Word::hashed(&Hash::Sha256.digest(name.as_bytes()));
    if value.zero() {
        value.0[0] = 1;
    }
    value.store()
}

pub fn share(name: &str) -> Vec<u8> {
    Group::Secp256r1.public(&secret(name)).unwrap()
}

pub fn signed(issuer: &str, tbs: &[u8]) -> Vec<u8> {
    let key = Word::load(&secret(issuer));
    let hash = Word::hashed(&Hash::Sha256.digest(tbs));
    for counter in 0u8..=255 {
        let mut seed = secret(issuer).to_vec();
        seed.push(counter);
        seed.extend_from_slice(tbs);
        let nonce = Word::hashed(&Hash::Sha256.digest(&seed));
        if nonce.zero() {
            continue;
        }
        let point = Group::Secp256r1.public(&nonce.store()).unwrap();
        let head: [u8; 32] = point[1..33].try_into().unwrap();
        let first = Word::load(&head).shrink();
        if first.zero() {
            continue;
        }
        let second = nonce.invert().times(hash.plus(first.times(key)));
        if second.zero() {
            continue;
        }
        let mut out = first.integer();
        out.extend(second.integer());
        let mut der = vec![0x30, out.len() as u8];
        der.extend(out);
        return der;
    }
    panic!("no nonce");
}

#[test]
fn checks() {
    use crate::support::*;
    use crypto::{Scheme, Verifier};
    let tbs = b"tbs-bytes-for-sign";
    let mark = signed("root", tbs);
    let key = share("root");
    Verifier::ecdsa(&key)
        .unwrap()
        .check(Scheme::Ecdsa, tbs, &mark)
        .unwrap();
    let mut bad = mark.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(
        Verifier::ecdsa(&key)
            .unwrap()
            .check(Scheme::Ecdsa, tbs, &bad)
            .is_err()
    );
    let cert = Spec::new("leaf", "inter", 3).cert();
    let issuer = Spec::new("inter", "root", 2).ca(None).cert();
    Verifier::ecdsa(match &issuer.key {
        tls::x509::Public::Ec { point, .. } => point,
        _ => panic!(),
    })
    .unwrap()
    .check(Scheme::Ecdsa, &cert.tbs, &cert.signature)
    .unwrap();
}

#[test]
fn scheme() {
    use crate::support::*;
    use tls::x509::trust::{Chain, Defect, Roots};
    use tls::x509::{Certificate, Time};
    let mut bytes = Spec::new("leaf", "inter", 3).der();
    let mark = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    let mut found = 0;
    for index in 0..bytes.len() - 7 {
        if bytes[index..index + 8] == mark {
            bytes[index + 7] = 3;
            found += 1;
        }
    }
    assert_eq!(found, 2);
    let leaf = Certificate::parse(&bytes).unwrap();
    let inter = Spec::new("inter", "root", 2).ca(None);
    let root = Spec::new("root", "root", 1).ca(None);
    let mut held = Roots::default();
    held.add(&root.der()).unwrap();
    let now = Time {
        year: 2027,
        month: 6,
        day: 15,
        hour: 12,
        minute: 0,
        second: 0,
    };
    assert_eq!(
        Chain::build(&leaf, &[inter.cert()], &held, now).unwrap_err(),
        Defect::Scheme
    );
}
