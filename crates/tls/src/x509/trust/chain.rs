use super::Roots;
use crate::x509::{Certificate, Curve, Public, Scheme, Time};
use crypto::{Hash, Scheme as Method, Verifier};

const SERVER: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
const ANY: &[u8] = &[0x55, 0x1d, 0x25, 0x00];
const KNOWN: [&[u8]; 4] = [
    &[0x55, 0x1d, 0x11],
    &[0x55, 0x1d, 0x13],
    &[0x55, 0x1d, 0x0f],
    &[0x55, 0x1d, 0x25],
];
const SIGN: u16 = 1 << 5;
const LIMIT: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Defect {
    Unlinked,
    Dated,
    Authority,
    Usage,
    Depth,
    Purpose,
    Critical,
    Long,
    Scheme,
    Forged,
}

#[derive(Debug, Clone)]
pub struct Chain {
    certs: Vec<Certificate>,
}

struct Search<'a> {
    pool: &'a [Certificate],
    roots: &'a Roots,
    now: Time,
    path: Vec<&'a Certificate>,
    defect: Option<Defect>,
}

impl Chain {
    pub fn build<'a>(
        leaf: &'a Certificate,
        pool: &'a [Certificate],
        roots: &'a Roots,
        now: Time,
    ) -> Result<Chain, Defect> {
        let mut search = Search {
            pool,
            roots,
            now,
            path: vec![leaf],
            defect: None,
        };
        search.common(leaf)?;
        Search::purpose(leaf)?;
        if search.walk() {
            let certs = search.path.into_iter().cloned().collect();
            return Ok(Chain { certs });
        }
        Err(search.defect.unwrap_or(Defect::Unlinked))
    }

    pub fn certs(&self) -> &[Certificate] {
        &self.certs
    }
}

impl<'a> Search<'a> {
    fn same(left: &Certificate, right: &Certificate) -> bool {
        left.tbs == right.tbs && left.signature == right.signature
    }

    fn issued(cert: &Certificate) -> bool {
        cert.subject.der == cert.issuer.der
    }

    fn trusted(&self, cert: &Certificate) -> bool {
        let anchors = self.roots.anchors(&cert.subject);
        anchors.iter().any(|anchor| Self::same(anchor, cert))
    }

    fn note(&mut self, defect: Defect) {
        if self.defect.is_none() {
            self.defect = Some(defect);
        }
    }

    fn common(&self, cert: &Certificate) -> Result<(), Defect> {
        let listed = |id: &[u8]| KNOWN.contains(&id);
        if cert
            .extensions
            .iter()
            .any(|ext| ext.critical && !listed(ext.id.bytes()))
        {
            return Err(Defect::Critical);
        }
        if self.now < cert.from || cert.until < self.now {
            return Err(Defect::Dated);
        }
        Ok(())
    }

    fn purpose(cert: &Certificate) -> Result<(), Defect> {
        let serves = |id: &[u8]| id == SERVER || id == ANY;
        let found = cert.purposes.as_ref();
        if found.is_some_and(|ids| !ids.iter().any(|id| serves(id.bytes()))) {
            return Err(Defect::Purpose);
        }
        Ok(())
    }

    fn authority(&self, cert: &Certificate, anchor: bool) -> Result<(), Defect> {
        self.common(cert)?;
        if !anchor {
            Self::purpose(cert)?;
        }
        match cert.basic {
            Some(basic) if !basic.ca => return Err(Defect::Authority),
            None if !anchor => return Err(Defect::Authority),
            _ => {}
        }
        if cert.usage.is_some_and(|bits| bits & SIGN == 0) {
            return Err(Defect::Usage);
        }
        let below = self.path[1..].iter().filter(|each| !Self::issued(each));
        let limit = cert.basic.and_then(|basic| basic.depth);
        if limit.is_some_and(|max| below.count() as u64 > max) {
            return Err(Defect::Depth);
        }
        Ok(())
    }

    fn candidates(&self, top: &Certificate) -> Vec<(&'a Certificate, bool)> {
        let roots = self.roots;
        let mut out: Vec<(&'a Certificate, bool)> = roots
            .anchors(&top.issuer)
            .into_iter()
            .map(|cert| (cert, true))
            .collect();
        let named = |cert: &&'a Certificate| cert.subject.der == top.issuer.der;
        out.extend(self.pool.iter().filter(named).map(|cert| (cert, false)));
        out
    }

    fn walk(&mut self) -> bool {
        let top = self.path[self.path.len() - 1];
        if self.trusted(top) {
            return true;
        }
        if self.path.len() >= LIMIT {
            self.note(Defect::Long);
            return false;
        }
        for (cert, anchor) in self.candidates(top) {
            if self.path.iter().any(|seen| Self::same(seen, cert)) {
                continue;
            }
            if let Err(defect) = self.authority(cert, anchor) {
                self.note(defect);
                continue;
            }
            if let Err(defect) = prove(top, cert) {
                self.note(defect);
                continue;
            }
            self.path.push(cert);
            if self.walk() {
                return true;
            }
            self.path.pop();
        }
        false
    }
}

fn prove(cert: &Certificate, issuer: &Certificate) -> Result<(), Defect> {
    let (verifier, method) = match (cert.outer.scheme(), &issuer.key) {
        (
            Scheme::Ecdsa256,
            Public::Ec {
                curve: Curve::P256,
                point,
            },
        ) => (
            Verifier::ecdsa(point).map_err(|_| Defect::Scheme)?,
            Method::Ecdsa,
        ),
        (Scheme::Rsa256, Public::Rsa { modulus, exponent }) => (
            Verifier::rsa(modulus, exponent).map_err(|_| Defect::Scheme)?,
            Method::Pkcs1(Hash::Sha256),
        ),
        (Scheme::Rsa384, Public::Rsa { modulus, exponent }) => (
            Verifier::rsa(modulus, exponent).map_err(|_| Defect::Scheme)?,
            Method::Pkcs1(Hash::Sha384),
        ),
        (Scheme::Rsa512, Public::Rsa { modulus, exponent }) => (
            Verifier::rsa(modulus, exponent).map_err(|_| Defect::Scheme)?,
            Method::Pkcs1(Hash::Sha512),
        ),
        _ => return Err(Defect::Scheme),
    };
    verifier
        .check(method, &cert.tbs, &cert.signature)
        .map_err(|_| Defect::Forged)
}
