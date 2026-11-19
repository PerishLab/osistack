use super::{Refusal, blocks};
use crate::x509::{Certificate, Name};

const LABEL: &str = "CERTIFICATE";

#[derive(Debug, Clone, Default)]
pub struct Roots {
    entries: Vec<(Vec<u8>, Certificate)>,
}

impl Roots {
    pub fn pem(text: &str) -> Result<Self, Refusal> {
        let mut roots = Roots::default();
        for block in blocks(text)? {
            if block.label == LABEL {
                roots.add(&block.data)?;
            }
        }
        Ok(roots)
    }

    pub fn add(&mut self, der: &[u8]) -> Result<bool, Refusal> {
        let cert = Certificate::parse(der).map_err(Refusal::Certificate)?;
        if self.contains(der) {
            return Ok(false);
        }
        self.entries.push((der.to_vec(), cert));
        Ok(true)
    }

    pub fn contains(&self, der: &[u8]) -> bool {
        self.entries.iter().any(|(held, _)| held == der)
    }

    pub fn count(&self) -> usize {
        self.entries.len()
    }

    pub fn anchors(&self, issuer: &Name) -> Vec<&Certificate> {
        let same = |cert: &&Certificate| cert.subject.der == issuer.der;
        self.entries
            .iter()
            .map(|(_, cert)| cert)
            .filter(same)
            .collect()
    }
}
