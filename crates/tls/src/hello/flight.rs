use crate::error::Error;
use crate::hello::Accepted;
use crate::message::{Kind, Message};
use crate::record::{Content, Layer, Record};
use crate::schedule::Traffic;
use crate::x509::trust::{Chain as Path, Host, Roots};
use crate::x509::{Certificate, Public, Time};
use crypto::{Aead, Hash, Running, Scheme, Verifier};

const CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify";

pub struct Verified {
    digest: Running,
    client: Traffic,
}

impl Verified {
    pub fn digest(&self) -> Vec<u8> {
        self.digest.peek()
    }

    pub fn client(&self) -> &Traffic {
        &self.client
    }
}

fn aead(suite: u16) -> Result<Aead, Error> {
    match suite {
        0x1301 => Ok(Aead::Aes128),
        0x1302 => Ok(Aead::Aes256),
        0x1303 => Ok(Aead::Chacha),
        _ => Err(Error::Suites),
    }
}

fn pull(data: &mut &[u8]) -> Result<Message, Error> {
    let (message, used) = Message::parse(data, (1 << 24) - 1)?.ok_or(Error::Length)?;
    *data = &data[used..];
    Ok(message)
}

fn need(message: &Message, kind: Kind) -> Result<(), Error> {
    if message.kind == kind {
        Ok(())
    } else {
        Err(Error::Kind)
    }
}

fn absorb(digest: &mut Running, message: &Message) -> Result<(), Error> {
    digest.update(&message.write()?);
    Ok(())
}

fn scheme(algorithm: u16) -> Result<Scheme, Error> {
    match algorithm {
        0x0403 => Ok(Scheme::Ecdsa),
        0x0804 => Ok(Scheme::Pss(Hash::Sha256)),
        0x0805 => Ok(Scheme::Pss(Hash::Sha384)),
        _ => Err(Error::Value),
    }
}

fn verifier(key: &Public) -> Result<Verifier, Error> {
    match key {
        Public::Ec { point, .. } => Ok(Verifier::ecdsa(point)?),
        Public::Rsa { modulus, exponent } => Ok(Verifier::rsa(modulus, exponent)?),
        Public::Other(..) => Err(Error::Value),
    }
}

fn signed(transcript: &[u8]) -> Vec<u8> {
    let mut data = vec![0x20; 64];
    data.extend_from_slice(CONTEXT);
    data.push(0);
    data.extend_from_slice(transcript);
    data
}

fn chain(entries: &[crate::Entry], roots: &Roots, now: Time, host: &Host) -> Result<Public, Error> {
    let leaf = entries.first().ok_or(Error::Missing)?;
    let cert = Certificate::parse(&leaf.cert).map_err(|_| Error::Value)?;
    let mut pool = Vec::new();
    for entry in &entries[1..] {
        pool.push(Certificate::parse(&entry.cert).map_err(|_| Error::Value)?);
    }
    Path::build(&cert, &pool, roots, now).map_err(|_| Error::Value)?;
    crate::x509::trust::verify(&cert, host).map_err(|_| Error::Value)?;
    Ok(cert.key.clone())
}

fn opened(accepted: &Accepted, records: &[Record]) -> Result<Vec<u8>, Error> {
    let aead = aead(accepted.reply.suite)?;
    let mut layer = Layer::new(aead, &accepted.server.keys(aead)?)?;
    let mut payload = Vec::new();
    for record in records {
        let opened = layer.unprotect(record)?;
        if opened.content != Content::Handshake {
            return Err(Error::Kind);
        }
        payload.extend(opened.payload);
    }
    Ok(payload)
}

impl Accepted {
    pub fn verify(
        &self,
        host: &str,
        roots: &Roots,
        now: Time,
        records: &[Record],
    ) -> Result<Verified, Error> {
        let host = Host::parse(host).map_err(|_| Error::Value)?;
        let payload = opened(self, records)?;
        let rest = payload.as_slice();
        let mut data = rest;
        let mut digest = self.digest.clone();
        let extensions = pull(&mut data)?;
        need(&extensions, Kind::Extensions)?;
        let found = crate::Encrypted::parse(&extensions.body)?;
        let _ = found;
        absorb(&mut digest, &extensions)?;
        let certificate = pull(&mut data)?;
        need(&certificate, Kind::Certificate)?;
        let chain = crate::Chain::parse(&certificate.body)?;
        if !chain.context.is_empty() {
            return Err(Error::Value);
        }
        let key = self::chain(&chain.entries, roots, now, &host)?;
        absorb(&mut digest, &certificate)?;
        let verify = pull(&mut data)?;
        need(&verify, Kind::Verify)?;
        let mark = crate::Verify::parse(&verify.body)?;
        verifier(&key)?.check(
            scheme(mark.algorithm)?,
            &signed(&digest.peek()),
            &mark.signature,
        )?;
        absorb(&mut digest, &verify)?;
        let finished = pull(&mut data)?;
        need(&finished, Kind::Finished)?;
        let tag = crate::Finished::parse(&finished.body, digest.hash().size())?;
        self.server.check(&digest.peek(), &tag.data)?;
        absorb(&mut digest, &finished)?;
        if !data.is_empty() {
            return Err(Error::Trailing);
        }
        Ok(Verified {
            digest,
            client: self.client.clone(),
        })
    }
}
