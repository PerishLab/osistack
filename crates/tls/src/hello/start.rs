use crate::error::Error;
use crate::extension::{Share, Typed};
use crate::hello::Offer;
use crate::message::{Kind, Message};
use crypto::{Hash, Running};

pub struct Hello {
    pub(super) offer: Offer,
    pub(super) spoken: Vec<u8>,
    pub(super) digest: Running,
}

impl Hello {
    pub fn start(
        host: &[u8],
        protocols: &[Vec<u8>],
        share: Share,
        random: [u8; 32],
    ) -> Result<Self, Error> {
        Self::begin(host, protocols, &[share], random)
    }

    pub fn begin(
        host: &[u8],
        protocols: &[Vec<u8>],
        shares: &[Share],
        random: [u8; 32],
    ) -> Result<Self, Error> {
        if shares.is_empty() {
            return Err(Error::Missing);
        }
        let groups: Vec<u16> = shares.iter().map(|share| share.group).collect();
        let extensions = vec![
            Typed::Name(Some(host.to_vec())).write()?,
            Typed::Groups(groups).write()?,
            Typed::Algorithms(vec![0x0403, 0x0804]).write()?,
            Typed::Protocols(protocols.to_vec()).write()?,
            Typed::Versions(vec![0x0304]).write()?,
            Typed::Shares(shares.to_vec()).write()?,
        ];
        let offer = Offer {
            random,
            session: Vec::new(),
            suites: vec![0x1301, 0x1303, 0x1302],
            extensions,
        };
        let spoken = Message {
            kind: Kind::Offer,
            body: offer.write()?,
        }
        .write()?;
        let mut digest = Running::new(Hash::Sha256);
        digest.update(&spoken);
        Ok(Self {
            offer,
            spoken,
            digest,
        })
    }

    pub fn offer(&self) -> &Offer {
        &self.offer
    }

    pub fn spoken(&self) -> &[u8] {
        &self.spoken
    }

    pub fn digest(&self) -> Vec<u8> {
        self.digest.peek()
    }

    pub fn offered(spoken: &[u8]) -> Result<Self, Error> {
        let (message, used) = Message::parse(spoken, (1 << 24) - 1)?.ok_or(Error::Length)?;
        if used != spoken.len() || message.kind != Kind::Offer {
            return Err(Error::Kind);
        }
        let offer = Offer::parse(&message.body)?;
        let mut digest = Running::new(Hash::Sha256);
        digest.update(spoken);
        Ok(Self {
            offer,
            spoken: spoken.to_vec(),
            digest,
        })
    }
}
