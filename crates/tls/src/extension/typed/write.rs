use super::{Identity, Share, Typed};
use crate::error::Error;
use crate::extension::Extension;
use crate::field::Out;

impl Typed {
    pub fn write(&self) -> Result<Extension, Error> {
        let (kind, data) = match self {
            Typed::Name(host) => (0, Self::name(host)?),
            Typed::Groups(items) => (10, Self::shorts(items, 2)?),
            Typed::Algorithms(items) => (13, Self::shorts(items, 2)?),
            Typed::Protocols(names) => (16, Self::protocols(names)?),
            Typed::Offered {
                identities,
                binders,
            } => (41, Self::offered(identities, binders)?),
            Typed::Selected(group) => (41, group.to_be_bytes().to_vec()),
            Typed::Early(None) => (42, Vec::new()),
            Typed::Early(Some(limit)) => (42, limit.to_be_bytes().to_vec()),
            Typed::Versions(items) => (43, Self::shorts(items, 1)?),
            Typed::Version(version) => (43, version.to_be_bytes().to_vec()),
            Typed::Cookie(bytes) => (44, Self::wrapped(bytes, 2)?),
            Typed::Modes(bytes) => (45, Self::wrapped(bytes, 1)?),
            Typed::Shares(items) => (51, Self::shares(items)?),
            Typed::Chosen(share) => (51, Self::share(share)?),
            Typed::Group(group) => (51, group.to_be_bytes().to_vec()),
        };
        Ok(Extension { kind, data })
    }

    fn name(host: &Option<Vec<u8>>) -> Result<Vec<u8>, Error> {
        let Some(host) = host else {
            return Ok(Vec::new());
        };
        if host.is_empty() {
            return Err(Error::Length);
        }
        let mut list = Out::new();
        list.byte(0);
        list.prefixed(host, 2)?;
        Self::wrapped(&list.finish(), 2)
    }

    fn shorts(items: &[u16], width: usize) -> Result<Vec<u8>, Error> {
        let bytes: Vec<u8> = items.iter().flat_map(|item| item.to_be_bytes()).collect();
        Self::wrapped(&bytes, width)
    }

    fn wrapped(bytes: &[u8], width: usize) -> Result<Vec<u8>, Error> {
        if bytes.is_empty() {
            return Err(Error::Length);
        }
        let mut out = Out::new();
        out.prefixed(bytes, width)?;
        Ok(out.finish())
    }

    fn protocols(names: &[Vec<u8>]) -> Result<Vec<u8>, Error> {
        let mut list = Out::new();
        for name in names {
            if name.is_empty() {
                return Err(Error::Length);
            }
            list.prefixed(name, 1)?;
        }
        Self::wrapped(&list.finish(), 2)
    }

    fn offered(identities: &[Identity], binders: &[Vec<u8>]) -> Result<Vec<u8>, Error> {
        if identities.is_empty() {
            return Err(Error::Length);
        }
        if identities.len() != binders.len() {
            return Err(Error::Value);
        }
        let mut first = Out::new();
        for identity in identities {
            if identity.label.is_empty() {
                return Err(Error::Length);
            }
            first.prefixed(&identity.label, 2)?;
            first.long(identity.age);
        }
        let mut second = Out::new();
        for binder in binders {
            if binder.len() < 32 {
                return Err(Error::Length);
            }
            second.prefixed(binder, 1)?;
        }
        let mut out = Out::new();
        out.prefixed(&first.finish(), 2)?;
        out.prefixed(&second.finish(), 2)?;
        Ok(out.finish())
    }

    fn shares(items: &[Share]) -> Result<Vec<u8>, Error> {
        let mut list = Out::new();
        for (at, item) in items.iter().enumerate() {
            if items[..at].iter().any(|seen| seen.group == item.group) {
                return Err(Error::Duplicate);
            }
            list.short(item.group);
            list.prefixed(&Self::nonempty(&item.key)?, 2)?;
        }
        let mut out = Out::new();
        out.prefixed(&list.finish(), 2)?;
        Ok(out.finish())
    }

    fn share(item: &Share) -> Result<Vec<u8>, Error> {
        let mut out = Out::new();
        out.short(item.group);
        out.prefixed(&Self::nonempty(&item.key)?, 2)?;
        Ok(out.finish())
    }

    fn nonempty(bytes: &[u8]) -> Result<Vec<u8>, Error> {
        if bytes.is_empty() {
            return Err(Error::Length);
        }
        Ok(bytes.to_vec())
    }
}
